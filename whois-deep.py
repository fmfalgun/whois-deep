#!/usr/bin/env python3
"""
whois-deep  —  Registrar WHOIS + IP WHOIS via RIR

External tools used:
  whois   system binary — registrar WHOIS query, IP WHOIS query
  dig     system binary — DNS A-record resolution

Executes two queries most WHOIS tools skip:
  1. Registrar-level WHOIS  → queries the registrar's own WHOIS server directly
  2. IP WHOIS via RIR       → resolves the domain to IP, queries the RIR for block info

Results are cached locally (SQLite, ./cache.db) with a configurable TTL.
Use --submit to opt-in to contributing findings back to the project.

Usage:
  python3 whois-deep.py -d startbitsolutions.com
  python3 whois-deep.py -d nmap.org --output nmap.json
  python3 whois-deep.py -d google.com --no-cache
  python3 whois-deep.py -d google.com --ttl 48
  python3 whois-deep.py -d nmap.org --submit
  python3 whois-deep.py --reconfigure
"""

import subprocess
import json
import re
import sys
import math
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

__version__       = "1.0.0"
CACHE_DB          = "./cache.db"
CONFIG_PATH       = Path.home() / ".config" / "whois-deep" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/whois-deep/issues"


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

RIR_SERVERS = {
    "arin":    "whois.arin.net",
    "ripe":    "whois.ripe.net",
    "apnic":   "whois.apnic.net",
    "lacnic":  "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}

# RIPE responses start with "%" comment lines which contain
# "% Information related to" — added as explicit markers.
# Also added "inetnum:" as a RIPE-specific field marker (ARIN uses NetRange).
RIR_MARKERS = {
    "arin":    ["american registry", "arin.net", "arin whois", "# arin"],
    "ripe":    [
        "ripe network", "ripe ncc", "ripe.net",
        "% information related to",    # RIPE's standard header line
        "% this is the ripe",
        "% the ripe",
        "inetnum:",                    # RIPE uses lowercase inetnum (ARIN uses NetRange)
    ],
    "apnic":   ["apnic", "asia pacific", "apnic.net", "% information related to 'apnic'"],
    "lacnic":  ["lacnic", "latin america", "lacnic.net"],
    "afrinic": ["afrinic", "africa", "afrinic.net"],
}

HOSTING_SIGNATURES = {
    "hostgator":    "Shared hosting (HostGator) — cPanel environment",
    "bluehost":     "Shared hosting (Bluehost) — cPanel environment",
    "cloudflare":   "Cloudflare edge node — NOT the origin server",
    "amazon":       "AWS — check for cloud misconfigs (S3, IAM, metadata service)",
    "amazonaws":    "AWS — check for cloud misconfigs (S3, IAM, metadata service)",
    "google":       "Google Cloud / GCP infrastructure",
    "digitalocean": "DigitalOcean VPS — often under-hardened",
    "vultr":        "Vultr VPS — often under-hardened",
    "linode":       "Linode/Akamai VPS",
    "microsoft":    "Azure cloud infrastructure",
    "fastly":       "Fastly CDN edge node — NOT the origin server",
    "akamai":       "Akamai CDN edge node — NOT the origin server",
    "hostinger":    "Hostinger shared hosting",
    "publicdomain": "PDR hosting — registrar-bundled hosting",
    "pdr":          "PDR hosting — registrar-bundled hosting",
}

PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^169\.254\.'),
    re.compile(r'^0\.'),
]


# ════════════════════════════════════════════════════════════════════════════
# CACHE
# ════════════════════════════════════════════════════════════════════════════

def get_cache_db():
    import sqlite3
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whois_deep_cache (
            domain     TEXT PRIMARY KEY,
            data       TEXT NOT NULL,
            cached_at  TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_get(domain: str, ttl_hours: int = 24) -> Optional[dict]:
    """Return cached result dict if it exists and is within TTL, else None."""
    try:
        conn = get_cache_db()
        row = conn.execute(
            "SELECT data, cached_at FROM whois_deep_cache WHERE domain = ?",
            (domain,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        data, cached_at_str = row
        cached_at = datetime.fromisoformat(cached_at_str)
        # Make cached_at timezone-aware if it isn't already
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - cached_at
        if age > timedelta(hours=ttl_hours):
            return None
        return json.loads(data)
    except Exception as e:
        print(f"[WARN] Cache read failed: {e}")
        return None


def cache_put(domain: str, data: dict):
    """Upsert result into local cache."""
    try:
        conn = get_cache_db()
        now  = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO whois_deep_cache (domain, data, cached_at)
            VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                data      = excluded.data,
                cached_at = excluded.cached_at
            """,
            (domain, json.dumps(data), now)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] Cache write failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# CONFIG / SUBMIT
# ════════════════════════════════════════════════════════════════════════════

def load_config() -> Optional[dict]:
    """Load config from CONFIG_PATH. Returns None if not found."""
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_config(cfg: dict):
    """Persist config to CONFIG_PATH, creating parent dirs as needed."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def setup_wizard() -> dict:
    """
    Interactive setup: prompts for a GitHub PAT (Issues write scope),
    display name, and location. Saves to CONFIG_PATH and returns the config.
    """
    print(f"\n{'─'*60}")
    print("  whois-deep — first-time setup")
    print(f"{'─'*60}")
    print("  Submission requires a GitHub Personal Access Token")
    print("  with 'issues: write' scope.")
    print("  Create one at: https://github.com/settings/tokens\n")

    pat          = input("  GitHub PAT (leave blank to skip submissions): ").strip()
    display_name = input("  Display name for submissions (e.g. 'alice' or blank): ").strip()
    display_loc  = input("  Location / affiliation (e.g. 'IN' or blank): ").strip()

    cfg = {
        "github_pat":    pat          or None,
        "display_name":  display_name or None,
        "display_loc":   display_loc  or None,
        "configured_at": datetime.now(timezone.utc).isoformat(),
    }
    save_config(cfg)
    print(f"\n  Config saved → {CONFIG_PATH}")
    return cfg


def submit_result(result: dict, config: dict):
    """
    Opt-in submission of a whois-deep result to the project's GitHub Issues
    tracker. Shows the user exactly what will be posted and asks for consent.
    """
    import urllib.request
    import urllib.error

    pat = config.get("github_pat")
    if not pat:
        print("[WARN] No GitHub PAT configured — run with --reconfigure to set one.")
        return

    domain       = result.get("domain", "unknown")
    display_name = config.get("display_name") or "anonymous"
    display_loc  = config.get("display_loc")  or "unknown"

    print(f"\n{'─'*60}")
    print("  Submission preview")
    print(f"{'─'*60}")
    print(f"  Domain       : {domain}")
    print(f"  Display name : {display_name}")
    print(f"  Location     : {display_loc}")
    print(f"  Issue title  : [submission] {domain}")
    print("  Body         : full JSON result (shown above)")
    confirm = input("\n  Submit? [y/N] ").strip().lower()
    if confirm != "y":
        print("  Submission cancelled.")
        return

    body_data = {
        "domain":       domain,
        "submitted_by": display_name,
        "location":     display_loc,
        "result":       result,
    }

    payload = json.dumps({
        "title": f"[submission] {domain}",
        "body":  f"```json\n{json.dumps(body_data, indent=2)}\n```",
    }).encode("utf-8")

    req = urllib.request.Request(
        GITHUB_ISSUES_URL,
        data=payload,
        headers={
            "Authorization": f"token {pat}",
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.github+json",
            "User-Agent":    f"whois-deep/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            print(f"  Submitted  →  {resp_data.get('html_url', 'ok')}")
    except urllib.error.HTTPError as e:
        print(f"[ERROR] GitHub API error {e.code}: {e.read().decode()}")
    except Exception as e:
        print(f"[ERROR] Submission failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd: list, timeout: int = 30) -> str:
    """Run a system command and return stdout. Empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[WARN] Timed out: {' '.join(cmd)}")
        return ""
    except FileNotFoundError:
        print(f"[ERROR] Binary not found: {cmd[0]}  →  sudo apt install {cmd[0]}")
        return ""


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def is_valid_whois_hostname(value: str) -> bool:
    """
    Reject values that are HTTP URLs rather than WHOIS server hostnames.
    A valid WHOIS hostname has no scheme and no slashes.
    The fallback probe can extract 'Registrar URL' (an HTTP URL) and
    attempt to use it as a WHOIS server hostname, causing silent failures.
    """
    if not value:
        return False
    if value.lower().startswith("http://") or value.lower().startswith("https://"):
        return False
    if "/" in value:
        return False
    return True


# ════════════════════════════════════════════════════════════════════════════
# STEP 1 — Resolve domain to IP via dig
# ════════════════════════════════════════════════════════════════════════════

def resolve_ips(domain: str) -> list:
    """
    Return all IPv4 A records for a domain.
    Uses dig +short which auto-follows CNAME chains and returns final IPs.
    Filters to only lines matching IPv4 pattern — strips CNAME intermediate hops.
    """
    raw = run_cmd(["dig", "+short", "A", domain])
    ips = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
            ips.append(line)
    return ips


# ════════════════════════════════════════════════════════════════════════════
# STEP 2 — Fetch registrar WHOIS
# ════════════════════════════════════════════════════════════════════════════

def fetch_registrar_whois(domain: str, server: str) -> str:
    """Query registrar's own WHOIS server. server must be a hostname not URL."""
    if not server or not is_valid_whois_hostname(server):
        return ""
    print(f"[*] Querying registrar WHOIS: {server}")
    return run_cmd(["whois", "-h", server, domain])


# ════════════════════════════════════════════════════════════════════════════
# STEP 3 — Fetch IP WHOIS
# ════════════════════════════════════════════════════════════════════════════

def fetch_ip_whois(ip: str) -> str:
    """
    Query IP WHOIS. Tries system auto-routing first, then each RIR explicitly.
    Returns the first non-empty, non-error response.
    """
    print(f"[*] Querying IP WHOIS for: {ip}")
    raw = run_cmd(["whois", ip])
    if raw.strip() and len(raw) > 100 and "no match" not in raw.lower():
        return raw

    for rir_name, rir_server in RIR_SERVERS.items():
        print(f"[*] Trying {rir_name.upper()} ({rir_server})")
        raw = run_cmd(["whois", "-h", rir_server, ip])
        if raw.strip() and len(raw) > 100 and "no match" not in raw.lower():
            return raw
    return ""


# ════════════════════════════════════════════════════════════════════════════
# PARSING HELPERS
# ════════════════════════════════════════════════════════════════════════════

def extract_field(raw: str, *keys: str) -> Optional[str]:
    """Extract first non-redacted value matching any of the given field names."""
    REDACTED = {
        "redacted for privacy", "redacted", "n/a",
        "not available from registry", "data redacted", "",
    }
    for key in keys:
        pattern = rf"(?i)^{re.escape(key)}\s*:\s*(.+)$"
        match = re.search(pattern, raw, re.MULTILINE)
        if match:
            val = match.group(1).strip()
            if val.lower() not in REDACTED:
                return val
    return None


# ════════════════════════════════════════════════════════════════════════════
# STEP 4 — Parse registrar WHOIS
# ════════════════════════════════════════════════════════════════════════════

def parse_registrar_whois(raw: str, domain: str) -> dict:
    if not raw.strip():
        return {"available": False, "reason": "Empty response"}

    return {
        "available": True,
        "domain":    domain,
        "contacts": {
            "registrant": {
                "name":  extract_field(raw, "Registrant Name"),
                "org":   extract_field(raw, "Registrant Organization", "Registrant Organisation"),
                "email": extract_field(raw, "Registrant Email"),
                "phone": extract_field(raw, "Registrant Phone"),
            },
            "admin":   {"email": extract_field(raw, "Admin Email")},
            "tech":    {"email": extract_field(raw, "Tech Email")},
            # Billing contact — only exposed at registrar level, never registry
            "billing": {
                "name":  extract_field(raw, "Billing Name"),
                "email": extract_field(raw, "Billing Email"),
                "phone": extract_field(raw, "Billing Phone"),
            },
        },
        "reseller": extract_field(raw, "Registration Service Provided By", "Reseller"),
        "updated":  extract_field(raw, "Updated Date", "Last Updated"),
    }


# ════════════════════════════════════════════════════════════════════════════
# STEP 5 — Parse IP WHOIS
# ════════════════════════════════════════════════════════════════════════════

def detect_rir(raw: str) -> str:
    """
    Identify which RIR produced this response.
    RIPE responses start with "%" comment lines containing
    "% Information related to" — added as explicit markers.
    Also "inetnum:" is RIPE-specific (ARIN uses NetRange).
    """
    raw_lower = raw.lower()
    for rir, markers in RIR_MARKERS.items():
        if any(m.lower() in raw_lower for m in markers):
            return rir.upper()
    return "UNKNOWN"


def extract_asn(raw: str) -> Optional[str]:
    """
    Extract ASN as a clean numeric string.

    ARIN returns a concatenated response containing both IP block info AND
    ASN record info in the same output. The ASN record section contains
    "ASOrganization: Google LLC (GOGL)" — when OriginAS was blank, the
    fallback "origin" key accidentally matched within the ASN block.

    Fix: search the raw text directly for the AS number pattern using regex.

    Priority order:
      ASHandle:   AS15169   (ARIN ASN record)
      OriginAS:   AS15169   (ARIN IP record, sometimes present)
      origin:     AS15169   (RIPE format)
      aut-num:    AS15169   (RIPE ASN object)
    """
    # Strategy 1: explicit field containing ASN
    for key in ("ASHandle", "OriginAS", "origin", "aut-num"):
        pattern = rf"(?i)^{re.escape(key)}\s*:\s*(.+)$"
        match = re.search(pattern, raw, re.MULTILINE)
        if match:
            val = match.group(1).strip()
            num_match = re.search(r'AS(\d+)', val, re.IGNORECASE)
            if num_match:
                return num_match.group(1)

    # Strategy 2: scan entire raw for any "AS<digits>" pattern as fallback
    all_asns = re.findall(r'\bAS(\d{4,6})\b', raw)
    if all_asns:
        from collections import Counter
        return Counter(all_asns).most_common(1)[0][0]

    return None


def parse_cidr_range(inetnum: Optional[str]) -> dict:
    """Parse IP range string into structured form with block size calculation."""
    if not inetnum:
        return {"raw": None, "start": None, "end": None, "size": None, "cidr_notation": None}

    range_match = re.search(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[-/]\s*(\S+)', inetnum
    )
    if not range_match:
        return {"raw": inetnum, "start": None, "end": None, "size": None, "cidr_notation": None}

    start_ip      = range_match.group(1)
    end_or_prefix = range_match.group(2)

    if re.match(r'^\d+$', end_or_prefix):
        prefix = int(end_or_prefix)
        size   = 2 ** (32 - prefix)
        return {"raw": inetnum, "start": start_ip, "end": None,
                "size": size, "cidr_notation": f"{start_ip}/{prefix}"}

    try:
        def ip_int(ip):
            parts = ip.split(".")
            return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))

        size   = ip_int(end_or_prefix) - ip_int(start_ip) + 1
        prefix = 32 - int(math.log2(size)) if size > 0 else 32
        return {"raw": inetnum, "start": start_ip, "end": end_or_prefix,
                "size": size, "cidr_notation": f"{start_ip}/{prefix}"}
    except Exception:
        return {"raw": inetnum, "start": start_ip, "end": end_or_prefix,
                "size": None, "cidr_notation": None}


def classify_block(size: Optional[int]) -> str:
    if size is None:      return "unknown"
    if size == 1:         return "single IP — dedicated or VPS"
    if size <= 256:       return "/24 or smaller — small org or dedicated"
    if size <= 4096:      return "shared hosting pool — many tenants on same infra"
    if size <= 65536:     return "large provider block"
    return "massive block — major ISP or cloud provider"


def identify_hosting(raw: str) -> Optional[str]:
    raw_lower = raw.lower()
    for sig, desc in HOSTING_SIGNATURES.items():
        if sig in raw_lower:
            return desc
    return None


def parse_ip_whois(raw: str, ip: str) -> dict:
    if not raw.strip():
        return {"available": False, "ip": ip, "reason": "Empty IP WHOIS response"}

    # ARIN uses NetRange/NetName/OrgName — RIPE uses inetnum/netname/descr
    inetnum  = extract_field(raw, "inetnum", "NetRange")
    net_name = extract_field(raw, "netname", "NetName")
    org_name = extract_field(raw, "OrgName", "descr", "owner", "org-name")
    country  = extract_field(raw, "country", "Country")
    abuse    = extract_field(raw, "OrgAbuseEmail", "abuse-mailbox", "OrgTechEmail")

    asn          = extract_asn(raw)
    cidr_info    = parse_cidr_range(inetnum)
    block_label  = classify_block(cidr_info.get("size"))
    hosting_hint = identify_hosting(raw)
    rir          = detect_rir(raw)

    return {
        "available":     True,
        "ip":            ip,
        "rir":           rir,
        "inetnum":       inetnum,
        "cidr":          cidr_info,
        "block_context": block_label,
        "net_name":      net_name,
        "org_name":      org_name,
        "country":       country,
        "asn":           asn,
        "abuse_email":   abuse,
        "hosting_hint":  hosting_hint,
    }


# ════════════════════════════════════════════════════════════════════════════
# PRINTER
# ════════════════════════════════════════════════════════════════════════════

COLOURS = {
    "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m",
    "INFO": "\033[92m", "BOLD":   "\033[1m",  "DIM": "\033[2m",
    "CYAN": "\033[96m", "RESET":  "\033[0m",
}

def c(key: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLOURS.get(key, '')}{text}{COLOURS['RESET']}"


def print_result(result: dict):
    domain   = result.get("domain", "unknown")
    ip_data  = result.get("ip_whois", {})
    reg_data = result.get("registrar_whois", {})
    resolved = result.get("resolved_ip")
    cached   = result.get("cached", False)

    print(f"\n{c('BOLD', '═' * 65)}")
    cache_tag = f"  {c('DIM', '[cached]')}" if cached else ""
    print(f"  {c('BOLD','WHOIS Deep Analysis')}  →  {c('BOLD', domain)}{cache_tag}")
    print(c('BOLD', '═' * 65))

    # IP Resolution
    print(f"\n  {c('BOLD','IP Resolution')}")
    if resolved:
        all_ips = result.get("all_resolved", [resolved])
        print(f"    A Record(s) : {c('CYAN', ', '.join(all_ips))}")
        if is_private_ip(resolved):
            print(f"    {c('MEDIUM','WARNING: private/bogon IP — split-horizon DNS likely')}")
    else:
        print(f"    {c('DIM','Domain did not resolve — parked or dead')}")

    # IP WHOIS
    print(f"\n  {c('BOLD','IP WHOIS  (RIR level)')}")
    if ip_data.get("available"):
        cidr = ip_data.get("cidr", {})
        asn  = ip_data.get("asn")
        print(f"    RIR         : {ip_data.get('rir','N/A')}")
        print(f"    IP Block    : {ip_data.get('inetnum','N/A')}")
        print(f"    CIDR        : {cidr.get('cidr_notation','N/A')}")
        print(f"    Block Size  : {cidr.get('size','N/A')} IPs  — {ip_data.get('block_context','')}")
        print(f"    Net Name    : {ip_data.get('net_name','N/A')}")
        print(f"    Org         : {ip_data.get('org_name','N/A')}")
        print(f"    Country     : {ip_data.get('country','N/A')}")
        print(f"    ASN         : {c('CYAN','AS'+asn) if asn else 'N/A'}")
        print(f"    Abuse Email : {ip_data.get('abuse_email','N/A')}")
        if ip_data.get("hosting_hint"):
            print(f"    Hosting     : {c('MEDIUM', ip_data['hosting_hint'])}")
        if ip_data.get("rir") == "UNKNOWN":
            print(f"    {c('MEDIUM','RIR unknown — check raw response for manual identification')}")
    else:
        print(f"    {c('DIM', ip_data.get('reason','no data'))}")

    # Registrar WHOIS
    print(f"\n  {c('BOLD','Registrar WHOIS  (registrar level)')}")
    if reg_data.get("available"):
        contacts  = reg_data.get("contacts", {})
        found_new = False
        for role in ["registrant", "admin", "tech", "billing"]:
            row = {k: v for k, v in contacts.get(role, {}).items() if v}
            if row:
                found_new = True
                print(f"    {role.capitalize():12}: " + ", ".join(f"{k}={v}" for k, v in row.items()))
        if reg_data.get("reseller"):
            print(f"    Reseller    : {reg_data['reseller']}")
        if not found_new:
            print(f"    {c('DIM','No additional fields beyond registry-level WHOIS (redundant)')}")
    else:
        print(f"    {c('DIM', reg_data.get('reason','skipped'))}")

    # Pivots
    print(f"\n  {c('BOLD','Pivots')}")
    asn      = ip_data.get("asn")
    cidr_str = ip_data.get("cidr", {}).get("cidr_notation")

    if resolved and not is_private_ip(resolved):
        print(f"    {c('DIM',f'nmap -sV -sC {resolved}')}")
        print(f"    {c('DIM',f'curl -I https://{domain}')}")
    if asn:
        print(f"    {c('DIM',f'# ASN: https://bgp.he.net/AS{asn}')}")
        print(f"    {c('DIM',f'# Shodan: asn:AS{asn}')}")
    if cidr_str:
        print(f"    {c('DIM',f'nmap -sn {cidr_str}  # ping sweep block')}")

    billing = reg_data.get("contacts", {}).get("billing", {}) if reg_data.get("available") else {}
    if billing.get("email"):
        bill_email = billing["email"]
        print(f"    {c('DIM', f'# New billing email: {bill_email}')}")
    print()


# ════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR — single domain
# ════════════════════════════════════════════════════════════════════════════

def run(domain: str, registrar_whois_server: Optional[str] = None) -> dict:
    """
    Execute the full WHOIS deep analysis for one domain.
    Returns a result dict. Does not touch the cache — caller manages that.
    """
    now    = datetime.now(timezone.utc).isoformat()
    result = {"domain": domain, "queried_at": now, "cached": False}

    # Resolve IP
    ips = resolve_ips(domain)
    if ips:
        ip = ips[0]
        result["resolved_ip"]  = ip
        result["all_resolved"] = ips
        if len(ips) > 1:
            print(f"[*] Multiple A records: {ips} — using {ip}")
    else:
        result["resolved_ip"]  = None
        result["all_resolved"] = []
        print(f"[!] {domain} did not resolve — parked or dead")

    # IP WHOIS
    if result["resolved_ip"] and not is_private_ip(result["resolved_ip"]):
        raw_ip = fetch_ip_whois(result["resolved_ip"])
        if raw_ip:
            result["ip_whois"] = parse_ip_whois(raw_ip, result["resolved_ip"])
        else:
            result["ip_whois"] = {"available": False, "ip": result["resolved_ip"],
                                   "reason": "No response from any RIR"}
    elif result["resolved_ip"] and is_private_ip(result["resolved_ip"]):
        result["ip_whois"] = {"available": False, "ip": result["resolved_ip"],
                               "reason": "Private/bogon IP — IP WHOIS not applicable"}
    else:
        result["ip_whois"] = {"available": False, "ip": None,
                               "reason": "Domain did not resolve"}

    # Find registrar WHOIS server if not provided
    if not registrar_whois_server:
        probe = run_cmd(["whois", domain])
        match = re.search(r'(?i)^Registrar WHOIS Server\s*:\s*(.+)$',
                          probe, re.MULTILINE)
        if match:
            candidate = match.group(1).strip()
            if is_valid_whois_hostname(candidate):
                registrar_whois_server = candidate
                print(f"[*] Found registrar WHOIS server: {registrar_whois_server}")
            else:
                print(f"[WARN] Registrar WHOIS Server field contains URL not hostname — skipping")
                print(f"       Value was: {candidate}")

    # Registrar WHOIS
    if registrar_whois_server:
        raw_reg = fetch_registrar_whois(domain, registrar_whois_server)
        if raw_reg:
            result["registrar_whois"] = parse_registrar_whois(raw_reg, domain)
            result["registrar_whois"]["server"] = registrar_whois_server
        else:
            result["registrar_whois"] = {
                "available": False,
                "reason": f"Empty response from {registrar_whois_server}"
            }
    else:
        result["registrar_whois"] = {
            "available": False,
            "reason": "No valid registrar WHOIS server found"
        }

    print_result(result)
    return result


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="whois-deep",
        description=f"whois-deep {__version__} — Registrar WHOIS + IP WHOIS via RIR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tools required: whois (system binary), dig (system binary)

Examples:
  python3 whois-deep.py -d startbitsolutions.com
  python3 whois-deep.py -d nmap.org --output nmap.json
  python3 whois-deep.py -d google.com --no-cache
  python3 whois-deep.py -d google.com --ttl 48
  python3 whois-deep.py -d nmap.org --submit
  python3 whois-deep.py --reconfigure
        """
    )

    parser.add_argument("-d", "--domain", metavar="DOMAIN",
                        help="Domain to query (strips http(s):// prefix automatically)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write JSON result to file")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass cache — always run live queries")
    parser.add_argument("--ttl", type=int, default=24, metavar="HOURS",
                        help="Cache TTL in hours (default: 24)")
    parser.add_argument("--submit", action="store_true",
                        help="Opt-in: submit result to project issue tracker")
    parser.add_argument("--reconfigure", action="store_true",
                        help="Re-run the setup wizard (update GitHub PAT / display info)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # --reconfigure: run wizard and exit
    if args.reconfigure:
        setup_wizard()
        sys.exit(0)

    # --domain is required for all other operations
    if not args.domain:
        parser.error("--domain / -d is required (or use --reconfigure)")

    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/")[0]

    print(f"\n{'─'*65}")
    print(f"[*] whois-deep {__version__}  →  {domain}")

    result = None

    # Cache lookup
    if not args.no_cache:
        result = cache_get(domain, ttl_hours=args.ttl)
        if result is not None:
            result["cached"] = True
            print(f"[*] Cache hit (TTL={args.ttl}h) — serving cached result")
            print_result(result)

    # Live run
    if result is None:
        result = run(domain, registrar_whois_server=None)
        result["cached"] = False
        cache_put(domain, result)

    # --output: write JSON to file
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[*] JSON written → {out_path.resolve()}")

    # --submit: opt-in submission
    if args.submit:
        config = load_config()
        if not config:
            print("[*] No config found — running setup wizard first")
            config = setup_wizard()
        submit_result(result, config)


if __name__ == "__main__":
    main()
