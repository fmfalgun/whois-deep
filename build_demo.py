#!/usr/bin/env python3
"""
build_demo.py — generate nmap.org demo data for the whois-deep web UI.
Called by build-demo.yml CI cron and locally for testing.
"""

import json
import subprocess
import sys
import datetime
from pathlib import Path

DOMAIN      = "nmap.org"
DOMAIN_FILE = Path("web/data/domains") / f"{DOMAIN}.json"
INDEX_FILE  = Path("web/data/index.json")
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"


def run_tool():
    print(f"[*] Running whois-deep.py on {DOMAIN}...")
    result = subprocess.run(
        ["python3", "whois-deep.py", "-d", DOMAIN, "-o", str(DOMAIN_FILE), "--no-cache"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[ERROR] whois-deep.py failed:\n{result.stderr}")
        sys.exit(1)
    print(f"[OK] wrote {DOMAIN_FILE}")


def update_domain_file():
    """Merge display metadata into the domain JSON."""
    with open(DOMAIN_FILE) as f:
        data = json.load(f)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    data["display_name"]   = DISPLAY_NAME
    data["display_loc"]    = DISPLAY_LOC
    data["last_refreshed"] = now
    with open(DOMAIN_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return data


def update_index(data):
    """Upsert nmap.org into index.json."""
    ip   = data.get("ip_whois", {})
    cidr = ip.get("cidr", {})
    now  = data.get("last_refreshed", "")

    entry = {
        "domain":        DOMAIN,
        "display_name":  DISPLAY_NAME,
        "display_loc":   DISPLAY_LOC,
        "queried_at":    data.get("queried_at", now),
        "last_refreshed": now,
        "rir":           ip.get("rir"),
        "asn":           ip.get("asn"),
        "org":           ip.get("org_name"),
        "country":       ip.get("country"),
        "netblock":      cidr.get("cidr_notation"),
        "ip_range":      ip.get("inetnum"),
    }

    try:
        with open(INDEX_FILE) as f:
            index = json.load(f)
    except Exception:
        index = {"total_domains": 0, "domains": []}

    existing = [d for d in index.get("domains", []) if d["domain"] != DOMAIN]
    existing.append(entry)
    existing.sort(key=lambda d: d["domain"])
    index["domains"]       = existing
    index["total_domains"] = len(existing)

    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)
    print(f"[OK] updated {INDEX_FILE} — {len(existing)} domain(s)")


if __name__ == "__main__":
    DOMAIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    run_tool()
    data = update_domain_file()
    update_index(data)
    print("[DONE]")
