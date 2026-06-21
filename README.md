# whois-deep

Registrar WHOIS + IP WHOIS via RIR — ASN, org, netblock, hosting fingerprint.

Goes two levels deeper than standard WHOIS:
1. **Registrar WHOIS** — queries the registrar's own server (exposes billing contacts, reseller info not in registry WHOIS)
2. **IP WHOIS via RIR** — resolves the domain IP, queries ARIN/RIPE/APNIC/LACNIC/AFRINIC directly for ASN, org, and netblock

**[→ RIR Board](https://fmfalgun.github.io/whois-deep/rir-board.html)** — community-submitted results, browsable without the tool.

## Requirements

- Python 3.8+
- `whois` binary (`sudo apt-get install whois` / `brew install whois`)
- `dig` binary (`sudo apt-get install dnsutils` / `brew install bind`)

No pip dependencies.

## Usage

```bash
# basic query
python3 whois-deep.py -d nmap.org

# save structured JSON
python3 whois-deep.py -d nmap.org -o results.json

# bypass 24h cache
python3 whois-deep.py -d nmap.org --no-cache

# submit to RIR Board
python3 whois-deep.py -d nmap.org --submit

# reconfigure stored credentials
python3 whois-deep.py --reconfigure
```

## Output schema

```json
{
  "domain": "nmap.org",
  "queried_at": "2026-06-21T05:00:00Z",
  "cached": false,
  "resolved_ip": "45.33.32.156",
  "ip_whois": {
    "rir": "ARIN",
    "asn": "63949",
    "net_name": "LINODE-US",
    "org_name": "Akamai Technologies, Inc.",
    "country": "US",
    "inetnum": "45.33.0.0 - 45.33.127.255",
    "cidr": { "cidr_notation": "45.33.0.0/17", "size": 32768 },
    "block_context": "massive block — major ISP or cloud provider",
    "hosting_hint": "Linode/Akamai VPS",
    "abuse_email": "abuse@akamai.com"
  },
  "registrar_whois": {
    "server": "whois.networksolutions.com",
    "contacts": {
      "registrant": { "org": "Insecure.Com LLC" },
      "billing": { "email": null }
    }
  }
}
```

## Flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Domain to query |
| `-o`, `--output` | Write JSON to file |
| `--no-cache` | Bypass 24h SQLite cache |
| `--ttl` | Cache TTL in hours (default: 24) |
| `--submit` | Submit result to RIR Board |
| `--reconfigure` | Update stored GitHub token / display info |

## --submit flow

First run with `--submit` opens a setup wizard. Enter a GitHub PAT (Issues: write scope), your display name, and location. Results are submitted as GitHub Issues and processed by CI — your domain appears on the RIR Board within minutes.

## Pairs with

- [whois-extracter](https://github.com/fmfalgun/whois-extracter) — registry-level WHOIS (risk scoring, DNSSEC, NS type)
- [crtsh-recon](https://github.com/fmfalgun/crtsh-recon) — certificate transparency subdomain discovery

---

MIT License · Built by [Falgun Marothia](https://fmfalgun.github.io)
