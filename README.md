# 🔭 NeatLabs™ Domain Threat Timeline

**Passive Domain Intelligence & Recon Timeline**

Build a chronological intelligence timeline for any domain using only public, passive OSINT sources. No active scanning. No API keys required.

Enter a domain → get a full dossier: registration history, DNS records, certificate transparency, Wayback Machine snapshots, subdomain discovery, technology fingerprinting, and automated threat analysis. All rendered as an interactive HTML intelligence report.

---

## Why This Exists

OSINT analysts and security researchers do this manually every day — bouncing between WHOIS lookups, crt.sh, the Wayback Machine, DNS tools, and header analysis, then manually assembling a timeline. It takes 30-60 minutes per domain.

Domain Threat Timeline does it in seconds, from a single command, with zero API keys.

---

## Quick Start

```bash
# No API keys needed — just Python 3.8+
python domain_timeline.py                           # GUI mode
python domain_timeline.py --cli example.com         # CLI mode
python domain_timeline.py --cli example.com --html  # HTML report
python domain_timeline.py --cli --demo              # Demo with sample data
```

Optional (improves WHOIS parsing): `pip install python-whois`
Optional (improves DNS enumeration): `pip install dnspython`

Works without either — falls back to system `whois` and `dig` commands plus socket lookups.

---

## Data Sources (All Passive)

| Source | What It Collects |
|--------|-----------------|
| **WHOIS** | Registration date, registrar, expiration, nameservers, privacy status |
| **DNS** | A, AAAA, MX, NS, TXT, CNAME, SOA records + SPF/DMARC/DKIM detection |
| **crt.sh** | Certificate Transparency logs — every cert ever issued, with SANs |
| **Wayback Machine** | CDX API — snapshot count, first/last archive dates, yearly samples |
| **HTTP Headers** | Server software, framework detection, CDN identification, security header audit |
| **robots.txt** | Disallowed paths, sitemaps, sensitive/hidden path detection |
| **security.txt** | RFC 9116 vulnerability disclosure contacts, policies, expiry |
| **Reverse DNS** | PTR records for resolved IPs — hosting provider identification |
| **Typosquat Detection** | Permutation generation + DNS resolution of lookalike domains |

No active scanning, no port scanning, no brute forcing. Everything comes from public records and passive observation.

---

## Features

### 📜 Chronological Timeline
Every data point placed on a timeline — domain registration, certificate issuances, infrastructure changes, content snapshots, subdomain appearances, technology shifts. Filter by category with one click.

### ⚠️ Automated Threat Analysis
The analysis engine evaluates collected data for threat indicators:
- **Newly registered domains** — statistical association with malicious activity
- **WHOIS privacy** — legitimate use but obscures ownership
- **Missing email authentication** — SPF/DMARC gaps enable spoofing
- **Private IPs in public DNS** — misconfiguration or DNS rebinding
- **No SSL/TLS certificate** — unusual for legitimate services
- **Certificate patterns** — all free CAs, high churn, wildcard changes
- **Subdomain sprawl** — large attack surface with potential shadow IT
- **Exposed internal infrastructure** — monitoring/admin tools in CT logs
- **Active typosquat domains** — lookalikes resolving to different IPs (phishing risk)
- **Sensitive paths in robots.txt** — admin panels, config files, backups exposed as roadmap
- **Missing security.txt** — no RFC 9116 vulnerability disclosure contact

### 🌐 Subdomain Discovery
Extracts subdomains from Certificate Transparency logs and TLS SANs. No brute forcing — purely passive discovery from public certificate records.

### ⚙️ Technology Fingerprinting
Identifies web servers (Nginx, Apache, Cloudflare, etc.), frameworks (Next.js, Django, WordPress, etc.), CDN/platforms (Vercel, Netlify, AWS CloudFront, etc.), and audits security headers.

### 🎭 Typosquat Detection
Generates hundreds of permutations of the target domain — character swaps, omissions, homoglyphs, TLD variations, hyphen tricks, dot insertions — then DNS-checks which ones actually resolve. Flags domains resolving to different IPs as potential phishing/impersonation threats.

### 🤖 robots.txt & security.txt Analysis
Fetches and parses robots.txt to identify disallowed paths that reveal sensitive infrastructure (admin panels, backup directories, config files, .env, .git). Checks for security.txt (RFC 9116) to assess vulnerability disclosure maturity.

### ↩️ Reverse DNS
PTR lookups on all resolved IP addresses to identify hosting providers, shared infrastructure, and internal naming conventions that leak organizational information.

### 📊 Export Formats
- **HTML** — Rich interactive intelligence dossier with timeline, threat indicators, data tables, category filters, and print styles
- **JSON** — Structured data for automation, SIEM integration, or further analysis

### 🖥️ Dual Mode
- **GUI** — Tkinter desktop app with warm intelligence-dossier aesthetic
- **CLI** — Terminal output with color coding, ideal for scripting and pipelines

---

## Event Categories

| Icon | Category | Examples |
|------|----------|----------|
| 📋 | Registration | Domain registered, WHOIS updated, expiration date |
| 🔀 | DNS | Record changes, SPF/DMARC configured, nameserver updates |
| 🔒 | Certificate | Cert issued, renewed, wildcard upgrade, issuer changes |
| 🏗️ | Infrastructure | CDN changes, security headers, hosting migrations |
| 📸 | Content | Wayback snapshots, major page changes |
| 🌐 | Subdomain | New subdomain discovered, internal tools exposed |
| ⚙️ | Technology | Server software, framework detection, stack changes |
| ⚠️ | Threat Intel | Suspicious patterns, risk indicators |

---

## CLI Usage

```bash
# Basic scan
python domain_timeline.py --cli example.com

# Generate HTML intelligence report
python domain_timeline.py --cli example.com --html -o report.html

# JSON output for automation
python domain_timeline.py --cli example.com --json -o data.json

# Demo mode (no network, uses sample data)
python domain_timeline.py --cli --demo

# Demo with HTML output
python domain_timeline.py --cli --demo --html -o demo-report.html
```

---

## HTML Report

The HTML report uses an **intelligence dossier** design:
- Warm dark tones with amber/gold accents
- Serif display typography (DM Serif Display) for headings
- Monospace data presentation (IBM Plex Mono)
- Glowing vertical timeline with category-colored event markers
- Interactive category filter buttons
- Collapsible data sections (WHOIS, DNS, Certificates, Subdomains)
- Print-optimized styles for physical reports
- Fully self-contained single HTML file — no external dependencies

---

## Use Cases

- **OSINT Analysts** — Rapid domain profiling during investigations
- **Threat Hunters** — Evaluate suspicious domains from alerts and logs
- **Red Teams** — Reconnaissance and attack surface mapping
- **Blue Teams** — Validate domain reputation before allowing access
- **Incident Response** — Understand domain history during active incidents
- **Brand Protection** — Monitor lookalike domains targeting your organization
- **Due Diligence** — Evaluate domains in M&A, partnerships, or vendor assessments

---

## Requirements

- Python 3.8+
- No required external dependencies (works with stdlib only)
- Optional: `python-whois` for richer WHOIS parsing
- Optional: `dnspython` for comprehensive DNS enumeration
- GUI requires tkinter (included with most Python installations)

---

## Contributing

Contributions welcome — especially:
- **New passive data sources** (SecurityTrails, VirusTotal, Shodan passive)
- **Additional analysis rules** for emerging threat patterns
- **Export formats** — PDF, STIX/TAXII, Maltego
- **MCP server knowledge** for Agent Scope integration

---

## License

MIT License — see [LICENSE](LICENSE)

---

## About NeatLabs™

**NeatLabs™** is a Service-Disabled Veteran-Owned Small Business (SDVOSB) specializing in cybersecurity, AI platform development, and federal compliance consulting.

Domain Threat Timeline is part of NeatLabs' OSINT tooling portfolio. See also:
- [MD Mirror](https://github.com/neatlabs/md-mirror) — Markdown security scanner
- [Agent Scope](https://github.com/neatlabs/agent-scope) — AI agent permission auditor

🌐 [neatlabs.ai](https://neatlabs.ai)
📧 [info@neatlabs.ai](mailto:info@neatlabs.ai)

---

*Built with 🔭 by NeatLabs™*
