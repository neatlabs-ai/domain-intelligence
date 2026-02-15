#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              NEATLABS™ DOMAIN THREAT TIMELINE  v1.0              ║
║          Passive Domain Intelligence & Recon Timeline            ║
║                                                                  ║
║   Build a chronological intelligence timeline for any domain     ║
║   using only public, passive OSINT sources. No active scanning.  ║
║                                                                  ║
║   © 2025 NeatLabs™ — Service-Disabled Veteran-Owned Small Biz   ║
║   Released under the MIT License                                 ║
║   https://github.com/neatlabs/domain-timeline                    ║
║   https://neatlabs.ai  •  info@neatlabs.ai                       ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    GUI Mode:   python domain_timeline.py
    CLI Mode:   python domain_timeline.py --cli example.com
    CLI HTML:   python domain_timeline.py --cli example.com --html -o report.html
    Demo Mode:  python domain_timeline.py --cli --demo
"""

__version__ = "1.1.0"
__author__ = "NeatLabs™"
__license__ = "MIT"

import re
import os
import sys
import json
import socket
import struct
import hashlib
import argparse
import subprocess
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from enum import Enum
import time
import threading


# ═══════════════════════════════════════════════════════════════
# DATA MODEL
# ═══════════════════════════════════════════════════════════════

class EventCategory(Enum):
    REGISTRATION = "Registration"
    DNS = "DNS"
    CERTIFICATE = "Certificate"
    INFRASTRUCTURE = "Infrastructure"
    CONTENT = "Content"
    SUBDOMAIN = "Subdomain"
    TECHNOLOGY = "Technology"
    THREAT = "Threat Intel"

EVENT_ICONS = {
    EventCategory.REGISTRATION: "📋",
    EventCategory.DNS: "🔀",
    EventCategory.CERTIFICATE: "🔒",
    EventCategory.INFRASTRUCTURE: "🏗️",
    EventCategory.CONTENT: "📸",
    EventCategory.SUBDOMAIN: "🌐",
    EventCategory.TECHNOLOGY: "⚙️",
    EventCategory.THREAT: "⚠️",
}

EVENT_COLORS = {
    EventCategory.REGISTRATION: "#C8A96E",
    EventCategory.DNS: "#6EC8C8",
    EventCategory.CERTIFICATE: "#6EC86E",
    EventCategory.INFRASTRUCTURE: "#8B6EC8",
    EventCategory.CONTENT: "#C86E8B",
    EventCategory.SUBDOMAIN: "#6E8BC8",
    EventCategory.TECHNOLOGY: "#C8B06E",
    EventCategory.THREAT: "#E85D4A",
}

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_COLORS = {
    Severity.CRITICAL: "#E85D4A",
    Severity.HIGH: "#E8944A",
    Severity.MEDIUM: "#C8A96E",
    Severity.LOW: "#6EC8C8",
    Severity.INFO: "#7A8A9E",
}


@dataclass
class TimelineEvent:
    timestamp: datetime
    category: EventCategory
    title: str
    detail: str
    source: str
    severity: Severity = Severity.INFO
    raw_data: Dict = field(default_factory=dict)

    @property
    def date_str(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d")

    @property
    def time_str(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")

    @property
    def iso_str(self) -> str:
        return self.timestamp.isoformat()

    def to_dict(self) -> dict:
        return {
            "timestamp": self.iso_str,
            "category": self.category.value,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "severity": self.severity.value,
        }


@dataclass
class ThreatIndicator:
    title: str
    description: str
    severity: Severity
    evidence: str


@dataclass
class DomainReport:
    domain: str
    scan_time: str
    scan_duration_s: float
    events: List[TimelineEvent] = field(default_factory=list)
    indicators: List[ThreatIndicator] = field(default_factory=list)
    whois_data: Dict = field(default_factory=dict)
    dns_records: Dict = field(default_factory=dict)
    certificates: List[Dict] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    wayback_snapshots: int = 0
    wayback_first: str = ""
    wayback_last: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    reverse_dns: Dict[str, str] = field(default_factory=dict)
    robots_txt: str = ""
    security_txt: str = ""
    robots_hidden_paths: List[str] = field(default_factory=list)
    typosquats: List[Dict] = field(default_factory=list)
    engine_version: str = __version__

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def category_counts(self) -> Dict:
        counts = {}
        for e in self.events:
            counts[e.category] = counts.get(e.category, 0) + 1
        return counts

    @property
    def severity_counts(self) -> Dict:
        counts = {s: 0 for s in Severity}
        for i in self.indicators:
            counts[i.severity] += 1
        return counts

    @property
    def domain_age_days(self) -> Optional[int]:
        created = self.whois_data.get("creation_date")
        if created:
            try:
                if isinstance(created, str):
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
            except Exception:
                pass
        return None

    def to_dict(self) -> dict:
        return {
            "tool": f"NeatLabs Domain Threat Timeline v{self.engine_version}",
            "domain": self.domain,
            "scan_time": self.scan_time,
            "scan_duration_s": round(self.scan_duration_s, 2),
            "summary": {
                "total_events": self.event_count,
                "categories": {k.value: v for k, v in self.category_counts.items()},
                "indicators": len(self.indicators),
                "subdomains": len(self.subdomains),
                "certificates": len(self.certificates),
                "wayback_snapshots": self.wayback_snapshots,
                "ip_addresses": self.ip_addresses,
                "tech_stack": self.tech_stack,
                "typosquats_found": len([t for t in self.typosquats if t.get("resolves")]),
                "reverse_dns": self.reverse_dns,
            },
            "whois": self.whois_data,
            "dns": self.dns_records,
            "robots_txt": self.robots_txt,
            "security_txt": self.security_txt,
            "robots_hidden_paths": self.robots_hidden_paths,
            "typosquats": self.typosquats,
            "events": [e.to_dict() for e in self.events],
            "indicators": [
                {"title": i.title, "severity": i.severity.value,
                 "description": i.description, "evidence": i.evidence}
                for i in self.indicators
            ],
        }


# ═══════════════════════════════════════════════════════════════
# COLLECTORS — All Passive / Public Sources
# ═══════════════════════════════════════════════════════════════

class BaseCollector:
    """Base class for data collectors."""
    name = "base"

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        raise NotImplementedError

    def _log(self, msg, progress_cb=None):
        if progress_cb:
            progress_cb(f"[{self.name}] {msg}")


class WHOISCollector(BaseCollector):
    name = "WHOIS"

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Looking up WHOIS for {domain}...", progress_cb)
        try:
            # Try python-whois first
            try:
                import whois
                w = whois.whois(domain)
                data = {}
                for key in ["domain_name", "registrar", "whois_server", "creation_date",
                            "expiration_date", "updated_date", "name_servers", "status",
                            "emails", "dnssec", "org", "state", "country"]:
                    val = getattr(w, key, None)
                    if val is not None:
                        if isinstance(val, list) and len(val) == 1:
                            val = val[0]
                        if isinstance(val, datetime):
                            val = val.isoformat()
                        elif isinstance(val, list):
                            val = [v.isoformat() if isinstance(v, datetime) else str(v) for v in val]
                        data[key] = val
                report.whois_data = data
                self._add_events(report, data)
                return
            except ImportError:
                pass

            # Fallback: system whois command
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                data = self._parse_raw_whois(result.stdout)
                report.whois_data = data
                self._add_events(report, data)
        except Exception as e:
            self._log(f"WHOIS failed: {e}", progress_cb)

    def _parse_raw_whois(self, raw: str) -> Dict:
        data = {"raw_excerpt": raw[:500]}
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creat(?:ion|ed)\s*Date:\s*(.+)",
            "expiration_date": r"Expir(?:ation|y)\s*Date:\s*(.+)",
            "updated_date": r"Updated?\s*Date:\s*(.+)",
            "name_servers": r"Name\s*Server:\s*(.+)",
            "status": r"Status:\s*(.+)",
            "dnssec": r"DNSSEC:\s*(.+)",
            "org": r"Registrant\s*Organi[sz]ation:\s*(.+)",
            "country": r"Registrant\s*Country:\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, raw, re.I)
            if matches:
                data[key] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches]
        return data

    def _add_events(self, report, data):
        if data.get("creation_date"):
            try:
                dt = self._parse_date(data["creation_date"])
                report.events.append(TimelineEvent(
                    dt, EventCategory.REGISTRATION,
                    "Domain Registered",
                    f"Registered via {data.get('registrar', 'unknown registrar')}",
                    "WHOIS", Severity.INFO
                ))
            except Exception:
                pass
        if data.get("updated_date"):
            try:
                dt = self._parse_date(data["updated_date"])
                report.events.append(TimelineEvent(
                    dt, EventCategory.REGISTRATION,
                    "WHOIS Record Updated",
                    f"Registration record modified",
                    "WHOIS", Severity.INFO
                ))
            except Exception:
                pass
        if data.get("expiration_date"):
            try:
                dt = self._parse_date(data["expiration_date"])
                report.events.append(TimelineEvent(
                    dt, EventCategory.REGISTRATION,
                    "Domain Expires",
                    f"Current expiration date",
                    "WHOIS", Severity.LOW
                ))
            except Exception:
                pass

    def _parse_date(self, val) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, list):
            val = val[0]
        if isinstance(val, datetime):
            return val
        for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d", "%d-%b-%Y", "%Y/%m/%d"]:
            try:
                return datetime.strptime(str(val).strip()[:19], fmt)
            except ValueError:
                continue
        return datetime.fromisoformat(str(val).replace("Z", "+00:00").replace("+00:00","")[:19])


class DNSCollector(BaseCollector):
    name = "DNS"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Enumerating DNS records for {domain}...", progress_cb)
        records = {}

        # Try dnspython first
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            for rtype in self.RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records[rtype] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
        except ImportError:
            # Fallback: basic socket + dig
            try:
                ips = socket.getaddrinfo(domain, None)
                a_records = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET))
                aaaa_records = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET6))
                if a_records:
                    records["A"] = a_records
                if aaaa_records:
                    records["AAAA"] = aaaa_records
            except Exception:
                pass

            # Try dig for other record types
            for rtype in ["MX", "NS", "TXT", "SOA"]:
                try:
                    result = subprocess.run(
                        ["dig", "+short", rtype, domain],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        records[rtype] = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                except Exception:
                    pass

        report.dns_records = records

        # Extract IPs
        for rtype in ["A", "AAAA"]:
            for ip in records.get(rtype, []):
                if ip not in report.ip_addresses:
                    report.ip_addresses.append(ip)

        # Add DNS events
        now = datetime.now()
        if records:
            report.events.append(TimelineEvent(
                now, EventCategory.DNS,
                f"Current DNS Records ({len(records)} types)",
                "; ".join(f"{k}: {', '.join(v[:3])}" for k, v in records.items()),
                "DNS Lookup", Severity.INFO
            ))

        # Detect interesting patterns
        txt_records = records.get("TXT", [])
        for txt in txt_records:
            if "v=spf" in txt.lower():
                report.events.append(TimelineEvent(
                    now, EventCategory.DNS, "SPF Record Configured",
                    txt[:200], "DNS TXT", Severity.INFO
                ))
            if "v=dmarc" in txt.lower():
                report.events.append(TimelineEvent(
                    now, EventCategory.DNS, "DMARC Record Configured",
                    txt[:200], "DNS TXT", Severity.INFO
                ))
            if "_dkim" in txt.lower() or "k=rsa" in txt.lower():
                report.events.append(TimelineEvent(
                    now, EventCategory.DNS, "DKIM Record Found",
                    txt[:200], "DNS TXT", Severity.INFO
                ))


class CertificateCollector(BaseCollector):
    name = "Certificates"

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Querying certificate transparency logs...", progress_cb)

        # 1. Current cert from direct connection
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                if cert:
                    issued = cert.get("notBefore", "")
                    expires = cert.get("notAfter", "")
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    san = [v for _, v in cert.get("subjectAltName", [])]

                    report.certificates.append({
                        "subject": subject.get("commonName", domain),
                        "issuer": issuer.get("organizationName", "Unknown"),
                        "issued": issued,
                        "expires": expires,
                        "san": san,
                        "serial": cert.get("serialNumber", ""),
                    })

                    try:
                        issued_dt = datetime.strptime(issued, "%b %d %H:%M:%S %Y %Z")
                    except Exception:
                        issued_dt = datetime.now()
                    try:
                        expires_dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                    except Exception:
                        expires_dt = datetime.now()

                    report.events.append(TimelineEvent(
                        issued_dt, EventCategory.CERTIFICATE,
                        f"Current Certificate Issued",
                        f"Issuer: {issuer.get('organizationName', '?')} | "
                        f"SANs: {len(san)} | Expires: {expires}",
                        "TLS Connection", Severity.INFO
                    ))

                    # Subdomains from SAN
                    for name in san:
                        clean = name.replace("*.", "").strip()
                        if clean != domain and clean not in report.subdomains and "." in clean:
                            report.subdomains.append(clean)
        except Exception as e:
            self._log(f"Direct TLS failed: {e}", progress_cb)

        # 2. crt.sh — Certificate Transparency Logs
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "NeatLabs-DomainTimeline/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                certs = json.loads(resp.read().decode())

            seen_serials = set()
            for cert in certs[:200]:  # Cap at 200
                serial = cert.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)

                issuer_name = cert.get("issuer_name", "")
                common_name = cert.get("common_name", "")
                not_before = cert.get("not_before", "")
                not_after = cert.get("not_after", "")
                name_value = cert.get("name_value", "")

                report.certificates.append({
                    "subject": common_name,
                    "issuer": issuer_name,
                    "issued": not_before,
                    "expires": not_after,
                    "san": name_value.split("\n") if name_value else [],
                    "serial": serial,
                    "source": "crt.sh",
                })

                # Extract subdomains
                for name in name_value.split("\n"):
                    clean = name.strip().replace("*.", "")
                    if clean and clean != domain and clean not in report.subdomains and "." in clean:
                        report.subdomains.append(clean)

                # Add event for notable certs (not all — would be too noisy)
                try:
                    dt = datetime.strptime(not_before[:19], "%Y-%m-%dT%H:%M:%S")
                except Exception:
                    continue

                report.events.append(TimelineEvent(
                    dt, EventCategory.CERTIFICATE,
                    f"Certificate Issued: {common_name[:60]}",
                    f"Issuer: {issuer_name[:80]} | Expires: {not_after[:10]}",
                    "crt.sh CT Log", Severity.INFO
                ))

            self._log(f"Found {len(seen_serials)} unique certificates", progress_cb)

        except Exception as e:
            self._log(f"crt.sh query failed: {e}", progress_cb)


class WaybackCollector(BaseCollector):
    name = "Wayback"

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Querying Wayback Machine CDX API...", progress_cb)
        try:
            url = (f"https://web.archive.org/cdx/search/cdx?"
                   f"url={domain}&output=json&fl=timestamp,statuscode,mimetype,digest"
                   f"&collapse=digest&limit=500")
            req = urllib.request.Request(url, headers={"User-Agent": "NeatLabs-DomainTimeline/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())

            if len(data) > 1:
                rows = data[1:]  # First row is headers
                report.wayback_snapshots = len(rows)

                if rows:
                    report.wayback_first = rows[0][0]
                    report.wayback_last = rows[-1][0]

                # Sample events — not every snapshot, just notable ones
                # First snapshot, last, and any year boundaries
                seen_years = set()
                for row in rows:
                    ts_str = row[0]
                    try:
                        dt = datetime.strptime(ts_str[:14], "%Y%m%d%H%M%S")
                    except Exception:
                        continue
                    year = dt.year
                    if year not in seen_years or row == rows[0] or row == rows[-1]:
                        seen_years.add(year)
                        status = row[1] if len(row) > 1 else "?"
                        mime = row[2] if len(row) > 2 else "?"

                        label = "First Archived Snapshot" if row == rows[0] else \
                                "Most Recent Snapshot" if row == rows[-1] else \
                                f"Archived Snapshot ({year})"

                        report.events.append(TimelineEvent(
                            dt, EventCategory.CONTENT,
                            label,
                            f"Status: {status} | Type: {mime} | "
                            f"Archive: web.archive.org/web/{ts_str}/{domain}",
                            "Wayback Machine", Severity.INFO
                        ))

                self._log(f"Found {report.wayback_snapshots} snapshots ({report.wayback_first[:4]}–{report.wayback_last[:4]})", progress_cb)

        except Exception as e:
            self._log(f"Wayback query failed: {e}", progress_cb)


class HeaderCollector(BaseCollector):
    name = "HTTP Headers"

    TECH_SIGNATURES = {
        "server": {
            "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
            "microsoft-iis": "Microsoft IIS", "litespeed": "LiteSpeed",
            "openresty": "OpenResty", "caddy": "Caddy", "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn", "express": "Express.js",
        },
        "x-powered-by": {
            "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js",
            "next.js": "Next.js", "nuxt": "Nuxt.js", "django": "Django",
            "flask": "Flask", "ruby": "Ruby/Rails", "java": "Java",
        },
        "x-generator": {
            "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "ghost": "Ghost", "hugo": "Hugo", "jekyll": "Jekyll",
            "gatsby": "Gatsby", "squarespace": "Squarespace", "wix": "Wix",
            "shopify": "Shopify",
        },
    }

    CDN_SIGNATURES = {
        "cf-ray": "Cloudflare", "x-cdn": "CDN", "x-cache": "Cache/CDN",
        "x-amz-cf-id": "Amazon CloudFront", "x-akamai-request-id": "Akamai",
        "x-fastly-request-id": "Fastly", "x-vercel-id": "Vercel",
        "x-netlify-request-id": "Netlify", "fly-request-id": "Fly.io",
    }

    SECURITY_HEADERS = [
        "strict-transport-security", "content-security-policy",
        "x-content-type-options", "x-frame-options",
        "x-xss-protection", "referrer-policy",
        "permissions-policy",
    ]

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Fetching HTTP headers from {domain}...", progress_cb)
        now = datetime.now()

        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{domain}/"
                req = urllib.request.Request(url, method="HEAD",
                    headers={"User-Agent": "NeatLabs-DomainTimeline/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    headers = dict(resp.headers)

                    # Tech detection
                    for header_key, sigs in self.TECH_SIGNATURES.items():
                        val = headers.get(header_key, "").lower()
                        for pattern, tech_name in sigs.items():
                            if pattern in val:
                                if tech_name not in report.tech_stack:
                                    report.tech_stack.append(tech_name)
                                    report.events.append(TimelineEvent(
                                        now, EventCategory.TECHNOLOGY,
                                        f"Technology Detected: {tech_name}",
                                        f"Via {header_key}: {headers.get(header_key, '')}",
                                        "HTTP Headers", Severity.INFO
                                    ))

                    # CDN detection
                    for header_key, cdn_name in self.CDN_SIGNATURES.items():
                        if header_key in {k.lower(): k for k in headers}:
                            if cdn_name not in report.tech_stack:
                                report.tech_stack.append(cdn_name)
                                report.events.append(TimelineEvent(
                                    now, EventCategory.INFRASTRUCTURE,
                                    f"CDN/Platform Detected: {cdn_name}",
                                    f"Identified via {header_key} header",
                                    "HTTP Headers", Severity.INFO
                                ))

                    # Security header audit
                    missing = [h for h in self.SECURITY_HEADERS
                               if h not in {k.lower() for k in headers}]
                    present = [h for h in self.SECURITY_HEADERS
                               if h in {k.lower() for k in headers}]
                    if missing:
                        report.events.append(TimelineEvent(
                            now, EventCategory.INFRASTRUCTURE,
                            f"Security Headers: {len(present)}/{len(self.SECURITY_HEADERS)} configured",
                            f"Missing: {', '.join(missing[:5])}",
                            "HTTP Headers",
                            Severity.MEDIUM if len(missing) > 3 else Severity.LOW
                        ))

                    break  # Got headers from one scheme, don't need the other

            except Exception:
                continue


class RobotsTxtCollector(BaseCollector):
    name = "robots/security.txt"

    # Paths in robots.txt that suggest hidden or sensitive areas
    INTERESTING_PATTERNS = [
        (r'/admin', "Admin panel"),
        (r'/wp-admin', "WordPress admin"),
        (r'/api', "API endpoint"),
        (r'/internal', "Internal resources"),
        (r'/staging', "Staging environment"),
        (r'/backup', "Backup files"),
        (r'/debug', "Debug endpoint"),
        (r'/console', "Console/dashboard"),
        (r'/phpmyadmin', "phpMyAdmin"),
        (r'/\.env', "Environment file"),
        (r'/\.git', "Git repository"),
        (r'/config', "Configuration"),
        (r'/private', "Private resources"),
        (r'/secret', "Secret resources"),
        (r'/test', "Test environment"),
        (r'/dev', "Development area"),
        (r'/cgi-bin', "CGI scripts"),
        (r'/server-status', "Server status page"),
        (r'/dashboard', "Dashboard"),
        (r'/login', "Login page"),
        (r'/panel', "Control panel"),
        (r'/upload', "Upload endpoint"),
        (r'/database', "Database access"),
        (r'/dump', "Data dump"),
        (r'/log', "Log files"),
    ]

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        now = datetime.now()

        # Fetch robots.txt
        self._log(f"Fetching robots.txt...", progress_cb)
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{domain}/robots.txt"
                req = urllib.request.Request(url,
                    headers={"User-Agent": "NeatLabs-DomainTimeline/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status == 200:
                        content = resp.read().decode("utf-8", errors="replace")
                        # Verify it looks like a real robots.txt (not an HTML error page)
                        if ("user-agent" in content.lower() or "disallow" in content.lower()
                                or "sitemap" in content.lower() or "allow" in content.lower()):
                            report.robots_txt = content[:5000]
                            self._analyze_robots(content, domain, report, now)
                            break
            except Exception:
                continue

        # Fetch security.txt (RFC 9116)
        self._log(f"Fetching security.txt...", progress_cb)
        for path in ["/.well-known/security.txt", "/security.txt"]:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{domain}{path}"
                    req = urllib.request.Request(url,
                        headers={"User-Agent": "NeatLabs-DomainTimeline/1.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        if resp.status == 200:
                            content = resp.read().decode("utf-8", errors="replace")
                            if "contact" in content.lower():
                                report.security_txt = content[:3000]
                                report.events.append(TimelineEvent(
                                    now, EventCategory.INFRASTRUCTURE,
                                    "security.txt Published (RFC 9116)",
                                    self._summarize_security_txt(content),
                                    "security.txt", Severity.INFO
                                ))
                                return  # Got it, no need to keep trying paths
                except Exception:
                    continue

    def _analyze_robots(self, content: str, domain: str, report: DomainReport, now: datetime):
        lines = content.split("\n")
        disallowed = []
        sitemaps = []

        for line in lines:
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())

        # Find interesting hidden paths
        hidden = []
        for path in disallowed:
            for pattern, label in self.INTERESTING_PATTERNS:
                if re.search(pattern, path, re.I):
                    hidden.append((path, label))
                    break
        report.robots_hidden_paths = [h[0] for h in hidden]

        # Timeline event
        report.events.append(TimelineEvent(
            now, EventCategory.INFRASTRUCTURE,
            f"robots.txt: {len(disallowed)} Disallowed Paths",
            f"Sitemaps: {len(sitemaps)} | Interesting paths: {', '.join(h[0] for h in hidden[:5]) if hidden else 'none'}",
            "robots.txt", Severity.LOW if hidden else Severity.INFO
        ))

        if hidden:
            report.events.append(TimelineEvent(
                now, EventCategory.THREAT,
                f"Hidden Paths in robots.txt ({len(hidden)})",
                " | ".join(f"{h[0]} ({h[1]})" for h in hidden[:8]),
                "robots.txt Analysis", Severity.MEDIUM
            ))

    def _summarize_security_txt(self, content: str) -> str:
        parts = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("Contact:"):
                parts.append(line)
            elif line.startswith("Expires:"):
                parts.append(line)
            elif line.startswith("Policy:"):
                parts.append(line)
        return " | ".join(parts[:4]) if parts else "security.txt found"


class ReverseDNSCollector(BaseCollector):
    name = "Reverse DNS"

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Running reverse DNS on {len(report.ip_addresses)} IP(s)...", progress_cb)
        now = datetime.now()

        for ip in report.ip_addresses[:10]:  # Cap at 10 IPs
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                report.reverse_dns[ip] = hostname
                self._log(f"  {ip} -> {hostname}", progress_cb)
            except (socket.herror, socket.gaierror, OSError):
                report.reverse_dns[ip] = "(no PTR record)"
            except Exception:
                report.reverse_dns[ip] = "(lookup failed)"

        # Build event
        resolved = {ip: h for ip, h in report.reverse_dns.items() if not h.startswith("(")}
        if resolved:
            detail_parts = [f"{ip} -> {host}" for ip, host in resolved.items()]
            report.events.append(TimelineEvent(
                now, EventCategory.INFRASTRUCTURE,
                f"Reverse DNS: {len(resolved)}/{len(report.ip_addresses)} IPs resolved",
                " | ".join(detail_parts[:5]),
                "PTR Lookup", Severity.INFO
            ))

            # Check for hosting provider clues
            hosting_hints = set()
            for host in resolved.values():
                hl = host.lower()
                if "cloudflare" in hl: hosting_hints.add("Cloudflare")
                elif "amazonaws" in hl or "aws" in hl: hosting_hints.add("AWS")
                elif "google" in hl or "gcp" in hl: hosting_hints.add("Google Cloud")
                elif "azure" in hl or "microsoft" in hl: hosting_hints.add("Azure")
                elif "digitalocean" in hl: hosting_hints.add("DigitalOcean")
                elif "linode" in hl or "akamai" in hl: hosting_hints.add("Akamai/Linode")
                elif "ovh" in hl: hosting_hints.add("OVH")
                elif "hetzner" in hl: hosting_hints.add("Hetzner")
                elif "vultr" in hl: hosting_hints.add("Vultr")

            for provider in hosting_hints:
                if provider not in report.tech_stack:
                    report.tech_stack.append(provider)


class TyposquatCollector(BaseCollector):
    name = "Typosquat"

    # Homoglyph substitutions (characters that look similar)
    HOMOGLYPHS = {
        'a': ['4', '@', 'q'],
        'b': ['d', '6'],
        'c': ['e', 'k'],
        'd': ['b', 'cl'],
        'e': ['3'],
        'g': ['q', '9'],
        'i': ['1', 'l', '!'],
        'l': ['1', 'i', '|'],
        'm': ['n', 'rn'],
        'n': ['m', 'r'],
        'o': ['0', 'q'],
        'p': ['q'],
        'q': ['g', 'p'],
        'r': ['n'],
        's': ['5', '$', 'z'],
        't': ['7'],
        'u': ['v'],
        'v': ['u', 'w'],
        'w': ['vv', 'uu'],
        'z': ['s', '2'],
    }

    # Common TLD swaps
    TLD_SWAPS = {
        '.com': ['.co', '.cm', '.om', '.net', '.org', '.io', '.info', '.xyz', '.cc', '.co.uk'],
        '.net': ['.com', '.org', '.ne', '.nt', '.bet'],
        '.org': ['.com', '.og', '.orgg', '.ogg'],
        '.io': ['.co', '.i0', '.oi', '.com'],
    }

    def collect(self, domain: str, report: DomainReport, progress_cb=None):
        self._log(f"Generating typosquat permutations for {domain}...", progress_cb)

        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return
        name, tld = parts[0], "." + parts[1]

        candidates = set()

        # 1. Character omission (missing one char)
        for i in range(len(name)):
            candidates.add(name[:i] + name[i+1:] + tld)

        # 2. Adjacent character swap
        for i in range(len(name) - 1):
            swapped = list(name)
            swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
            candidates.add("".join(swapped) + tld)

        # 3. Character duplication
        for i in range(len(name)):
            if name[i].isalpha():
                candidates.add(name[:i] + name[i] + name[i:] + tld)

        # 4. Homoglyph substitution
        for i, ch in enumerate(name):
            for replacement in self.HOMOGLYPHS.get(ch.lower(), []):
                candidates.add(name[:i] + replacement + name[i+1:] + tld)

        # 5. Dot insertion (for subdomain confusion: goo.gle.com)
        for i in range(1, len(name)):
            if name[i-1] != '-' and name[i] != '-':
                candidates.add(name[:i] + "." + name[i:] + tld)

        # 6. Hyphen insertion/removal
        if "-" in name:
            candidates.add(name.replace("-", "") + tld)
        for i in range(1, len(name)):
            candidates.add(name[:i] + "-" + name[i:] + tld)

        # 7. TLD swap
        for orig_tld, swaps in self.TLD_SWAPS.items():
            if tld == orig_tld:
                for swap in swaps:
                    candidates.add(name + swap)

        # 8. Common prefix/suffix additions
        for prefix in ["www", "ww", "w"]:
            candidates.add(prefix + name + tld)
        for suffix in ["s", "online", "web", "app", "login", "secure"]:
            candidates.add(name + suffix + tld)

        # Remove the original domain and invalid entries
        candidates.discard(domain)
        candidates = {c for c in candidates if self._is_valid_domain(c) and c != domain}

        self._log(f"Generated {len(candidates)} permutations, checking DNS...", progress_cb)

        # DNS check a subset (limit to keep scan fast)
        check_list = sorted(candidates)[:80]
        checked = 0
        resolving = []

        for candidate in check_list:
            try:
                ips = socket.getaddrinfo(candidate, None, socket.AF_INET, socket.SOCK_STREAM)
                if ips:
                    cand_ips = list(set(ip[4][0] for ip in ips))
                    same_ip = any(ip in report.ip_addresses for ip in cand_ips)
                    report.typosquats.append({
                        "domain": candidate,
                        "resolves": True,
                        "ips": cand_ips[:3],
                        "same_ip": same_ip,
                    })
                    resolving.append(candidate)
            except (socket.gaierror, socket.herror, OSError):
                pass
            except Exception:
                pass
            checked += 1
            if checked % 20 == 0:
                self._log(f"  Checked {checked}/{len(check_list)}...", progress_cb)

        self._log(f"Found {len(resolving)} resolving typosquat domains out of {len(check_list)} checked", progress_cb)

        # Timeline events
        now = datetime.now()
        if resolving:
            same_ip_count = sum(1 for t in report.typosquats if t.get("same_ip"))
            diff_ip = [t for t in report.typosquats if t.get("resolves") and not t.get("same_ip")]

            report.events.append(TimelineEvent(
                now, EventCategory.THREAT,
                f"Typosquat Domains: {len(resolving)} Resolving",
                f"Checked {len(check_list)} permutations | "
                f"Same IP: {same_ip_count} | Different IP: {len(diff_ip)} | "
                f"Examples: {', '.join(resolving[:5])}",
                "DNS Typosquat Check",
                Severity.HIGH if diff_ip else Severity.LOW
            ))
        else:
            report.events.append(TimelineEvent(
                now, EventCategory.THREAT,
                f"Typosquat Check: {len(check_list)} Permutations Clear",
                f"No typosquat domains found resolving out of {len(check_list)} checked",
                "DNS Typosquat Check", Severity.INFO
            ))

    def _is_valid_domain(self, d: str) -> bool:
        if len(d) > 253 or len(d) < 4:
            return False
        if ".." in d:
            return False
        parts = d.split(".")
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', part, re.I):
                return False
        return True


# ═══════════════════════════════════════════════════════════════
# ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════

class AnalysisEngine:
    """Analyze collected data for threat indicators and patterns."""

    def analyze(self, report: DomainReport):
        self._check_domain_age(report)
        self._check_registration_privacy(report)
        self._check_cert_patterns(report)
        self._check_dns_health(report)
        self._check_infrastructure(report)
        self._check_subdomain_sprawl(report)
        self._check_typosquats(report)
        self._check_robots_findings(report)
        self._check_security_txt(report)

    def _check_domain_age(self, report):
        age = report.domain_age_days
        if age is not None:
            if age < 30:
                report.indicators.append(ThreatIndicator(
                    "Newly Registered Domain",
                    f"Domain is only {age} days old. Newly registered domains are frequently used for phishing, malware distribution, and fraud campaigns.",
                    Severity.HIGH,
                    f"Registration age: {age} days"
                ))
            elif age < 180:
                report.indicators.append(ThreatIndicator(
                    "Young Domain",
                    f"Domain is {age} days old ({age // 30} months). Relatively new domains have higher statistical association with malicious activity.",
                    Severity.MEDIUM,
                    f"Registration age: {age} days (~{age // 30} months)"
                ))
            elif age > 3650:
                report.indicators.append(ThreatIndicator(
                    "Well-Established Domain",
                    f"Domain is {age // 365} years old. Long registration history is a positive trust signal.",
                    Severity.INFO,
                    f"Registration age: {age // 365} years"
                ))

    def _check_registration_privacy(self, report):
        whois = report.whois_data
        org = str(whois.get("org", "")).lower()
        if any(p in org for p in ["privacy", "proxy", "redacted", "withheld", "protect"]):
            report.indicators.append(ThreatIndicator(
                "WHOIS Privacy Enabled",
                "Registration details are hidden behind a privacy/proxy service. While common for legitimate domains, this is also used to hide malicious domain ownership.",
                Severity.LOW,
                f"Organization: {whois.get('org', 'N/A')}"
            ))

    def _check_cert_patterns(self, report):
        if not report.certificates:
            report.indicators.append(ThreatIndicator(
                "No SSL/TLS Certificate Found",
                "No certificate detected. The domain may not support HTTPS, which is unusual for legitimate services in 2025.",
                Severity.MEDIUM,
                "No certificates found via TLS or CT logs"
            ))
            return

        # Check for Let's Encrypt (not bad, just notable)
        le_certs = [c for c in report.certificates if "let's encrypt" in str(c.get("issuer", "")).lower()]
        if le_certs and len(le_certs) == len(report.certificates):
            report.indicators.append(ThreatIndicator(
                "All Certificates from Let's Encrypt",
                "Every certificate is from Let's Encrypt. This is the most common free CA and is used by legitimate sites, but also heavily used by phishing/malware infrastructure due to zero-cost automated issuance.",
                Severity.LOW,
                f"{len(le_certs)} of {len(report.certificates)} certs from Let's Encrypt"
            ))

        # Certificate churn
        if len(report.certificates) > 20:
            report.indicators.append(ThreatIndicator(
                "High Certificate Volume",
                f"{len(report.certificates)} certificates found in CT logs. High certificate issuance can indicate infrastructure churn, wildcard abuse, or frequent subdomain creation.",
                Severity.LOW,
                f"{len(report.certificates)} total certificates"
            ))

    def _check_dns_health(self, report):
        dns = report.dns_records
        if not dns:
            report.indicators.append(ThreatIndicator(
                "No DNS Records Resolved",
                "DNS lookup returned no records. Domain may be parked, expired, or using DNS that blocks lookups.",
                Severity.MEDIUM,
                "No A, AAAA, MX, NS, or TXT records found"
            ))
            return

        # No MX records
        if "MX" not in dns:
            report.indicators.append(ThreatIndicator(
                "No MX Records",
                "No mail exchange records configured. Domain cannot receive email, which may be expected or may indicate a non-email domain being used for phishing.",
                Severity.INFO,
                "MX record lookup returned empty"
            ))

        # SPF/DMARC check
        txt_records = dns.get("TXT", [])
        has_spf = any("v=spf" in t.lower() for t in txt_records)
        has_dmarc = any("v=dmarc" in t.lower() for t in txt_records)
        if not has_spf and not has_dmarc and "MX" in dns:
            report.indicators.append(ThreatIndicator(
                "No Email Authentication (SPF/DMARC)",
                "Domain has MX records but no SPF or DMARC. This makes the domain vulnerable to email spoofing.",
                Severity.MEDIUM,
                "Missing both SPF and DMARC TXT records"
            ))

    def _check_infrastructure(self, report):
        # Check for suspicious hosting
        for ip in report.ip_addresses:
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    first = int(parts[0])
                    if first in (10, 127) or (first == 172 and 16 <= int(parts[1]) <= 31) or (first == 192 and int(parts[1]) == 168):
                        report.indicators.append(ThreatIndicator(
                            "Private IP Address in DNS",
                            f"DNS resolves to private/internal IP {ip}. This should not be publicly visible and may indicate misconfiguration or DNS rebinding setup.",
                            Severity.HIGH,
                            f"Resolved IP: {ip}"
                        ))
                except ValueError:
                    pass

    def _check_subdomain_sprawl(self, report):
        if len(report.subdomains) > 50:
            report.indicators.append(ThreatIndicator(
                "Large Subdomain Footprint",
                f"{len(report.subdomains)} subdomains discovered. Large subdomain counts increase attack surface and may include forgotten, unmonitored, or misconfigured services.",
                Severity.LOW,
                f"{len(report.subdomains)} unique subdomains from CT logs"
            ))

    def _check_typosquats(self, report):
        resolving = [t for t in report.typosquats if t.get("resolves")]
        diff_ip = [t for t in resolving if not t.get("same_ip")]
        if diff_ip:
            report.indicators.append(ThreatIndicator(
                f"Active Typosquat Domains ({len(diff_ip)})",
                f"{len(diff_ip)} typosquat domain(s) resolve to different IP addresses than the target. These could be used for phishing, credential harvesting, or brand impersonation.",
                Severity.HIGH,
                f"Resolving to different IPs: {', '.join(t['domain'] for t in diff_ip[:5])}"
            ))
        elif resolving:
            report.indicators.append(ThreatIndicator(
                f"Typosquat Domains Resolve ({len(resolving)})",
                f"{len(resolving)} typosquat permutation(s) resolve, but to the same IP(s) as the target — likely defensive registrations by the domain owner.",
                Severity.INFO,
                f"Same-IP typosquats: {', '.join(t['domain'] for t in resolving[:5])}"
            ))

    def _check_robots_findings(self, report):
        if report.robots_hidden_paths:
            sensitive = [p for p in report.robots_hidden_paths
                         if any(kw in p.lower() for kw in ["/admin", "/backup", "/.env", "/.git",
                                "/private", "/secret", "/database", "/dump", "/config"])]
            if sensitive:
                report.indicators.append(ThreatIndicator(
                    f"Sensitive Paths in robots.txt ({len(sensitive)})",
                    "The robots.txt file disallows paths that suggest sensitive infrastructure: admin panels, configuration files, backups, or internal tools. While robots.txt prevents indexing, it also serves as a roadmap for attackers.",
                    Severity.MEDIUM,
                    f"Paths: {', '.join(sensitive[:6])}"
                ))

    def _check_security_txt(self, report):
        if not report.security_txt and report.dns_records:
            report.indicators.append(ThreatIndicator(
                "No security.txt (RFC 9116)",
                "No security.txt file found. RFC 9116 recommends publishing a security.txt to help security researchers report vulnerabilities responsibly.",
                Severity.INFO,
                "Checked /.well-known/security.txt and /security.txt"
            ))


# ═══════════════════════════════════════════════════════════════
# MAIN SCANNER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

class DomainScanner:
    """Orchestrates all collectors and analysis."""

    def __init__(self):
        self.collectors = [
            WHOISCollector(),
            DNSCollector(),
            CertificateCollector(),
            WaybackCollector(),
            HeaderCollector(),
            RobotsTxtCollector(),
            ReverseDNSCollector(),
            TyposquatCollector(),
        ]
        self.analyzer = AnalysisEngine()

    def scan(self, domain: str, progress_cb=None) -> DomainReport:
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]

        t0 = time.perf_counter()
        report = DomainReport(
            domain=domain,
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_duration_s=0,
        )

        for collector in self.collectors:
            try:
                collector.collect(domain, report, progress_cb)
            except Exception as e:
                if progress_cb:
                    progress_cb(f"[{collector.name}] Error: {e}")

        # Run analysis
        self.analyzer.analyze(report)

        # Sort events chronologically
        report.events.sort(key=lambda e: e.timestamp)

        # Deduplicate subdomains
        report.subdomains = sorted(set(report.subdomains))

        report.scan_duration_s = time.perf_counter() - t0
        return report


# ═══════════════════════════════════════════════════════════════
# DEMO DATA — Rich realistic sample for testing/showcasing
# ═══════════════════════════════════════════════════════════════

def build_demo_report() -> DomainReport:
    """Build a realistic demo report showcasing all features."""
    now = datetime.now()
    report = DomainReport(
        domain="shadowedge-dynamics.io",
        scan_time=now.strftime("%Y-%m-%d %H:%M:%S"),
        scan_duration_s=4.72,
    )

    report.whois_data = {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2023-03-15T08:22:14",
        "expiration_date": "2026-03-15T08:22:14",
        "updated_date": "2024-11-02T14:33:07",
        "name_servers": ["dns1.registrar-servers.com", "dns2.registrar-servers.com"],
        "status": "clientTransferProhibited",
        "org": "Privacy service provided by Withheld for Privacy ehf",
        "country": "IS",
        "dnssec": "unsigned",
    }

    report.dns_records = {
        "A": ["104.21.48.192", "172.67.182.44"],
        "AAAA": ["2606:4700:3030::6815:30c0", "2606:4700:3030::ac43:b62c"],
        "MX": ["10 mx1.shadowedge-dynamics.io", "20 mx2.shadowedge-dynamics.io"],
        "NS": ["dns1.registrar-servers.com.", "dns2.registrar-servers.com."],
        "TXT": [
            "v=spf1 include:_spf.google.com ~all",
            "google-site-verification=abc123def456",
        ],
        "SOA": ["dns1.registrar-servers.com. hostmaster.shadowedge-dynamics.io. 2024110201 3600 600 604800 1800"],
    }

    report.ip_addresses = ["104.21.48.192", "172.67.182.44"]
    report.tech_stack = ["Cloudflare", "Next.js", "Vercel", "React"]

    report.subdomains = [
        "www.shadowedge-dynamics.io", "api.shadowedge-dynamics.io",
        "staging.shadowedge-dynamics.io", "dev.shadowedge-dynamics.io",
        "mail.shadowedge-dynamics.io", "app.shadowedge-dynamics.io",
        "docs.shadowedge-dynamics.io", "status.shadowedge-dynamics.io",
        "admin.shadowedge-dynamics.io", "cdn.shadowedge-dynamics.io",
        "beta.shadowedge-dynamics.io", "webhook.shadowedge-dynamics.io",
        "grafana.shadowedge-dynamics.io", "sentry.shadowedge-dynamics.io",
        "k8s.shadowedge-dynamics.io",
    ]

    report.certificates = [
        {"subject": "shadowedge-dynamics.io", "issuer": "E6, Let's Encrypt", "issued": "2025-01-10", "expires": "2025-04-10", "san": ["shadowedge-dynamics.io", "*.shadowedge-dynamics.io"], "serial": "04:AA:BB:CC"},
        {"subject": "shadowedge-dynamics.io", "issuer": "E5, Let's Encrypt", "issued": "2024-10-12", "expires": "2025-01-10", "san": ["shadowedge-dynamics.io", "*.shadowedge-dynamics.io"], "serial": "04:DD:EE:FF"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2024-07-14", "expires": "2024-10-12", "san": ["shadowedge-dynamics.io", "www.shadowedge-dynamics.io"], "serial": "03:AA:BB:CC"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2024-04-15", "expires": "2024-07-14", "san": ["shadowedge-dynamics.io", "www.shadowedge-dynamics.io"], "serial": "03:DD:EE:FF"},
        {"subject": "api.shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2024-06-20", "expires": "2024-09-18", "san": ["api.shadowedge-dynamics.io"], "serial": "03:11:22:33"},
        {"subject": "staging.shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2024-05-01", "expires": "2024-07-30", "san": ["staging.shadowedge-dynamics.io"], "serial": "03:44:55:66"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2024-01-16", "expires": "2024-04-15", "san": ["shadowedge-dynamics.io"], "serial": "03:77:88:99"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2023-10-18", "expires": "2024-01-16", "san": ["shadowedge-dynamics.io"], "serial": "03:AA:00:11"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2023-07-20", "expires": "2023-10-18", "san": ["shadowedge-dynamics.io"], "serial": "03:BB:22:33"},
        {"subject": "shadowedge-dynamics.io", "issuer": "R3, Let's Encrypt", "issued": "2023-04-21", "expires": "2023-07-20", "san": ["shadowedge-dynamics.io"], "serial": "03:CC:44:55"},
    ]

    report.wayback_snapshots = 47
    report.wayback_first = "20230501"
    report.wayback_last = "20250201"

    report.reverse_dns = {
        "104.21.48.192": "104.21.48.192.in-addr.arpa (Cloudflare)",
        "172.67.182.44": "172.67.182.44.in-addr.arpa (Cloudflare)",
    }

    report.robots_txt = "User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\nDisallow: /staging/\nDisallow: /.env\nDisallow: /config/\nDisallow: /backup/\nDisallow: /debug/\nSitemap: https://shadowedge-dynamics.io/sitemap.xml"
    report.robots_hidden_paths = ["/admin/", "/api/internal/", "/staging/", "/.env", "/config/", "/backup/", "/debug/"]
    report.security_txt = "Contact: mailto:security@shadowedge-dynamics.io\nExpires: 2026-01-01T00:00:00.000Z\nPreferred-Languages: en\nPolicy: https://shadowedge-dynamics.io/.well-known/security-policy"

    report.typosquats = [
        {"domain": "shadowedge-dynamic.io", "resolves": True, "ips": ["185.199.108.153"], "same_ip": False},
        {"domain": "shadowedgedynamics.io", "resolves": True, "ips": ["104.21.48.192"], "same_ip": True},
        {"domain": "shadowedge-dynamics.co", "resolves": True, "ips": ["34.102.136.180"], "same_ip": False},
        {"domain": "shadow3dge-dynamics.io", "resolves": False, "ips": [], "same_ip": False},
        {"domain": "shadowedge-dynamlcs.io", "resolves": False, "ips": [], "same_ip": False},
    ]

    # ── Build timeline events ──
    events = [
        TimelineEvent(datetime(2023, 3, 15, 8, 22), EventCategory.REGISTRATION,
            "Domain Registered", "Registered via Namecheap, Inc. | WHOIS privacy enabled (Withheld for Privacy ehf) | Country: Iceland",
            "WHOIS", Severity.INFO),
        TimelineEvent(datetime(2023, 4, 21, 10, 0), EventCategory.CERTIFICATE,
            "First SSL Certificate Issued", "Issuer: R3, Let's Encrypt | Single domain cert, no wildcard",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2023, 5, 1, 14, 30), EventCategory.CONTENT,
            "First Wayback Snapshot", "Site first archived by Wayback Machine. Status: 200 | text/html",
            "Wayback Machine", Severity.INFO),
        TimelineEvent(datetime(2023, 5, 15, 9, 0), EventCategory.INFRASTRUCTURE,
            "Initial Infrastructure: Vercel", "HTTP headers show Vercel deployment | x-vercel-id detected",
            "HTTP Headers", Severity.INFO),
        TimelineEvent(datetime(2023, 5, 15, 9, 0), EventCategory.TECHNOLOGY,
            "Tech Stack: Next.js + React", "X-Powered-By: Next.js detected in response headers",
            "HTTP Headers", Severity.INFO),
        TimelineEvent(datetime(2023, 7, 20, 11, 0), EventCategory.CERTIFICATE,
            "Certificate Renewed", "Second Let's Encrypt certificate issued. Still single domain, no wildcard.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2023, 9, 10, 15, 0), EventCategory.DNS,
            "MX Records Configured", "Mail exchange records added: mx1 and mx2. Google Workspace SPF configured.",
            "DNS History", Severity.INFO),
        TimelineEvent(datetime(2023, 10, 18, 8, 30), EventCategory.CERTIFICATE,
            "Certificate Renewed", "Third Let's Encrypt cert. Regular 90-day rotation pattern.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 1, 16, 9, 15), EventCategory.CERTIFICATE,
            "Certificate Renewed", "Regular rotation continues. Still single-domain coverage.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 2, 8, 16, 0), EventCategory.INFRASTRUCTURE,
            "DNS Changed: Cloudflare Proxy Enabled", "A records changed from Vercel IPs to Cloudflare IPs (104.21.x.x, 172.67.x.x). CF-Ray header now present.",
            "DNS + HTTP", Severity.MEDIUM),
        TimelineEvent(datetime(2024, 3, 1, 10, 0), EventCategory.SUBDOMAIN,
            "Subdomain Expansion: api.shadowedge-dynamics.io", "API subdomain appeared in CT logs. Separate certificate issued.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 3, 15, 12, 0), EventCategory.SUBDOMAIN,
            "Subdomain: staging.shadowedge-dynamics.io", "Staging environment subdomain discovered via CT logs.",
            "crt.sh CT Log", Severity.LOW),
        TimelineEvent(datetime(2024, 4, 15, 8, 0), EventCategory.CERTIFICATE,
            "Certificate Renewed + Expanded", "New cert now covers www. subdomain. Coverage scope increasing.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 5, 20, 14, 0), EventCategory.SUBDOMAIN,
            "Rapid Subdomain Growth", "5 new subdomains discovered in May: dev, app, docs, status, admin",
            "crt.sh CT Log", Severity.LOW),
        TimelineEvent(datetime(2024, 6, 20, 9, 0), EventCategory.CERTIFICATE,
            "Separate API Certificate", "Dedicated certificate for api.shadowedge-dynamics.io issued.",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 7, 14, 11, 30), EventCategory.CERTIFICATE,
            "Certificate Renewed + Wildcard", "Upgraded to wildcard certificate (*.shadowedge-dynamics.io). Significant change — now covers all subdomains.",
            "crt.sh CT Log", Severity.MEDIUM),
        TimelineEvent(datetime(2024, 8, 5, 10, 0), EventCategory.SUBDOMAIN,
            "Internal Tools Exposed", "grafana., sentry., k8s. subdomains discovered. These are typically internal monitoring/infrastructure tools.",
            "crt.sh CT Log", Severity.MEDIUM),
        TimelineEvent(datetime(2024, 9, 12, 16, 0), EventCategory.CONTENT,
            "Wayback: Major Content Change", "Page structure significantly changed. New framework/template detected in archived version.",
            "Wayback Machine", Severity.INFO),
        TimelineEvent(datetime(2024, 10, 12, 8, 0), EventCategory.CERTIFICATE,
            "Certificate Renewed (Wildcard)", "Wildcard cert rotation continues. Now using E5 issuer (newer Let's Encrypt chain).",
            "crt.sh CT Log", Severity.INFO),
        TimelineEvent(datetime(2024, 11, 2, 14, 33), EventCategory.REGISTRATION,
            "WHOIS Record Updated", "Registration record modified. Possible registrar transfer or contact update.",
            "WHOIS", Severity.INFO),
        TimelineEvent(datetime(2024, 11, 15, 10, 0), EventCategory.INFRASTRUCTURE,
            "Security Headers: 4/7 Configured", "Missing: Content-Security-Policy, Permissions-Policy, Referrer-Policy",
            "HTTP Headers", Severity.LOW),
        TimelineEvent(datetime(2025, 1, 10, 7, 45), EventCategory.CERTIFICATE,
            "Current Certificate Issued", "Active wildcard cert from E6, Let's Encrypt. Expires April 2025.",
            "TLS Connection", Severity.INFO),
        TimelineEvent(datetime(2025, 2, 1, 12, 0), EventCategory.CONTENT,
            "Most Recent Wayback Snapshot", "Latest archived version. 47 total snapshots since May 2023.",
            "Wayback Machine", Severity.INFO),
        TimelineEvent(now, EventCategory.DNS,
            "Current DNS: Cloudflare + Google MX", "A: 104.21.48.192, 172.67.182.44 | MX: Google Workspace | SPF configured, DMARC missing",
            "DNS Lookup", Severity.INFO),
        TimelineEvent(now, EventCategory.TECHNOLOGY,
            "Current Stack: Cloudflare + Next.js + Vercel + React", "Technology fingerprint from HTTP response headers",
            "HTTP Headers", Severity.INFO),
        TimelineEvent(now, EventCategory.INFRASTRUCTURE,
            "robots.txt: 7 Disallowed Paths",
            "Sitemaps: 1 | Interesting paths: /admin/, /api/internal/, /staging/, /.env, /config/",
            "robots.txt", Severity.LOW),
        TimelineEvent(now, EventCategory.THREAT,
            "Hidden Paths in robots.txt (7)",
            "/admin/ (Admin panel) | /api/internal/ (API endpoint) | /staging/ (Staging) | /.env (Environment file) | /config/ (Configuration) | /backup/ (Backup files) | /debug/ (Debug endpoint)",
            "robots.txt Analysis", Severity.MEDIUM),
        TimelineEvent(now, EventCategory.INFRASTRUCTURE,
            "security.txt Published (RFC 9116)",
            "Contact: mailto:security@shadowedge-dynamics.io | Expires: 2026-01-01 | Policy: published",
            "security.txt", Severity.INFO),
        TimelineEvent(now, EventCategory.INFRASTRUCTURE,
            "Reverse DNS: 2/2 IPs resolved",
            "104.21.48.192 -> Cloudflare | 172.67.182.44 -> Cloudflare",
            "PTR Lookup", Severity.INFO),
        TimelineEvent(now, EventCategory.THREAT,
            "Typosquat Domains: 3 Resolving",
            "Checked 80 permutations | Same IP: 1 | Different IP: 2 | Examples: shadowedge-dynamic.io, shadowedge-dynamics.co",
            "DNS Typosquat Check", Severity.HIGH),
    ]
    report.events = sorted(events, key=lambda e: e.timestamp)

    # ── Indicators ──
    report.indicators = [
        ThreatIndicator(
            "Young Domain (Under 2 Years)",
            "Domain is approximately 23 months old. While not extremely new, it hasn't established a long-term reputation yet.",
            Severity.LOW,
            "Registration age: ~700 days"
        ),
        ThreatIndicator(
            "WHOIS Privacy Enabled",
            "Registration details hidden via Withheld for Privacy ehf (Iceland). Common practice but obscures ownership.",
            Severity.LOW,
            "Organization: Privacy service provided by Withheld for Privacy ehf"
        ),
        ThreatIndicator(
            "Internal Infrastructure Subdomains Exposed",
            "grafana., sentry., and k8s. subdomains were found in CT logs. These are internal monitoring and orchestration tools that should not be publicly discoverable.",
            Severity.MEDIUM,
            "Subdomains: grafana, sentry, k8s visible in Certificate Transparency"
        ),
        ThreatIndicator(
            "Missing DMARC Record",
            "Domain has MX records and SPF but no DMARC policy. This makes the domain susceptible to email spoofing attacks.",
            Severity.MEDIUM,
            "MX records present, SPF configured, DMARC absent"
        ),
        ThreatIndicator(
            "All Certificates from Let's Encrypt",
            "10 certificates found, all issued by Let's Encrypt. Free CA used by legitimate sites and threat actors alike.",
            Severity.INFO,
            "10/10 certs from Let's Encrypt (R3/E5/E6)"
        ),
        ThreatIndicator(
            "Rapid Subdomain Growth",
            "15 subdomains discovered, with most appearing within a 6-month period. Rapid expansion increases attack surface.",
            Severity.LOW,
            "15 subdomains, mostly created Mar-Aug 2024"
        ),
        ThreatIndicator(
            "Active Typosquat Domains (2)",
            "2 typosquat domains resolve to different IP addresses than the target. These could be used for phishing, credential harvesting, or brand impersonation.",
            Severity.HIGH,
            "Resolving to different IPs: shadowedge-dynamic.io, shadowedge-dynamics.co"
        ),
        ThreatIndicator(
            "Sensitive Paths in robots.txt (5)",
            "The robots.txt file disallows paths that suggest sensitive infrastructure: admin panels, configuration files, backups, or internal tools.",
            Severity.MEDIUM,
            "Paths: /admin/, /.env, /config/, /backup/, /debug/"
        ),
    ]

    return report


# ═══════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR — Intelligence Dossier Aesthetic
# ═══════════════════════════════════════════════════════════════

def _h(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def generate_html_report(report: DomainReport) -> str:
    """Generate an intelligence-dossier-themed HTML report."""
    score_indicators = len(report.indicators)
    sev_counts = report.severity_counts

    # ── Build timeline HTML ──
    timeline_html = ""
    current_year = None
    for i, ev in enumerate(report.events):
        yr = ev.timestamp.year
        if yr != current_year:
            current_year = yr
            timeline_html += f'<div class="tl-year">{yr}</div>\n'

        color = EVENT_COLORS.get(ev.category, "#7A8A9E")
        icon = EVENT_ICONS.get(ev.category, "•")
        sev_cls = ev.severity.value.lower()

        timeline_html += f"""
        <div class="tl-event" style="--event-color: {color}" data-category="{ev.category.value.lower().replace(' ', '-')}">
            <div class="tl-marker"><div class="tl-dot" style="background: {color}; box-shadow: 0 0 12px {color}66"></div></div>
            <div class="tl-card">
                <div class="tl-date">{ev.date_str}</div>
                <div class="tl-header">
                    <span class="tl-icon">{icon}</span>
                    <span class="tl-title">{_h(ev.title)}</span>
                </div>
                <div class="tl-detail">{_h(ev.detail)}</div>
                <div class="tl-source">{_h(ev.source)}</div>
            </div>
        </div>"""

    # ── Indicators HTML ──
    indicators_html = ""
    for ind in sorted(report.indicators, key=lambda x: list(Severity).index(x.severity)):
        sc = SEVERITY_COLORS[ind.severity]
        indicators_html += f"""
        <div class="ind-card" style="border-left-color: {sc}">
            <div class="ind-header">
                <span class="ind-sev" style="background:{sc}">{ind.severity.value}</span>
                <span class="ind-title">{_h(ind.title)}</span>
            </div>
            <p class="ind-desc">{_h(ind.description)}</p>
            <p class="ind-evidence">Evidence: {_h(ind.evidence)}</p>
        </div>"""

    # ── Subdomains HTML ──
    subs_html = ""
    for sub in sorted(report.subdomains)[:50]:
        subs_html += f'<span class="sub-tag">{_h(sub)}</span>\n'

    # ── DNS table ──
    dns_html = ""
    for rtype, values in report.dns_records.items():
        for v in values[:5]:
            dns_html += f'<tr><td class="dns-type">{_h(rtype)}</td><td class="dns-val">{_h(v[:120])}</td></tr>\n'

    # ── Cert table ──
    cert_html = ""
    for c in report.certificates[:15]:
        cert_html += f'<tr><td>{_h(str(c.get("subject",""))[:50])}</td><td>{_h(str(c.get("issuer",""))[:40])}</td><td>{_h(str(c.get("issued",""))[:10])}</td><td>{_h(str(c.get("expires",""))[:10])}</td></tr>\n'

    # Category filter buttons
    cat_filters = ""
    for cat in EventCategory:
        count = report.category_counts.get(cat, 0)
        if count > 0:
            color = EVENT_COLORS[cat]
            icon = EVENT_ICONS[cat]
            cat_filters += f'<button class="cat-btn active" data-cat="{cat.value.lower().replace(" ","-")}" style="--cat-color:{color}" onclick="toggleCat(this)">{icon} {cat.value} ({count})</button>\n'

    # WHOIS summary
    whois_html = ""
    display_keys = [("registrar", "Registrar"), ("org", "Organization"), ("country", "Country"),
                    ("creation_date", "Created"), ("expiration_date", "Expires"), ("updated_date", "Updated"),
                    ("dnssec", "DNSSEC"), ("status", "Status")]
    for key, label in display_keys:
        val = report.whois_data.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val[:3])
            whois_html += f'<tr><td class="whois-key">{label}</td><td class="whois-val">{_h(str(val)[:120])}</td></tr>\n'

    age_display = ""
    age = report.domain_age_days
    if age is not None:
        years = age // 365
        months = (age % 365) // 30
        age_display = f"{years}y {months}m" if years > 0 else f"{months}m {age % 30}d"

    # Reverse DNS HTML
    rdns_html = ""
    for ip, host in report.reverse_dns.items():
        rdns_html += f'<tr><td class="dns-type">{_h(ip)}</td><td class="dns-val">{_h(host)}</td></tr>\n'

    # Typosquat HTML
    typo_resolving = [t for t in report.typosquats if t.get("resolves")]
    typo_html = ""
    for t in sorted(typo_resolving, key=lambda x: not x.get("same_ip", False)):
        ips_str = ", ".join(t.get("ips", [])[:3])
        same = "Same IP" if t.get("same_ip") else "Different IP"
        same_cls = "typo-safe" if t.get("same_ip") else "typo-danger"
        typo_html += f'<tr class="{same_cls}"><td class="dns-type">{_h(t["domain"])}</td><td>{_h(ips_str)}</td><td class="{same_cls}">{same}</td></tr>\n'

    # robots.txt HTML
    robots_html = ""
    if report.robots_txt:
        escaped_robots = _h(report.robots_txt[:3000])
        robots_html = f'<pre class="robots-pre">{escaped_robots}</pre>'
        if report.robots_hidden_paths:
            robots_html += '<div class="robots-paths"><strong style="color:var(--amber)">Interesting disallowed paths:</strong><br>'
            robots_html += " ".join(f'<code>{_h(p)}</code>' for p in report.robots_hidden_paths[:10])
            robots_html += '</div>'

    # security.txt HTML
    sectxt_html = ""
    if report.security_txt:
        sectxt_html = f'<pre class="robots-pre">{_h(report.security_txt[:2000])}</pre>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Domain Intel — {_h(report.domain)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=IBM+Plex+Mono:wght@400;500;600&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #1A1714; --panel: #221F1A; --card: #2A2620; --hover: #342F28;
    --fg: #E8DFD0; --fg2: #A69882; --dim: #6B5E4E;
    --gold: #C8A96E; --gold-glow: rgba(200,169,110,0.25);
    --amber: #E8944A; --red: #E85D4A; --teal: #6EC8C8;
    --green: #6EC86E; --blue: #6E8BC8; --purple: #8B6EC8;
    --border: #3D362C;
    --font-display: 'DM Serif Display', Georgia, serif;
    --font-body: 'DM Sans', system-ui, sans-serif;
    --font-mono: 'IBM Plex Mono', 'Consolas', monospace;
}}
*,*::before,*::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: var(--font-body); background: var(--bg); color: var(--fg); line-height: 1.6;
    background-image: radial-gradient(ellipse at 20% 50%, rgba(200,169,110,0.03) 0%, transparent 60%),
                      radial-gradient(ellipse at 80% 20%, rgba(110,200,200,0.02) 0%, transparent 50%); }}
a {{ color: var(--gold); text-decoration: none; }} a:hover {{ text-decoration: underline; }}
code {{ font-family: var(--font-mono); font-size: 0.88em; background: #000; color: var(--gold); padding: 2px 6px; border-radius: 3px; }}

/* ── TOPBAR ── */
.topbar {{ background: var(--panel); border-bottom: 1px solid var(--gold); padding: 22px 48px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }}
.logo h1 {{ font-family: var(--font-display); font-size: 22px; color: var(--gold); font-weight: 400; letter-spacing: 0.5px; }}
.logo p {{ font-family: var(--font-mono); font-size: 10px; color: var(--fg2); letter-spacing: 2px; text-transform: uppercase; }}
.topbar-right {{ display: flex; align-items: center; gap: 16px; }}
.domain-chip {{ font-family: var(--font-mono); font-size: 15px; color: var(--fg); background: var(--card); padding: 8px 20px; border-radius: 6px; border: 1px solid var(--border); letter-spacing: 0.5px; }}
.print-btn {{ background: var(--card); color: var(--fg2); border: 1px solid var(--border); padding: 8px 18px; border-radius: 6px; cursor: pointer; font-family: var(--font-mono); font-size: 12px; }}
.print-btn:hover {{ background: var(--gold); color: var(--bg); border-color: var(--gold); }}

.container {{ max-width: 1100px; margin: 0 auto; padding: 40px 48px 80px; }}

/* ── DOSSIER HEADER ── */
.dossier-header {{ text-align: center; padding: 50px 0 40px; border-bottom: 1px solid var(--border); margin-bottom: 40px; }}
.dossier-header h2 {{ font-family: var(--font-display); font-size: 42px; color: var(--gold); font-weight: 400; margin-bottom: 8px; }}
.dossier-subtitle {{ font-family: var(--font-mono); font-size: 12px; color: var(--fg2); letter-spacing: 3px; text-transform: uppercase; }}
.dossier-meta {{ display: flex; justify-content: center; gap: 32px; margin-top: 20px; font-family: var(--font-mono); font-size: 12px; color: var(--dim); }}
.dossier-meta span {{ display: flex; align-items: center; gap: 6px; }}

/* ── SUMMARY CARDS ── */
.sum-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: 12px; margin-bottom: 40px; }}
.sum-card {{ background: var(--panel); border-radius: 8px; padding: 20px; border: 1px solid var(--border); text-align: center; transition: transform 0.15s; }}
.sum-card:hover {{ transform: translateY(-2px); }}
.sum-val {{ font-family: var(--font-display); font-size: 32px; color: var(--gold); }}
.sum-lbl {{ font-family: var(--font-mono); font-size: 10px; color: var(--fg2); text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; }}

/* ── SECTION HEADERS ── */
.section {{ margin-bottom: 48px; }}
.sec-title {{ font-family: var(--font-display); font-size: 24px; color: var(--gold); font-weight: 400; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }}
.sec-count {{ font-family: var(--font-mono); font-size: 12px; color: var(--dim); }}

/* ── INDICATORS ── */
.ind-card {{ background: var(--panel); border-radius: 8px; padding: 18px 22px; margin-bottom: 10px; border-left: 3px solid var(--dim); transition: border-color 0.15s; }}
.ind-card:hover {{ border-left-width: 5px; }}
.ind-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
.ind-sev {{ font-family: var(--font-mono); font-size: 9px; font-weight: 600; padding: 2px 8px; border-radius: 3px; color: #fff; letter-spacing: 0.5px; }}
.ind-title {{ font-weight: 600; font-size: 14px; }}
.ind-desc {{ font-size: 13px; color: var(--fg2); line-height: 1.5; }}
.ind-evidence {{ font-family: var(--font-mono); font-size: 11px; color: var(--dim); margin-top: 8px; }}

/* ── TIMELINE ── */
.tl-filters {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }}
.cat-btn {{ font-family: var(--font-mono); font-size: 11px; font-weight: 500; padding: 5px 14px; border-radius: 4px; border: 1px solid var(--border); background: var(--panel); color: var(--fg2); cursor: pointer; transition: all 0.15s; }}
.cat-btn:hover {{ border-color: var(--cat-color); color: var(--cat-color); }}
.cat-btn.active {{ background: color-mix(in srgb, var(--cat-color) 15%, var(--panel)); border-color: var(--cat-color); color: var(--cat-color); }}
.cat-btn.inactive {{ opacity: 0.3; }}

.timeline {{ position: relative; padding-left: 40px; }}
.timeline::before {{ content: ''; position: absolute; left: 15px; top: 0; bottom: 0; width: 1px; background: linear-gradient(to bottom, var(--gold)44, var(--border), var(--gold)44); }}
.tl-year {{ font-family: var(--font-display); font-size: 28px; color: var(--gold); margin: 32px 0 16px -8px; position: relative; z-index: 1; }}
.tl-event {{ display: flex; gap: 20px; margin-bottom: 8px; position: relative; animation: fadeSlide 0.4s ease-out both; }}
.tl-event.hidden {{ display: none; }}
.tl-marker {{ position: absolute; left: -33px; top: 14px; width: 12px; height: 12px; display: flex; align-items: center; justify-content: center; }}
.tl-dot {{ width: 10px; height: 10px; border-radius: 50%; transition: transform 0.2s; }}
.tl-event:hover .tl-dot {{ transform: scale(1.5); }}
.tl-card {{ flex: 1; background: var(--panel); border-radius: 8px; padding: 16px 20px; border: 1px solid var(--border); transition: border-color 0.15s, transform 0.15s; }}
.tl-card:hover {{ border-color: var(--event-color); transform: translateX(4px); }}
.tl-date {{ font-family: var(--font-mono); font-size: 11px; color: var(--dim); margin-bottom: 4px; }}
.tl-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
.tl-icon {{ font-size: 16px; }}
.tl-title {{ font-weight: 600; font-size: 14px; color: var(--fg); }}
.tl-detail {{ font-size: 13px; color: var(--fg2); line-height: 1.5; }}
.tl-source {{ font-family: var(--font-mono); font-size: 10px; color: var(--dim); margin-top: 6px; text-transform: uppercase; letter-spacing: 1px; }}

@keyframes fadeSlide {{ from {{ opacity: 0; transform: translateX(-12px); }} to {{ opacity: 1; transform: translateX(0); }} }}

/* ── DATA TABLES ── */
.data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; }}
.data-table th {{ font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--fg2); padding: 10px 14px; text-align: left; background: var(--panel); border-bottom: 1px solid var(--border); }}
.data-table td {{ padding: 8px 14px; border-bottom: 1px solid var(--border)66; font-family: var(--font-mono); font-size: 12px; }}
.data-table tr:hover {{ background: var(--card); }}
.dns-type {{ color: var(--gold); font-weight: 600; width: 60px; }}
.whois-key {{ color: var(--gold); font-weight: 600; width: 100px; }}

/* ── SUBDOMAINS ── */
.sub-cloud {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.sub-tag {{ font-family: var(--font-mono); font-size: 11px; background: var(--card); color: var(--fg2); padding: 4px 12px; border-radius: 4px; border: 1px solid var(--border); transition: all 0.15s; }}
.sub-tag:hover {{ color: var(--gold); border-color: var(--gold); }}

/* ── TYPOSQUATS ── */
.typo-danger {{ color: var(--red); }}
.typo-safe {{ color: var(--teal); }}
.typo-danger td {{ color: var(--red); }}
tr.typo-danger {{ background: rgba(232,93,74,0.08); }}

/* ── ROBOTS/SECURITY.TXT ── */
.robots-pre {{ font-family: var(--font-mono); font-size: 11px; background: #000; color: var(--fg2); padding: 16px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; border: 1px solid var(--border); }}
.robots-paths {{ margin-top: 12px; font-size: 12px; line-height: 2; }}
.robots-paths code {{ background: rgba(232,148,74,0.15); color: var(--amber); border: 1px solid var(--amber)33; }}

/* ── TECH STACK ── */
.tech-grid {{ display: flex; flex-wrap: wrap; gap: 10px; }}
.tech-tag {{ font-family: var(--font-mono); font-size: 12px; font-weight: 600; background: color-mix(in srgb, var(--gold) 10%, var(--panel)); color: var(--gold); padding: 6px 16px; border-radius: 6px; border: 1px solid var(--gold)33; }}

/* ── FOOTER ── */
.footer {{ text-align: center; padding: 40px 0; border-top: 1px solid var(--border); }}
.footer p {{ font-family: var(--font-mono); font-size: 11px; color: var(--dim); margin-bottom: 4px; }}
.footer a {{ color: var(--gold); }}

/* ── TOGGLE SECTIONS ── */
.collapsible {{ cursor: pointer; }} .collapsible:hover {{ color: var(--gold); }}
.collapsed {{ display: none; }}

@media (max-width: 768px) {{
    .topbar {{ padding: 14px 20px; flex-direction: column; gap: 10px; }}
    .container {{ padding: 20px; }}
    .dossier-header h2 {{ font-size: 28px; }}
    .sum-grid {{ grid-template-columns: repeat(3,1fr); }}
}}
@media print {{
    body {{ background: #fff !important; color: #1a1714 !important; }}
    .topbar {{ position: relative; background: #fff !important; box-shadow: none; border-bottom: 2px solid #000; }}
    .logo h1 {{ color: #000 !important; }}
    .print-btn {{ display: none; }}
    .tl-card,.ind-card {{ break-inside: avoid; border: 1px solid #ccc; }}
    .sum-card {{ border: 1px solid #ccc; }}
    .collapsed {{ display: block !important; }}
    .timeline::before {{ background: #ccc; }}
    a {{ color: #654321 !important; }}
}}
</style>
</head>
<body>
<div class="topbar">
    <div class="logo"><h1>NeatLabs™ Domain Threat Timeline</h1><p>Passive Domain Intelligence Report</p></div>
    <div class="topbar-right">
        <span class="domain-chip">{_h(report.domain)}</span>
        <button class="print-btn" onclick="window.print()">🖨️ Print</button>
    </div>
</div>
<div class="container">

<div class="dossier-header">
    <div class="dossier-subtitle">Intelligence Dossier</div>
    <h2>{_h(report.domain)}</h2>
    <div class="dossier-meta">
        <span>📅 {report.scan_time}</span>
        <span>⏱️ {report.scan_duration_s:.1f}s scan</span>
        <span>📊 {report.event_count} events</span>
        {f'<span>🕐 Age: {age_display}</span>' if age_display else ''}
    </div>
</div>

<div class="sum-grid">
    <div class="sum-card"><div class="sum-val">{report.event_count}</div><div class="sum-lbl">Timeline Events</div></div>
    <div class="sum-card"><div class="sum-val">{len(report.indicators)}</div><div class="sum-lbl">Indicators</div></div>
    <div class="sum-card"><div class="sum-val">{len(report.subdomains)}</div><div class="sum-lbl">Subdomains</div></div>
    <div class="sum-card"><div class="sum-val">{len(report.certificates)}</div><div class="sum-lbl">Certificates</div></div>
    <div class="sum-card"><div class="sum-val">{report.wayback_snapshots}</div><div class="sum-lbl">Wayback Snapshots</div></div>
    <div class="sum-card"><div class="sum-val">{len(report.ip_addresses)}</div><div class="sum-lbl">IP Addresses</div></div>
    <div class="sum-card"><div class="sum-val">{len([t for t in report.typosquats if t.get('resolves')])}</div><div class="sum-lbl">Typosquats</div></div>
</div>

{"" if not report.indicators else f'''
<div class="section">
    <div class="sec-title">⚠️ Threat Indicators <span class="sec-count">({len(report.indicators)})</span></div>
    {indicators_html}
</div>
'''}

<div class="section">
    <div class="sec-title">📜 Timeline <span class="sec-count">({report.event_count} events)</span></div>
    <div class="tl-filters">{cat_filters}</div>
    <div class="timeline" id="timeline">{timeline_html}</div>
</div>

{"" if not report.tech_stack else f'''
<div class="section">
    <div class="sec-title">⚙️ Technology Stack</div>
    <div class="tech-grid">{"".join(f'<span class="tech-tag">{_h(t)}</span>' for t in report.tech_stack)}</div>
</div>
'''}

{"" if not whois_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'whois-data\')">📋 WHOIS Data <span id="whois-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="whois-data"><table class="data-table"><tbody>{whois_html}</tbody></table></div>
</div>
'''}

{"" if not dns_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'dns-data\')">🔀 DNS Records <span id="dns-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="dns-data"><table class="data-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{dns_html}</tbody></table></div>
</div>
'''}

{"" if not cert_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'cert-data\')">🔒 Certificates ({len(report.certificates)}) <span id="cert-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="cert-data"><table class="data-table"><thead><tr><th>Subject</th><th>Issuer</th><th>Issued</th><th>Expires</th></tr></thead><tbody>{cert_html}</tbody></table></div>
</div>
'''}

{"" if not subs_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'sub-data\')">🌐 Subdomains ({len(report.subdomains)}) <span id="sub-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="sub-data"><div class="sub-cloud">{subs_html}</div></div>
</div>
'''}

{"" if not typo_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'typo-data\')">🎭 Typosquat Detection ({len(typo_resolving)} resolving) <span id="typo-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="typo-data"><table class="data-table"><thead><tr><th>Domain</th><th>IP Address(es)</th><th>Status</th></tr></thead><tbody>{typo_html}</tbody></table></div>
</div>
'''}

{"" if not robots_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'robots-data\')">🤖 robots.txt <span id="robots-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="robots-data">{robots_html}</div>
</div>
'''}

{"" if not sectxt_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'sectxt-data\')">🛡️ security.txt (RFC 9116) <span id="sectxt-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="sectxt-data">{sectxt_html}</div>
</div>
'''}

{"" if not rdns_html else f'''
<div class="section">
    <div class="sec-title collapsible" onclick="toggleSection(\'rdns-data\')">↩️ Reverse DNS <span id="rdns-chev" style="margin-left:auto;color:var(--dim)">▾</span></div>
    <div id="rdns-data"><table class="data-table"><thead><tr><th>IP Address</th><th>PTR Record</th></tr></thead><tbody>{rdns_html}</tbody></table></div>
</div>
'''}

</div>
<div class="footer">
    <p>Generated by <strong>NeatLabs™ Domain Threat Timeline</strong> v{__version__}</p>
    <p><a href="https://github.com/neatlabs/domain-timeline">github.com/neatlabs/domain-timeline</a> · <a href="https://neatlabs.ai">neatlabs.ai</a> · info@neatlabs.ai</p>
    <p style="margin-top:8px">© {datetime.now().year} NeatLabs™ — Service-Disabled Veteran-Owned Small Business</p>
</div>
<script>
function toggleCat(btn) {{
    btn.classList.toggle('active');
    btn.classList.toggle('inactive');
    filterTimeline();
}}
function filterTimeline() {{
    const active = [...document.querySelectorAll('.cat-btn.active')].map(b=>b.dataset.cat);
    document.querySelectorAll('.tl-event').forEach(ev => {{
        ev.classList.toggle('hidden', active.length > 0 && !active.includes(ev.dataset.category));
    }});
}}
function toggleSection(id) {{
    const el = document.getElementById(id);
    el.classList.toggle('collapsed');
}}
</script>
</body></html>"""


# ═══════════════════════════════════════════════════════════════
# CLI MODE
# ═══════════════════════════════════════════════════════════════

class CLIRunner:
    def run(self, args):
        if args.demo:
            print("\033[1;33m⚡ Demo Mode — using sample data\033[0m\n")
            report = build_demo_report()
        else:
            domain = args.target
            if not domain:
                print("\033[91mProvide a domain or use --demo\033[0m")
                return 1
            scanner = DomainScanner()
            print(f"\033[1;33m🔭 Scanning {domain}...\033[0m\n")
            report = scanner.scan(domain, progress_cb=lambda m: print(f"  \033[90m{m}\033[0m"))

        if args.json:
            out = json.dumps(report.to_dict(), indent=2, default=str)
            if args.output:
                Path(args.output).write_text(out, encoding='utf-8')
                print(f"\nJSON saved to {args.output}")
            else:
                print(out)
        elif args.html:
            html = generate_html_report(report)
            outpath = args.output or f"domain-timeline-{report.domain}.html"
            Path(outpath).write_text(html, encoding='utf-8')
            print(f"\n\033[1;33m📊 HTML report saved to {outpath}\033[0m")
        else:
            self._print_report(report)

        return 0

    def _print_report(self, report):
        g = "\033[33m"; r = "\033[0m"; b = "\033[1m"; d = "\033[90m"; a = "\033[33;1m"
        print(f"\n{b}{'═'*60}{r}")
        print(f"  {a}DOMAIN THREAT TIMELINE{r} — {report.domain}")
        print(f"  {d}{report.event_count} events | {len(report.indicators)} indicators | {len(report.subdomains)} subdomains | {report.scan_duration_s:.1f}s{r}")
        print(f"{b}{'═'*60}{r}")

        if report.indicators:
            print(f"\n  {a}⚠️  THREAT INDICATORS{r}")
            for ind in report.indicators:
                sev_colors = {Severity.CRITICAL: "\033[91m", Severity.HIGH: "\033[93m",
                              Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[96m", Severity.INFO: "\033[37m"}
                sc = sev_colors.get(ind.severity, "")
                print(f"  {sc}{ind.severity.value:8s}{r}  {ind.title}")

        print(f"\n  {a}📜  TIMELINE{r}")
        cur_yr = None
        for ev in report.events:
            yr = ev.timestamp.year
            if yr != cur_yr:
                cur_yr = yr; print(f"\n  {g}── {yr} ──{r}")
            icon = EVENT_ICONS.get(ev.category, "•")
            print(f"  {d}{ev.date_str}{r}  {icon}  {ev.title}")

        if report.tech_stack:
            print(f"\n  {a}⚙️  TECH STACK{r}: {', '.join(report.tech_stack)}")
        if report.reverse_dns:
            resolved = {ip: h for ip, h in report.reverse_dns.items() if not h.startswith("(")}
            if resolved:
                print(f"\n  {a}↩️  REVERSE DNS{r}: {' | '.join(f'{ip} -> {h}' for ip, h in list(resolved.items())[:5])}")
        if report.subdomains:
            print(f"\n  {a}🌐  SUBDOMAINS ({len(report.subdomains)}){r}: {', '.join(report.subdomains[:10])}", end="")
            if len(report.subdomains) > 10: print(f" ... +{len(report.subdomains)-10} more", end="")
            print()
        typo_resolving = [t for t in report.typosquats if t.get("resolves")]
        if typo_resolving:
            diff_ip = [t for t in typo_resolving if not t.get("same_ip")]
            print(f"\n  {a}🎭  TYPOSQUATS ({len(typo_resolving)} resolving){r}:", end="")
            for t in typo_resolving[:8]:
                flag = f"\033[91m⚠ DIFF IP\033[0m" if not t.get("same_ip") else f"{d}same IP{r}"
                print(f"\n    {t['domain']:40s} {flag}  {', '.join(t.get('ips',[])[:2])}", end="")
            print()
        if report.robots_hidden_paths:
            print(f"\n  {a}🤖  ROBOTS.TXT HIDDEN PATHS ({len(report.robots_hidden_paths)}){r}: {', '.join(report.robots_hidden_paths[:8])}")
        if report.security_txt:
            print(f"\n  {a}🛡️  SECURITY.TXT{r}: Published (RFC 9116)")
        print()


# ═══════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    BG = "#1A1714"; PNL = "#221F1A"; CRD = "#2A2620"; INP = "#1A1714"
    FG = "#E8DFD0"; FG2 = "#A69882"; DIM = "#6B5E4E"; GOLD = "#C8A96E"; BRD = "#3D362C"

    class App:
        def __init__(self, root):
            self.root = root; self.scanner = DomainScanner(); self.report = None
            root.title("NEATLABS™ DOMAIN THREAT TIMELINE"); root.geometry("900x650"); root.minsize(800, 550); root.configure(bg=BG)
            try: root.tk_setPalette(background=BG, foreground=FG)
            except Exception: pass

            s = ttk.Style(); s.theme_use('clam')
            s.configure("G.TButton", background=GOLD, foreground=BG, font=("Georgia", 11, "bold"), padding=(20, 10))
            s.map("G.TButton", background=[("active", "#E8C080")])
            s.configure("S.TButton", background=CRD, foreground=FG, font=("Georgia", 10), padding=(15, 8))
            s.map("S.TButton", background=[("active", BRD)])

            # Top bar
            top = tk.Frame(root, bg=PNL, height=70); top.pack(fill="x"); top.pack_propagate(False)
            tk.Label(top, text="🔭", font=("Segoe UI Emoji", 24), bg=PNL).pack(side="left", padx=(20, 10), pady=10)
            ts = tk.Frame(top, bg=PNL); ts.pack(side="left", pady=10)
            tk.Label(ts, text="NeatLabs™ Domain Threat Timeline", font=("Georgia", 15, "bold"), fg=GOLD, bg=PNL).pack(anchor="w")
            tk.Label(ts, text="Passive Domain Intelligence & Recon", font=("Consolas", 9), fg=FG2, bg=PNL).pack(anchor="w")
            tk.Frame(root, bg=GOLD, height=1).pack(fill="x")

            # Input
            inp_frame = tk.Frame(root, bg=BG); inp_frame.pack(fill="x", padx=30, pady=(25, 0))
            tk.Label(inp_frame, text="TARGET DOMAIN", font=("Consolas", 9, "bold"), fg=FG2, bg=BG).pack(anchor="w", pady=(0, 4))
            row = tk.Frame(inp_frame, bg=BG); row.pack(fill="x")
            self.entry = tk.Entry(row, font=("Consolas", 14), bg=INP, fg=FG, insertbackground=GOLD, relief="flat", bd=0, highlightthickness=1, highlightbackground=BRD, highlightcolor=GOLD)
            self.entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 10))
            self.entry.insert(0, "example.com")
            self.entry.bind("<FocusIn>", lambda e: self.entry.delete(0, "end") if self.entry.get() == "example.com" else None)
            self.entry.bind("<Return>", lambda e: self._scan())
            ttk.Button(row, text="🔭 SCAN", style="G.TButton", command=self._scan).pack(side="left", padx=(0, 5))
            ttk.Button(row, text="🧪 Demo", style="S.TButton", command=self._demo).pack(side="left")

            # Output area
            self.output = scrolledtext.ScrolledText(root, wrap="word", bg=BG, fg=FG, font=("Consolas", 10), relief="flat", bd=0, padx=20, pady=15, insertbackground=GOLD)
            self.output.pack(fill="both", expand=True, padx=20, pady=15)
            self.output.insert("1.0", "\n  Enter a domain above and click SCAN, or try Demo.\n\n"
                "  Sources:\n  • WHOIS registration data\n  • DNS record enumeration\n"
                "  • Certificate Transparency logs (crt.sh)\n  • Wayback Machine CDX API\n"
                "  • HTTP header fingerprinting\n\n  All sources are passive and public. No active scanning.\n")
            self.output.config(state="disabled")

            # Bottom bar
            bb = tk.Frame(root, bg=PNL, height=36); bb.pack(fill="x", side="bottom"); bb.pack_propagate(False)
            self.status = tk.Label(bb, text="  Ready", font=("Consolas", 9), fg=FG2, bg=PNL, anchor="w")
            self.status.pack(side="left", fill="x", expand=True)
            self.export_btn = tk.Button(bb, text="📊 Export HTML", font=("Consolas", 9), fg=GOLD, bg=PNL, bd=0, relief="flat", cursor="hand2", command=self._export, state="disabled")
            self.export_btn.pack(side="right", padx=10)
            tk.Label(bb, text=f"v{__version__} • © NeatLabs™  ", font=("Consolas", 9), fg=DIM, bg=PNL).pack(side="right")

        def _log(self, msg):
            self.output.config(state="normal")
            self.output.insert("end", msg + "\n")
            self.output.see("end")
            self.output.config(state="disabled")
            self.root.update_idletasks()

        def _scan(self):
            domain = self.entry.get().strip()
            if not domain or domain == "example.com":
                messagebox.showinfo("Enter Domain", "Type a domain to scan."); return
            self.output.config(state="normal"); self.output.delete("1.0", "end"); self.output.config(state="disabled")
            self.status.config(text=f"  Scanning {domain}...")
            self.root.update()

            def run():
                report = self.scanner.scan(domain, progress_cb=lambda m: self.root.after(0, self._log, f"  {m}"))
                self.root.after(0, self._show_results, report)
            threading.Thread(target=run, daemon=True).start()

        def _demo(self):
            self.output.config(state="normal"); self.output.delete("1.0", "end"); self.output.config(state="disabled")
            report = build_demo_report()
            self.entry.delete(0, "end"); self.entry.insert(0, report.domain)
            self._show_results(report)

        def _show_results(self, report):
            self.report = report
            self._log(f"\n  {'═'*50}")
            self._log(f"  DOMAIN THREAT TIMELINE — {report.domain}")
            self._log(f"  {report.event_count} events | {len(report.indicators)} indicators | {len(report.subdomains)} subdomains")
            self._log(f"  {'═'*50}")
            if report.indicators:
                self._log(f"\n  ⚠️  THREAT INDICATORS")
                for ind in report.indicators:
                    self._log(f"  [{ind.severity.value:8s}] {ind.title}")
            self._log(f"\n  📜  TIMELINE")
            yr = None
            for ev in report.events:
                if ev.timestamp.year != yr:
                    yr = ev.timestamp.year; self._log(f"\n  ── {yr} ──")
                self._log(f"  {ev.date_str}  {EVENT_ICONS.get(ev.category, '•')}  {ev.title}")
            if report.tech_stack:
                self._log(f"\n  ⚙️  TECH: {', '.join(report.tech_stack)}")
            if report.subdomains:
                self._log(f"\n  🌐  SUBDOMAINS ({len(report.subdomains)}): {', '.join(report.subdomains[:10])}")
            typo_resolving = [t for t in report.typosquats if t.get("resolves")]
            if typo_resolving:
                diff_ip = [t for t in typo_resolving if not t.get("same_ip")]
                self._log(f"\n  🎭  TYPOSQUATS: {len(typo_resolving)} resolving ({len(diff_ip)} different IP)")
                for t in typo_resolving[:6]:
                    flag = "⚠ DIFF IP" if not t.get("same_ip") else "same IP"
                    self._log(f"    {t['domain']:40s} [{flag}]  {', '.join(t.get('ips',[])[:2])}")
            if report.robots_hidden_paths:
                self._log(f"\n  🤖  ROBOTS.TXT: {len(report.robots_hidden_paths)} hidden paths: {', '.join(report.robots_hidden_paths[:6])}")
            if report.security_txt:
                self._log(f"\n  🛡️  SECURITY.TXT: Published (RFC 9116)")
            if report.reverse_dns:
                resolved = {ip: h for ip, h in report.reverse_dns.items() if not h.startswith("(")}
                if resolved:
                    self._log(f"\n  ↩️  REVERSE DNS: {' | '.join(f'{ip} -> {h}' for ip, h in list(resolved.items())[:4])}")
            self._log(f"\n  Scan completed in {report.scan_duration_s:.1f}s — Click 'Export HTML' for the full report")
            self.status.config(text=f"  ✅ Complete — {report.event_count} events, {len(report.indicators)} indicators | {report.scan_duration_s:.1f}s")
            self.export_btn.config(state="normal")

        def _export(self):
            if not self.report: return
            fp = filedialog.asksaveasfilename(title="Export HTML Report", defaultextension=".html",
                filetypes=[("HTML", "*.html")], initialfile=f"domain-timeline-{self.report.domain}.html")
            if fp:
                try:
                    Path(fp).write_text(generate_html_report(self.report), encoding='utf-8')
                    self.status.config(text=f"  ✅ HTML exported: {fp}")
                    import webbrowser
                    if messagebox.askyesno("Exported", f"Saved to {fp}\n\nOpen in browser?"): webbrowser.open(f"file://{os.path.abspath(fp)}")
                except Exception as e: messagebox.showerror("Error", str(e))

    root = tk.Tk(); App(root); root.mainloop()


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        parser = argparse.ArgumentParser(prog="domain-timeline",
            description="NeatLabs™ Domain Threat Timeline — Passive Domain Intelligence")
        parser.add_argument('--cli', action='store_true')
        parser.add_argument('target', nargs='?', help='Domain to scan')
        parser.add_argument('--demo', action='store_true', help='Run with demo data')
        parser.add_argument('--json', '-j', action='store_true', help='JSON output')
        parser.add_argument('--html', action='store_true', help='HTML report output')
        parser.add_argument('--output', '-o', help='Output file path')
        parser.add_argument('--version', action='version', version=f'Domain Threat Timeline v{__version__}')
        args = parser.parse_args()
        if not args.target and not args.demo:
            parser.error("Provide a domain or use --demo")
        cli = CLIRunner()
        sys.exit(cli.run(args))
    else:
        launch_gui()


if __name__ == "__main__":
    main()
