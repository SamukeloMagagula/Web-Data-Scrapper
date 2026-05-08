"""
Defensive Web Security Auditor
==============================

PURPOSE
-------
A defensive security posture assessment tool for:
- SMEs
- client websites
- security consulting
- compliance reviews
- exposure analysis

This tool performs:
✔ passive analysis
✔ public exposure checks
✔ configuration audits
✔ metadata analysis
✔ TLS inspection
✔ header analysis
✔ JS exposure analysis
✔ secret exposure detection
✔ technology fingerprinting
✔ report generation

This tool DOES NOT:
✘ brute force
✘ exploit vulnerabilities
✘ bypass authentication
✘ attack systems
✘ perform destructive actions

Install
-------
pip install:
    curl_cffi
    beautifulsoup4
    lxml
    aiofiles
    pandas
    dnspython
    python-whois
    reportlab

Optional:
    playwright
    trafilatura
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import hashlib
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
from pathlib import Path
from typing import Optional

import dns.resolver
import whois

from bs4 import BeautifulSoup
from curl_cffi import requests as cffi_requests


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("SecurityAuditor")


# ============================================================
# CONSTANTS
# ============================================================

SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing CSP header",
    "Strict-Transport-Security": "Missing HSTS header",
    "X-Frame-Options": "Missing clickjacking protection",
    "X-Content-Type-Options": "Missing MIME protection",
    "Referrer-Policy": "Missing referrer policy",
    "Permissions-Policy": "Missing permissions policy",
}

EXPOSED_FILES = [
    ".env",
    ".git/config",
    ".git/HEAD",
    "backup.zip",
    "database.sql",
    "db.sql",
    "swagger.json",
    "openapi.json",
    ".DS_Store",
]

SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Firebase URL": r"firebaseio\.com",
    "Supabase": r"supabase",
}

TECH_PATTERNS = {
    "WordPress": r"wp-content|wordpress",
    "React": r"react",
    "Next.js": r"__NEXT_DATA__",
    "Vue": r"vue",
    "Laravel": r"laravel",
    "Django": r"csrfmiddlewaretoken",
    "Cloudflare": r"cloudflare",
}


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    recommendation: str


@dataclass
class AuditReport:
    target: str
    findings: list[Finding]
    technologies: list[str]
    risk_score: int


# ============================================================
# MAIN AUDITOR
# ============================================================

class SecurityAuditor:

    def __init__(self, target: str):

        self.target = self._validate_url(target)

        self.session = cffi_requests.Session(
            impersonate="chrome131"
        )

        self.findings = []

        self.technologies = []

    # ========================================================
    # URL VALIDATION
    # ========================================================

    def _validate_url(self, url: str):

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP/HTTPS URLs allowed")

        return url

    # ========================================================
    # REQUEST
    # ========================================================

    def request(self, path: str = ""):

        url = urljoin(self.target, path)

        try:

            response = self.session.get(
                url,
                timeout=20,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "Chrome/131"
                    )
                }
            )

            return response

        except Exception as e:

            logger.error(f"Request failed: {e}")

            return None

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    def scan_security_headers(self):

        logger.info("Scanning headers")

        response = self.request()

        if not response:
            return

        for header, issue in SECURITY_HEADERS.items():

            if header not in response.headers:

                self.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Headers",
                        title=issue,
                        description=f"{header} is not configured.",
                        recommendation=f"Configure {header} securely."
                    )
                )

    # ========================================================
    # TLS CHECK
    # ========================================================

    def scan_tls(self):

        logger.info("Scanning TLS")

        parsed = urlparse(self.target)

        hostname = parsed.hostname

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (hostname, 443),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as secure_sock:

                    cert = secure_sock.getpeercert()

                    tls_version = secure_sock.version()

                    if tls_version in (
                        "TLSv1",
                        "TLSv1.1"
                    ):

                        self.findings.append(
                            Finding(
                                severity="HIGH",
                                category="TLS",
                                title="Weak TLS Version",
                                description=f"Using {tls_version}",
                                recommendation="Upgrade to TLS 1.2 or 1.3"
                            )
                        )

        except Exception as e:

            self.findings.append(
                Finding(
                    severity="HIGH",
                    category="TLS",
                    title="TLS Error",
                    description=str(e),
                    recommendation="Review TLS configuration"
                )
            )

    # ========================================================
    # EXPOSED FILES
    # ========================================================

    def scan_exposed_files(self):

        logger.info("Checking exposed files")

        for file in EXPOSED_FILES:

            response = self.request(file)

            if not response:
                continue

            if response.status_code == 200:

                self.findings.append(
                    Finding(
                        severity="HIGH",
                        category="Exposure",
                        title=f"Exposed File: {file}",
                        description=f"Publicly accessible file detected: {file}",
                        recommendation="Remove or restrict access immediately"
                    )
                )

    # ========================================================
    # JAVASCRIPT ANALYSIS
    # ========================================================

    def analyze_javascript(self):

        logger.info("Analyzing JavaScript")

        response = self.request()

        if not response:
            return

        soup = BeautifulSoup(
            response.text,
            "lxml"
        )

        scripts = soup.find_all(
            "script",
            src=True
        )

        for script in scripts:

            src = script.get("src")

            js_url = urljoin(
                self.target,
                src
            )

            js_response = self.request(js_url)

            if not js_response:
                continue

            content = js_response.text

            self._detect_secrets(content)

            self._detect_source_maps(content)

            self._fingerprint_tech(content)

    # ========================================================
    # SECRET DETECTION
    # ========================================================

    def _detect_secrets(self, content: str):

        for name, pattern in SECRET_PATTERNS.items():

            matches = re.findall(
                pattern,
                content
            )

            if matches:

                self.findings.append(
                    Finding(
                        severity="CRITICAL",
                        category="Secrets",
                        title=f"Exposed {name}",
                        description=f"Detected possible {name}",
                        recommendation="Remove exposed secrets immediately"
                    )
                )

    # ========================================================
    # SOURCE MAPS
    # ========================================================

    def _detect_source_maps(self, content: str):

        if "sourceMappingURL" in content:

            self.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="Source Maps",
                    title="Source Map Exposure",
                    description="JavaScript source maps detected",
                    recommendation="Disable source maps in production"
                )
            )

    # ========================================================
    # TECHNOLOGY FINGERPRINTING
    # ========================================================

    def _fingerprint_tech(self, content: str):

        lowered = content.lower()

        for tech, pattern in TECH_PATTERNS.items():

            if re.search(
                pattern,
                lowered
            ):

                if tech not in self.technologies:
                    self.technologies.append(tech)

    # ========================================================
    # COOKIE ANALYSIS
    # ========================================================

    def scan_cookies(self):

        logger.info("Scanning cookies")

        response = self.request()

        if not response:
            return

        cookies = response.cookies

        for cookie in cookies:

            if not cookie.secure:

                self.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Cookies",
                        title="Insecure Cookie",
                        description=f"{cookie.name} missing Secure flag",
                        recommendation="Enable Secure flag"
                    )
                )

            if not cookie.has_nonstandard_attr(
                "HttpOnly"
            ):

                self.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Cookies",
                        title="Missing HttpOnly",
                        description=f"{cookie.name} missing HttpOnly",
                        recommendation="Enable HttpOnly flag"
                    )
                )

    # ========================================================
    # CORS ANALYSIS
    # ========================================================

    def scan_cors(self):

        logger.info("Scanning CORS")

        response = self.request()

        if not response:
            return

        origin = response.headers.get(
            "Access-Control-Allow-Origin"
        )

        creds = response.headers.get(
            "Access-Control-Allow-Credentials"
        )

        if origin == "*":

            self.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="CORS",
                    title="Wildcard CORS",
                    description="CORS allows all origins",
                    recommendation="Restrict allowed origins"
                )
            )

        if origin == "*" and creds == "true":

            self.findings.append(
                Finding(
                    severity="HIGH",
                    category="CORS",
                    title="Dangerous CORS",
                    description="Wildcard origin with credentials enabled",
                    recommendation="Disable credentials or restrict origins"
                )
            )

    # ========================================================
    # ROBOTS.TXT
    # ========================================================

    def scan_robots(self):

        logger.info("Scanning robots.txt")

        response = self.request("robots.txt")

        if not response:
            return

        if response.status_code == 200:

            text = response.text

            sensitive = re.findall(
                r"Disallow:\s*(.*)",
                text
            )

            if sensitive:

                self.findings.append(
                    Finding(
                        severity="LOW",
                        category="Robots",
                        title="Sensitive Paths in robots.txt",
                        description=", ".join(sensitive),
                        recommendation="Avoid exposing sensitive paths"
                    )
                )

    # ========================================================
    # DNS SECURITY
    # ========================================================

    def scan_dns(self):

        logger.info("Scanning DNS")

        hostname = urlparse(
            self.target
        ).hostname

        try:

            txt_records = dns.resolver.resolve(
                hostname,
                "TXT"
            )

            txt_values = [
                str(r)
                for r in txt_records
            ]

            if not any(
                "v=spf1"
                in r
                for r in txt_values
            ):

                self.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="DNS",
                        title="Missing SPF",
                        description="No SPF record found",
                        recommendation="Configure SPF"
                    )
                )

        except:
            pass

    # ========================================================
    # WHOIS
    # ========================================================

    def scan_domain_info(self):

        logger.info("Checking domain")

        hostname = urlparse(
            self.target
        ).hostname

        try:

            data = whois.whois(hostname)

            logger.info(
                f"Registrar: {data.registrar}"
            )

        except:
            pass

    # ========================================================
    # RISK SCORING
    # ========================================================

    def calculate_risk(self):

        score = 0

        for finding in self.findings:

            if finding.severity == "LOW":
                score += 2

            elif finding.severity == "MEDIUM":
                score += 5

            elif finding.severity == "HIGH":
                score += 10

            elif finding.severity == "CRITICAL":
                score += 20

        return min(score, 100)

    # ========================================================
    # FULL AUDIT
    # ========================================================

    def run(self):

        logger.info(
            f"Starting audit: {self.target}"
        )

        self.scan_security_headers()

        self.scan_tls()

        self.scan_exposed_files()

        self.scan_cookies()

        self.scan_cors()

        self.scan_robots()

        self.scan_dns()

        self.scan_domain_info()

        self.analyze_javascript()

        risk = self.calculate_risk()

        return AuditReport(
            target=self.target,
            findings=self.findings,
            technologies=self.technologies,
            risk_score=risk
        )

    # ========================================================
    # EXPORT
    # ========================================================

    def export_json(
        self,
        report,
        filename="security_report.json"
    ):

        data = asdict(report)

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

        logger.info(
            f"Saved {filename}"
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    target = input(
        "Target URL: "
    ).strip()

    auditor = SecurityAuditor(target)

    report = auditor.run()

    auditor.export_json(report)

    print("\n===== SECURITY SUMMARY =====")

    print(f"Target: {report.target}")

    print(f"Risk Score: {report.risk_score}/100")

    print(f"Technologies: {report.technologies}")

    print("\nFindings:")

    for finding in report.findings:

        print(
            f"\n[{finding.severity}] "
            f"{finding.title}"
        )

        print(
            f"Category: {finding.category}"
        )

        print(
            f"Description: {finding.description}"
        )

        print(
            f"Recommendation: {finding.recommendation}"
        )