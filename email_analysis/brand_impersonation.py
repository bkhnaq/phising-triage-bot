"""
Brand Impersonation Detection Module
--------------------------------------
Comprehensive brand impersonation database and detection engine.

Consolidates multiple detection techniques:
  - Keyword matching in domains and URLs
  - Edit distance (Levenshtein) for lookalike domains
  - Homograph normalization (ASCII look-alikes)
  - Domain similarity scoring
  - Display name spoofing detection

Covers major brands: PayPal, Google, Microsoft, Apple, Amazon, Facebook,
Netflix, banking brands, and more.

Usage:
    from email_analysis.brand_impersonation import BrandDetector
    detector = BrandDetector()
    findings = detector.analyze(urls, from_header, body_text)
"""

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Brand Database ───────────────────────────────────────────

BRAND_DATABASE: dict[str, dict] = {
    "paypal": {
        "domains": {"paypal.com", "paypal.me", "paypal.co.uk"},
        "keywords": ["paypal", "pay-pal", "paypa1"],
        "display_names": ["paypal", "pay pal"],
    },
    "google": {
        "domains": {"google.com", "gmail.com", "googleapis.com", "google.co.uk",
                     "google.de", "google.fr", "google.ca"},
        "keywords": ["google", "gmail", "g00gle"],
        "display_names": ["google", "gmail"],
    },
    "microsoft": {
        "domains": {"microsoft.com", "outlook.com", "office.com", "office365.com",
                     "live.com", "hotmail.com", "onedrive.com", "sharepoint.com",
                     "microsoftonline.com", "azure.com"},
        "keywords": ["microsoft", "outlook", "office365", "onedrive", "sharepoint",
                      "micr0soft", "micros0ft"],
        "display_names": ["microsoft", "outlook", "office 365", "microsoft 365",
                          "onedrive", "sharepoint"],
    },
    "apple": {
        "domains": {"apple.com", "icloud.com", "me.com", "apple.co.uk"},
        "keywords": ["apple", "icloud", "app1e"],
        "display_names": ["apple", "icloud", "apple id", "apple support"],
    },
    "amazon": {
        "domains": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
                     "amazon.ca", "amazon.co.jp", "amazonaws.com", "aws.amazon.com"},
        "keywords": ["amazon", "amaz0n"],
        "display_names": ["amazon", "amazon prime", "aws"],
    },
    "facebook": {
        "domains": {"facebook.com", "fb.com", "meta.com", "messenger.com",
                     "instagram.com", "whatsapp.com"},
        "keywords": ["facebook", "faceb00k", "instagram", "whatsapp", "meta"],
        "display_names": ["facebook", "meta", "instagram", "whatsapp"],
    },
    "netflix": {
        "domains": {"netflix.com"},
        "keywords": ["netflix", "netf1ix"],
        "display_names": ["netflix"],
    },
    "linkedin": {
        "domains": {"linkedin.com"},
        "keywords": ["linkedin", "linked1n"],
        "display_names": ["linkedin"],
    },
    "dropbox": {
        "domains": {"dropbox.com", "dropboxapi.com"},
        "keywords": ["dropbox", "dr0pbox"],
        "display_names": ["dropbox"],
    },
    "twitter": {
        "domains": {"twitter.com", "x.com", "t.co"},
        "keywords": ["twitter"],
        "display_names": ["twitter", "x"],
    },
    "chase": {
        "domains": {"chase.com"},
        "keywords": ["chase"],
        "display_names": ["chase", "jpmorgan chase", "chase bank"],
    },
    "wellsfargo": {
        "domains": {"wellsfargo.com"},
        "keywords": ["wellsfargo", "wells fargo", "we11sfargo"],
        "display_names": ["wells fargo", "wellsfargo"],
    },
    "bankofamerica": {
        "domains": {"bankofamerica.com", "bofa.com"},
        "keywords": ["bankofamerica", "bofa"],
        "display_names": ["bank of america", "bofa"],
    },
    "citibank": {
        "domains": {"citi.com", "citibank.com", "citigroup.com"},
        "keywords": ["citibank", "citi"],
        "display_names": ["citibank", "citi"],
    },
    "usps": {
        "domains": {"usps.com"},
        "keywords": ["usps"],
        "display_names": ["usps", "us postal service", "united states postal"],
    },
    "fedex": {
        "domains": {"fedex.com"},
        "keywords": ["fedex", "fed3x"],
        "display_names": ["fedex", "federal express"],
    },
    "dhl": {
        "domains": {"dhl.com", "dhl.de"},
        "keywords": ["dhl"],
        "display_names": ["dhl", "dhl express"],
    },
    "docusign": {
        "domains": {"docusign.com", "docusign.net"},
        "keywords": ["docusign", "d0cusign"],
        "display_names": ["docusign"],
    },
}

# ── Lookalike character map for normalization ────────────────

_LOOKALIKE_MAP: dict[str, str] = {
    "1": "l", "0": "o", "3": "e", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


class BrandDetector:
    """Comprehensive brand impersonation detection engine."""

    def __init__(self, brand_db: dict[str, dict] | None = None):
        self.brands = brand_db or BRAND_DATABASE

    def analyze(
        self,
        urls: list[dict],
        from_header: str = "",
        body_text: str = "",
    ) -> dict:
        """
        Run all brand impersonation checks.

        Returns:
            Dict with keys:
                domain_impersonation  – list of domain-based findings
                display_name_spoofing – list of display-name findings
                body_brand_mentions   – list of body-text findings
                risk_score            – aggregate risk score
        """
        domains = self._extract_domains(urls)
        domain_findings = self._check_domains(domains)
        display_findings = self._check_display_name(from_header)
        body_findings = self._check_body_brands(body_text, from_header)

        total_risk = (
            sum(f["risk_score"] for f in domain_findings)
            + sum(f["risk_score"] for f in display_findings)
            + sum(f["risk_score"] for f in body_findings)
        )

        return {
            "domain_impersonation": domain_findings,
            "display_name_spoofing": display_findings,
            "body_brand_mentions": body_findings,
            "risk_score": min(total_risk, 50),
        }

    def _check_domains(self, domains: list[str]) -> list[dict]:
        """Check domains for brand keyword presence and lookalike patterns."""
        findings: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for domain in domains:
            domain_lower = domain.lower()
            normalized = self._normalize(domain_lower)

            for brand_name, brand_info in self.brands.items():
                if (brand_name, domain_lower) in seen:
                    continue

                legit = brand_info["domains"]
                if domain_lower in legit:
                    continue

                # Keyword match in domain
                for keyword in brand_info["keywords"]:
                    if keyword in domain_lower or keyword in normalized:
                        seen.add((brand_name, domain_lower))
                        findings.append({
                            "type": "domain_keyword",
                            "brand": brand_name,
                            "domain": domain,
                            "detail": f"Brand keyword '{keyword}' in domain",
                            "risk_score": 25,
                        })
                        break

                # Levenshtein distance check
                if (brand_name, domain_lower) not in seen:
                    base = self._extract_base_label(domain_lower)
                    segments = self._candidate_segments(base)
                    for segment in segments:
                        if abs(len(segment) - len(brand_name)) > 2:
                            continue
                        dist = self._levenshtein(segment, brand_name)
                        if 0 < dist <= 2:
                            seen.add((brand_name, domain_lower))
                            findings.append({
                                "type": "lookalike",
                                "brand": brand_name,
                                "domain": domain,
                                "distance": dist,
                                "detail": f"Lookalike: '{segment}' vs '{brand_name}' (distance={dist})",
                                "risk_score": 20,
                            })
                            break

        return findings

    def _check_display_name(self, from_header: str) -> list[dict]:
        """Detect brand names in the From display name with mismatched sender domain."""
        findings: list[dict] = []
        if not from_header:
            return findings

        angle_match = re.match(r"^(.*?)\s*<[^>]+>", from_header)
        display_name = angle_match.group(1).strip().strip('"').lower() if angle_match else ""
        if not display_name:
            return findings

        email_match = _EMAIL_RE.search(from_header)
        if not email_match:
            return findings
        sender_domain = email_match.group(1).lower()

        for brand_name, brand_info in self.brands.items():
            for dn_keyword in brand_info.get("display_names", []):
                if dn_keyword in display_name:
                    if not any(
                        sender_domain == d or sender_domain.endswith("." + d)
                        for d in brand_info["domains"]
                    ):
                        findings.append({
                            "type": "display_name_spoofing",
                            "brand": brand_name,
                            "sender_domain": sender_domain,
                            "display_name": display_name,
                            "detail": f"Display name contains '{dn_keyword}' but sender is {sender_domain}",
                            "risk_score": 20,
                        })
                    break

        return findings

    def _check_body_brands(self, body_text: str, from_header: str) -> list[dict]:
        """Detect brand mentions in body text that don't match the sender domain."""
        findings: list[dict] = []
        if not body_text:
            return findings

        email_match = _EMAIL_RE.search(from_header)
        sender_domain = email_match.group(1).lower() if email_match else ""

        body_lower = body_text.lower()

        for brand_name, brand_info in self.brands.items():
            if any(sender_domain == d or sender_domain.endswith("." + d)
                   for d in brand_info["domains"]):
                continue

            for keyword in brand_info["keywords"][:2]:
                if keyword in body_lower:
                    findings.append({
                        "type": "body_brand_mention",
                        "brand": brand_name,
                        "sender_domain": sender_domain,
                        "detail": f"Brand '{brand_name}' mentioned in body but sender is {sender_domain}",
                        "risk_score": 5,
                    })
                    break

        return findings[:5]

    def _normalize(self, domain: str) -> str:
        """Replace common look-alike characters."""
        normalized = domain
        for fake, real in _LOOKALIKE_MAP.items():
            normalized = normalized.replace(fake, real)
        return normalized

    @staticmethod
    def _extract_base_label(domain: str) -> str:
        parts = domain.split(".")
        if len(parts) >= 3 and len(parts[-2]) <= 3:
            return parts[-3]
        if len(parts) >= 2:
            return parts[-2]
        return parts[0]

    @staticmethod
    def _candidate_segments(base_label: str) -> list[str]:
        segments = [base_label]
        if "-" in base_label:
            segments.extend(base_label.split("-"))
        return segments

    @staticmethod
    def _levenshtein(s: str, t: str) -> int:
        n, m = len(s), len(t)
        if n == 0:
            return m
        if m == 0:
            return n
        prev = list(range(m + 1))
        curr = [0] * (m + 1)
        for i in range(1, n + 1):
            curr[0] = i
            for j in range(1, m + 1):
                cost = 0 if s[i - 1] == t[j - 1] else 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            prev, curr = curr, prev
        return prev[m]

    @staticmethod
    def _extract_domains(urls: list[dict]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for u in urls:
            d = u.get("domain", "").lower()
            if d and d not in seen:
                seen.add(d)
                result.append(d)
        return result
