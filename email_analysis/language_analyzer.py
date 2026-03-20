"""
Advanced Phishing Language Analyzer
-------------------------------------
Detects phishing language patterns in email body text:

  - Urgency language
  - Threat / account suspension language
  - Credential harvesting phrases
  - Payment / financial request language
  - Authority impersonation language

Returns structured findings with matched patterns and risk scores.

Usage:
    from email_analysis.language_analyzer import analyze_language
    findings = analyze_language(body_text, subject)
"""

import logging
import re

logger = logging.getLogger(__name__)


# ── Pattern Categories ───────────────────────────────────────

_PATTERNS: dict[str, dict] = {
    "urgency": {
        "description": "Urgency / time-pressure language",
        # Urgency alone is weak evidence in modern marketing and transactional mail.
        "risk_per_match": 1,
        "max_risk": 4,
        "patterns": [
            r"\burgent(?:ly)?\b",
            r"\bimmediate(?:ly)?\b",
            r"\bact\s+now\b",
            r"\bexpir(?:e[sd]?|ing|ation)\b",
            r"\btime[- ]?sensitive\b",
            r"\blast\s+(?:chance|warning|notice)\b",
            r"\bwithin\s+\d+\s+hours?\b",
            r"\bdo\s+(?:it\s+)?(?:now|immediately|today)\b",
            r"\bas\s+soon\s+as\s+possible\b",
            r"\basap\b",
            r"\bdon'?t\s+delay\b",
            r"\blimited\s+time\b",
            r"\bhurry\b",
            r"\bresponse\s+required\b",
        ],
    },
    "threats": {
        "description": "Threats / negative consequences",
        "risk_per_match": 5,
        "max_risk": 15,
        "patterns": [
            r"\baccount\s+(?:will\s+be\s+)?(?:suspend|clos|terminat|deactivat|lock|restrict|delet)",
            r"\bsuspend(?:ed)?\b",
            r"\block(?:ed)?\s+(?:out|account)\b",
            r"\bun(?:authorized|usual)\s+(?:access|activity|login|transaction)",
            r"\bsecurity\s+(?:breach|alert|warning|violation|threat)\b",
            r"\bfail(?:ure)?\s+to\s+(?:comply|verify|respond|update|confirm)\b",
            r"\blegal\s+(?:action|consequences)\b",
            r"\bpermanent(?:ly)?\s+(?:lock|clos|delet|suspend|block)\b",
            r"\brestrict(?:ed)?\s+access\b",
            r"\bfraud(?:ulent)?\s+activity\b",
        ],
    },
    "credential_harvesting": {
        "description": "Credential harvesting / verification language",
        "risk_per_match": 5,
        "max_risk": 15,
        "patterns": [
            r"\bverify\s+(?:your\s+)?(?:account|identity|email|information|details)\b",
            r"\bconfirm\s+(?:your\s+)?(?:account|identity|email|information|details|password)\b",
            r"\bupdate\s+(?:your\s+)?(?:account|payment|billing|information|details|password)\b",
            r"\breset\s+(?:your\s+)?password\b",
            r"\bclick\s+(?:here|below|the\s+link|the\s+button)\b",
            r"\blog\s*in\s+(?:to\s+)?(?:verify|confirm|update|secure)\b",
            r"\benter\s+(?:your\s+)?(?:credentials|password|username|ssn|social)\b",
            r"\bprovide\s+(?:your\s+)?(?:credentials|password|personal|information)\b",
            r"\bsign\s+in\s+(?:to\s+)?(?:verify|confirm|secure)\b",
            r"\bvalidate\s+(?:your\s+)?(?:account|identity)\b",
        ],
    },
    "financial": {
        "description": "Financial / payment request language",
        "risk_per_match": 5,
        "max_risk": 15,
        "patterns": [
            r"\bpayment\s+(?:required|due|pending|declined|failed)\b",
            r"\binvoice\s+(?:attached|enclosed|due|overdue|pending)\b",
            r"\bwire\s+transfer\b",
            r"\bbank\s+(?:account|transfer|details)\b",
            r"\bcredit\s+card\s+(?:expired|declined|update|information)\b",
            r"\brefund\s+(?:pending|available|approved)\b",
            r"\btax\s+(?:return|refund|document)\b",
            r"\boutstanding\s+(?:balance|payment|invoice)\b",
            r"\bbilling\s+(?:issue|problem|update|information)\b",
            r"\bgift\s+card\b",
        ],
    },
    "authority": {
        "description": "Authority / impersonation language",
        "risk_per_match": 3,
        "max_risk": 10,
        "patterns": [
            r"\bsecurity\s+(?:team|department|division)\b",
            r"\bIT\s+(?:department|support|team|admin)\b",
            r"\btechnical\s+support\b",
            r"\bcustomer\s+(?:service|support|care)\b",
            r"\baccount\s+(?:team|department|manager|administrator)\b",
            r"\bhelp\s*desk\b",
            r"\bcompliance\s+(?:team|department|officer)\b",
        ],
    },
}


def analyze_language(body_text: str, subject: str = "") -> dict:
    """
    Analyze email text for phishing language patterns.

    Args:
        body_text: Plain-text email body (or HTML-stripped text).
        subject:   Email subject line.

    Returns:
        Dict with keys:
            categories    – dict of category name → list of matched patterns
            total_matches – int total pattern matches
            risk_score    – int aggregate risk
            summary       – list of human-readable summary strings
    """
    result: dict = {
        "categories": {},
        "total_matches": 0,
        "risk_score": 0,
        "summary": [],
    }

    combined_text = f"{subject}\n{body_text}".lower() if body_text or subject else ""
    if not combined_text.strip():
        return result

    total_risk = 0

    for category_name, category_info in _PATTERNS.items():
        matches: list[str] = []
        category_risk = 0

        for pattern_str in category_info["patterns"]:
            found = re.findall(pattern_str, combined_text, re.IGNORECASE)
            if found:
                # Deduplicate matches
                unique_matches = list(set(m.strip() for m in found))
                matches.extend(unique_matches[:3])
                category_risk += category_info["risk_per_match"] * len(unique_matches)

        # Cap per-category risk
        category_risk = min(category_risk, category_info["max_risk"])

        if matches:
            result["categories"][category_name] = {
                "description": category_info["description"],
                "matches": matches[:5],
                "match_count": len(matches),
                "risk_score": category_risk,
            }
            total_risk += category_risk
            result["summary"].append(
                f"{category_info['description']}: {', '.join(matches[:3])}"
            )

    result["total_matches"] = sum(
        cat["match_count"] for cat in result["categories"].values()
    )
    result["risk_score"] = min(total_risk, 40)

    if result["total_matches"] > 0:
        logger.info(
            "Language analysis: %d matches across %d categories, risk=%d",
            result["total_matches"],
            len(result["categories"]),
            result["risk_score"],
        )

    return result
