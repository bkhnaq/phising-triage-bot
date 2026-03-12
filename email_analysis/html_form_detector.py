"""
HTML Form / Credential Harvesting Detector
-------------------------------------------
Scans email HTML body for indicators of credential harvesting:

  - <form> elements (especially with external POST action)
  - <input type="password"> fields
  - Suspicious POST endpoints
  - Hidden input fields
  - JavaScript-based form submission

Usage:
    from email_analysis.html_form_detector import detect_credential_harvesting
    findings = detect_credential_harvesting(body_html)
"""

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class _FormParser(HTMLParser):
    """HTML parser that collects forms, password fields, and hidden inputs."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self.password_inputs: list[dict] = []
        self.hidden_inputs: list[dict] = []
        self.submit_buttons: int = 0
        self._in_form = False
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = {k.lower(): v or "" for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "form":
            self._in_form = True
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "").upper() or "GET",
            }
            self.forms.append(self._current_form)

        elif tag_lower == "input":
            input_type = attr_dict.get("type", "text").lower()
            if input_type == "password":
                self.password_inputs.append({
                    "name": attr_dict.get("name", ""),
                    "in_form": self._in_form,
                })
            elif input_type == "hidden":
                self.hidden_inputs.append({
                    "name": attr_dict.get("name", ""),
                    "value": attr_dict.get("value", ""),
                })
            elif input_type == "submit":
                self.submit_buttons += 1

        elif tag_lower == "button" and attr_dict.get("type", "").lower() in ("submit", ""):
            self.submit_buttons += 1

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._in_form = False
            self._current_form = None


# Patterns for JavaScript form submission
_JS_SUBMIT_PATTERNS = [
    re.compile(r"\.submit\s*\(", re.IGNORECASE),
    re.compile(r"document\.forms", re.IGNORECASE),
    re.compile(r"XMLHttpRequest|fetch\s*\(", re.IGNORECASE),
]


def detect_credential_harvesting(body_html: str) -> dict:
    """
    Analyze email HTML body for credential harvesting indicators.

    Args:
        body_html: Raw HTML string of the email body.

    Returns:
        Dict with keys:
            detected       – bool, True if harvesting indicators found
            forms          – list of form dicts (action, method)
            password_fields – count of password input fields
            hidden_inputs  – count of hidden input fields
            post_endpoints – list of external POST action URLs
            js_submission  – bool, JavaScript form submission detected
            findings       – list of human-readable finding strings
            risk_score     – int
    """
    result: dict = {
        "detected": False,
        "forms": [],
        "password_fields": 0,
        "hidden_inputs": 0,
        "post_endpoints": [],
        "js_submission": False,
        "findings": [],
        "risk_score": 0,
    }

    if not body_html:
        return result

    # Parse HTML structure
    parser = _FormParser()
    try:
        parser.feed(body_html)
    except Exception:
        logger.debug("HTML parsing error in credential harvesting detector")
        return result

    result["forms"] = parser.forms
    result["password_fields"] = len(parser.password_inputs)
    result["hidden_inputs"] = len(parser.hidden_inputs)

    findings: list[str] = []

    # Check for forms
    if parser.forms:
        findings.append(f"HTML form(s) detected: {len(parser.forms)}")
        result["risk_score"] += 10

        for form in parser.forms:
            action = form.get("action", "")
            method = form.get("method", "")

            if method == "POST" and action:
                parsed = urlparse(action)
                if parsed.scheme in ("http", "https") and parsed.netloc:
                    result["post_endpoints"].append(action)
                    findings.append(
                        f"External POST endpoint: {action}"
                    )
                    result["risk_score"] += 15

    # Check for password fields
    if parser.password_inputs:
        findings.append(
            f"Password input field(s) detected: {len(parser.password_inputs)}"
        )
        result["risk_score"] += 20

    # Check for excessive hidden inputs (common in phishing kits)
    if len(parser.hidden_inputs) > 3:
        findings.append(
            f"Suspicious number of hidden inputs: {len(parser.hidden_inputs)}"
        )
        result["risk_score"] += 5

    # Check for JavaScript form submission
    for pattern in _JS_SUBMIT_PATTERNS:
        if pattern.search(body_html):
            result["js_submission"] = True
            findings.append("JavaScript form submission detected")
            result["risk_score"] += 10
            break

    # Combined detection: form + password = likely credential harvesting
    if parser.forms and parser.password_inputs:
        findings.append("⚠️ Possible credential harvesting attempt")
        result["risk_score"] += 10

    result["findings"] = findings
    result["detected"] = bool(findings)

    if result["detected"]:
        logger.warning(
            "Credential harvesting indicators: %d finding(s), risk=%d",
            len(findings), result["risk_score"],
        )

    return result
