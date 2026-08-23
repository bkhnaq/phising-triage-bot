"""Normalize URL keyword findings into one weak, non-duplicative signal."""

from __future__ import annotations

from urllib.parse import urlsplit

from scoring.config import URL_KEYWORD_CONFIG


def build_url_keyword_context(
    *,
    urls: list[dict] | None,
    heuristics: dict | None,
    url_intelligence: dict | None,
) -> list[dict]:
    """Return deduplicated keyword context with a shared standalone score cap.

    Keywords associated with a deceptive displayed-URL/HREF pair are explanatory
    context only. They do not add weight on top of the stronger deceptive-link
    finding. Standalone URL keywords retain only a small shared heuristic budget.
    """
    deceptive_values = _deceptive_context_values(urls or [], url_intelligence or {})
    keyword_sources: dict[str, set[str]] = {}

    def add(keyword: object, source: object) -> None:
        normalized_keyword = str(keyword or "").strip().lower()
        normalized_source = str(source or "").strip()
        if not normalized_keyword:
            return
        keyword_sources.setdefault(normalized_keyword, set()).add(normalized_source)

    for finding in (url_intelligence or {}).get("suspicious_endpoints", []):
        for keyword in finding.get("keywords", []):
            add(keyword, finding.get("url"))

    for finding in (heuristics or {}).get("suspicious_keywords", []):
        add(finding.get("keyword"), finding.get("source"))

    remaining = int(URL_KEYWORD_CONFIG["standalone_maximum"])
    per_keyword = int(URL_KEYWORD_CONFIG["per_keyword_weight"])
    contexts: list[dict] = []
    for keyword, sources in keyword_sources.items():
        related = any(
            _source_matches_deceptive_context(source, deceptive_values)
            for source in sources
            if source
        )
        contribution = 0
        if not related and remaining > 0:
            contribution = min(per_keyword, remaining)
            remaining -= contribution
        contexts.append(
            {
                "keyword": keyword,
                "sources": sorted(source for source in sources if source),
                "related_to_deceptive_link": related,
                "risk_score": contribution,
                "role": "SUPPORTING_CONTEXT" if related else "WEAK_HEURISTIC",
                "supporting_for": (
                    "credential_lure_deceptive_link" if related else None
                ),
            }
        )
    return contexts


def is_credential_keyword_only_url_signal(url: dict) -> bool:
    """Return true when URL normalization risk is only credential-path wording."""
    warnings = [str(item).lower() for item in url.get("url_warnings", [])]
    return bool(warnings) and all(
        warning.startswith("credential-style path keywords:") for warning in warnings
    )


def url_is_deceptive_context(
    url_value: object,
    urls: list[dict] | None,
    url_intelligence: dict | None,
) -> bool:
    contexts = _deceptive_context_values(urls or [], url_intelligence or {})
    return _source_matches_deceptive_context(str(url_value or ""), contexts)


def _deceptive_context_values(urls: list[dict], url_intelligence: dict) -> set[str]:
    values: set[str] = set()

    def add(value: object) -> None:
        normalized = str(value or "").strip().lower().rstrip(".")
        if not normalized:
            return
        values.add(normalized)
        hostname = urlsplit(normalized).hostname
        if hostname:
            values.add(hostname.lower().rstrip("."))

    for item in urls:
        if not item.get("deceptive_hyperlink"):
            continue
        for key in (
            "url",
            "normalized_url",
            "actual_domain",
            "domain",
            "displayed_url",
            "displayed_domain",
        ):
            add(item.get(key))

    for finding in url_intelligence.get("deceptive_links", []):
        if int(finding.get("risk_score", 0)) <= 0:
            continue
        for key in ("url", "actual_domain", "displayed_url", "displayed_domain"):
            add(finding.get(key))
    return values


def _source_matches_deceptive_context(source: str, contexts: set[str]) -> bool:
    normalized = str(source or "").strip().lower().rstrip(".")
    if not normalized:
        return False
    if normalized in contexts:
        return True
    hostname = urlsplit(normalized).hostname
    return bool(hostname and hostname.lower().rstrip(".") in contexts)
