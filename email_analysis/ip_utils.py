"""Extract IPv4/IPv6 literals from email text without DNS resolution."""

import ipaddress
import re

_IP_CANDIDATE = re.compile(
    r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|[0-9A-Fa-f]*:[0-9A-Fa-f:.]+"
)


def extract_ip_literals(text: str) -> list[str]:
    values = []
    for match in _IP_CANDIDATE.findall(text.replace("IPv6:", "")):
        try:
            value = str(ipaddress.ip_address(match.rstrip(".")))
        except ValueError:
            continue
        if value not in values:
            values.append(value)
    return values
