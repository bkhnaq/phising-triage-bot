import ipaddress

import pytest

from email_analysis.ip_utils import extract_ip_literals
from email_analysis.observables import collect_observables


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Connect to 8.8.8.8:443", ["8.8.8.8"]),
        ("8.8.8.8:443, 8.8.8.8:53; 1.1.1.1.", ["8.8.8.8", "1.1.1.1"]),
        (
            "[2001:db8::1]:443 ::1 IPv6:::ffff:192.0.2.1",
            ["2001:db8::1", "::1", "::ffff:c000:201"],
        ),
        ("999.8.8.8:443 1.2.3.4.5 a8.8.8.8 8.8.8.8x", []),
    ],
)
def test_ip_literal_boundaries_and_ports(text, expected):
    assert [ipaddress.ip_address(value) for value in extract_ip_literals(text)] == [
        ipaddress.ip_address(value) for value in expected
    ]


def test_body_ip_with_port_reaches_observables():
    records = collect_observables(
        urls=[],
        attachments=[],
        url_intelligence=None,
        email_data={"body_text": "Connect to 8.8.8.8:443"},
    )
    assert any(item["type"] == "ip" and item["value"] == "8.8.8.8" for item in records)
