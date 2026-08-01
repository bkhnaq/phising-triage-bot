from email.message import EmailMessage
from pathlib import Path

from email_analysis.pipeline import PhishingPipeline


def test_parser_recovers_headers_after_blank_subject_line(tmp_path) -> None:
    from email_analysis.email_parser import parse_eml_file

    eml = tmp_path / "pasted.eml"
    eml.write_text(
        "\n".join(
            [
                "Subject: [TEST] Urgent notice",
                "",
                "From: Security Team <security@example.com>",
                "To: user@example.com",
                "Date: Mon, 18 Mar 2026 09:14:22 +0700",
                "",
                "Please verify your account.",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_eml_file(str(eml))

    assert result["subject"] == "[TEST] Urgent notice"
    assert result["from"] == "Security Team <security@example.com>"
    assert result["to"] == "user@example.com"
    assert result["date"] == "Mon, 18 Mar 2026 09:14:22 +0700"
    assert result["body_text"] == "Please verify your account."


def test_pipeline_deduplicates_url_indicators_and_hashes() -> None:
    urls = [
        {"url": "https://a.example/login", "domain": "a.example"},
        {"url": "https://short.example/x", "expanded_url": "https://a.example/login"},
        {"url": "https://b.example", "domain": "b.example:443"},
    ]
    attachments = [
        {"sha256": "A" * 64},
        {"sha256": "a" * 64},
        {"sha256": "b" * 64},
    ]

    indicators = PhishingPipeline._build_url_indicators(urls)
    domains = PhishingPipeline._extract_unique_domains(urls)
    hashes = PhishingPipeline._extract_unique_hashes(attachments)

    assert [item["lookup_url"] for item in indicators] == [
        "https://a.example/login",
        "https://b.example",
    ]
    assert domains == ["a.example", "b.example"]
    assert hashes == ["a" * 64, "b" * 64]


def test_pipeline_url_indicators_prefer_redirect_final_url() -> None:
    urls = [
        {
            "url": "https://tracker.example/click",
            "domain": "tracker.example",
            "expanded_url": "https://tracker.example/click",
        }
    ]
    url_intelligence = {
        "shortener_findings": [],
        "redirect_findings": [
            {
                "source_url": "https://tracker.example/click",
                "final_url": "https://landing.example/login/verify",
                "error": None,
            }
        ],
    }

    indicators = PhishingPipeline._build_url_indicators(urls, url_intelligence)

    assert indicators == [
        {
            "source_url": "https://tracker.example/click",
            "lookup_url": "https://landing.example/login/verify",
            "is_shortened": False,
            "source": "body",
        }
    ]


def test_parallel_lookup_preserves_input_order() -> None:
    pipeline = PhishingPipeline(analysis_id="test")

    def worker(value: int) -> dict:
        return {"value": value}

    assert pipeline._run_parallel([3, 1, 2], worker) == [
        {"value": 3},
        {"value": 1},
        {"value": 2},
    ]


def test_attachment_extraction_stops_before_hashing_extra_parts(
    monkeypatch, tmp_path: Path
) -> None:
    from email_analysis import attachment_analyzer

    message = EmailMessage()
    message.set_content("Email body")
    for index in range(3):
        message.add_attachment(
            f"payload-{index}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"sample-{index}.bin",
        )

    hashed: list[bytes] = []
    real_compute_sha256 = attachment_analyzer.compute_sha256

    def recording_compute_sha256(data: bytes) -> str:
        hashed.append(data)
        return real_compute_sha256(data)

    monkeypatch.setattr(attachment_analyzer, "compute_sha256", recording_compute_sha256)

    assert attachment_analyzer.count_attachments(message) == 3
    attachments = attachment_analyzer.extract_attachments(
        message, save_dir=str(tmp_path), max_attachments=2
    )

    assert [item["filename"] for item in attachments] == [
        "sample-0.bin",
        "sample-1.bin",
    ]
    assert hashed == [b"payload-0", b"payload-1"]
    assert len(list(tmp_path.iterdir())) == 2


def test_qr_urls_share_the_total_url_limit() -> None:
    body_urls = [
        {"url": "https://body.example", "source": "body"},
    ]
    qr_urls = [
        {"url": "https://qr-one.example", "source": "qr_code"},
        {"url": "https://qr-two.example", "source": "qr_code"},
    ]

    bounded, truncated = PhishingPipeline._merge_bounded_url_lists(
        body_urls, qr_urls, max_urls=2
    )

    assert [item["url"] for item in bounded] == [
        "https://body.example",
        "https://qr-one.example",
    ]
    assert truncated is True
