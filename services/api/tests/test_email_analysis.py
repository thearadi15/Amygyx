"""Tests for bounded, explainable manual email analysis."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import email_analysis
from app.db.models import AuditEvent, Finding
from app.email_analysis import InvalidEmailMessage, analyze_email
from tests.test_findings_api import bearer_for


def test_analyze_suspicious_email_emits_sanitized_tenant_finding(
    api_client: TestClient,
) -> None:
    raw_message = (
        b"From: Executive <chief@example.test>\r\n"
        b"Reply-To: attacker@lookalike.test\r\n"
        b"Return-Path: <bounces@example.test>\r\n"
        b"Authentication-Results: mx.example.test; spf=fail; dkim=pass; dmarc=softfail\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please review this account urgently: "
        b"http://192.0.2.10/private/path?token=private-token-987\r\n"
        b"Private body marker: customer-message-secret\r\n"
    )

    response = api_client.post(
        "/email/analyze",
        content=raw_message,
        headers={**bearer_for(), "Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "suspicious_indicators"
    assert result["ruleset_version"] == "email-rules-v1"
    assert result["sender_domain"] == "example.test"
    assert result["reply_to_domain"] == "lookalike.test"
    assert result["return_path_domain"] == "example.test"
    assert result["authentication_results_source"] == "unverified_message_header"
    assert result["urls"] == [{"scheme": "http", "host": "192.0.2.10", "is_ip_literal": True}]
    assert result["urls_truncated"] is False
    assert {item["rule_id"] for item in result["indicators"]} == {
        "email.authentication-failure",
        "email.reply-to-domain-mismatch",
        "email.ip-literal-link",
    }
    authentication_indicator = next(
        item for item in result["indicators"] if item["rule_id"] == "email.authentication-failure"
    )
    assert authentication_indicator["evidence"]["source"] == "unverified_message_header"
    assert result["finding_id"]
    assert "private-token-987" not in response.text
    assert "customer-message-secret" not in response.text
    assert "chief@" not in response.text
    assert "/private/path" not in response.text

    with api_client.app.state.test_session() as db:
        finding = db.get(Finding, result["finding_id"])
        assert finding is not None
        assert finding.tenant_id == "tenant-a"
        assert finding.source_type == "email"
        assert finding.detector_version == "email-rules-v1"
        assert finding.confidence == 0.5
        assert "private-token-987" not in str(finding.evidence)
        assert "customer-message-secret" not in str(finding.evidence)
        assert "chief@" not in str(finding.evidence)
        events = db.scalars(select(AuditEvent)).all()
        assert {event.event_type for event in events} == {
            "email.analyzed",
            "finding.created",
        }
        assert all(event.tenant_id == "tenant-a" for event in events)


def test_benign_email_returns_no_finding_but_audits_analysis(api_client: TestClient) -> None:
    response = api_client.post(
        "/email/analyze",
        content=(
            b"From: updates@example.test\r\n"
            b"Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Routine service update.\r\n"
        ),
        headers=bearer_for(),
    )

    assert response.status_code == 200
    assert response.json()["result"] == "no_indicators"
    assert response.json()["finding_id"] is None
    assert response.json()["authentication_results_source"] == "unverified_message_header"
    with api_client.app.state.test_session() as db:
        assert db.scalars(select(Finding)).all() == []
        events = db.scalars(select(AuditEvent)).all()
        assert len(events) == 1
        assert events[0].event_type == "email.analyzed"


def test_email_analysis_requires_authentication(api_client: TestClient) -> None:
    response = api_client.post("/email/analyze", content=b"From: test@example.test\r\n\r\nbody")

    assert response.status_code == 401


def test_email_analysis_rejects_empty_or_malformed_messages(api_client: TestClient) -> None:
    empty = api_client.post("/email/analyze", content=b"", headers=bearer_for())
    malformed = api_client.post(
        "/email/analyze",
        content=b"not an email message",
        headers=bearer_for(),
    )
    malformed_headers = api_client.post(
        "/email/analyze",
        content=b"From: user@example.test\r\nBroken-Header\r\n\r\nbody",
        headers=bearer_for(),
    )

    assert empty.status_code == 422
    assert malformed.status_code == 422
    assert malformed_headers.status_code == 422


def test_email_analysis_enforces_streamed_size_limit(api_client: TestClient) -> None:
    response = api_client.post(
        "/email/analyze",
        content=b"From: user@example.test\r\n\r\n" + (b"x" * 1_048_576),
        headers=bearer_for(),
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Email message exceeds the 1 MiB upload limit."


def test_email_analysis_never_fetches_or_parses_attachment_content(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/email/analyze",
        content=(
            b"From: sender@example.test\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=part\r\n"
            b"\r\n"
            b"--part\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello.\r\n"
            b"--part\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=unsafe.exe\r\n"
            b"\r\n"
            b"http://192.0.2.99/attachment-link\r\n"
            b"--part--\r\n"
        ),
        headers=bearer_for(),
    )

    assert response.status_code == 200
    assert response.json()["urls"] == []
    assert response.json()["finding_id"] is None


def test_email_analysis_is_tenant_scoped(api_client: TestClient) -> None:
    response = api_client.post(
        "/email/analyze",
        content=b"From: user@example.test\r\nReply-To: other@elsewhere.test\r\n\r\nHello.",
        headers=bearer_for(subject="user-b", tenant_id="tenant-b"),
    )

    assert response.status_code == 200
    with api_client.app.state.test_session() as db:
        finding = db.scalar(select(Finding))
        assert finding is not None
        assert finding.tenant_id == "tenant-b"


def test_url_output_is_bounded_and_later_ip_indicator_is_preserved(
    api_client: TestClient,
) -> None:
    urls = " ".join(f"https://host-{index}.example.test/path" for index in range(101))
    content = (
        "From: sender@example.test\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{urls} http://192.0.2.123/late-link"
    ).encode()

    response = api_client.post("/email/analyze", content=content, headers=bearer_for())

    assert response.status_code == 200
    result = response.json()
    assert len(result["urls"]) == 100
    assert result["urls_truncated"] is True
    assert "email.ip-literal-link" in {indicator["rule_id"] for indicator in result["indicators"]}


def test_excessively_nested_mime_is_reported_as_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_recursive_walk(_: object) -> str:
        raise RecursionError

    monkeypatch.setattr(email_analysis, "_extract_message_text", reject_recursive_walk)

    with pytest.raises(InvalidEmailMessage, match="could not be parsed safely"):
        analyze_email(b"From: sender@example.test\r\n\r\nBody")


@pytest.mark.parametrize(
    ("filename", "expected_result"),
    [
        ("benign_update.eml", "no_indicators"),
        ("suspicious_indicators.eml", "suspicious_indicators"),
    ],
)
def test_synthetic_email_corpus_through_api(
    api_client: TestClient,
    filename: str,
    expected_result: str,
) -> None:
    sample_path = Path(__file__).parent / "fixtures" / "emails" / filename

    response = api_client.post(
        "/email/analyze",
        content=sample_path.read_bytes(),
        headers=bearer_for(),
    )

    assert response.status_code == 200
    assert response.json()["result"] == expected_result
