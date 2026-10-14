"""Tests for bounded Bitcoin transfer-edge analysis."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.bitcoin_analysis import InvalidBitcoinData, analyze_bitcoin_transfers
from app.db.models import AuditEvent, Finding
from tests.test_findings_api import bearer_for

FIXTURES = Path(__file__).parent / "fixtures" / "bitcoin"


def test_transfer_patterns_create_shared_findings_without_raw_addresses(
    api_client: TestClient,
) -> None:
    raw_csv = (FIXTURES / "synthetic_transfers.csv").read_bytes()
    response = api_client.post(
        "/bitcoin/analyze",
        content=raw_csv,
        headers=bearer_for(),
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "suspicious_indicators"
    assert result["ruleset_version"] == "bitcoin-transfer-rules-v1"
    assert result["rows_processed"] == 21
    assert {item["rule_id"] for item in result["indicators"]} == {
        "bitcoin.address-fan-out",
        "bitcoin.address-fan-in",
        "bitcoin.transfer-value-outlier",
    }
    assert "synthetic-fanout-sender" not in response.text
    assert "synthetic-fan-in-recipient" not in response.text

    with api_client.app.state.test_session() as db:
        findings = db.scalars(select(Finding)).all()
        assert len(findings) == 3
        assert all(finding.tenant_id == "tenant-a" for finding in findings)
        assert all(finding.source_type == "bitcoin_transaction" for finding in findings)
        assert all(finding.detector_version == "bitcoin-transfer-rules-v1" for finding in findings)
        stored_evidence = str([finding.evidence for finding in findings])
        assert "synthetic-fanout-sender" not in stored_evidence
        assert "synthetic-fan-in-recipient" not in stored_evidence
        assert "bitcoin.analyzed" in {
            event.event_type for event in db.scalars(select(AuditEvent)).all()
        }


def test_routine_transfers_create_no_findings_but_are_audited(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/bitcoin/analyze",
        content=(FIXTURES / "synthetic_routine.csv").read_bytes(),
        headers=bearer_for(),
    )

    assert response.status_code == 200
    assert response.json()["result"] == "no_indicators"
    assert response.json()["indicators"] == []
    with api_client.app.state.test_session() as db:
        assert db.scalars(select(Finding)).all() == []
        events = db.scalars(select(AuditEvent)).all()
        assert len(events) == 1
        assert events[0].event_type == "bitcoin.analyzed"


def test_bitcoin_analysis_requires_authentication(api_client: TestClient) -> None:
    response = api_client.post(
        "/bitcoin/analyze",
        content=(FIXTURES / "synthetic_routine.csv").read_bytes(),
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("raw_csv", "message"),
    [
        (b"", "Transaction CSV is empty."),
        (
            b"sender_address,recipient_address,amount_btc\nsource,destination,0.1\n",
            "Transaction CSV is missing required columns:",
        ),
        (
            b"transaction_id,sender_address,recipient_address,amount_btc\n"
            b"not-a-txid,source,destination,0.1\n",
            "transaction_id must be a 64-character hexadecimal txid.",
        ),
        (
            b"transaction_id,sender_address,recipient_address,amount_btc\n"
            b"0000000000000000000000000000000000000000000000000000000000000001,"
            b"source,destination,0.000000001\n",
            "amount_btc must be a non-negative BTC value with up to 8 decimals.",
        ),
        (
            b"transaction_id,sender_address,recipient_address,amount_btc\n"
            b"0000000000000000000000000000000000000000000000000000000000000001,"
            b'source,destination,"0.1\n',
            "Transaction CSV has malformed quoting or row structure.",
        ),
    ],
)
def test_invalid_transfer_data_is_rejected(
    api_client: TestClient,
    raw_csv: bytes,
    message: str,
) -> None:
    response = api_client.post("/bitcoin/analyze", content=raw_csv, headers=bearer_for())

    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_bitcoin_upload_enforces_size_limit(api_client: TestClient) -> None:
    response = api_client.post(
        "/bitcoin/analyze",
        content=b"x" * 1_048_577,
        headers=bearer_for(),
    )

    assert response.status_code == 413


def test_bitcoin_findings_are_tenant_scoped(api_client: TestClient) -> None:
    response = api_client.post(
        "/bitcoin/analyze",
        content=(FIXTURES / "synthetic_transfers.csv").read_bytes(),
        headers=bearer_for(subject="user-b", tenant_id="tenant-b"),
    )

    assert response.status_code == 200
    with api_client.app.state.test_session() as db:
        findings = db.scalars(select(Finding)).all()
        assert findings
        assert all(finding.tenant_id == "tenant-b" for finding in findings)


def test_analyzer_rejects_header_only_file() -> None:
    with pytest.raises(InvalidBitcoinData, match="at least one transfer row"):
        analyze_bitcoin_transfers(b"transaction_id,sender_address,recipient_address,amount_btc\n")
