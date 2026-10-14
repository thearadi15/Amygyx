"""Tests for bounded unidirectional IP flow analysis."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditEvent, Finding
from app.traffic_analysis import InvalidTrafficData, analyze_unidirectional_flows
from tests.test_findings_api import bearer_for

FIXTURES = Path(__file__).parent / "fixtures" / "traffic"


def test_port_scan_pattern_creates_a_tenant_scoped_shared_finding(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/traffic/analyze",
        content=(FIXTURES / "synthetic_port_scan.csv").read_bytes(),
        headers=bearer_for(),
    )

    assert response.status_code == 200
    result = response.json()
    assert result["result"] == "suspicious_indicators"
    assert result["ruleset_version"] == "unidirectional-ip-rules-v1"
    assert result["rows_processed"] == 20
    assert len(result["indicators"]) == 1
    indicator = result["indicators"][0]
    assert indicator["rule_id"] == "network.unidirectional-port-scan"
    assert indicator["evidence"] == {
        "source_ip": "192.0.2.25",
        "protocol": "tcp",
        "distinct_destination_ports": 20,
        "flow_count": 20,
        "threshold": 20,
    }

    with api_client.app.state.test_session() as db:
        finding = db.get(Finding, indicator["finding_id"])
        assert finding is not None
        assert finding.tenant_id == "tenant-a"
        assert finding.source_type == "unidirectional_ip_traffic"
        assert finding.detector_version == "unidirectional-ip-rules-v1"
        events = db.scalars(select(AuditEvent)).all()
        assert {event.event_type for event in events} == {
            "finding.created",
            "traffic.analyzed",
        }


def test_routine_flow_creates_no_finding_but_audits_the_run(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/traffic/analyze",
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
        assert events[0].event_type == "traffic.analyzed"


def test_traffic_analysis_requires_authentication(api_client: TestClient) -> None:
    response = api_client.post(
        "/traffic/analyze",
        content=(FIXTURES / "synthetic_routine.csv").read_bytes(),
    )

    assert response.status_code == 401


def test_local_web_origin_can_call_traffic_analysis(api_client: TestClient) -> None:
    response = api_client.options(
        "/traffic/analyze",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


@pytest.mark.parametrize(
    ("raw_csv", "message"),
    [
        (b"", "Flow CSV is empty."),
        (
            b"source_ip,destination_ip\n192.0.2.1,198.51.100.1\n",
            "Flow CSV is missing required columns:",
        ),
        (
            b"source_ip,destination_ip,destination_port,protocol,bytes,packets\n"
            b"not-an-ip,198.51.100.1,443,tcp,10,1\n",
            "Invalid IP address in source_ip.",
        ),
        (
            b"source_ip,destination_ip,destination_port,protocol,bytes,packets\n"
            b"192.0.2.1,198.51.100.1,70000,tcp,10,1\n",
            "destination_port must be between 1 and 65535.",
        ),
        (
            b"source_ip,destination_ip,destination_port,protocol,bytes,packets\n"
            b'192.0.2.1,198.51.100.1,443,tcp,10,"1\n',
            "Flow CSV has malformed quoting or row structure.",
        ),
    ],
)
def test_invalid_flow_files_are_reported(
    api_client: TestClient,
    raw_csv: bytes,
    message: str,
) -> None:
    response = api_client.post("/traffic/analyze", content=raw_csv, headers=bearer_for())

    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_traffic_upload_enforces_size_limit(api_client: TestClient) -> None:
    response = api_client.post(
        "/traffic/analyze",
        content=b"x" * 1_048_577,
        headers=bearer_for(),
    )

    assert response.status_code == 413


def test_traffic_findings_are_tenant_scoped(api_client: TestClient) -> None:
    response = api_client.post(
        "/traffic/analyze",
        content=(FIXTURES / "synthetic_port_scan.csv").read_bytes(),
        headers=bearer_for(subject="user-b", tenant_id="tenant-b"),
    )

    assert response.status_code == 200
    with api_client.app.state.test_session() as db:
        finding = db.scalar(select(Finding))
        assert finding is not None
        assert finding.tenant_id == "tenant-b"


def test_analyzer_rejects_empty_flow_records() -> None:
    with pytest.raises(InvalidTrafficData, match="at least one flow record"):
        analyze_unidirectional_flows(
            b"source_ip,destination_ip,destination_port,protocol,bytes,packets\n"
        )
