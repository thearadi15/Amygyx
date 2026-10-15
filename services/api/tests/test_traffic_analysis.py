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


def test_ddos_flood_concentration_detected() -> None:
    """SIH26145: DDoS source-IP entropy/concentration detector fires on flood fixture."""
    result = analyze_unidirectional_flows(
        (FIXTURES / "synthetic_ddos_flood.csv").read_bytes()
    )
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "network.volumetric-flood-concentration" in rule_ids
    flood_ind = next(i for i in result.indicators if i.rule_id == "network.volumetric-flood-concentration")
    assert flood_ind.severity == "high"
    assert flood_ind.evidence["dominant_source_flow_fraction"] >= 0.80
    assert "source_ip_entropy_bits" in flood_ind.evidence
    assert result.threat_summary is not None
    assert "DETECTED" in result.threat_summary["volumetric_ddos_status"]


def test_c2_beacon_periodicity_detected() -> None:
    """SIH26145: Botnet C2 FFT periodicity detector fires on synthetic beacon fixture."""
    result = analyze_unidirectional_flows(
        (FIXTURES / "synthetic_c2_beacon.csv").read_bytes()
    )
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "network.botnet-c2-beacon-periodicity" in rule_ids
    c2_ind = next(i for i in result.indicators if i.rule_id == "network.botnet-c2-beacon-periodicity")
    assert c2_ind.severity == "high"
    assert c2_ind.evidence["iat_samples_analyzed"] >= 8
    assert c2_ind.evidence["fft_peak_to_mean_ratio"] >= 4.0
    assert result.threat_summary is not None
    assert "DETECTED" in result.threat_summary["botnet_c2_periodicity_status"]


def test_dga_dns_tunneling_entropy_detected() -> None:
    """SIH26145: DGA Shannon entropy detector fires on high-entropy DNS query labels."""
    result = analyze_unidirectional_flows(
        (FIXTURES / "synthetic_dga.csv").read_bytes()
    )
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "network.dga-dns-tunneling-entropy" in rule_ids
    dga_ind = next(i for i in result.indicators if i.rule_id == "network.dga-dns-tunneling-entropy")
    assert dga_ind.severity == "high"
    assert dga_ind.evidence["high_entropy_query_count"] >= 1
    assert dga_ind.evidence["entropy_threshold_bits"] == 3.5
    assert result.threat_summary is not None
    assert "DETECTED" in result.threat_summary["dga_dns_tunneling_status"]


def test_exfiltration_byte_ratio_detected() -> None:
    """SIH26145: Data exfiltration asymmetric byte-ratio detector fires on exfil fixture."""
    result = analyze_unidirectional_flows(
        (FIXTURES / "synthetic_exfiltration.csv").read_bytes()
    )
    rule_ids = {ind.rule_id for ind in result.indicators}
    assert "network.data-exfiltration-asymmetry" in rule_ids
    exfil_ind = next(i for i in result.indicators if i.rule_id == "network.data-exfiltration-asymmetry")
    assert exfil_ind.severity == "high"
    assert exfil_ind.evidence["suspicious_flow_count"] >= 1
    assert exfil_ind.evidence["total_suspicious_outbound_bytes"] > 0
    assert result.threat_summary is not None
    assert "DETECTED" in result.threat_summary["exfiltration_status"]


def test_optional_columns_backward_compatible() -> None:
    """Old CSVs without optional columns continue to work without errors."""
    result = analyze_unidirectional_flows(
        (FIXTURES / "synthetic_routine.csv").read_bytes()
    )
    assert result.rows_processed == 2
    assert result.threat_summary is not None
    assert "Requires iat_mean_ms column" in result.threat_summary["botnet_c2_periodicity_status"]
    assert "Requires dns_query_name column" in result.threat_summary["dga_dns_tunneling_status"]
    assert "Requires bytes_out column" in result.threat_summary["exfiltration_status"]
