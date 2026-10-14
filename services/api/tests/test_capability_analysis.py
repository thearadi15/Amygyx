"""Tests for bounded offline analysis profiles for the remaining capabilities."""

import wave
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import select

from app.db.models import AuditEvent, Finding
from tests.test_findings_api import bearer_for

FIXTURES = Path(__file__).parent / "fixtures" / "capabilities"


def upload(
    api_client: TestClient,
    capability: str,
    filename: str,
    data: bytes,
) -> Response:
    return api_client.post(
        f"/capabilities/{capability}/analyze",
        params={"filename": filename},
        content=data,
        headers=bearer_for(),
    )


@pytest.mark.parametrize(
    ("capability", "filename", "fixture", "expected_rule"),
    [
        ("risk", "risk.csv", "risk_scenarios.csv", "risk.investment-positive-net-benefit"),
        (
            "forecasting",
            "events.csv",
            "network_events.csv",
            "network.forecast-elevated-trend",
        ),
        (
            "compliance",
            "router.txt",
            "cisco_ios_config.txt",
            "compliance.cisco-ssh-only",
        ),
        (
            "identity",
            "document.pdf",
            "document_active_content.pdf",
            "identity.document-pdf-active-content",
        ),
        (
            "video",
            "events.csv",
            "cctv_events.csv",
            "video.event-low-model-confidence",
        ),
        (
            "ipsec",
            "ipsec.conf",
            "strongswan_ipsec.conf",
            "ipsec.no-known-weak-algorithms",
        ),
    ],
)
def test_local_profiles_return_review_signals_and_shared_findings(
    api_client: TestClient,
    capability: str,
    filename: str,
    fixture: str,
    expected_rule: str,
) -> None:
    response = upload(
        api_client,
        capability,
        filename,
        (FIXTURES / fixture).read_bytes(),
    )

    assert response.status_code == 200
    result = response.json()
    assert result["capability_id"] == capability
    assert result["result"] == "review_required"
    assert result["records_processed"] > 0
    assert expected_rule in {item["rule_id"] for item in result["indicators"]}
    assert all(item["finding_id"] for item in result["indicators"])
    with api_client.app.state.test_session() as db:
        findings = db.scalars(select(Finding)).all()
        assert len(findings) == len(result["indicators"])
        assert all(finding.tenant_id == "tenant-a" for finding in findings)
        assert all(finding.detector_version == result["ruleset_version"] for finding in findings)
        assert f"capability.{capability}.analyzed" in {
            event.event_type for event in db.scalars(select(AuditEvent)).all()
        }


def _silent_pcm_wav() -> bytes:
    output = BytesIO()
    with wave.open(output, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(8_000)
        audio.writeframes(b"\0\0" * 800)
    return output.getvalue()


def test_voice_profile_only_reports_audio_quality_not_cloned_voice(api_client: TestClient) -> None:
    response = upload(api_client, "voice", "synthetic.wav", _silent_pcm_wav())

    assert response.status_code == 200
    result = response.json()
    assert (
        result["summary"]["spoof_detection"] == "not_available_in_offline_signal_integrity_profile"
    )
    assert "voice.audio-low-signal" in {item["rule_id"] for item in result["indicators"]}
    assert "speaker identity" not in response.text


def test_local_profiles_require_authentication(api_client: TestClient) -> None:
    response = api_client.post(
        "/capabilities/voice/analyze?filename=sample.wav",
        content=_silent_pcm_wav(),
    )

    assert response.status_code == 401


def test_local_profiles_reject_unknown_extensions_and_malformed_inputs(
    api_client: TestClient,
) -> None:
    unsupported_document = upload(api_client, "identity", "sample.docx", b"not a supported file")
    invalid_wav = upload(api_client, "voice", "sample.wav", b"not a wav")
    invalid_timezone = upload(
        api_client,
        "video",
        "events.csv",
        b"timestamp,camera_id,event_type,confidence\n2026-10-13T02:15:00,camera-1,motion,0.9\n",
    )

    assert unsupported_document.status_code == 422
    assert invalid_wav.status_code == 422
    assert invalid_timezone.status_code == 422


def test_audio_rejects_truncated_pcm_frames(api_client: TestClient) -> None:
    response = upload(api_client, "voice", "sample.wav", _silent_pcm_wav()[:-2])

    assert response.status_code == 422
    assert response.json()["detail"] == "WAV audio data is truncated."


def test_forecast_rejects_uneven_intervals(api_client: TestClient) -> None:
    data = (
        (FIXTURES / "network_events.csv")
        .read_bytes()
        .replace(
            b"2026-10-13T03:00:00+00:00",
            b"2026-10-13T03:30:00+00:00",
        )
    )
    response = upload(api_client, "forecasting", "events.csv", data)

    assert response.status_code == 422
    assert response.json()["detail"] == "timestamps must use evenly spaced intervals."


def test_local_profiles_enforce_upload_limit(api_client: TestClient) -> None:
    response = upload(api_client, "compliance", "router.txt", b"x" * 1_048_577)

    assert response.status_code == 413


def test_unknown_capability_profile_returns_not_found(api_client: TestClient) -> None:
    response = upload(api_client, "not-a-profile", "file.txt", b"content")

    assert response.status_code == 404


def test_risk_totals_count_each_asset_once_and_reject_inconsistent_scenarios() -> None:
    from app.capability_analysis import InvalidCapabilityInput, analyze_risk_investments

    inconsistent = (
        b"asset,asset_value_usd,annual_event_probability,impact_fraction,control,"
        b"annual_control_cost_usd,risk_reduction_fraction\n"
        b"asset-a,1000,0.1,0.5,control-a,10,0.5\n"
        b"asset-a,2000,0.1,0.5,control-b,10,0.5\n"
    )
    with pytest.raises(InvalidCapabilityInput, match="identical"):
        analyze_risk_investments(inconsistent)

    duplicate_asset_controls = (FIXTURES / "risk_scenarios.csv").read_bytes()
    analysis = analyze_risk_investments(duplicate_asset_controls)
    assert analysis.summary["total_annual_expected_loss_usd"] == 500_000


def test_local_profile_findings_are_tenant_scoped(api_client: TestClient) -> None:
    response = api_client.post(
        "/capabilities/compliance/analyze?filename=router.txt",
        content=(FIXTURES / "cisco_ios_config.txt").read_bytes(),
        headers=bearer_for(subject="user-b", tenant_id="tenant-b"),
    )

    assert response.status_code == 200
    with api_client.app.state.test_session() as db:
        findings = db.scalars(select(Finding)).all()
        assert findings
        assert all(finding.tenant_id == "tenant-b" for finding in findings)


def test_risk_budget_optimizer_finds_best_combination_and_records_plan(
    api_client: TestClient,
) -> None:
    data = (
        b"asset,asset_value_usd,annual_event_probability,impact_fraction,control,"
        b"annual_control_cost_usd,risk_reduction_fraction\n"
        b"asset-a,1000,1,1,control-a,60,0.1\n"
        b"asset-b,1000,1,1,control-b,50,0.08\n"
        b"asset-c,1000,1,1,control-c,50,0.08\n"
    )
    response = api_client.post(
        "/capabilities/risk/analyze?filename=risk.csv&budget_usd=100",
        content=data,
        headers=bearer_for(),
    )

    assert response.status_code == 200
    result = response.json()
    assert result["summary"]["optimizer"] == "0_1_knapsack_max_avoided_loss"
    assert result["summary"]["optimizer_cost_granularity_usd"] == 10
    assert result["summary"]["selected_control_options"] == 2
    assert result["summary"]["projected_annual_loss_avoided_usd"] == 160
    selected = {
        item["evidence"]["control"]
        for item in result["indicators"]
        if item["evidence"]["selected_for_budget"]
    }
    assert selected == {"control-b", "control-c"}


def test_budget_is_rejected_for_profiles_without_investment_options(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/capabilities/voice/analyze?filename=sample.wav&budget_usd=100",
        content=_silent_pcm_wav(),
        headers=bearer_for(),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "budget_usd is supported only by the risk capability."
