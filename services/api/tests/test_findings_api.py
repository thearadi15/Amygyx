"""Tests for authenticated, tenant-scoped finding APIs."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import create_access_token
from app.db.models import AuditEvent, Finding


def bearer_for(subject: str = "user-a", tenant_id: str = "tenant-a") -> dict[str, str]:
    token = create_access_token(
        subject=subject,
        tenant_id=tenant_id,
        email="analyst@example.test",
        role="admin",
    )
    return {"Authorization": f"Bearer {token}"}


def test_list_findings_requires_authentication(api_client: TestClient) -> None:
    response = api_client.get("/findings")

    assert response.status_code == 401


def test_create_list_and_read_finding_for_member(api_client: TestClient) -> None:
    payload = {
        "source_type": "email",
        "source_id": "sample-42",
        "title": "Suspicious sender authentication",
        "summary": "SPF and DMARC checks did not align.",
        "severity": "high",
        "confidence": 0.87,
        "business_impact": "critical",
        "rule_id": "email.auth-alignment",
        "detector_version": "1.0.0",
        "evidence": {"authentication_results": ["spf=fail", "dmarc=fail"]},
    }

    created = api_client.post("/findings", json=payload, headers=bearer_for())

    assert created.status_code == 201
    body = created.json()
    assert body["severity"] == "high"
    assert body["confidence"] == 0.87
    assert body["business_impact"] == "critical"
    assert body["status"] == "open"

    listed = api_client.get("/findings?severity=high", headers=bearer_for())
    assert listed.status_code == 200
    assert [finding["id"] for finding in listed.json()] == [body["id"]]

    retrieved = api_client.get(f"/findings/{body['id']}", headers=bearer_for())
    assert retrieved.status_code == 200
    assert retrieved.json()["title"] == payload["title"]

    with api_client.app.state.test_session() as db:
        events = db.scalars(select(AuditEvent)).all()
        assert len(events) == 1
        assert events[0].event_type == "finding.created"
        assert events[0].actor_id == "user-a"


def test_tenant_cannot_list_or_read_another_tenants_findings(api_client: TestClient) -> None:
    with api_client.app.state.test_session() as db:
        finding = Finding(
            id="finding-b",
            tenant_id="tenant-b",
            source_type="network",
            title="Tenant B finding",
            severity="medium",
            confidence=0.5,
            business_impact="moderate",
            status="open",
        )
        db.add(finding)
        db.commit()

    listing = api_client.get("/findings", headers=bearer_for())
    detail = api_client.get("/findings/finding-b", headers=bearer_for())

    assert listing.status_code == 200
    assert listing.json() == []
    assert detail.status_code == 404
    assert detail.json()["detail"] == "Finding not found."


def test_claims_without_persisted_tenant_membership_are_denied(
    api_client: TestClient,
) -> None:
    response = api_client.get(
        "/findings",
        headers=bearer_for(subject="user-a", tenant_id="tenant-b"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant membership required."


@pytest.mark.parametrize(
    "payload",
    [
        {"source_type": "email", "title": "Invalid confidence", "confidence": 1.01},
        {"source_type": "email", "title": "Invalid severity", "severity": "urgent"},
        {"source_type": "email", "title": "Forged tenant", "tenant_id": "tenant-b"},
    ],
)
def test_invalid_finding_payload_is_rejected(
    api_client: TestClient,
    payload: dict[str, object],
) -> None:
    response = api_client.post("/findings", json=payload, headers=bearer_for())

    assert response.status_code == 422


def test_list_supports_bounded_pagination(api_client: TestClient) -> None:
    with api_client.app.state.test_session() as db:
        db.add_all(
            [
                Finding(
                    id=f"finding-{index}",
                    tenant_id="tenant-a",
                    source_type="network",
                    title=f"Finding {index}",
                    severity="low",
                    confidence=0.25,
                    business_impact="low",
                    status="open",
                )
                for index in range(3)
            ]
        )
        db.commit()

    response = api_client.get("/findings?limit=2&offset=1", headers=bearer_for())

    assert response.status_code == 200
    assert len(response.json()) == 2
