"""Tests for tenant-scoped incident workflows."""

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import create_access_token
from app.db.models import AuditEvent, Finding, Incident, IncidentFinding


def bearer_for(subject: str = "user-a", tenant_id: str = "tenant-a") -> dict[str, str]:
    token = create_access_token(
        subject=subject,
        tenant_id=tenant_id,
        email="analyst@example.test",
        role="admin",
    )
    return {"Authorization": f"Bearer {token}"}


def add_finding(api_client: TestClient, finding_id: str, tenant_id: str = "tenant-a") -> None:
    with api_client.app.state.test_session() as db:
        db.add(
            Finding(
                id=finding_id,
                tenant_id=tenant_id,
                source_type="email",
                title=f"Finding {finding_id}",
                severity="medium",
                confidence=0.75,
                business_impact="high",
                status="open",
            )
        )
        db.commit()


def test_create_list_and_read_incident_with_finding(api_client: TestClient) -> None:
    add_finding(api_client, "finding-a")

    response = api_client.post(
        "/incidents",
        json={
            "title": "Email investigation",
            "summary": "Investigate suspicious authentication failures.",
            "severity": "high",
            "finding_ids": ["finding-a"],
        },
        headers=bearer_for(),
    )

    assert response.status_code == 201
    incident = response.json()
    assert incident["status"] == "new"
    assert incident["finding_ids"] == ["finding-a"]

    listed = api_client.get("/incidents?status=new", headers=bearer_for())
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [incident["id"]]

    retrieved = api_client.get(f"/incidents/{incident['id']}", headers=bearer_for())
    assert retrieved.status_code == 200
    assert retrieved.json()["title"] == "Email investigation"

    with api_client.app.state.test_session() as db:
        assert len(db.scalars(select(IncidentFinding)).all()) == 1
        audit_types = set(db.scalars(select(AuditEvent.event_type)).all())
        assert audit_types == {"incident.created", "incident.finding_linked"}


def test_incident_apis_require_authentication(api_client: TestClient) -> None:
    assert api_client.get("/incidents").status_code == 401
    assert api_client.post("/incidents", json={"title": "Unauthenticated"}).status_code == 401


def test_cross_tenant_incidents_and_findings_are_not_exposed(api_client: TestClient) -> None:
    add_finding(api_client, "finding-b", tenant_id="tenant-b")
    created = api_client.post(
        "/incidents",
        json={"title": "Tenant A incident"},
        headers=bearer_for(),
    )
    incident_id = created.json()["id"]

    foreign_finding = api_client.post(
        f"/incidents/{incident_id}/findings",
        json={"finding_id": "finding-b"},
        headers=bearer_for(),
    )
    assert foreign_finding.status_code == 404

    foreign_incident = api_client.get(
        f"/incidents/{incident_id}",
        headers=bearer_for(subject="user-b", tenant_id="tenant-b"),
    )
    assert foreign_incident.status_code == 404

    with api_client.app.state.test_session() as db:
        incident = db.get(Incident, incident_id)
        assert incident is not None
        assert incident.tenant_id == "tenant-a"


def test_incident_status_transitions_are_controlled_and_audited(api_client: TestClient) -> None:
    created = api_client.post(
        "/incidents",
        json={"title": "Status workflow"},
        headers=bearer_for(),
    )
    incident_id = created.json()["id"]

    invalid_transition = api_client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers=bearer_for(),
    )
    assert invalid_transition.status_code == 409

    investigating = api_client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "investigating"},
        headers=bearer_for(),
    )
    assert investigating.status_code == 200
    assert investigating.json()["status"] == "investigating"

    resolved = api_client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "resolved"},
        headers=bearer_for(),
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"

    closed = api_client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers=bearer_for(),
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"

    terminal_transition = api_client.patch(
        f"/incidents/{incident_id}/status",
        json={"status": "investigating"},
        headers=bearer_for(),
    )
    assert terminal_transition.status_code == 409

    with api_client.app.state.test_session() as db:
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "incident.status_changed")
        ).all()
        assert len(events) == 3
        transitions = {
            (event.event_data["from_status"], event.event_data["to_status"])
            for event in events
            if event.event_data is not None
        }
        assert transitions == {
            ("new", "investigating"),
            ("investigating", "resolved"),
            ("resolved", "closed"),
        }


def test_link_endpoint_rejects_unknown_duplicate_and_foreign_findings(
    api_client: TestClient,
) -> None:
    add_finding(api_client, "finding-local")
    add_finding(api_client, "finding-foreign", tenant_id="tenant-b")
    incident_id = api_client.post(
        "/incidents",
        json={"title": "Link workflow"},
        headers=bearer_for(),
    ).json()["id"]

    unknown = api_client.post(
        f"/incidents/{incident_id}/findings",
        json={"finding_id": "missing"},
        headers=bearer_for(),
    )
    foreign = api_client.post(
        f"/incidents/{incident_id}/findings",
        json={"finding_id": "finding-foreign"},
        headers=bearer_for(),
    )
    linked = api_client.post(
        f"/incidents/{incident_id}/findings",
        json={"finding_id": "finding-local"},
        headers=bearer_for(),
    )
    duplicate = api_client.post(
        f"/incidents/{incident_id}/findings",
        json={"finding_id": "finding-local"},
        headers=bearer_for(),
    )

    assert unknown.status_code == 404
    assert foreign.status_code == 404
    assert linked.status_code == 200
    assert linked.json()["finding_ids"] == ["finding-local"]
    assert duplicate.status_code == 409


def test_invalid_incident_inputs_are_rejected(api_client: TestClient) -> None:
    duplicate_ids = api_client.post(
        "/incidents",
        json={"title": "Duplicates", "finding_ids": ["same", "same"]},
        headers=bearer_for(),
    )
    invalid_status = api_client.patch(
        "/incidents/nonexistent/status",
        json={"status": "invalid"},
        headers=bearer_for(),
    )
    forged_tenant = api_client.post(
        "/incidents",
        json={"title": "Forged", "tenant_id": "tenant-b"},
        headers=bearer_for(),
    )

    assert duplicate_ids.status_code == 422
    assert invalid_status.status_code == 422
    assert forged_tenant.status_code == 422
