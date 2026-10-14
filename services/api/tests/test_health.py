"""Smoke tests for the API foundation and database readiness."""

from fastapi.testclient import TestClient

from app import main

client = TestClient(main.app)


def test_liveness_returns_ok() -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_liveness_does_not_disclose_configuration() -> None:
    response = client.get("/health/live")
    body = response.text.lower()

    assert "development" not in body
    assert "secret" not in body
    assert "password" not in body


def test_readiness_reports_database_ready(monkeypatch) -> None:
    monkeypatch.setattr(main, "check_database_available", lambda: True)

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ready"}


def test_readiness_reports_database_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(main, "check_database_available", lambda: False)

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "error", "database": "unavailable"}
