"""Authentication and authorization tests for the API."""

from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt import PyJWKClientConnectionError
from pytest import MonkeyPatch

from app import auth
from app.auth import create_access_token
from app.config import Settings, get_settings
from app.db.models import User


def bearer_for(
    subject: str = "user-a",
    tenant_id: str = "tenant-a",
    *,
    email: str = "token-claim@example.test",
    role: str = "analyst",
) -> dict[str, str]:
    token = create_access_token(
        subject=subject,
        tenant_id=tenant_id,
        email=email,
        role=role,
    )
    return {"Authorization": f"Bearer {token}"}


def test_requires_authentication_for_protected_route(api_client: TestClient) -> None:
    response = api_client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_identity_is_resolved_from_persisted_membership(api_client: TestClient) -> None:
    response = api_client.get(
        "/auth/me",
        headers=bearer_for(email="untrusted@example.test", role="admin"),
    )

    assert response.status_code == 200
    assert response.json() == {
        "subject": "user-a",
        "tenant_id": "tenant-a",
        "email": "analyst-a@example.test",
        "role": "analyst",
    }


def test_admin_role_is_read_from_database_not_token_claim(api_client: TestClient) -> None:
    denied = api_client.get("/auth/admin", headers=bearer_for(role="admin"))
    assert denied.status_code == 403

    with api_client.app.state.test_session() as db:
        user = db.get(User, "user-a")
        assert user is not None
        user.role = "admin"
        db.commit()

    allowed = api_client.get("/auth/admin", headers=bearer_for(role="analyst"))

    assert allowed.status_code == 200
    assert allowed.json()["role"] == "admin"


def test_unrecognized_persisted_role_is_denied_business_access(
    api_client: TestClient,
) -> None:
    with api_client.app.state.test_session() as db:
        user = db.get(User, "user-a")
        assert user is not None
        user.role = "viewer"
        db.commit()

    headers = bearer_for(role="admin")
    findings = api_client.get("/findings", headers=headers)
    incidents = api_client.get("/incidents", headers=headers)

    assert findings.status_code == 403
    assert incidents.status_code == 403


def test_tenant_scope_enforces_persisted_membership(api_client: TestClient) -> None:
    response = api_client.get(
        "/auth/tenant/tenant-b",
        headers=bearer_for(tenant_id="tenant-a"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant access denied."


def test_missing_tenant_membership_is_denied(api_client: TestClient) -> None:
    response = api_client.get(
        "/auth/me",
        headers=bearer_for(subject="unknown-user"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant membership required."


def test_invalid_token_is_rejected(api_client: TestClient) -> None:
    response = api_client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired authentication token."


def test_local_jwt_authentication_fails_closed_outside_development(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    headers = bearer_for()
    monkeypatch.setattr(get_settings(), "app_env", "production")
    monkeypatch.setattr(get_settings(), "oidc_issuer", None)
    monkeypatch.setattr(get_settings(), "oidc_audience", None)
    monkeypatch.setattr(get_settings(), "oidc_jwks_url", None)

    response = api_client.get("/findings", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication provider is not configured."
    with pytest.raises(RuntimeError, match="only available in development"):
        create_access_token(
            subject="user-a",
            tenant_id="tenant-a",
            email="analyst@example.test",
        )


def test_development_token_issuer_is_not_public(api_client: TestClient) -> None:
    response = api_client.get("/auth/token")

    assert response.status_code == 404


@pytest.mark.parametrize(
    "setting",
    [
        {"oidc_issuer": "http://identity.example.test"},
        {"oidc_jwks_url": "http://identity.example.test/keys"},
    ],
)
def test_oidc_endpoints_require_https(setting: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(_env_file=None, **setting)


def make_oidc_token(
    private_key: rsa.RSAPrivateKey,
    *,
    subject: str = "oidc-subject-1",
    issuer: str = "https://identity.example.test/",
    audience: str = "cip-api",
    role: str | None = None,
) -> str:
    issued_at = int(datetime.now(UTC).timestamp())
    claims = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + 3600,
    }
    if role is not None:
        claims["role"] = role
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def configure_oidc(
    monkeypatch: MonkeyPatch,
    public_key: rsa.RSAPublicKey,
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "oidc_issuer", "https://identity.example.test/")
    monkeypatch.setattr(settings, "oidc_audience", "cip-api")
    monkeypatch.setattr(settings, "oidc_jwks_url", "https://identity.example.test/keys")

    class TestJwksClient:
        def get_signing_key_from_jwt(self, token: str) -> object:
            return type("SigningKey", (), {"key": public_key})()

    monkeypatch.setattr(auth, "_get_jwks_client", lambda _: TestJwksClient())


def test_oidc_access_token_maps_exact_issuer_subject_to_membership(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    configure_oidc(monkeypatch, private_key.public_key())
    with api_client.app.state.test_session() as db:
        member = db.get(User, "user-a")
        assert member is not None
        member.identity_issuer = "https://identity.example.test/"
        member.identity_subject = "oidc-subject-1"
        db.commit()

    response = api_client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {make_oidc_token(private_key)}"},
    )

    assert response.status_code == 200
    assert response.json()["subject"] == "user-a"
    assert response.json()["role"] == "analyst"


def test_oidc_role_claim_cannot_grant_admin_access(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    configure_oidc(monkeypatch, private_key.public_key())
    with api_client.app.state.test_session() as db:
        member = db.get(User, "user-a")
        assert member is not None
        member.identity_issuer = "https://identity.example.test/"
        member.identity_subject = "oidc-subject-1"
        db.commit()

    token = make_oidc_token(private_key, role="admin")
    response = api_client.get("/auth/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


@pytest.mark.parametrize(
    ("issuer", "audience"),
    [
        ("https://attacker.example.test/", "cip-api"),
        ("https://identity.example.test/", "other-api"),
    ],
)
def test_oidc_rejects_wrong_issuer_or_audience(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
    issuer: str,
    audience: str,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    configure_oidc(monkeypatch, private_key.public_key())

    response = api_client.get(
        "/auth/me",
        headers={
            "Authorization": (
                f"Bearer {make_oidc_token(private_key, issuer=issuer, audience=audience)}"
            )
        },
    )

    assert response.status_code == 401


def test_oidc_unmapped_identity_is_denied(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    configure_oidc(monkeypatch, private_key.public_key())

    response = api_client.get(
        "/findings",
        headers={"Authorization": f"Bearer {make_oidc_token(private_key)}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant membership required."


def test_oidc_jwks_outage_returns_service_unavailable(
    api_client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "oidc_issuer", "https://identity.example.test/")
    monkeypatch.setattr(settings, "oidc_audience", "cip-api")
    monkeypatch.setattr(settings, "oidc_jwks_url", "https://identity.example.test/keys")

    def unavailable(_: str) -> object:
        raise PyJWKClientConnectionError("network error")

    monkeypatch.setattr(auth, "_get_jwks_client", unavailable)
    response = api_client.get(
        "/findings",
        headers={"Authorization": "Bearer any-token"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication provider is temporarily unavailable."
