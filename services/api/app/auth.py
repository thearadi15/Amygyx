"""Authentication and authorization primitives for the API."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import User
from app.db.session import get_db

settings = get_settings()
security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Authenticated identity claims; authorization comes from persisted membership."""

    subject: str
    issuer: str
    tenant_id: str | None = None


@lru_cache(maxsize=4)
def _get_jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url, cache_keys=True, timeout=5)


def _decode_oidc_access_token(token: str) -> dict[str, Any]:
    """Verify an OIDC access token using the configured issuer's HTTPS JWKS."""

    if not settings.oidc_issuer or not settings.oidc_audience or not settings.oidc_jwks_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication provider is not configured.",
        )

    try:
        signing_key = _get_jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication provider is temporarily unavailable.",
        ) from exc
    except PyJWKClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["sub", "iss", "aud", "exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_access_token(
    *,
    subject: str,
    tenant_id: str,
    email: str,
    role: str = "analyst",
) -> str:
    """Create a signed JWT representing an authenticated tenant-scoped principal."""

    if settings.app_env != "development":
        raise RuntimeError("Local token issuance is only available in development.")

    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "email": email,
        "role": role,
        "iss": settings.auth_issuer,
        "aud": settings.auth_audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.auth_token_ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.auth_secret_key, algorithm=settings.auth_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Validate a signed token and return the JWT payload."""

    return jwt.decode(
        token,
        settings.auth_secret_key,
        algorithms=[settings.auth_algorithm],
        audience=settings.auth_audience,
        issuer=settings.auth_issuer,
        options={"require": ["sub", "tenant_id", "email", "role", "exp", "iat"]},
    )


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> Principal:
    """Return the authenticated principal for a request."""

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if settings.app_env == "development":
        try:
            payload = decode_access_token(credentials.credentials)
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        issuer = settings.auth_issuer
        tenant_id = str(payload.get("tenant_id", ""))
    else:
        payload = _decode_oidc_access_token(credentials.credentials)
        issuer = str(payload.get("iss", ""))
        tenant_id = None

    subject = str(payload.get("sub", ""))
    if not subject or not issuer or (settings.app_env == "development" and not tenant_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing required identity claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return Principal(subject=subject, issuer=issuer, tenant_id=tenant_id)


def require_role(*allowed_roles: str) -> Callable[..., User]:
    """Create a dependency that enforces roles from persisted tenant membership."""

    def dependency(member: User = Depends(get_tenant_member)) -> User:
        if member.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This action requires a higher role.",
            )
        return member

    return dependency


def get_tenant_member(
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> User:
    """Resolve a token identity against persisted tenant membership and role."""

    if settings.app_env == "development":
        member = db.scalar(
            select(User).where(
                User.id == principal.subject,
                User.tenant_id == principal.tenant_id,
            )
        )
    else:
        member = db.scalar(
            select(User).where(
                User.identity_issuer == principal.issuer,
                User.identity_subject == principal.subject,
            )
        )
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant membership required.",
        )
    return member
