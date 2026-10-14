"""HTTP API entry point."""

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth import get_tenant_member, require_role
from app.config import get_settings
from app.db.models import User
from app.db.session import check_database_available
from app.routers.bitcoin_analysis import router as bitcoin_analysis_router
from app.routers.capability_analysis import router as capability_analysis_router
from app.routers.email_analysis import router as email_analysis_router
from app.routers.findings import router as findings_router
from app.routers.incidents import router as incidents_router
from app.routers.traffic_analysis import router as traffic_analysis_router

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url="/redoc" if settings.app_env != "production" else None,
)

# Keep origins explicit. Do not use wildcard origins when credentials are enabled.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.web_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.include_router(findings_router)
app.include_router(incidents_router)
app.include_router(email_analysis_router)
app.include_router(traffic_analysis_router)
app.include_router(bitcoin_analysis_router)
app.include_router(capability_analysis_router)


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    """Indicate that the API process is running; do not expose runtime details."""

    return {"status": "ok"}


@app.get("/health/ready", tags=["health"], response_model=None)
def readiness() -> dict[str, str] | JSONResponse:
    """Report whether the service can access its configured PostgreSQL dependency."""

    if check_database_available():
        return {"status": "ok", "database": "ready"}

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "error", "database": "unavailable"},
    )


@app.get("/auth/me", tags=["auth"])
def auth_me(member: User = Depends(get_tenant_member)) -> dict[str, str]:
    """Return the identity bound to the current request."""

    return {
        "subject": member.id,
        "tenant_id": member.tenant_id,
        "email": member.email,
        "role": member.role,
    }


@app.get("/auth/tenant/{tenant_id}", tags=["auth"])
def auth_tenant_scope(
    tenant_id: str,
    member: User = Depends(get_tenant_member),
) -> dict[str, str]:
    """Require the caller to operate within a specific tenant scope."""

    if member.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant access denied.",
        )
    return {"tenant_id": member.tenant_id, "status": "ok"}


@app.get("/auth/admin", tags=["auth"])
def auth_admin(
    member: User = Depends(require_role("admin")),
) -> dict[str, str]:
    """Return an admin-only role check using the persisted membership role."""

    return {"tenant_id": member.tenant_id, "role": member.role, "status": "ok"}
