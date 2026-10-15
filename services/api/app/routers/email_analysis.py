"""Authenticated manual email analysis endpoint."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import require_role
from app.db.models import AuditEvent, Finding, User
from app.db.session import get_db
from app.email_analysis import EMAIL_RULESET_VERSION, InvalidEmailMessage, analyze_email
from app.schemas.email_analysis import EmailAnalysisRead, EmailIndicatorRead

MAX_EMAIL_BYTES = 1_048_576

router = APIRouter(prefix="/email", tags=["email analysis"])
DbSession = Annotated[Session, Depends(get_db)]
TenantMember = Annotated[User, Depends(require_role("admin", "analyst"))]


async def _read_bounded_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_EMAIL_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="Email message exceeds the 1 MiB upload limit.",
            )
        body.extend(chunk)
    return bytes(body)


@router.post("/analyze", response_model=EmailAnalysisRead)
async def analyze_uploaded_email(
    request: Request,
    db: DbSession,
    member: TenantMember,
) -> EmailAnalysisRead:
    """Analyze raw RFC 5322 message bytes without executing or retaining the message."""

    raw_message = await _read_bounded_body(request)
    try:
        analysis = analyze_email(raw_message)
    except InvalidEmailMessage as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    finding: Finding | None = None
    now = datetime.now(UTC)
    if analysis.indicators:
        severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        highest_severity = max(
            (indicator.severity for indicator in analysis.indicators),
            key=severity_order.__getitem__,
        )
        finding = Finding(
            id=str(uuid.uuid4()),
            tenant_id=member.tenant_id,
            source_type="email",
            title="Email contains suspicious indicators",
            summary=(
                f"Analysis identified {len(analysis.indicators)} suspicious indicator(s). "
                "Indicators are not confirmation of malicious activity."
            ),
            severity=highest_severity,
            confidence=0.5,
            business_impact="moderate",
            status="open",
            rule_id=analysis.indicators[0].rule_id,
            detector_version=EMAIL_RULESET_VERSION,
            evidence={
                "ruleset_version": EMAIL_RULESET_VERSION,
                "indicators": [
                    {
                        "rule_id": indicator.rule_id,
                        "description": indicator.description,
                        "evidence": indicator.evidence,
                    }
                    for indicator in analysis.indicators
                ],
                "sender_domain": analysis.sender_domain,
                "url_hosts": sorted({str(url["host"]) for url in analysis.urls}),
                "urls_truncated": analysis.urls_truncated,
            },
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        db.flush()
        db.add(
            AuditEvent(
                tenant_id=member.tenant_id,
                actor_id=member.id,
                event_type="finding.created",
                resource_type="finding",
                resource_id=finding.id,
                event_data={"source_type": "email", "severity": finding.severity},
                created_at=now,
            )
        )

    db.add(
        AuditEvent(
            tenant_id=member.tenant_id,
            actor_id=member.id,
            event_type="email.analyzed",
            resource_type="finding" if finding else None,
            resource_id=finding.id if finding else None,
            event_data={
                "ruleset_version": EMAIL_RULESET_VERSION,
                "indicator_count": len(analysis.indicators),
                "message_bytes": len(raw_message),
            },
            created_at=now,
        )
    )
    db.commit()

    return EmailAnalysisRead(
        result="suspicious_indicators" if analysis.indicators else "no_indicators",
        ruleset_version=EMAIL_RULESET_VERSION,
        sender_domain=analysis.sender_domain,
        return_path_domain=analysis.return_path_domain,
        reply_to_domain=analysis.reply_to_domain,
        urls=analysis.urls,
        urls_truncated=analysis.urls_truncated,
        authentication_results=analysis.authentication_results,
        authentication_results_source="unverified_message_header",
        indicators=[
            EmailIndicatorRead(
                rule_id=indicator.rule_id,
                description=indicator.description,
                evidence=indicator.evidence,
                severity=indicator.severity,
            )
            for indicator in analysis.indicators
        ],
        finding_id=finding.id if finding else None,
        origin_ip=analysis.origin_ip,
        origin_country=analysis.origin_country,
        origin_city=analysis.origin_city,
        origin_asn=analysis.origin_asn,
        is_vpn_tor=analysis.is_vpn_tor,
        bec_risk_score=analysis.bec_risk_score,
        urgency_score=analysis.urgency_score,
        lookalike_detected=analysis.lookalike_detected,
    )
