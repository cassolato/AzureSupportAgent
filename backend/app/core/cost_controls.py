"""Shared, database-backed limits for expensive AI and live-analysis requests."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import load_settings
from app.models import AuditLog, Usage

_EXPENSIVE = (
    re.compile(r"^/api/chats/[^/]+/messages/stream$"),
    re.compile(r"^/api/chats/deep-reviews/fleet$"),
    re.compile(r"^/api/admin/llm/(test|models)/stream$"),
    re.compile(r"^/api/architectures/.+/(generate|suggest)(/stream)?$"),
    re.compile(r"^/api/assessments/(run|enqueue|custom-checks/generate)$"),
    re.compile(r"^/api/changeexplorer/(analyze/stream|runs/[^/]+/ai-enrich/stream)$"),
    re.compile(r"^/api/(dnsdebug|netcheck)/run/stream$"),
    re.compile(r"^/api/fmea/.*/?generate/stream$"),
    re.compile(r"^/api/graph/build/stream$"),
    re.compile(r"^/api/identity/app-registrations/refresh/stream$"),
    re.compile(r"^/api/missions/(run|fleet)$"),
    re.compile(r"^/api/(performance|telemetry)/refresh/stream$"),
    re.compile(r"^/api/policy/simulate/stream$"),
    re.compile(r"^/api/quota/scan/stream$"),
    re.compile(r"^/api/rbac/refresh/stream$"),
    re.compile(r"^/api/workloads/autopilot/(trace|discover)$"),
)


def is_expensive_request(method: str, path: str) -> bool:
    return method.upper() in {"GET", "POST", "PUT", "PATCH"} and any(p.match(path) for p in _EXPENSIVE)


async def enforce_cost_controls(
    request: Request,
    db: AsyncSession,
    *,
    tenant_id: str,
    user_id: str,
) -> None:
    """Reject excessive request volume/token spend and record the admitted request.

    State lives in the application database, so limits are shared by all workers and
    replicas. The insert occurs before work begins, making failed/cancelled launches count
    against burst limits as they still consume server capacity.
    """
    if not is_expensive_request(request.method, request.url.path):
        return
    if getattr(request.state, "cost_control_checked", False):
        return
    request.state.cost_control_checked = True

    cfg = load_settings()
    user_hourly = max(0, int(cfg.get("expensive_requests_per_user_hour", 60)))
    tenant_hourly = max(0, int(cfg.get("expensive_requests_per_tenant_hour", 600)))
    user_monthly_tokens = max(0, int(cfg.get("monthly_tokens_per_user", 5_000_000)))
    tenant_monthly_tokens = max(0, int(cfg.get("monthly_tokens_per_tenant", 50_000_000)))
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    month_ago = now - timedelta(days=30)

    base_requests = (
        AuditLog.action == "security.expensive_request",
        AuditLog.created_at >= hour_ago,
    )
    if user_hourly:
        count = await db.scalar(
            select(func.count(AuditLog.id)).where(*base_requests, AuditLog.actor_id == user_id)
        )
        if int(count or 0) >= user_hourly:
            raise HTTPException(
                status_code=429,
                detail="Hourly expensive-operation limit reached. Try again later.",
                headers={"Retry-After": "3600"},
            )
    if tenant_hourly:
        count = await db.scalar(
            select(func.count(AuditLog.id)).where(*base_requests, AuditLog.tenant_id == tenant_id)
        )
        if int(count or 0) >= tenant_hourly:
            raise HTTPException(
                status_code=429,
                detail="Tenant hourly expensive-operation limit reached. Try again later.",
                headers={"Retry-After": "3600"},
            )

    token_expr = func.coalesce(func.sum(Usage.prompt_tokens + Usage.completion_tokens), 0)
    if user_monthly_tokens:
        used = await db.scalar(
            select(token_expr).where(Usage.user_id == user_id, Usage.created_at >= month_ago)
        )
        if int(used or 0) >= user_monthly_tokens:
            raise HTTPException(status_code=429, detail="Monthly AI token budget reached.")
    if tenant_monthly_tokens:
        used = await db.scalar(
            select(token_expr).where(Usage.tenant_id == tenant_id, Usage.created_at >= month_ago)
        )
        if int(used or 0) >= tenant_monthly_tokens:
            raise HTTPException(status_code=429, detail="Tenant monthly AI token budget reached.")

    db.add(
        AuditLog(
            tenant_id=tenant_id,
            actor_id=user_id,
            action="security.expensive_request",
            target=request.url.path[:512],
            metadata_json={"method": request.method},
        )
    )
    await db.commit()