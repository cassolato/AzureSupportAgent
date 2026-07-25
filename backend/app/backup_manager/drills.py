"""Restore / failover drill register.

Backup coverage proves data is being copied; only a drill proves it can come back.  This is
the register auditors ask for: which workloads have a scheduled recovery test, when it was
last executed, by whom, what the measured RTO was, and the immutable evidence captured.

Drills are records, not automation.  The one drill Backup Manager can *execute* is a Site
Recovery test failover, which goes through the managed-change ledger like any other write;
restore drills are recorded manually because Backup Manager never performs restores.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.backup_manager import reference, service
from app.models import BackupDrill

KINDS = ("restore", "test_failover")
STATUSES = ("scheduled", "in_progress", "passed", "failed", "cancelled")
OPEN_STATUSES = ("scheduled", "in_progress")


def public_drill(drill: BackupDrill, *, now: Any = None) -> dict[str, Any]:
    reference_time = now or service.now()
    due = drill.due_at
    if due is not None and due.tzinfo is None:
        due = due.replace(tzinfo=reference_time.tzinfo)
    overdue = bool(due and drill.status in OPEN_STATUSES and due < reference_time)
    days_until_due = None
    if due:
        days_until_due = round((due - reference_time).total_seconds() / 86400.0, 1)
    return {
        "id": drill.id,
        "connection_id": drill.connection_id,
        "name": drill.name,
        "kind": drill.kind,
        "scope_kind": drill.scope_kind,
        "scope_id": drill.scope_id,
        "target_id": drill.target_id,
        "target_name": drill.target_name,
        "status": drill.status,
        "cadence_days": int(drill.cadence_days or 0),
        "due_at": drill.due_at.isoformat() if drill.due_at else "",
        "executed_at": drill.executed_at.isoformat() if drill.executed_at else "",
        "executed_by": drill.executed_by or "",
        "outcome_notes": drill.outcome_notes or "",
        "rto_minutes": drill.rto_minutes,
        "change_id": drill.change_id or "",
        "evidence_id": drill.evidence_id or "",
        "metadata": dict(drill.metadata_json or {}),
        "created_by": drill.created_by,
        "created_at": drill.created_at.isoformat() if drill.created_at else "",
        "overdue": overdue,
        "days_until_due": days_until_due,
    }


def build_drill(
    *,
    tenant_id: str,
    connection_id: str,
    name: str,
    kind: str,
    scope_kind: str = "workload",
    scope_id: str = "",
    target_id: str = "",
    target_name: str = "",
    cadence_days: int | None = None,
    created_by: str = "",
    metadata: dict[str, Any] | None = None,
) -> BackupDrill:
    if kind not in KINDS:
        raise ValueError(f"Unsupported drill kind '{kind}'.")
    cadence = int(cadence_days if cadence_days is not None else reference.sla().get("drill_stale_days", 180))
    cadence = max(0, min(cadence, 3650))
    now = service.now()
    return BackupDrill(
        tenant_id=tenant_id,
        connection_id=connection_id,
        name=str(name or "Recovery drill")[:256],
        kind=kind,
        scope_kind=str(scope_kind or "workload")[:24],
        scope_id=str(scope_id or "")[:256],
        target_id=str(target_id or "")[:1024],
        target_name=str(target_name or "")[:256],
        status="scheduled",
        cadence_days=cadence,
        due_at=now + timedelta(days=cadence) if cadence else None,
        metadata_json=dict(metadata or {}),
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )


def record_outcome(
    drill: BackupDrill,
    *,
    status: str,
    executed_by: str,
    notes: str = "",
    rto_minutes: int | None = None,
    evidence_id: str = "",
) -> BackupDrill:
    """Close out a drill and schedule the next one from its cadence."""
    if status not in ("passed", "failed", "cancelled"):
        raise ValueError("A drill outcome must be passed, failed, or cancelled.")
    now = service.now()
    drill.status = status
    drill.executed_at = now
    drill.executed_by = executed_by
    drill.outcome_notes = str(notes or "")[:4000]
    if rto_minutes is not None:
        drill.rto_minutes = max(0, min(int(rto_minutes), 100_000))
    if evidence_id:
        drill.evidence_id = evidence_id
    drill.updated_at = now
    return drill


def next_occurrence(drill: BackupDrill, *, created_by: str) -> BackupDrill | None:
    """The follow-up drill for a completed recurring drill (``None`` for one-offs)."""
    if not drill.cadence_days:
        return None
    return build_drill(
        tenant_id=drill.tenant_id,
        connection_id=drill.connection_id,
        name=drill.name,
        kind=drill.kind,
        scope_kind=drill.scope_kind,
        scope_id=drill.scope_id,
        target_id=drill.target_id,
        target_name=drill.target_name,
        cadence_days=drill.cadence_days,
        created_by=created_by,
        metadata={**dict(drill.metadata_json or {}), "previous_drill_id": drill.id},
    )


async def list_drills(
    db: AsyncSession, *, tenant_id: str, connection_id: str = "", status: str = "",
) -> list[BackupDrill]:
    query = select(BackupDrill).where(BackupDrill.tenant_id == tenant_id)
    if connection_id:
        query = query.where(BackupDrill.connection_id == connection_id)
    if status:
        query = query.where(BackupDrill.status == status)
    query = query.order_by(BackupDrill.due_at.is_(None), BackupDrill.due_at, BackupDrill.created_at.desc())
    return list((await db.execute(query)).scalars())


def summarize(drills: list[dict[str, Any]], readiness: dict[str, Any] | None = None) -> dict[str, Any]:
    """Register rollup, cross-referenced with live Site Recovery drill staleness."""
    open_drills = [d for d in drills if d["status"] in OPEN_STATUSES]
    executed = [d for d in drills if d["status"] in ("passed", "failed")]
    passed = [d for d in executed if d["status"] == "passed"]
    rtos = [d["rto_minutes"] for d in executed if isinstance(d.get("rto_minutes"), int)]
    asr_summary = (readiness or {}).get("summary", {})
    return {
        "total": len(drills),
        "open": len(open_drills),
        "overdue": sum(1 for d in open_drills if d["overdue"]),
        "executed": len(executed),
        "passed": len(passed),
        "failed": len(executed) - len(passed),
        "pass_rate_pct": round(100 * len(passed) / len(executed)) if executed else None,
        "avg_rto_minutes": round(sum(rtos) / len(rtos)) if rtos else None,
        "replicated_items_never_tested": asr_summary.get("stale_drills", 0),
        "recovery_plans_stale": asr_summary.get("recovery_plans_stale", 0),
    }
