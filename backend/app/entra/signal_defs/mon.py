"""Monitoring and hybrid pillar.

Small in P1/P2 — the log-export checks need ARM diagnostic settings, which arrive with the
later phase. What is measurable today is directory synchronisation health, which is
collected as part of the tenant profile.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.entra import model
from app.entra.signals import IMPACT_BINARY, SignalContext, SignalSpec, SignalUnavailable, domain

SYNC_DOC = "https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sync-staging-server"

# Entra Connect syncs every 30 minutes by default; 3 hours is a clear failure, not a blip.
_STALE_SYNC_HOURS = 3


def _hybrid_sync_stale(data: dict[str, Any], ctx: SignalContext) -> list[dict[str, Any]]:
    tenant = domain(data, "tenant")
    hybrid = tenant.get("hybrid") or {}
    if not tenant:
        raise SignalUnavailable("The tenant profile was not collected.")
    if not hybrid.get("sync_enabled"):
        return []           # cloud-only tenant: nothing to synchronise
    last = str(hybrid.get("last_sync") or "")
    if not last:
        return [model.finding(
            signal_id="mon.hybrid_sync_stale", severity="high", pillar="mon",
            object_kind="tenant", object_id=ctx.tenant_id or "tenant", object_name="Tenant",
            title="Directory synchronisation is enabled but has never reported a sync",
            detail="On-premises changes — including disabling a departing employee — are not "
                   "reaching Entra ID.",
            evidence={"sync_enabled": True, "last_sync": ""},
            discriminator="never",
        )]
    days = ctx.days_since(last)
    if days is None:
        return []
    # days_since is too coarse for a 3-hour threshold — recompute in hours.
    parsed = datetime.fromisoformat(last.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    hours = (ctx.now - parsed).total_seconds() / 3600
    if hours < _STALE_SYNC_HOURS:
        return []
    return [model.finding(
        signal_id="mon.hybrid_sync_stale", severity="high", pillar="mon",
        object_kind="tenant", object_id=ctx.tenant_id or "tenant", object_name="Tenant",
        title=f"Directory synchronisation last ran {hours:.1f} hours ago",
        detail="Entra Connect normally syncs every 30 minutes. A long gap means on-premises "
               "changes — including offboarding — are not reaching the cloud directory.",
        evidence={"last_sync": last, "hours_since": round(hours, 1), "threshold_hours": _STALE_SYNC_HOURS},
        discriminator="stale",
    )]


SPECS: list[SignalSpec] = [
    SignalSpec(
        id="mon.hybrid_sync_stale", title="Directory synchronisation is stale",
        question="Are on-premises changes still reaching Entra ID?",
        why="If sync has stopped, a user disabled on-premises stays enabled in the cloud — the "
            "offboarding you think happened did not.",
        pillar="mon", severity="high", weight=8, object_kind="tenant",
        domains=("tenant",), requires=("Organization.Read.All",), impact=IMPACT_BINARY,
        remediation="Check Entra Connect Health on the sync server and resolve the failing sync cycle.",
        remediation_steps=(
            "Open Entra Connect Health and review the sync service status.",
            "On the sync server, run Start-ADSyncSyncCycle -PolicyType Delta.",
            "Investigate any export errors reported by the sync engine.",
        ),
        doc_link=SYNC_DOC, evaluate=_hybrid_sync_stale,
    ),
]
