"""Disaster-recovery readiness: Site Recovery health, RPO attainment, and drill orchestration.

Site Recovery is first-class here rather than a separate module because the question an
operator actually asks — *can we recover this workload, and when did we last prove it?* — spans
both backup recovery points and replication state.

Test failover and its cleanup are the only DR mutations Backup Manager performs.  They are
approval-gated, high risk, and constrained to an explicitly chosen recovery network; a real
(unplanned or planned) failover is never offered.
"""
from __future__ import annotations

from typing import Any

from app.backup_manager import reference, service

# Replication states that mean the item is genuinely protected right now.
HEALTHY_STATES = {"protected", "replicationinprogress"}
TEST_FAILOVER_ACTIVE = {"inprogress", "waitingforcompletion", "testfailover"}


def _token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "").replace("_", "")


def build_readiness(estate: dict[str, Any]) -> dict[str, Any]:
    """Roll up replicated items and recovery plans into a DR scorecard."""
    sla = reference.sla()
    stale_days = int(sla.get("drill_stale_days", 180))
    items = estate.get("replication", []) or []
    plans = estate.get("recovery_plans", []) or []

    rows: list[dict[str, Any]] = []
    for item in items:
        health = _token(item.get("replication_health"))
        state = _token(item.get("protection_state"))
        rpo = item.get("rpo_seconds")
        drill_age = item.get("last_test_failover_age_days")
        stale_drill = drill_age is None or drill_age > stale_days
        issues: list[str] = []
        if health not in ("normal", "healthy"):
            issues.append(f"Replication health is {item.get('replication_health') or 'unknown'}.")
        if state not in HEALTHY_STATES:
            issues.append(f"Protection state is {item.get('protection_state') or 'unknown'}.")
        if stale_drill:
            issues.append(
                "No successful test failover on record."
                if drill_age is None else f"Last test failover was {int(drill_age)} days ago."
            )
        if isinstance(rpo, (int, float)) and rpo > 900:
            issues.append(f"RPO is {int(rpo // 60)} minutes.")
        status = "red" if (health not in ("normal", "healthy") or state not in HEALTHY_STATES) else ("amber" if issues else "green")
        rows.append({
            **item,
            "status": status,
            "stale_drill": stale_drill,
            "drill_stale_days": stale_days,
            "issues": issues,
            "test_failover_active": _token(item.get("test_failover_state")) in TEST_FAILOVER_ACTIVE,
        })

    rows.sort(key=lambda r: ({"red": 0, "amber": 1, "green": 2}.get(r["status"], 3), r.get("friendly_name", "")))
    total = len(rows)
    plan_rows = [
        {
            **plan,
            "stale_drill": plan.get("last_test_failover_age_days") is None
            or plan["last_test_failover_age_days"] > stale_days,
            "drill_stale_days": stale_days,
        }
        for plan in plans
    ]
    return {
        "items": rows,
        "recovery_plans": sorted(plan_rows, key=lambda p: p.get("friendly_name", "")),
        "summary": {
            "replicated_items": total,
            "healthy": sum(1 for r in rows if r["status"] == "green"),
            "degraded": sum(1 for r in rows if r["status"] == "amber"),
            "unhealthy": sum(1 for r in rows if r["status"] == "red"),
            "stale_drills": sum(1 for r in rows if r["stale_drill"]),
            "recovery_plans": len(plan_rows),
            "recovery_plans_stale": sum(1 for p in plan_rows if p["stale_drill"]),
            "drill_stale_days": stale_days,
            "health_pct": round(100 * sum(1 for r in rows if r["status"] == "green") / total) if total else 100,
        },
    }


def rpo_attainment(instances: list[dict[str, Any]], *, tier_by_datasource: dict[str, str] | None = None) -> dict[str, Any]:
    """Backup-side RPO: how fresh is the newest recovery point versus the tier objective."""
    tier_map = tier_by_datasource or {}
    rows: list[dict[str, Any]] = []
    for instance in instances:
        if instance.get("protection_stopped"):
            continue
        tier = reference.tier_for(tier_map.get(instance.get("datasource_id", "")))
        target = int(tier.get("rpo_hours") or 24)
        age = instance.get("recovery_point_age_hours")
        if age is None:
            status = "unknown"
        elif age <= target:
            status = "met"
        elif age <= target * 2:
            status = "at_risk"
        else:
            status = "breached"
        rows.append({
            "instance_id": instance.get("id", ""),
            "name": instance.get("friendly_name", ""),
            "datasource_id": instance.get("datasource_id", ""),
            "datasource_type": instance.get("datasource_type", ""),
            "vault_name": instance.get("vault_name", ""),
            "subscription_id": instance.get("subscription_id", ""),
            "tier": tier.get("id"),
            "rpo_target_hours": target,
            "recovery_point_age_hours": round(age, 1) if isinstance(age, (int, float)) else None,
            "latest_recovery_point": instance.get("latest_recovery_point", ""),
            "recovery_point_source": instance.get("recovery_point_source", ""),
            "status": status,
        })
    rows.sort(key=lambda r: ({"breached": 0, "at_risk": 1, "unknown": 2, "met": 3}.get(r["status"], 4), -(r["recovery_point_age_hours"] or 0)))
    total = len(rows)
    met = sum(1 for r in rows if r["status"] == "met")
    return {
        "rows": rows,
        "total": total,
        "met": met,
        "at_risk": sum(1 for r in rows if r["status"] == "at_risk"),
        "breached": sum(1 for r in rows if r["status"] == "breached"),
        "unknown": sum(1 for r in rows if r["status"] == "unknown"),
        "attainment_pct": round(100 * met / total) if total else 100,
    }


# --------------------------------------------------------------------------- drill bodies
NETWORK_MODES = {"NoNetwork", "ExistingNetwork", "NewNetwork", "VmNetworkAsInput"}


def build_test_failover_body(
    *, direction: str = "PrimaryToRecovery", network_type: str = "NoNetwork",
    network_id: str = "", recovery_point_id: str = "", instance_type: str = "A2A",
) -> dict[str, Any]:
    """Test-failover body. Defaults to an isolated (no-network) drill, which is the only
    variant that cannot disturb production connectivity."""
    if network_type not in NETWORK_MODES:
        raise ValueError(f"Unsupported network type '{network_type}'.")
    if network_type != "NoNetwork" and not network_id:
        raise ValueError("A recovery network id is required unless the drill runs with no network.")
    provider: dict[str, Any] = {"instanceType": instance_type}
    if recovery_point_id:
        provider["recoveryPointId"] = recovery_point_id
    properties: dict[str, Any] = {
        "failoverDirection": direction,
        "networkType": network_type,
        "providerSpecificDetails": provider,
    }
    if network_id:
        properties["networkId"] = network_id
    return {"properties": properties}


def build_cleanup_body(comments: str = "Automated drill cleanup requested from Backup Manager.") -> dict[str, Any]:
    return {"properties": {"comments": str(comments or "")[:500]}}


def test_failover_path(replicated_item_id: str) -> str:
    return f"{replicated_item_id.rstrip('/')}/testFailover"


def cleanup_path(replicated_item_id: str) -> str:
    return f"{replicated_item_id.rstrip('/')}/testFailoverCleanup"


def recovery_plan_test_failover_path(recovery_plan_id: str) -> str:
    return f"{recovery_plan_id.rstrip('/')}/testFailover"


def recovery_plan_cleanup_path(recovery_plan_id: str) -> str:
    return f"{recovery_plan_id.rstrip('/')}/testFailoverCleanup"


def validate_drill_target(item: dict[str, Any]) -> str:
    """Reasons a drill must not be started right now (empty string means it may proceed)."""
    if _token(item.get("test_failover_state")) in TEST_FAILOVER_ACTIVE:
        return "A test failover is already in progress for this item; clean it up before starting another."
    if _token(item.get("protection_state")) not in HEALTHY_STATES:
        return f"Protection state is '{item.get('protection_state') or 'unknown'}' — replication must be healthy before a drill."
    if _token(item.get("replication_health")) not in ("normal", "healthy"):
        return f"Replication health is '{item.get('replication_health') or 'unknown'}' — resolve health errors before a drill."
    if _token(item.get("active_location")) == "recovery":
        return "The item is currently running in the recovery region; a test failover is not valid."
    return ""


async def list_recovery_points(connection: dict[str, Any], replicated_item_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """Recent Site Recovery recovery points for a replicated item (drill point picker)."""
    body, _status, error = await service.arm_get_with(
        await service.token_for(connection), f"{replicated_item_id.rstrip('/')}/recoveryPoints", service.ASR_API,
    )
    if error or not body:
        return []
    out: list[dict[str, Any]] = []
    for entry in service.as_list(body.get("value"))[: max(1, limit)]:
        props = service.as_dict(service.as_dict(entry).get("properties"))
        out.append({
            "id": str(service.as_dict(entry).get("id") or ""),
            "name": str(service.as_dict(entry).get("name") or ""),
            "recovery_point_time": str(props.get("recoveryPointTime") or ""),
            "recovery_point_type": str(props.get("recoveryPointType") or ""),
        })
    out.sort(key=lambda r: r["recovery_point_time"], reverse=True)
    return out
