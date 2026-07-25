"""Backup policy library: sprawl, drift, compliance floors, and retention-change impact.

Two things go wrong with backup policies at scale.  First, sprawl: every vault ends up with
its own near-identical "DefaultPolicy" copy, so a retention decision has to be re-made N
times.  Second, silent non-compliance: a policy quietly retains 7 days while the workload's
tier demands 30, and nobody notices until a restore is requested.

The retention-impact simulator answers the question the Azure portal does not: *if I shorten
this policy, exactly which recovery points disappear?*  Where possible it enumerates real
recovery points from ARM (bounded); otherwise it derives the count from schedule x retention
and says so, rather than presenting an estimate as fact.
"""
from __future__ import annotations

import json
from typing import Any

from app.backup_manager import reference, service

# Recovery point enumeration is a per-item ARM call, so exact impact is capped. Beyond this
# the simulator reports a derived estimate and flags it.
MAX_EXACT_ITEMS = 25
RECOVERY_POINT_API = "2024-04-01"


def _fingerprint(policy: dict[str, Any]) -> str:
    """Structural identity of a policy — two policies with the same fingerprint are duplicates
    regardless of name or which vault they live in."""
    return service.canonical_hash({
        "kind": policy.get("vault_kind"),
        "management": (policy.get("backup_management_type") or "").lower(),
        "workload": (policy.get("workload_type") or "").lower(),
        "schedule": policy.get("schedule_raw") or policy.get("schedule_summary"),
        "retention": policy.get("retention_raw"),
        "instant_rp": policy.get("instant_rp_days"),
    })


def analyze(policies: list[dict[str, Any]], instances: list[dict[str, Any]]) -> dict[str, Any]:
    """Annotate policies with usage, duplicates, and compliance, and roll up the findings."""
    tiers = reference.tier_index()
    default_tier = reference.tier_for(None)
    floor_days = int(default_tier.get("retention_days") or 30)

    usage: dict[str, list[dict[str, Any]]] = {}
    for instance in instances:
        pid = instance.get("policy_id") or ""
        if pid:
            usage.setdefault(pid, []).append(instance)

    groups: dict[str, list[dict[str, Any]]] = {}
    rows: list[dict[str, Any]] = []
    for policy in policies:
        row = dict(policy)
        members = usage.get(row["id"], [])
        row["in_use_count"] = len(members) or int(row.get("protected_items_count") or 0)
        row["fingerprint"] = _fingerprint(row)
        retention = row.get("retention_days")
        row["below_floor"] = bool(retention is not None and retention < floor_days)
        row["retention_floor_days"] = floor_days
        row["unused"] = row["in_use_count"] == 0
        row["schedule_summary"] = row.get("schedule_summary") or ""
        # Raw schedule/retention are only needed by the editor, not the grid.
        row["schedule_raw"] = row.get("schedule_raw")
        row["retention_raw"] = row.get("retention_raw")
        groups.setdefault(row["fingerprint"], []).append(row)
        rows.append(row)

    duplicates: list[dict[str, Any]] = []
    for fingerprint, members in groups.items():
        if len(members) < 2:
            for member in members:
                member["duplicate_of"] = []
            continue
        names = sorted({m["name"] for m in members})
        vaults = sorted({m["vault_name"] for m in members})
        for member in members:
            member["duplicate_of"] = [m["id"] for m in members if m["id"] != member["id"]]
        duplicates.append({
            "fingerprint": fingerprint,
            "policy_count": len(members),
            "vault_count": len(vaults),
            "names": names[:20],
            "vaults": vaults[:20],
            "protected_items": sum(m["in_use_count"] for m in members),
            "retention_days": members[0].get("retention_days"),
            "schedule_summary": members[0].get("schedule_summary", ""),
            "backup_management_type": members[0].get("backup_management_type", ""),
        })
    duplicates.sort(key=lambda d: (-d["policy_count"], -d["protected_items"]))

    rows.sort(key=lambda p: (p.get("vault_name", ""), p.get("name", "").lower()))
    return {
        "policies": rows,
        "duplicate_groups": duplicates,
        "summary": {
            "total": len(rows),
            "unused": sum(1 for p in rows if p["unused"]),
            "below_floor": sum(1 for p in rows if p["below_floor"]),
            "duplicate_groups": len(duplicates),
            "duplicate_policies": sum(d["policy_count"] for d in duplicates),
            "retention_floor_days": floor_days,
            "tiers": list(tiers.values()),
        },
    }


def _schedule_points_per_day(policy: dict[str, Any]) -> float:
    """How many recovery points a policy's schedule produces per day."""
    schedule = policy.get("schedule_raw")
    if isinstance(schedule, dict):
        hourly = schedule.get("hourlySchedule") or {}
        if isinstance(hourly, dict) and hourly.get("interval"):
            try:
                interval = max(1, int(hourly["interval"]))
                window = int(hourly.get("scheduleWindowDuration") or 24)
                return max(1.0, window / interval)
            except (TypeError, ValueError):
                return 1.0
        frequency = str(schedule.get("scheduleRunFrequency") or "").lower()
        if frequency == "weekly":
            days = schedule.get("scheduleRunDays") or []
            return (len(days) or 1) / 7.0
        times = schedule.get("scheduleRunTimes") or []
        return float(len(times) or 1)
    summary = str(policy.get("schedule_summary") or "").lower()
    if summary.startswith("hourly"):
        return 24.0
    if summary.startswith("weekly"):
        return 1 / 7.0
    return 1.0


def _prune_window(current_days: int, proposed_days: int, points_per_day: float) -> int:
    return max(0, int(round((current_days - proposed_days) * points_per_day)))


async def retention_impact(
    connection: dict[str, Any],
    policy: dict[str, Any],
    instances: list[dict[str, Any]],
    *,
    proposed_retention_days: int,
    exact: bool = True,
) -> dict[str, Any]:
    """What a retention change would destroy, before anyone approves it.

    Returns per-instance impact plus a total.  ``exact`` enumerates real recovery points for
    up to :data:`MAX_EXACT_ITEMS` Recovery Services items; anything beyond that (and every
    Backup vault instance, which does not expose an equivalent list) is derived from the
    schedule and clearly marked ``estimated``.
    """
    current = policy.get("retention_days")
    try:
        current_days = int(current) if current is not None else 0
    except (TypeError, ValueError):
        current_days = 0
    proposed = max(1, int(proposed_retention_days))
    members = [i for i in instances if i.get("policy_id") == policy.get("id")]
    points_per_day = _schedule_points_per_day(policy)

    direction = "increase" if proposed > current_days else ("decrease" if proposed < current_days else "none")
    per_instance: list[dict[str, Any]] = []
    exact_used = 0
    token = ""
    if exact and direction == "decrease" and members:
        try:
            token = await service.token_for(connection)
        except (ValueError, KeyError) as exc:  # noqa: BLE001 - degrade to estimate
            token = ""
            policy.setdefault("_impact_note", service.safe_error(str(exc)))

    async def enumerate_points(instance: dict[str, Any]) -> dict[str, Any]:
        cutoff = service.now().timestamp() - proposed * 86400
        keep_cutoff = service.now().timestamp() - current_days * 86400
        body, _status, error = await service.arm_get_with(
            token, f"{instance['id']}/recoveryPoints", RECOVERY_POINT_API,
        )
        if error or not body:
            return {"estimated": True, "error": error}
        pruned = 0
        total = 0
        oldest_kept = ""
        for entry in service.as_list(body.get("value")):
            props = service.as_dict(service.as_dict(entry).get("properties"))
            stamp = str(props.get("recoveryPointTime") or "")
            parsed = service.parse_iso(stamp)
            if not parsed:
                continue
            total += 1
            if parsed.timestamp() < cutoff and parsed.timestamp() >= keep_cutoff - 86400:
                pruned += 1
            elif parsed.timestamp() < cutoff:
                pruned += 1
            elif not oldest_kept or stamp < oldest_kept:
                oldest_kept = stamp
        return {"estimated": False, "total": total, "pruned": pruned, "oldest_kept": oldest_kept}

    exact_targets = members[:MAX_EXACT_ITEMS] if token else []
    exact_results: dict[str, dict[str, Any]] = {}
    if exact_targets:
        eligible = [i for i in exact_targets if i.get("vault_kind") == "recovery_services"]
        results = await service.bounded_gather(
            [lambda i=i: enumerate_points(i) for i in eligible], limit=6,
        )
        for instance, result in zip(eligible, service.unwrap(results, {"estimated": True})):
            exact_results[instance["id"]] = result if isinstance(result, dict) else {"estimated": True}

    derived_per_item = _prune_window(current_days, proposed, points_per_day)
    total_pruned = 0
    for instance in members:
        result = exact_results.get(instance["id"])
        if result and not result.get("estimated"):
            pruned = int(result.get("pruned") or 0)
            exact_used += 1
            estimated = False
        else:
            pruned = derived_per_item if direction == "decrease" else 0
            estimated = True
        total_pruned += pruned
        per_instance.append({
            "instance_id": instance["id"],
            "name": instance.get("friendly_name", ""),
            "datasource_type": instance.get("datasource_type", ""),
            "vault_name": instance.get("vault_name", ""),
            "recovery_points_removed": pruned,
            "estimated": estimated,
            "oldest_retained": (result or {}).get("oldest_kept", ""),
        })

    per_instance.sort(key=lambda r: -r["recovery_points_removed"])
    return {
        "policy_id": policy.get("id", ""),
        "policy_name": policy.get("name", ""),
        "vault_name": policy.get("vault_name", ""),
        "direction": direction,
        "current_retention_days": current_days,
        "proposed_retention_days": proposed,
        "protected_item_count": len(members),
        "points_per_day": round(points_per_day, 2),
        "recovery_points_removed": total_pruned,
        "exact_items": exact_used,
        "estimated_items": len(members) - exact_used,
        "fully_exact": exact_used == len(members) and len(members) > 0,
        "irreversible": direction == "decrease" and total_pruned > 0,
        "per_instance": per_instance[:200],
        "note": (
            "Recovery points removed by a retention decrease cannot be recovered."
            if direction == "decrease"
            else "Increasing retention only affects future pruning; existing points are unaffected."
        ),
    }


def compliance(
    instances: list[dict[str, Any]], policies: list[dict[str, Any]], *, tier_by_datasource: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Score each protected item against its workload tier's RPO and retention floor."""
    tier_map = tier_by_datasource or {}
    policy_index = {p["id"]: p for p in policies}
    rows: list[dict[str, Any]] = []
    breaches = 0
    for instance in instances:
        tier = reference.tier_for(tier_map.get(instance.get("datasource_id", "")))
        policy = policy_index.get(instance.get("policy_id", ""))
        retention = (policy or {}).get("retention_days")
        rpo_hours = int(tier.get("rpo_hours") or 24)
        age = instance.get("recovery_point_age_hours")
        rpo_ok = age is not None and age <= rpo_hours
        retention_ok = retention is None or retention >= int(tier.get("retention_days") or 30)
        offsite_ok = (not tier.get("require_offsite")) or bool(instance.get("offsite"))
        compliant = bool(rpo_ok and retention_ok and offsite_ok and not instance.get("protection_stopped"))
        if not compliant:
            breaches += 1
        rows.append({
            "instance_id": instance.get("id", ""),
            "name": instance.get("friendly_name", ""),
            "datasource_id": instance.get("datasource_id", ""),
            "datasource_type": instance.get("datasource_type", ""),
            "vault_name": instance.get("vault_name", ""),
            "tier": tier.get("id"),
            "tier_label": tier.get("label"),
            "rpo_target_hours": rpo_hours,
            "recovery_point_age_hours": age,
            "rpo_ok": rpo_ok,
            "retention_days": retention,
            "retention_target_days": tier.get("retention_days"),
            "retention_ok": retention_ok,
            "offsite_required": bool(tier.get("require_offsite")),
            "offsite_ok": offsite_ok,
            "compliant": compliant,
        })
    total = len(rows)
    rows.sort(key=lambda r: (r["compliant"], -(r["recovery_point_age_hours"] or 0)))
    return {
        "rows": rows,
        "total": total,
        "compliant": total - breaches,
        "breaches": breaches,
        "compliance_pct": round(100 * (total - breaches) / total) if total else 100,
    }


def policy_body_summary(policy: dict[str, Any]) -> str:
    """One-line human summary used in change-request summaries and audit records."""
    parts = [policy.get("schedule_summary") or "Scheduled"]
    if policy.get("retention_days"):
        parts.append(f"{policy['retention_days']}d retention")
    if policy.get("instant_rp_days"):
        parts.append(f"{policy['instant_rp_days']}d instant restore")
    return " · ".join(str(p) for p in parts if p)


def dumps(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"), default=str)
