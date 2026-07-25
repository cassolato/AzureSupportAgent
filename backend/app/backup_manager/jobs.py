"""Backup job inbox: triage, failure-code enrichment, clustering, chronic-failure detection.

The direct analogue of the Alerts Manager fired-alert inbox.  A raw list of failed backup jobs
is close to useless at fleet scale — seventeen VMs failing with one error code is one problem,
not seventeen — so this module joins each job to the editable failure knowledge base, groups
failures by root cause, and separates a transient blip from an item that has been silently
unprotected for days.
"""
from __future__ import annotations

from typing import Any

from app.backup_manager import reference, service

# Operations that actually produce a recovery point. Configure/Delete/Restore jobs are shown
# but never counted towards protection freshness.
BACKUP_OPERATIONS = ("backup", "fullbackup", "incrementalbackup", "logbackup", "differentialbackup")


def is_backup_operation(operation: str) -> bool:
    low = str(operation or "").replace(" ", "").lower()
    return any(op in low for op in BACKUP_OPERATIONS)


def enrich(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach knowledge-base cause/remediation to each job that carries an error code."""
    kb = reference.failure_index()
    out: list[dict[str, Any]] = []
    for job in jobs:
        row = dict(job)
        code = str(row.get("error_code") or "").strip()
        entry = kb.get(code.lower()) if code else None
        row["is_backup_operation"] = is_backup_operation(row.get("operation", ""))
        row["known_failure"] = bool(entry)
        row["failure_title"] = str((entry or {}).get("title") or "")
        row["failure_category"] = str((entry or {}).get("category") or ("other" if code else ""))
        row["failure_cause"] = str((entry or {}).get("cause") or "")
        row["failure_remediation"] = str((entry or {}).get("remediation") or "")
        row["failure_severity"] = str((entry or {}).get("severity") or ("error" if row.get("status_bucket") == "failed" else "info"))
        row["retryable"] = bool((entry or {}).get("auto_fix")) and row["is_backup_operation"]
        out.append(row)
    return out


def summarize(jobs: list[dict[str, Any]], *, window_hours: int = 24) -> dict[str, Any]:
    """Counts for the overview scorecard, restricted to a trailing window."""
    recent = [j for j in jobs if (j.get("age_hours") is None or j["age_hours"] <= window_hours)]
    buckets = {"succeeded": 0, "failed": 0, "running": 0, "unknown": 0}
    for job in recent:
        buckets[job.get("status_bucket", "unknown")] = buckets.get(job.get("status_bucket", "unknown"), 0) + 1
    total = sum(buckets.values())
    completed = buckets["succeeded"] + buckets["failed"]
    return {
        "window_hours": window_hours,
        "total": total,
        **buckets,
        "success_rate_pct": round(100 * buckets["succeeded"] / completed) if completed else None,
    }


def cluster_failures(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group failed jobs by error code so one root cause is one row, not N rows."""
    kb = reference.failure_index()
    clusters: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if job.get("status_bucket") != "failed":
            continue
        code = str(job.get("error_code") or "").strip() or "UnknownError"
        cluster = clusters.setdefault(code, {
            "error_code": code,
            "title": str((kb.get(code.lower()) or {}).get("title") or "Unclassified backup failure"),
            "category": str((kb.get(code.lower()) or {}).get("category") or "other"),
            "severity": str((kb.get(code.lower()) or {}).get("severity") or "error"),
            "cause": str((kb.get(code.lower()) or {}).get("cause") or ""),
            "remediation": str((kb.get(code.lower()) or {}).get("remediation") or ""),
            "known": code.lower() in kb,
            "retryable": bool((kb.get(code.lower()) or {}).get("auto_fix")),
            "job_count": 0,
            "entities": [],
            "subscriptions": set(),
            "vaults": set(),
            "sample_message": "",
            "latest_at": "",
        })
        cluster["job_count"] += 1
        entity = str(job.get("entity_name") or "")
        if entity and entity not in cluster["entities"]:
            cluster["entities"].append(entity)
        if job.get("subscription_id"):
            cluster["subscriptions"].add(job["subscription_id"])
        if job.get("vault_name"):
            cluster["vaults"].add(job["vault_name"])
        if not cluster["sample_message"] and job.get("error_message"):
            cluster["sample_message"] = job["error_message"]
        stamp = job.get("start_time") or ""
        if stamp > cluster["latest_at"]:
            cluster["latest_at"] = stamp

    out: list[dict[str, Any]] = []
    for cluster in clusters.values():
        cluster["entity_count"] = len(cluster["entities"])
        cluster["entities"] = cluster["entities"][:25]
        cluster["subscription_count"] = len(cluster["subscriptions"])
        cluster["vault_count"] = len(cluster["vaults"])
        cluster.pop("subscriptions", None)
        cluster.pop("vaults", None)
        out.append(cluster)
    severity_rank = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    out.sort(key=lambda c: (-c["job_count"], severity_rank.get(c["severity"], 3), c["error_code"]))
    return out


def chronic_failures(
    jobs: list[dict[str, Any]], instances: list[dict[str, Any]], *, days: int | None = None,
) -> list[dict[str, Any]]:
    """Protected items with no successful backup for ``days`` — the quietly unprotected set.

    Uses the item's own latest recovery point where Azure reports one (authoritative and not
    limited by the Resource Graph job window) and falls back to job history otherwise."""
    threshold_days = days if days is not None else int(reference.sla().get("chronic_failure_days", 3))
    threshold_hours = max(1, threshold_days) * 24

    last_success: dict[str, str] = {}
    last_failure: dict[str, dict[str, Any]] = {}
    for job in jobs:
        if not is_backup_operation(job.get("operation", "")):
            continue
        key = (job.get("entity_name") or "").lower()
        if not key:
            continue
        stamp = job.get("end_time") or job.get("start_time") or ""
        if job.get("status_bucket") == "succeeded":
            if stamp > last_success.get(key, ""):
                last_success[key] = stamp
        elif job.get("status_bucket") == "failed":
            current = last_failure.get(key)
            if not current or stamp > (current.get("start_time") or ""):
                last_failure[key] = job

    out: list[dict[str, Any]] = []
    for instance in instances:
        if instance.get("protection_stopped"):
            continue
        key = (instance.get("friendly_name") or "").lower()
        age = instance.get("recovery_point_age_hours")
        if age is None:
            success_stamp = last_success.get(key, "")
            age = service.age_hours(success_stamp) if success_stamp else None
        if age is None:
            # No recovery point and no successful job in the visible window: this item has
            # never demonstrably produced a restore point, which is worse, not unknown.
            failure = last_failure.get(key)
            if not failure:
                continue
            out.append(_chronic_row(instance, None, failure))
            continue
        if age > threshold_hours:
            out.append(_chronic_row(instance, age, last_failure.get(key)))
    out.sort(key=lambda r: (-(r["age_hours"] or 10**6), r["name"]))
    return out


def _chronic_row(instance: dict[str, Any], age: float | None, failure: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "instance_id": instance.get("id", ""),
        "name": instance.get("friendly_name", ""),
        "datasource_id": instance.get("datasource_id", ""),
        "datasource_type": instance.get("datasource_type", ""),
        "vault_id": instance.get("vault_id", ""),
        "vault_name": instance.get("vault_name", ""),
        "vault_kind": instance.get("vault_kind", ""),
        "subscription_id": instance.get("subscription_id", ""),
        "policy_name": instance.get("policy_name", ""),
        "age_hours": age,
        "age_days": round(age / 24.0, 1) if age is not None else None,
        "latest_recovery_point": instance.get("latest_recovery_point", ""),
        "error_code": str((failure or {}).get("error_code") or instance.get("last_error_code") or ""),
        "error_message": str((failure or {}).get("error_message") or instance.get("last_error_message") or ""),
        "severity": "critical" if age is None or age > threshold_critical() else "error",
    }


def threshold_critical() -> float:
    """Hours after which a missing recovery point is treated as critical rather than an error."""
    return max(24.0, float(reference.sla().get("chronic_failure_days", 3)) * 24.0 * 2)


def congestion(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Job starts bucketed by UTC hour — surfaces the 02:00 thundering herd that stretches the
    backup window and pushes jobs past their SLA."""
    buckets: dict[int, dict[str, Any]] = {h: {"hour": h, "total": 0, "failed": 0, "avg_duration_s": 0.0} for h in range(24)}
    durations: dict[int, list[float]] = {h: [] for h in range(24)}
    for job in jobs:
        started = service.parse_iso(job.get("start_time"))
        if not started:
            continue
        bucket = buckets[started.hour]
        bucket["total"] += 1
        if job.get("status_bucket") == "failed":
            bucket["failed"] += 1
        if isinstance(job.get("duration_seconds"), (int, float)):
            durations[started.hour].append(float(job["duration_seconds"]))
    for hour, values in durations.items():
        if values:
            buckets[hour]["avg_duration_s"] = round(sum(values) / len(values), 1)
    return [buckets[h] for h in range(24)]
