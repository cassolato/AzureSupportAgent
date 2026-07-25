"""CSV exports for Backup Manager grids and the compliance evidence pack.

Kept deliberately simple: one function per grid, all producing RFC-4180 CSV text with a
stable column order so a saved spreadsheet template keeps working across releases.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Iterable, Sequence

INSTANCE_COLUMNS: Sequence[tuple[str, str]] = (
    ("friendly_name", "Item"),
    ("datasource_type", "Datasource type"),
    ("datasource_id", "Datasource id"),
    ("vault_name", "Vault"),
    ("vault_kind", "Vault kind"),
    ("policy_name", "Policy"),
    ("protection_state", "Protection state"),
    ("last_backup_status", "Last backup status"),
    ("latest_recovery_point", "Latest recovery point"),
    ("recovery_point_age_hours", "Recovery point age (h)"),
    ("orphaned", "Orphaned"),
    ("subscription_id", "Subscription"),
)

JOB_COLUMNS: Sequence[tuple[str, str]] = (
    ("start_time", "Started"),
    ("entity_name", "Item"),
    ("operation", "Operation"),
    ("status", "Status"),
    ("duration_seconds", "Duration (s)"),
    ("error_code", "Error code"),
    ("failure_title", "Cause"),
    ("failure_remediation", "Remediation"),
    ("vault_name", "Vault"),
    ("subscription_id", "Subscription"),
)

POLICY_COLUMNS: Sequence[tuple[str, str]] = (
    ("name", "Policy"),
    ("vault_name", "Vault"),
    ("backup_management_type", "Management type"),
    ("schedule_summary", "Schedule"),
    ("retention_days", "Retention (days)"),
    ("in_use_count", "Protected items"),
    ("below_floor", "Below baseline"),
    ("unused", "Unused"),
)

GAP_COLUMNS: Sequence[tuple[str, str]] = (
    ("resource_name", "Resource"),
    ("display_type", "Type"),
    ("resource_id", "Resource id"),
    ("resource_group", "Resource group"),
    ("subscription_id", "Subscription"),
    ("location", "Region"),
    ("severity", "Severity"),
    ("reason", "Reason"),
)

POSTURE_COLUMNS: Sequence[tuple[str, str]] = (
    ("vault_name", "Vault"),
    ("vault_kind", "Kind"),
    ("subscription_id", "Subscription"),
    ("score", "Score"),
    ("band", "Band"),
    ("instance_count", "Protected items"),
)

DRILL_COLUMNS: Sequence[tuple[str, str]] = (
    ("name", "Drill"),
    ("kind", "Kind"),
    ("target_name", "Target"),
    ("status", "Status"),
    ("due_at", "Due"),
    ("executed_at", "Executed"),
    ("executed_by", "Executed by"),
    ("rto_minutes", "RTO (min)"),
    ("outcome_notes", "Notes"),
)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def to_csv(rows: Iterable[dict[str, Any]], columns: Sequence[tuple[str, str]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([label for _key, label in columns])
    for row in rows:
        writer.writerow([_cell(row.get(key)) for key, _label in columns])
    return buffer.getvalue()


EXPORTS = {
    "instances": INSTANCE_COLUMNS,
    "jobs": JOB_COLUMNS,
    "policies": POLICY_COLUMNS,
    "gaps": GAP_COLUMNS,
    "posture": POSTURE_COLUMNS,
    "drills": DRILL_COLUMNS,
}


def export(kind: str, rows: Iterable[dict[str, Any]]) -> str:
    columns = EXPORTS.get(kind)
    if columns is None:
        raise ValueError(f"Unknown Backup Manager export '{kind}'.")
    return to_csv(rows, columns)


def evidence_payload(
    *, estate: dict[str, Any], posture: dict[str, Any], compliance: dict[str, Any],
    rpo: dict[str, Any], drills: list[dict[str, Any]], scope: dict[str, Any],
) -> dict[str, Any]:
    """The recoverability evidence bundle handed to the Evidence Locker for hash-stamping.

    Deliberately a summary rather than a raw dump: an evidence snapshot must stay readable
    years later and must not embed anything an auditor should not see."""
    return {
        "kind": "backup_manager.recoverability",
        "generated_at": estate.get("generated_at"),
        "scope": scope,
        "estate": {
            "vaults": len(estate.get("vaults", [])),
            "protected_items": len(estate.get("instances", [])),
            "replicated_items": len(estate.get("replication", [])),
            "policies": len(estate.get("policies", [])),
        },
        "posture": {
            "average_score": posture.get("average_score"),
            "red_vaults": posture.get("red_vaults"),
            "by_check": posture.get("by_check", []),
        },
        "compliance": {
            "total": compliance.get("total"),
            "compliant": compliance.get("compliant"),
            "compliance_pct": compliance.get("compliance_pct"),
        },
        "rpo": {
            "attainment_pct": rpo.get("attainment_pct"),
            "breached": rpo.get("breached"),
            "at_risk": rpo.get("at_risk"),
        },
        "drills": [
            {
                "name": d.get("name"), "kind": d.get("kind"), "status": d.get("status"),
                "executed_at": d.get("executed_at"), "executed_by": d.get("executed_by"),
                "rto_minutes": d.get("rto_minutes"), "target_name": d.get("target_name"),
            }
            for d in drills
        ],
    }
