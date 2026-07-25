"""Backup Manager analysis: job triage, vault posture, policy hygiene, DR readiness, cost."""
from __future__ import annotations

from datetime import timedelta

from app.backup_manager import cost, demo, dr, inventory, jobs, policies, posture, reference, service


def _job(**overrides):
    base = {
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v/backupJobs/j",
        "name": "j", "operation": "Backup", "status": "Completed",
        "startTime": service.now_iso(), "endTime": service.now_iso(),
        "entityFriendlyName": "vm1", "backupManagementType": "AzureIaasVM",
    }
    base.update(overrides)
    return inventory.shape_job(base, kind="recovery_services")


def test_enrich_joins_the_failure_knowledge_base() -> None:
    rows = jobs.enrich([_job(status="Failed", errorCode="UserErrorGuestAgentStatusUnavailable")])
    row = rows[0]
    assert row["known_failure"] is True
    assert "guest agent" in row["failure_cause"].lower()
    assert row["retryable"] is True
    assert row["failure_category"] == "guest_agent"


def test_unknown_error_code_still_surfaces_actionably() -> None:
    rows = jobs.enrich([_job(status="Failed", errorCode="SomethingBrandNew")])
    assert rows[0]["known_failure"] is False
    assert rows[0]["failure_category"] == "other"
    assert rows[0]["retryable"] is False


def test_failure_clustering_groups_one_cause_into_one_row() -> None:
    rows = jobs.enrich([
        _job(name=f"j{i}", status="Failed", entityFriendlyName=f"vm{i}",
             errorCode="UserErrorVmNotInDesirableState")
        for i in range(17)
    ])
    clusters = jobs.cluster_failures(rows)
    assert len(clusters) == 1
    assert clusters[0]["job_count"] == 17
    assert clusters[0]["entity_count"] == 17
    assert clusters[0]["retryable"] is True


def test_chronic_failures_flag_items_with_no_recent_recovery_point() -> None:
    stale = service.now() - timedelta(days=9)
    instance = {
        "id": "item-1", "friendly_name": "vm-stale", "datasource_id": "d1", "datasource_type": "VM",
        "vault_id": "v", "vault_name": "v", "vault_kind": "recovery_services", "subscription_id": "s",
        "policy_name": "p", "recovery_point_age_hours": (service.now() - stale).total_seconds() / 3600,
        "latest_recovery_point": stale.isoformat(), "protection_stopped": False,
    }
    rows = jobs.chronic_failures([], [instance])
    assert len(rows) == 1
    assert rows[0]["name"] == "vm-stale"
    assert rows[0]["age_days"] and rows[0]["age_days"] > 8


def test_chronic_failures_ignore_intentionally_stopped_items() -> None:
    instance = {
        "id": "item-1", "friendly_name": "retired", "protection_stopped": True,
        "recovery_point_age_hours": 10_000, "datasource_id": "d", "datasource_type": "VM",
        "vault_id": "v", "vault_name": "v", "vault_kind": "recovery_services", "subscription_id": "s",
        "policy_name": "", "latest_recovery_point": "",
    }
    assert jobs.chronic_failures([], [instance]) == []


def test_congestion_buckets_by_hour() -> None:
    rows = jobs.enrich([_job(startTime=(service.now().replace(hour=2, minute=0)).isoformat()) for _ in range(5)])
    buckets = jobs.congestion(rows)
    assert len(buckets) == 24
    assert buckets[2]["total"] == 5


# --------------------------------------------------------------------------- posture
def _vault(**overrides):
    base = {
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v",
        "name": "v", "kind": "recovery_services", "subscription_id": "s", "resource_group": "rg",
        "location": "eastus", "soft_delete_state": "Enabled", "soft_delete_retention_days": 14,
        "immutability_state": "Locked", "mua_enabled": True, "redundancy": "GeoRedundant",
        "cross_region_restore": "Enabled", "cmk": True, "public_network_access": "Disabled",
        "private_endpoints": 1, "monitor_alerts": "Enabled", "diagnostics_enabled": True,
        "diagnostics_workspaces": ["/w"], "instance_count": 3, "policy_count": 2,
    }
    base.update(overrides)
    return base


def test_hardened_vault_scores_green() -> None:
    scored = posture.score_vault(_vault())
    assert scored["band"] == "green"
    assert scored["score"] >= 90
    assert scored["failing"] == []


def test_soft_delete_off_is_a_critical_failure() -> None:
    scored = posture.score_vault(_vault(soft_delete_state="Disabled", mua_enabled=False,
                                        immutability_state="Disabled", redundancy="LocallyRedundant",
                                        monitor_alerts="Disabled", instance_count=0))
    assert "soft_delete" in scored["failing"]
    assert scored["band"] == "red"
    # Redundancy is still actionable while the vault holds nothing.
    assert "set_redundancy" in {c["action"] for c in scored["checks"] if c["action"]}


def test_redundancy_action_is_withdrawn_once_items_exist() -> None:
    """Azure locks backup storage redundancy after the first protected item; offering the
    action anyway would guarantee a failed apply."""
    scored = posture.score_vault(_vault(redundancy="LocallyRedundant", instance_count=7))
    cell = next(c for c in scored["checks"] if c["id"] == "redundancy")
    assert cell["status"] == posture.FAIL
    assert cell["action"] == ""
    assert "locked" in cell["detail"].lower()


def test_crr_is_not_applicable_without_geo_redundancy() -> None:
    scored = posture.score_vault(_vault(redundancy="LocallyRedundant", cross_region_restore="Disabled"))
    cell = next(c for c in scored["checks"] if c["id"] == "cross_region_restore")
    assert cell["status"] == posture.NA


def test_portal_only_controls_are_reported_but_never_actionable() -> None:
    scored = posture.score_vault(_vault(immutability_state="Disabled", mua_enabled=False, cmk=False))
    portal_ids = {g["id"] for g in scored["portal_only_gaps"]}
    assert {"immutability", "mua"}.issubset(portal_ids)
    assert not any(c["id"] in portal_ids for c in scored["checks"] if c["id"] in scored["actionable"])


def test_capacity_flags_vaults_near_the_limit() -> None:
    limit = reference.limits()["rsv_protected_items_per_vault"]
    rows = posture.capacity([_vault(instance_count=int(limit * 0.95))])
    assert rows[0]["at_risk"] is True


# --------------------------------------------------------------------------- policies
def _policy(**overrides):
    base = {
        "id": "p1", "arm_id": "P1", "name": "DefaultPolicy", "vault_id": "v", "vault_name": "v",
        "vault_kind": "recovery_services", "subscription_id": "s", "resource_group": "rg",
        "backup_management_type": "AzureIaasVM", "policy_type": "V2", "workload_type": "VM",
        "protected_items_count": 0, "time_zone": "UTC", "instant_rp_days": 2,
        "schedule_summary": "Daily 02:00", "retention_days": 30,
        "schedule_raw": {"scheduleRunFrequency": "Daily", "scheduleRunTimes": ["2026-01-01T02:00:00Z"]},
        "retention_raw": {"dailySchedule": {"retentionDuration": {"count": 30, "durationType": "Days"}}},
        "datasource_types": [],
    }
    base.update(overrides)
    return base


def test_duplicate_policies_are_detected_across_vaults() -> None:
    a = _policy(id="a", vault_id="v1", vault_name="v1")
    b = _policy(id="b", vault_id="v2", vault_name="v2")
    result = policies.analyze([a, b], [])
    assert result["summary"]["duplicate_groups"] == 1
    assert result["summary"]["duplicate_policies"] == 2


def test_policy_below_retention_floor_is_flagged() -> None:
    short = _policy(id="s", retention_days=7,
                    retention_raw={"dailySchedule": {"retentionDuration": {"count": 7, "durationType": "Days"}}})
    result = policies.analyze([short], [])
    assert result["policies"][0]["below_floor"] is True
    assert result["summary"]["below_floor"] == 1


def test_compliance_scores_rpo_retention_and_offsite() -> None:
    fresh = {"id": "i1", "friendly_name": "ok", "datasource_id": "d1", "datasource_type": "VM",
             "vault_name": "v", "policy_id": "p1", "recovery_point_age_hours": 2.0,
             "protection_stopped": False, "offsite": True}
    stale = {"id": "i2", "friendly_name": "stale", "datasource_id": "d2", "datasource_type": "VM",
             "vault_name": "v", "policy_id": "p1", "recovery_point_age_hours": 200.0,
             "protection_stopped": False, "offsite": True}
    result = policies.compliance([fresh, stale], [_policy()])
    assert result["total"] == 2
    assert result["breaches"] == 1
    assert result["compliance_pct"] == 50


# --------------------------------------------------------------------------- DR
def test_dr_readiness_flags_unhealthy_and_stale_drills() -> None:
    estate = demo.build_demo_estate()
    readiness = dr.build_readiness(estate)
    assert readiness["summary"]["replicated_items"] >= 1
    assert readiness["summary"]["stale_drills"] >= 0
    for row in readiness["items"]:
        assert row["status"] in ("green", "amber", "red")


def test_drill_target_validation_blocks_unhealthy_replication() -> None:
    assert dr.validate_drill_target({"protection_state": "Protected", "replication_health": "Normal",
                                     "test_failover_state": "None", "active_location": "Primary"}) == ""
    assert "Replication health" in dr.validate_drill_target(
        {"protection_state": "Protected", "replication_health": "Critical",
         "test_failover_state": "None", "active_location": "Primary"}
    )
    assert "already in progress" in dr.validate_drill_target(
        {"protection_state": "Protected", "replication_health": "Normal",
         "test_failover_state": "InProgress", "active_location": "Primary"}
    )


def test_test_failover_body_defaults_to_an_isolated_drill() -> None:
    body = dr.build_test_failover_body()
    assert body["properties"]["networkType"] == "NoNetwork"
    assert body["properties"]["failoverDirection"] == "PrimaryToRecovery"


def test_test_failover_requires_a_network_when_one_is_requested() -> None:
    try:
        dr.build_test_failover_body(network_type="ExistingNetwork")
    except ValueError as exc:
        assert "network id is required" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected a validation error")


def test_rpo_attainment_classifies_each_item() -> None:
    instances = [
        {"id": "a", "friendly_name": "a", "datasource_id": "d1", "datasource_type": "VM",
         "vault_name": "v", "subscription_id": "s", "recovery_point_age_hours": 1.0,
         "latest_recovery_point": "x", "protection_stopped": False},
        {"id": "b", "friendly_name": "b", "datasource_id": "d2", "datasource_type": "VM",
         "vault_name": "v", "subscription_id": "s", "recovery_point_age_hours": 500.0,
         "latest_recovery_point": "x", "protection_stopped": False},
        {"id": "c", "friendly_name": "c", "datasource_id": "d3", "datasource_type": "VM",
         "vault_name": "v", "subscription_id": "s", "recovery_point_age_hours": None,
         "latest_recovery_point": "", "protection_stopped": False},
    ]
    result = dr.rpo_attainment(instances)
    assert result["met"] == 1 and result["breached"] == 1 and result["unknown"] == 1
    assert result["attainment_pct"] == 33


# --------------------------------------------------------------------------- cost
def test_cost_estimate_marks_its_own_confidence() -> None:
    estate = demo.build_demo_estate()
    assumed = cost.estimate(estate)
    assert assumed["confidence"] == "assumed"
    assert assumed["monthly_total"] > 0
    measured = cost.estimate(estate, storage_by_instance={i["id"]: 12.0 for i in estate["instances"]})
    assert measured["confidence"] == "measured"
    assert measured["storage_cost"] < assumed["storage_cost"]


def test_waste_finds_orphans_and_empty_vaults() -> None:
    estate = demo.build_demo_estate()
    result = cost.waste(estate)
    assert result["counts"]["orphaned_protection"] >= 1
    kinds = {f["kind"] for f in result["findings"]}
    assert "orphaned_protection" in kinds
    # Waste guidance must never suggest an operation Backup Manager refuses to perform.
    orphan = next(f for f in result["findings"] if f["kind"] == "orphaned_protection")
    assert "portal" in orphan["action"].lower()
