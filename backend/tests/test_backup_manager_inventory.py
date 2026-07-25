"""Backup Manager collection: row shaping, estate assembly, orphan detection, demo parity."""
from __future__ import annotations

import json

import pytest

from app.backup_manager import demo, inventory, service


def test_rsv_protected_item_shaping() -> None:
    vault = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv1"
    row = {
        "id": f"{vault}/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;rg-app;vm1"
              f"/protectedItems/vm;iaasvmcontainerv2;rg-app;vm1",
        "name": "vm;iaasvmcontainerv2;rg-app;vm1",
        "resourceGroup": "rg", "subscriptionId": "s1", "location": "eastus",
        "friendlyName": "vm1",
        "datasourceId": "/subscriptions/s1/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm1",
        "backupManagementType": "AzureIaasVM", "workloadType": "VM",
        "protectionState": "Protected", "protectionStatus": "Healthy", "healthStatus": "Passed",
        "lastBackupStatus": "Completed", "lastBackupTime": service.now_iso(),
        "lastRecoveryPoint": service.now_iso(),
        "policyId": f"{vault}/backupPolicies/DefaultPolicy".lower(), "policyName": "DefaultPolicy",
        "isArchiveEnabled": "false",
    }
    item = inventory.shape_rsv_item(row)
    assert item["vault_id"] == vault
    assert item["vault_kind"] == "recovery_services"
    assert item["friendly_name"] == "vm1"
    assert item["protection_stopped"] is False
    assert item["recovery_point_age_hours"] is not None and item["recovery_point_age_hours"] < 1


def test_stopped_protection_is_detected() -> None:
    vault = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv1"
    item = inventory.shape_rsv_item({
        "id": f"{vault}/backupFabrics/Azure/protectionContainers/c/protectedItems/i",
        "name": "i", "protectionState": "ProtectionStopped",
    })
    assert item["protection_stopped"] is True
    assert item["retain_data_only"] is True


def test_backup_vault_instance_shaping() -> None:
    vault = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.DataProtection/backupVaults/bv1"
    item = inventory.shape_dp_instance({
        "id": f"{vault}/backupInstances/blob-1", "name": "blob-1",
        "friendlyName": "storage1",
        "datasourceId": "/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/storage1/blobservices/default",
        "datasourceType": "Microsoft.Storage/storageAccounts/blobServices",
        "currentProtectionState": "ProtectionConfigured",
        "policyId": f"{vault}/backupPolicies/p1".lower(), "policyName": "p1",
    })
    assert item["vault_kind"] == "backup"
    assert item["vault_id"] == vault
    assert item["latest_recovery_point"] == ""


def test_vault_shaping_normalises_both_kinds() -> None:
    rsv = inventory.shape_vault({
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v",
        "name": "v", "type": "microsoft.recoveryservices/vaults", "location": "eastus",
        "securitySettings": json.dumps({"softDeleteSettings": {"state": "AlwaysOn", "retentionDurationInDays": 30},
                                        "immutabilitySettings": {"state": "Locked"}}),
        "redundancySettings": json.dumps({"standardTierStorageRedundancy": "GeoRedundant",
                                          "crossRegionRestore": "Enabled"}),
        "monitoringSettings": json.dumps({"azureMonitorAlertSettings": {"alertsForAllJobFailures": "Enabled"}}),
        "storageSettings": json.dumps([]), "featureSettings": json.dumps({}),
        "encryption": json.dumps({}), "privateEndpointConnections": json.dumps([]),
    })
    assert rsv["kind"] == "recovery_services"
    assert rsv["redundancy"] == "GeoRedundant"
    assert rsv["cross_region_restore"] == "Enabled"
    assert rsv["immutability_state"] == "Locked"
    assert rsv["monitor_alerts"] == "Enabled"

    bv = inventory.shape_vault({
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DataProtection/backupVaults/b",
        "name": "b", "type": "microsoft.dataprotection/backupvaults", "location": "eastus",
        "securitySettings": json.dumps({"softDeleteSettings": {"state": "On", "retentionDurationInDays": 14}}),
        "storageSettings": json.dumps([{"datastoreType": "VaultStore", "type": "LocallyRedundant"}]),
        "featureSettings": json.dumps({"crossSubscriptionRestoreSettings": {"state": "Enabled"}}),
        "redundancySettings": json.dumps({}), "monitoringSettings": json.dumps({}),
        "encryption": json.dumps({}), "privateEndpointConnections": json.dumps([]),
    })
    assert bv["kind"] == "backup"
    assert bv["redundancy"] == "LocallyRedundant"
    assert bv["cross_subscription_restore"] == "Enabled"


@pytest.mark.parametrize(
    "value,expected",
    [("PT1H30M", 5400.0), ("PT45S", 45.0), ("P1DT2H", 93600.0), ("01:15:00", 4500.0), ("", None), ("garbage", None)],
)
def test_duration_parsing(value: str, expected: float | None) -> None:
    assert inventory._duration_seconds(value) == expected


def test_job_status_buckets() -> None:
    assert inventory._status_bucket("Completed") == "succeeded"
    assert inventory._status_bucket("Failed") == "failed"
    assert inventory._status_bucket("InProgress") == "running"
    assert inventory._status_bucket("Weird") == "unknown"


def test_orphan_detection_resolves_child_datasources() -> None:
    """A blob backup addresses the storage account's blobServices child; the parent must count."""
    live = {"/subscriptions/s/resourcegroups/rg/providers/microsoft.storage/storageaccounts/sa"}
    child = "/subscriptions/s/resourcegroups/rg/providers/microsoft.storage/storageaccounts/sa/blobservices/default"
    assert inventory._is_orphaned(child, live) is False
    assert inventory._is_orphaned("/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/gone", live) is True


def test_orphan_detection_is_fail_open_when_unverifiable() -> None:
    """If the live-resource lookup failed we must not accuse every item of being orphaned."""
    assert inventory._is_orphaned("/subscriptions/s/anything", None) is False


def test_build_estate_derives_recovery_point_from_jobs() -> None:
    vault_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DataProtection/backupVaults/bv"
    vault = inventory.shape_vault({
        "id": vault_id, "name": "bv", "type": "microsoft.dataprotection/backupvaults", "location": "eastus",
        "securitySettings": "{}", "storageSettings": "[]", "redundancySettings": "{}",
        "featureSettings": "{}", "monitoringSettings": "{}", "encryption": "{}",
        "privateEndpointConnections": "[]",
    })
    datasource = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/disks/d1"
    instance = inventory.shape_dp_instance({
        "id": f"{vault_id}/backupInstances/d1", "name": "d1", "friendlyName": "d1",
        "datasourceId": datasource, "datasourceType": "Microsoft.Compute/disks",
        "currentProtectionState": "ProtectionConfigured",
    })
    stamp = service.now_iso()
    job = inventory.shape_job({
        "id": f"{vault_id}/backupJobs/j1", "name": "j1", "operation": "Backup", "status": "Completed",
        "startTime": stamp, "endTime": stamp, "datasourceId": datasource, "entityFriendlyName": "d1",
    }, kind="backup")
    estate = inventory.build_estate(
        vaults=[vault], rsv_items=[], dp_instances=[instance], rsv_jobs=[], dp_jobs=[job],
        rsv_policies=[], dp_policies=[], replication=[], recovery_plans=[],
        live_resource_ids={datasource},
    )
    assembled = estate["instances"][0]
    assert assembled["latest_recovery_point"] == stamp
    assert assembled["recovery_point_source"] == "job"
    assert estate["vaults"][0]["instance_count"] == 1
    assert estate["vaults"][0]["empty"] is False


def test_retention_parsers() -> None:
    rsv = json.dumps({"dailySchedule": {"retentionDuration": {"count": 30, "durationType": "Days"}},
                      "monthlySchedule": {"retentionDuration": {"count": 12, "durationType": "Months"}}})
    assert inventory._rsv_retention_days(rsv) == 360
    dp = json.dumps([{"lifecycles": [{"deleteAfter": {"duration": "P90D"}}]}])
    assert inventory._dp_retention_days(dp) == 90


def test_arg_queries_target_the_recovery_services_table() -> None:
    """Regression guard: these must query recoveryservicesresources, not resources."""
    for query in (inventory.RSV_ITEM_QUERY, inventory.DP_INSTANCE_QUERY, inventory.RSV_JOB_QUERY,
                  inventory.DP_JOB_QUERY, inventory.RSV_POLICY_QUERY, inventory.DP_POLICY_QUERY,
                  inventory.ASR_ITEM_QUERY, inventory.ASR_PLAN_QUERY):
        assert query.startswith("recoveryservicesresources")
        assert "parse_json(tostring(properties))" in query
    assert inventory.VAULT_QUERY.startswith("resources")


def test_demo_estate_is_coherent() -> None:
    estate = demo.build_demo_estate()
    assert estate["demo"] is True
    assert estate["vaults"] and estate["instances"] and estate["jobs"]
    assert any(i["orphaned"] for i in estate["instances"]), "demo should include one orphaned item"
    assert any(v["kind"] == "backup" for v in estate["vaults"])
    assert any(v["kind"] == "recovery_services" for v in estate["vaults"])
    # Every instance points at a vault that exists in the same estate.
    vault_ids = {v["id"].lower() for v in estate["vaults"]}
    assert all(i["vault_id"].lower() in vault_ids for i in estate["instances"])


def test_demo_gaps_are_disjoint_from_protected_items() -> None:
    estate = demo.build_demo_estate()
    protected = {i["datasource_id"] for i in estate["instances"]}
    gaps = demo.demo_gaps()["gaps"]
    for gap in gaps:
        assert gap["resource_id"].lower() not in protected
