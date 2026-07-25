"""Backup Manager API contracts exercised against a real (sqlite) ledger."""
from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import backup_manager as api
from app.backup_manager import changes as change_ops
from app.backup_manager import demo, gaps, inventory, service
from app.core.db import Base
from app.core.security import Principal
from app.models import BackupDrill, BackupManagerChange

TENANT = "tenant-backup"
CONNECTION = {"id": "conn-1", "tenant_id": "azure-tenant", "read_only": False,
              "display_name": "Test", "auth_method": "service_principal"}
VAULT = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv"
VM = "/subscriptions/s1/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"

ALL_PERMS = frozenset({
    "backup_manager.read", "backup_manager.protect_write", "backup_manager.policy_write",
    "backup_manager.vault_write", "backup_manager.ondemand", "backup_manager.drill_write",
    "backup_manager.reference_write", "backup_manager.approve",
})


def _principal(subject: str = "op@example.test", perms: frozenset[str] = ALL_PERMS) -> Principal:
    return Principal(subject, subject, TENANT, "operator", perms)


@pytest.fixture
async def session(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'backup.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        yield db
    await engine.dispose()


def _estate() -> dict[str, Any]:
    """A minimal live-shaped estate: one vault, one VM policy, no protected items."""
    vault = inventory.shape_vault({
        "id": VAULT, "name": "rsv", "type": "microsoft.recoveryservices/vaults", "location": "eastus",
        "resourceGroup": "rg", "subscriptionId": "s1",
        "securitySettings": '{"softDeleteSettings":{"state":"Disabled"}}',
        "redundancySettings": '{"standardTierStorageRedundancy":"LocallyRedundant"}',
        "monitoringSettings": '{"azureMonitorAlertSettings":{"alertsForAllJobFailures":"Disabled"}}',
        "storageSettings": "[]", "featureSettings": "{}", "encryption": "{}",
        "privateEndpointConnections": "[]",
    })
    policy = inventory.shape_rsv_policy({
        "id": f"{VAULT}/backupPolicies/DefaultPolicy", "name": "DefaultPolicy",
        "resourceGroup": "rg", "subscriptionId": "s1", "location": "eastus",
        "backupManagementType": "AzureIaasVM", "policyType": "V2",
        "schedulePolicy": '{"scheduleRunFrequency":"Daily","scheduleRunTimes":["2026-01-01T02:00:00Z"]}',
        "retentionPolicy": '{"dailySchedule":{"retentionDuration":{"count":30,"durationType":"Days"}}}',
    })
    return inventory.build_estate(
        vaults=[vault], rsv_items=[], dp_instances=[], rsv_jobs=[], dp_jobs=[],
        rsv_policies=[policy], dp_policies=[], replication=[], recovery_plans=[],
        live_resource_ids=set(), scope={"subscriptions": ["s1"], "connection_id": "conn-1"},
    )


@pytest.fixture
def live_scope(monkeypatch):
    """Serve a deterministic estate + gap set without touching Azure."""
    estate = _estate()

    async def fake_estate(_principal, **_kwargs):
        return estate, CONNECTION

    async def fake_arm_get(_connection, path, _api_version, **_kwargs):
        if str(path).lower() == VAULT.lower():
            return {
                "location": "eastus",
                "sku": {"name": "RS0"},
                "properties": {
                    "monitoringSettings": {
                        "azureMonitorAlertSettings": {
                            "alertsForAllJobFailures": "Disabled",
                            "alertsForAllReplicationIssues": "Enabled",
                        },
                        "classicAlertSettings": {"alertsForCriticalOperations": "Enabled"},
                    },
                },
            }, 200, ""
        return None, 404, "not found"

    async def fake_detect(_connection, _estate, **_kwargs):
        return {
            "gaps": [{
                "gap_id": "gap-vm1", "source": "live", "resource_id": VM, "resource_name": "vm1",
                "resource_type": "microsoft.compute/virtualmachines", "display_type": "Virtual machine",
                "resource_group": "rg-app", "subscription_id": "s1", "location": "eastus",
                "mechanism": "rsv_vm", "target_vault_kind": "recovery_services",
                "severity": "critical", "reason": "No backup instance protects this resource.",
            }],
            "eligible_total": 1, "protected_total": 0, "coverage_pct": 0, "error": "",
            "native_only": [],
        }

    monkeypatch.setattr(api, "_estate", fake_estate)
    monkeypatch.setattr(service, "arm_get", fake_arm_get)
    monkeypatch.setattr(gaps, "detect", fake_detect)
    return estate


# --------------------------------------------------------------------------- capabilities
@pytest.mark.asyncio
async def test_capabilities_declare_the_structural_refusals(monkeypatch) -> None:
    monkeypatch.setattr(api, "_connection", lambda *a, **k: CONNECTION)
    result = await api.capabilities(connection_id="conn-1", workload_id="", principal=_principal())
    assert result["can_restore"] is False
    assert result["can_delete_backup_data"] is False
    assert result["can_approve"] is True
    assert {op["id"] for op in result["portal_only_operations"]} >= {"restore", "delete_backup_data"}


@pytest.mark.asyncio
async def test_refusals_endpoint_explains_each_omission() -> None:
    result = await api.refusals(_principal=_principal())
    assert result["operations"]
    assert all(op["reason"] for op in result["operations"])


# --------------------------------------------------------------------------- remediation
@pytest.mark.asyncio
async def test_remediation_preview_hides_the_payload_but_shows_the_plan(live_scope) -> None:
    body = api.RemediationPreviewRequest(
        connection_id="conn-1", gap_ids=["gap-vm1"], vault_id=VAULT,
        policy_id=f"{VAULT}/backuppolicies/defaultpolicy", validate_datasources=False,
    )
    result = await api.remediation_preview(body, principal=_principal())
    assert result["ready_count"] == 1 and result["blocked_count"] == 0
    item = result["items"][0]
    assert "body" not in item
    assert item["target_id"].endswith("/protectedItems/vm;iaasvmcontainerv2;rg-app;vm1")


@pytest.mark.asyncio
async def test_remediation_submit_creates_pending_changes_only(live_scope, session) -> None:
    body = api.RemediationSubmitRequest(
        connection_id="conn-1", gap_ids=["gap-vm1"], vault_id=VAULT,
        policy_id=f"{VAULT}/backuppolicies/defaultpolicy", validate_datasources=False,
        reason="Close the VM protection gap",
    )
    result = await api.remediation_submit(body, principal=_principal(), db=session)
    assert result["created"] == 1
    rows = list((await session.execute(select(BackupManagerChange))).scalars())
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert rows[0].applied_at is None
    assert rows[0].plan_id


@pytest.mark.asyncio
async def test_remediation_rejects_an_unknown_gap(live_scope) -> None:
    body = api.RemediationPreviewRequest(connection_id="conn-1", gap_ids=["nope"], vault_id=VAULT,
                                         policy_id="p", validate_datasources=False)
    with pytest.raises(Exception) as excinfo:
        await api.remediation_preview(body, principal=_principal())
    assert "gaps" in str(excinfo.value).lower()


# --------------------------------------------------------------------------- vault hardening
@pytest.mark.asyncio
async def test_harden_drafts_one_change_per_control(live_scope, session) -> None:
    body = api.VaultHardenRequest(
        connection_id="conn-1", vault_id=VAULT,
        controls=["enable_soft_delete", "enable_vault_alerts"], soft_delete_retention_days=30,
    )
    result = await api.harden_vault(body, principal=_principal(), db=session)
    assert result["created"] == 2
    kinds = {c["target_type"] for c in result["changes"]}
    assert kinds == {"vault_security", "vault_alerts"}
    soft_delete = next(c for c in result["changes"] if c["target_type"] == "vault_security")
    assert soft_delete["summary"]["arm_path"].endswith("/backupconfig/vaultconfig")
    # The alerts PATCH must carry the whole monitoringSettings object, not just the one key,
    # because the Recovery Services vault API rejects a partial value.
    alerts = next(c for c in result["changes"] if c["target_type"] == "vault_alerts")
    assert alerts["summary"]["arm_method"] == "PATCH"


@pytest.mark.asyncio
async def test_alerts_hardening_is_skipped_when_live_settings_cannot_be_read(live_scope, session, monkeypatch) -> None:
    async def failing_arm_get(_connection, _path, _api_version, **_kwargs):
        return None, 503, "ARM 503: service unavailable"

    monkeypatch.setattr(service, "arm_get", failing_arm_get)
    body = api.VaultHardenRequest(connection_id="conn-1", vault_id=VAULT, controls=["enable_vault_alerts"])
    with pytest.raises(Exception) as excinfo:
        await api.harden_vault(body, principal=_principal(), db=session)
    assert "503" in str(excinfo.value)


@pytest.mark.asyncio
async def test_redundancy_change_is_refused_once_items_exist(live_scope, session, monkeypatch) -> None:
    estate = _estate()
    estate["vaults"][0]["instance_count"] = 5

    async def fake_estate(_principal, **_kwargs):
        return estate, CONNECTION

    monkeypatch.setattr(api, "_estate", fake_estate)
    body = api.VaultHardenRequest(connection_id="conn-1", vault_id=VAULT, controls=["set_redundancy"])
    with pytest.raises(Exception) as excinfo:
        await api.harden_vault(body, principal=_principal(), db=session)
    assert "before the first item is protected" in str(excinfo.value)


@pytest.mark.asyncio
async def test_crr_requires_geo_redundancy_first(live_scope, session) -> None:
    body = api.VaultHardenRequest(connection_id="conn-1", vault_id=VAULT, controls=["enable_crr"])
    with pytest.raises(Exception) as excinfo:
        await api.harden_vault(body, principal=_principal(), db=session)
    assert "geo-redundant" in str(excinfo.value)


@pytest.mark.asyncio
async def test_diagnostics_requires_a_workspace(live_scope, session) -> None:
    body = api.VaultHardenRequest(connection_id="conn-1", vault_id=VAULT, controls=["enable_diagnostics"])
    with pytest.raises(Exception) as excinfo:
        await api.harden_vault(body, principal=_principal(), db=session)
    assert "Log Analytics workspace" in str(excinfo.value)


# --------------------------------------------------------------------------- decisions + apply
async def _pending(session, **overrides) -> BackupManagerChange:
    payload = {
        "tenant_id": TENANT, "connection_id": "conn-1", "target_type": "protection",
        "target_id": gaps.rsv_protected_item_id(VAULT, "rg-app", "vm1"), "operation": "create",
        "requested_by": "op@example.test",
        "desired": {"body": gaps.build_vm_protection_body(vm_id=VM, policy_id=f"{VAULT}/backupPolicies/DefaultPolicy")},
        "summary": {"mechanism": "rsv_vm", "api_version": service.RSV_BACKUP_API},
    }
    payload.update(overrides)
    row = change_ops.build_change(**payload)
    session.add(row)
    await session.commit()
    return row


@pytest.mark.asyncio
async def test_approve_then_apply_marks_the_change_applying(session, monkeypatch) -> None:
    row = await _pending(session)
    await api.decide_change(row.id, api.ChangeDecisionRequest(decision="approved", reason="ok"),
                            principal=_principal(), db=session)
    assert row.status == "approved"

    async def apply_change(_connection, change):  # noqa: ARG001
        return service.ArmSubmission(status=202, body={"id": "job-1"}, error="",
                                     async_operation_url="https://management.azure.com/op/1"), {"before": {}}

    monkeypatch.setattr(change_ops, "apply_change", apply_change)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)
    result = await api.bulk_apply(api.ChangeSelectionRequest(connection_id="conn-1", change_ids=[row.id]),
                                  principal=_principal(), db=session)
    assert result["results"][0]["status"] == "applying"
    assert result["results"][0]["is_async"] is True


@pytest.mark.asyncio
async def test_apply_skips_changes_that_were_never_approved(session) -> None:
    row = await _pending(session)
    with pytest.raises(Exception) as excinfo:
        await api.bulk_apply(api.ChangeSelectionRequest(connection_id="conn-1", change_ids=[row.id]),
                             principal=_principal(), db=session)
    assert "No approved changes" in str(excinfo.value)


@pytest.mark.asyncio
async def test_dual_approval_requires_two_distinct_people(session) -> None:
    row = await _pending(session, target_type="asr_test_failover", target_id="/x", operation="invoke",
                         desired={"body": {}}, summary={})
    assert row.requires_dual_approval is True
    first = await api.decide_change(row.id, api.ChangeDecisionRequest(decision="approved", reason="drill"),
                                    principal=_principal("alice@example.test"), db=session)
    assert first["awaiting_second_approver"] is True
    assert row.status == "pending"

    with pytest.raises(Exception) as excinfo:
        await api.decide_change(row.id, api.ChangeDecisionRequest(decision="approved", reason="again"),
                                principal=_principal("alice@example.test"), db=session)
    assert "second, different approver" in str(excinfo.value)

    await api.decide_change(row.id, api.ChangeDecisionRequest(decision="approved", reason="second"),
                            principal=_principal("bob@example.test"), db=session)
    assert row.status == "approved"
    assert row.second_approver == "bob@example.test"


@pytest.mark.asyncio
async def test_bulk_decision_never_auto_approves_a_dual_approval_change(session) -> None:
    row = await _pending(session, target_type="asr_test_failover", target_id="/x", operation="invoke",
                         desired={"body": {}}, summary={})
    result = await api.bulk_decision(
        api.BulkDecisionRequest(connection_id="conn-1", change_ids=[row.id], decision="approved", reason="bulk"),
        principal=_principal(), db=session,
    )
    assert result["updated"] == []
    assert "two distinct approvers" in result["skipped"][0]["reason"]


@pytest.mark.asyncio
async def test_changes_listing_reports_actionable_counts(session) -> None:
    await _pending(session)
    approved = await _pending(session, target_id=gaps.rsv_protected_item_id(VAULT, "rg-app", "vm2"))
    approved.status = "approved"
    await session.commit()
    result = await api.list_changes(
        connection_id="conn-1", status="", view="all", page=1, page_size=100,
        principal=_principal(), db=session,
    )
    assert result["actionable_count"] == 2
    assert result["pending_count"] == 1
    assert result["approved_count"] == 1


@pytest.mark.asyncio
async def test_rollback_requires_an_applied_change(session) -> None:
    row = await _pending(session)
    with pytest.raises(Exception) as excinfo:
        await api.rollback_change(row.id, principal=_principal(), db=session)
    assert "applied change" in str(excinfo.value)


# --------------------------------------------------------------------------- drills
@pytest.mark.asyncio
async def test_drill_lifecycle_schedules_the_next_occurrence(session) -> None:
    created = await api.create_drill(
        api.DrillCreateRequest(connection_id="conn-1", name="Quarterly restore", kind="restore",
                               scope_kind="workload", scope_id="wl-1", cadence_days=90),
        principal=_principal(), db=session,
    )
    drill_id = created["drill"]["id"]
    assert created["drill"]["status"] == "scheduled"
    assert created["drill"]["due_at"]

    result = await api.record_drill_outcome(
        drill_id, api.DrillOutcomeRequest(status="passed", notes="Restored in 22 minutes", rto_minutes=22),
        principal=_principal(), db=session,
    )
    assert result["drill"]["status"] == "passed"
    assert result["drill"]["rto_minutes"] == 22
    assert result["next_drill"]["status"] == "scheduled"
    rows = list((await session.execute(select(BackupDrill))).scalars())
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_test_failover_is_drafted_not_executed(session, monkeypatch) -> None:
    estate = _estate()
    estate["replication"] = [inventory.shape_replication({
        "id": f"{VAULT}/replicationFabrics/f/replicationProtectionContainers/c/replicationProtectedItems/vm1",
        "name": "vm1", "friendlyName": "vm1", "protectionState": "Protected",
        "replicationHealth": "Normal", "testFailoverState": "None", "activeLocation": "Primary",
        "subscriptionId": "s1", "resourceGroup": "rg", "healthErrors": "[]",
    })]

    async def fake_estate(_principal, **_kwargs):
        return estate, CONNECTION

    monkeypatch.setattr(api, "_estate", fake_estate)
    result = await api.request_test_failover(
        api.TestFailoverRequest(connection_id="conn-1", replicated_item_id=estate["replication"][0]["id"]),
        principal=_principal(), db=session,
    )
    change = result["change"]
    assert change["status"] == "pending"
    assert change["risk"] == "high"
    assert change["requires_dual_approval"] is True
    assert "cleanup_reminder" in change["summary"]


@pytest.mark.asyncio
async def test_test_failover_blocked_on_unhealthy_replication(session, monkeypatch) -> None:
    estate = _estate()
    estate["replication"] = [inventory.shape_replication({
        "id": f"{VAULT}/replicationFabrics/f/replicationProtectionContainers/c/replicationProtectedItems/vm1",
        "name": "vm1", "friendlyName": "vm1", "protectionState": "Protected",
        "replicationHealth": "Critical", "testFailoverState": "None", "activeLocation": "Primary",
        "subscriptionId": "s1", "resourceGroup": "rg", "healthErrors": "[]",
    })]

    async def fake_estate(_principal, **_kwargs):
        return estate, CONNECTION

    monkeypatch.setattr(api, "_estate", fake_estate)
    with pytest.raises(Exception) as excinfo:
        await api.request_test_failover(
            api.TestFailoverRequest(connection_id="conn-1", replicated_item_id=estate["replication"][0]["id"]),
            principal=_principal(), db=session,
        )
    assert "Replication health" in str(excinfo.value)


# --------------------------------------------------------------------------- demo + guards
@pytest.mark.asyncio
async def test_demo_scope_is_read_only(session) -> None:
    body = api.AdhocBackupRequest(workload_id=demo.DEMO_WORKLOAD_ID, instance_id="anything")
    with pytest.raises(Exception) as excinfo:
        await api.backup_now(body, principal=_principal(), db=session)
    assert "Demo mode is read-only" in str(excinfo.value)


@pytest.mark.asyncio
async def test_read_only_connection_cannot_draft_changes(session, monkeypatch) -> None:
    estate = _estate()

    async def fake_estate(_principal, **_kwargs):
        return estate, {**CONNECTION, "read_only": True}

    monkeypatch.setattr(api, "_estate", fake_estate)
    with pytest.raises(Exception) as excinfo:
        await api.harden_vault(
            api.VaultHardenRequest(connection_id="conn-1", vault_id=VAULT, controls=["enable_vault_alerts"]),
            principal=_principal(), db=session,
        )
    assert "read-only" in str(excinfo.value)


def test_resource_type_parsing_from_arm_ids() -> None:
    assert api._type_from_id(VM) == "microsoft.compute/virtualmachines"
    assert api._type_from_id(
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/databases/db"
    ) == "microsoft.sql/servers/databases"
    assert api._type_from_id("not-an-arm-id") == ""
