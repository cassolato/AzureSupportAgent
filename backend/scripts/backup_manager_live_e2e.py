"""Live Backup Manager end-to-end drive against a real Azure subscription.

Not part of the pytest suite: it performs REAL Azure writes and is run manually against a
throwaway resource group. Drives the same API functions the HTTP layer calls, so the flow
under test is the production one.

    python scripts/backup_manager_live_e2e.py --connection <id> --subscription <sub> --vault <name>
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.api import backup_manager as api  # noqa: E402
from app.backup_manager import inventory, lro, service  # noqa: E402
from app.core.azure_connections import get_connection  # noqa: E402
from app.core.db import Base  # noqa: E402
from app.core.security import Principal  # noqa: E402
from app.models import BackupManagerChange  # noqa: E402

PERMS = frozenset({
    "backup_manager.read", "backup_manager.protect_write", "backup_manager.policy_write",
    "backup_manager.vault_write", "backup_manager.ondemand", "backup_manager.drill_write",
    "backup_manager.reference_write", "backup_manager.approve",
})
ALICE = Principal("alice@e2e.test", "alice@e2e.test", "e2e-tenant", "operator", PERMS)
BOB = Principal("bob@e2e.test", "bob@e2e.test", "e2e-tenant", "operator", PERMS)

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((PASS if ok else FAIL, name, detail))
    print(f"[{PASS if ok else FAIL}] {name}{f' — {detail}' if detail else ''}", flush=True)
    return ok


async def wait_for_terminal(maker, change_id: str, *, timeout_s: int = 900) -> str:
    """Drive the real LRO poller until the change reaches a terminal state."""
    deadline = service.now().timestamp() + timeout_s
    while service.now().timestamp() < deadline:
        await lro.poller.tick()
        async with maker() as db:
            row = await db.get(BackupManagerChange, change_id)
            status = row.status if row else "missing"
            if status in ("applied", "failed", "rejected", "rolled_back"):
                print(f"    change {change_id[:8]} -> {status} "
                      f"{'(' + (row.error_message or '') + ')' if row and row.error_message else ''}", flush=True)
                return status
        await asyncio.sleep(10)
    return "timeout"


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connection", required=True)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--vault", required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--policy", default="DefaultPolicy")
    parser.add_argument("--skip-protect", action="store_true")
    args = parser.parse_args()

    connection = get_connection(args.connection)
    if not connection:
        print("Connection not found.")
        return 2
    scope = {"connection_id": args.connection, "subscription_id": args.subscription}

    tmpdir = tempfile.mkdtemp(prefix="bkmgr-e2e-")
    engine = create_async_engine(f"sqlite+aiosqlite:///{os.path.join(tmpdir, 'e2e.db')}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    import app.core.db as core_db
    core_db.SessionLocal = maker  # the poller resolves its session through this

    # ---------------------------------------------------------------- read paths
    async with maker() as db:
        summary = await api.summary(
            connection_id=args.connection, workload_id="", subscription_id=args.subscription,
            management_group_id="", principal=ALICE, db=db,
        )
    check("summary returns without collector errors", not summary["errors"], str(summary["errors"]))
    check("summary counts vaults", summary["protection"]["vaults"] >= 1,
          f"{summary['protection']['vaults']} vault(s)")

    posture = await api.posture(
        connection_id=args.connection, workload_id="", subscription_id=args.subscription,
        management_group_id="", principal=ALICE,
    )
    vault = next((v for v in posture["vaults"] if v["vault_name"] == args.vault), None)
    check("target vault is scored", vault is not None, f"score={vault['score'] if vault else '?'}")
    check("locally-redundant vault fails the redundancy control",
          bool(vault and "redundancy" in vault["failing"]), str(vault["failing"] if vault else []))
    check("empty vault still offers the redundancy action",
          bool(vault and "set_redundancy" in vault["actionable"]), str(vault["actionable"] if vault else []))
    check("disabled built-in alerts are actionable",
          bool(vault and "enable_vault_alerts" in vault["actionable"]))
    check("portal-only controls are reported, not offered",
          bool(vault and {"immutability", "mua"} <= {g["id"] for g in vault["portal_only_gaps"]}))

    gaps = await api.list_gaps(
        connection_id=args.connection, workload_id="", subscription_id=args.subscription,
        management_group_id="", include_coverage=False, principal=ALICE,
    )
    vm_gap = next((g for g in gaps["gaps"] if g["resource_name"] == args.vm), None)
    check("unprotected VM is detected as a gap", vm_gap is not None)

    policy = next((p for p in (gaps["policies"] or []) if p["name"] == args.policy), None)
    vault_row = next((v for v in (gaps["vaults"] or []) if v["name"] == args.vault), None)
    check("target policy is offered for the vault", policy is not None and vault_row is not None)
    if not (vm_gap and policy and vault_row):
        return _report()

    # ---------------------------------------------------------------- refusals
    caps = await api.capabilities(connection_id=args.connection, workload_id="", principal=ALICE)
    check("restore capability is structurally false", caps["can_restore"] is False)
    check("delete-backup-data capability is structurally false", caps["can_delete_backup_data"] is False)

    # ---------------------------------------------------------------- vault hardening
    async with maker() as db:
        harden = await api.harden_vault(
            api.VaultHardenRequest(**scope, vault_id=vault_row["id"], controls=["enable_vault_alerts"]),
            principal=ALICE, db=db,
        )
    alert_change = harden["changes"][0]["id"]
    check("hardening drafts a pending change", harden["created"] == 1)
    async with maker() as db:
        await api.decide_change(alert_change, api.ChangeDecisionRequest(decision="approved", reason="e2e"),
                                principal=ALICE, db=db)
        applied = await api.bulk_apply(
            api.ChangeSelectionRequest(connection_id=args.connection, change_ids=[alert_change]),
            principal=BOB, db=db,
        )
    status = applied["results"][0]["status"]
    if status == "applying":
        status = await wait_for_terminal(maker, alert_change)
    check("vault alert hardening applied to Azure", status == "applied", status)

    live, _s, _e = await service.arm_get(connection, vault_row["id"], service.RSV_API)
    live_alerts = (
        service.as_dict(service.as_dict(service.as_dict((live or {}).get("properties")).get("monitoringSettings"))
                        .get("azureMonitorAlertSettings")).get("alertsForAllJobFailures")
    )
    check("Azure now reports job-failure alerts enabled", live_alerts == "Enabled", str(live_alerts))

    if args.skip_protect:
        return _report()

    # ---------------------------------------------------------------- protect the VM
    async with maker() as db:
        preview = await api.remediation_preview(
            api.RemediationPreviewRequest(**scope, gap_ids=[vm_gap["gap_id"]], vault_id=vault_row["id"],
                                          policy_id=policy["id"], validate_datasources=False),
            principal=ALICE,
        )
    check("remediation preview is ready", preview["ready_count"] == 1, str(preview["blocked"]))
    check("preview never returns the ARM payload", "body" not in preview["items"][0])

    async with maker() as db:
        submitted = await api.remediation_submit(
            api.RemediationSubmitRequest(**scope, gap_ids=[vm_gap["gap_id"]], vault_id=vault_row["id"],
                                         policy_id=policy["id"], validate_datasources=False,
                                         reason="Backup Manager live E2E"),
            principal=ALICE, db=db,
        )
    protect_change = submitted["changes"][0]["id"]
    check("submit creates a pending change only", submitted["changes"][0]["status"] == "pending")

    async with maker() as db:
        try:
            await api.bulk_apply(
                api.ChangeSelectionRequest(connection_id=args.connection, change_ids=[protect_change]),
                principal=BOB, db=db,
            )
            check("un-approved change cannot be applied", False, "apply succeeded unexpectedly")
        except Exception as exc:  # noqa: BLE001 - expected HTTPException
            check("un-approved change cannot be applied", "No approved changes" in str(exc), str(exc)[:120])

    async with maker() as db:
        await api.decide_change(protect_change, api.ChangeDecisionRequest(decision="approved", reason="e2e"),
                                principal=ALICE, db=db)
        applied = await api.bulk_apply(
            api.ChangeSelectionRequest(connection_id=args.connection, change_ids=[protect_change]),
            principal=BOB, db=db,
        )
    status = applied["results"][0]["status"]
    check("enable-protection submitted as a long-running operation", status == "applying", status)
    if status == "applying":
        status = await wait_for_terminal(maker, protect_change)
    check("enable-protection reached applied", status == "applied", status)

    # ---------------------------------------------------------------- verify in Azure
    from app.backup_manager import cache as inventory_cache
    await inventory_cache.clear()
    estate = await inventory.collect_estate(connection, tenant_id="e2e", subscription_id=args.subscription, force=True)
    protected = [i for i in estate["instances"] if i["friendly_name"].lower() == args.vm.lower()]
    check("protected item now appears in the inventory", len(protected) == 1,
          f"{[i['protection_state'] for i in protected]}")
    check("protected item carries the chosen policy",
          bool(protected and protected[0]["policy_name"] == args.policy),
          protected[0]["policy_name"] if protected else "")
    check("configure-backup job appears in the job inbox",
          any("configurebackup" in (j["operation"] or "").lower().replace(" ", "") for j in estate["jobs"]),
          str([j["operation"] for j in estate["jobs"]][:5]))

    await inventory.enrich_vaults(connection, estate["vaults"])
    from app.backup_manager import posture as posture_ops
    scored = posture_ops.build_posture(estate["vaults"])
    target = next((v for v in scored["vaults"] if v["vault_name"] == args.vault), None)
    check("redundancy action is withdrawn once the vault holds an item",
          bool(target and "set_redundancy" not in target["actionable"]),
          str(target["actionable"] if target else []))
    check("built-in alerts control now passes",
          bool(target and "monitor_alerts" not in target["failing"]),
          str(target["failing"] if target else []))

    # ---------------------------------------------------------------- rollback
    async with maker() as db:
        rollback = await api.rollback_change(protect_change, principal=ALICE, db=db)
    rollback_id = rollback["change"]["id"]
    check("rollback drafts stop-protection with data retained",
          rollback["change"]["operation"] == "delete"
          and rollback["change"]["summary"].get("stop_mode") == "stop_retain_data")
    async with maker() as db:
        await api.decide_change(rollback_id, api.ChangeDecisionRequest(decision="approved", reason="e2e rollback"),
                                principal=ALICE, db=db)
        applied = await api.bulk_apply(
            api.ChangeSelectionRequest(connection_id=args.connection, change_ids=[rollback_id]),
            principal=BOB, db=db,
        )
    status = applied["results"][0]["status"]
    if status == "applying":
        status = await wait_for_terminal(maker, rollback_id)
    check("rollback applied", status == "applied", status)

    await inventory_cache.clear()
    estate = await inventory.collect_estate(connection, tenant_id="e2e", subscription_id=args.subscription, force=True)
    stopped = [i for i in estate["instances"] if i["friendly_name"].lower() == args.vm.lower()]
    check("protection is stopped but the item (and its data) is retained",
          bool(stopped and stopped[0]["protection_stopped"]),
          stopped[0]["protection_state"] if stopped else "item gone")

    async with maker() as db:
        rows = list((await db.execute(select(BackupManagerChange))).scalars())
    check("every change ended in a terminal state",
          all(r.status in ("applied", "failed", "rejected", "rolled_back") for r in rows),
          str({r.status for r in rows}))

    await engine.dispose()
    return _report()


def _report() -> int:
    failures = [r for r in results if r[0] == FAIL]
    print("\n" + "=" * 70)
    print(f"Backup Manager live E2E: {len(results) - len(failures)}/{len(results)} checks passed")
    for status, name, detail in failures:
        print(f"  {status}: {name} — {detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
