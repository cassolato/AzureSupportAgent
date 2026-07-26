"""Backfill coverage for the fleet grid — see test_backup_manager_fleet.py for the rest."""
from __future__ import annotations

import pytest

from app.api import backup_manager as api
from app.backup_manager import fleet as fleet_store
from app.backup_manager import snapshot as snapshot_store
from app.core import coverage_runs
from app.core.security import Principal

TENANT = "tenant-backfill"
CONNECTION_ID = "conn-backfill"


def _principal() -> Principal:
    return Principal("op@example.test", "op@example.test", TENANT, "operator",
                     frozenset({"backup_manager.read"}))


@pytest.fixture(autouse=True)
def isolated_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_store, "_PATH", tmp_path / "snapshots.json")
    monkeypatch.setattr(snapshot_store, "_locks", {})
    monkeypatch.setattr(fleet_store, "_PATH", tmp_path / "fleet.json")
    monkeypatch.setattr(coverage_runs, "_PATH", tmp_path / "runs.json")


async def test_a_scope_analyzed_before_the_grid_existed_is_backfilled_on_first_read(monkeypatch) -> None:
    """Otherwise the fleet would report 'never analyzed' for estates that clearly were."""
    monkeypatch.setattr(api, "_workloads", lambda: [
        {"id": "wl-1", "name": "Legacy", "connection_id": CONNECTION_ID},
    ])
    snapshot_store.write_snapshot(TENANT, CONNECTION_ID, "workload", "wl-1", {
        "generated_at": "2026-07-20T09:00:00+00:00",
        "counts": {"protected_items": 6, "gaps": 2, "vaults": 1, "policies": 1, "failed_jobs": 0},
        "summary": {"protection": {"protected_items": 6, "vaults": 1, "policies": 1},
                    "jobs": {"failed": 0}, "rpo": {}, "posture": {}, "cost": {}, "dr": {}},
    })

    first = await api.fleet(principal=_principal())
    row = first["workloads"][0]

    assert row["has_analysis"] is True
    assert row["pct_protected"] == 75
    # And the derived row is kept, so the backfill is a one-time cost.
    assert fleet_store.key(CONNECTION_ID, "wl-1") in fleet_store.read_rows(TENANT)


async def test_backfill_only_looks_at_the_workloads_own_connection(monkeypatch) -> None:
    monkeypatch.setattr(api, "_workloads", lambda: [
        {"id": "wl-1", "name": "Legacy", "connection_id": CONNECTION_ID},
    ])
    snapshot_store.write_snapshot(TENANT, "other-conn", "workload", "wl-1", {
        "generated_at": "2026-07-20T09:00:00+00:00", "counts": {"protected_items": 6, "gaps": 0},
        "summary": {"protection": {"protected_items": 6}},
    })

    result = await api.fleet(principal=_principal())

    assert result["workloads"][0]["has_analysis"] is False
