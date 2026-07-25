"""LRO poller and reference-registry contracts."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.backup_manager import changes as change_ops
from app.backup_manager import lro, reference, service
from app.backup_manager.builtin_seed import seed_reference
from app.core.db import Base
from app.models import BackupManagerChange

VAULT = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv"
CONNECTION = {"id": "conn-1", "tenant_id": "t", "read_only": False, "auth_method": "service_principal"}


@pytest.fixture
async def maker(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'lro.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.db.SessionLocal", session_maker)
    yield session_maker
    await engine.dispose()


async def _applying(session_maker, *, url: str = "https://management.azure.com/op/1", **overrides):
    row = change_ops.build_change(
        tenant_id="t1", connection_id="conn-1", target_type="protection", target_id=f"{VAULT}/x",
        operation="create", requested_by="op", desired={"body": {}}, summary={},
    )
    row.status = "applying"
    row.operation_url = url
    row.poll_after = service.now() - timedelta(seconds=1)
    row.poll_deadline = service.now() + timedelta(minutes=30)
    for key, value in overrides.items():
        setattr(row, key, value)
    async with session_maker() as db:
        db.add(row)
        await db.commit()
    return row.id


@pytest.mark.asyncio
async def test_poller_promotes_a_succeeded_operation(maker, monkeypatch) -> None:
    change_id = await _applying(maker)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)

    async def token_for(_connection):
        return "token"

    async def arm_poll(_token, _url):
        return "succeeded", {"status": "Succeeded"}, "", 0.0

    monkeypatch.setattr(service, "token_for", token_for)
    monkeypatch.setattr(service, "arm_poll", arm_poll)
    assert await lro.poller.tick() == 1
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "applied"
        assert row.poll_after is None


@pytest.mark.asyncio
async def test_poller_records_a_failed_operation(maker, monkeypatch) -> None:
    change_id = await _applying(maker)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)

    async def token_for(_connection):
        return "token"

    async def arm_poll(_token, _url):
        return "failed", {}, "UserErrorGuestAgentStatusUnavailable", 0.0

    monkeypatch.setattr(service, "token_for", token_for)
    monkeypatch.setattr(service, "arm_poll", arm_poll)
    await lro.poller.tick()
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "failed"
        assert "GuestAgent" in (row.error_message or "")


@pytest.mark.asyncio
async def test_poller_reschedules_a_running_operation(maker, monkeypatch) -> None:
    change_id = await _applying(maker)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)

    async def token_for(_connection):
        return "token"

    async def arm_poll(_token, _url):
        return "running", {"status": "InProgress"}, "", 45.0

    monkeypatch.setattr(service, "token_for", token_for)
    monkeypatch.setattr(service, "arm_poll", arm_poll)
    await lro.poller.tick()
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "applying"
        assert row.poll_attempts == 1
        # SQLite round-trips naive datetimes; compare in UTC-aware terms.
        assert row.poll_after is not None and lro._aware(row.poll_after) > service.now()


@pytest.mark.asyncio
async def test_poller_times_out_rather_than_hanging_forever(maker, monkeypatch) -> None:
    change_id = await _applying(maker, poll_deadline=service.now() - timedelta(minutes=1))
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)
    await lro.poller.tick()
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "failed"
        assert row.error_code == "OperationTimeout"


@pytest.mark.asyncio
async def test_poller_fails_closed_when_the_connection_is_gone(maker, monkeypatch) -> None:
    change_id = await _applying(maker)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: None)
    await lro.poller.tick()
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "failed"
        assert row.error_code == "ConnectionMissing"


@pytest.mark.asyncio
async def test_poller_leaves_untouched_rows_alone(maker, monkeypatch) -> None:
    """A change that is not yet due must not be polled."""
    await _applying(maker, poll_after=service.now() + timedelta(minutes=5))
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)
    assert await lro.poller.tick() == 0


@pytest.mark.asyncio
async def test_poller_survives_a_transport_error(maker, monkeypatch) -> None:
    change_id = await _applying(maker)
    monkeypatch.setattr("app.core.azure_connections.resolve_connection", lambda _id: CONNECTION)

    async def token_for(_connection):
        raise ValueError("token endpoint unreachable")

    monkeypatch.setattr(service, "token_for", token_for)
    await lro.poller.tick()
    async with maker() as db:
        row = await db.get(BackupManagerChange, change_id)
        assert row.status == "applying"  # retried, not failed
        assert row.poll_attempts == 1


# --------------------------------------------------------------------------- ARM poll parsing
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,payload,expected",
    [
        (200, {"status": "Succeeded"}, "succeeded"),
        (200, {"status": "InProgress"}, "running"),
        (200, {"status": "Failed", "error": {"message": "nope"}}, "failed"),
        (202, {}, "running"),
        (204, {}, "succeeded"),
        (404, {}, "succeeded"),
        (500, {"error": {"message": "boom"}}, "failed"),
    ],
)
async def test_arm_poll_state_mapping(monkeypatch, status, payload, expected) -> None:
    class _Resp:
        status_code = status
        headers: dict[str, str] = {}

        def json(self):
            return payload

        @property
        def text(self):
            return json.dumps(payload)

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, *_args, **_kwargs):
            return _Resp()

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _Client())
    state, _body, _error, _retry = await service.arm_poll("token", "https://example.test/op")
    assert state == expected


# --------------------------------------------------------------------------- reference
@pytest.fixture
def isolated_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(reference, "_PATH", Path(tmp_path) / "ref.json")
    monkeypatch.setattr(reference, "_REV_PATH", Path(tmp_path) / "revs.json")
    return tmp_path


def test_reference_seeds_on_first_load(isolated_reference) -> None:
    doc = reference.load_reference()
    assert doc["version"] == 1
    assert len(doc["failure_kb"]) >= 20
    assert reference.failure_index()["usererrorguestagentstatusunavailable"]["auto_fix"] is True


def test_reference_sanitisation_drops_unknown_checks(isolated_reference) -> None:
    payload = seed_reference()
    payload["vault_checks"] = [{"id": "made_up_control", "label": "x", "weight": 99}]
    doc = reference.sanitize(payload)
    ids = {c["id"] for c in doc["vault_checks"]}
    assert "made_up_control" not in ids
    # Built-in controls are restored rather than silently lost.
    assert "soft_delete" in ids


def test_reference_rejects_malformed_failure_entries(isolated_reference) -> None:
    payload = seed_reference()
    payload["failure_kb"] = [
        {"code": "Valid_Code-1", "title": "t", "cause": "c", "remediation": "r"},
        {"code": "has spaces", "title": "bad"},
        {"title": "no code"},
        "not a dict",
    ]
    doc = reference.sanitize(payload)
    assert [entry["code"] for entry in doc["failure_kb"]] == ["Valid_Code-1"]


def test_reference_clamps_cost_and_sla_values(isolated_reference) -> None:
    payload = seed_reference()
    payload["cost_rates"]["storage_gb_month"]["lrs"] = -5
    payload["sla"]["job_sla_hours"] = 99999
    doc = reference.sanitize(payload)
    assert doc["cost_rates"]["storage_gb_month"]["lrs"] == 0.0
    assert doc["sla"]["job_sla_hours"] == 720


def test_reference_versions_and_restores(isolated_reference) -> None:
    original = reference.load_reference()
    edited = seed_reference()
    edited["sla"]["job_sla_hours"] = 12
    saved = reference.save_reference(edited, actor="admin@example.test", reason="Tighten SLA")
    assert saved["version"] == original["version"] + 1
    assert reference.sla()["job_sla_hours"] == 12

    revisions = reference.list_revisions()
    assert revisions and revisions[0]["by"] == "admin@example.test"
    restored = reference.restore_revision(revisions[0]["id"], actor="admin@example.test")
    assert restored["sla"]["job_sla_hours"] == 24

    reset = reference.reset_reference(actor="admin@example.test")
    assert reset["sla"]["job_sla_hours"] == seed_reference()["sla"]["job_sla_hours"]


def test_restoring_an_unknown_revision_raises(isolated_reference) -> None:
    with pytest.raises(ValueError):
        reference.restore_revision("nope", actor="a@b.test")
