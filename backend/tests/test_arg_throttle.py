"""ARG 429 handling: server-side pacing, retry coverage, and failure caching.

Azure Resource Graph meters roughly 15 queries per 5-second window PER SECURITY PRINCIPAL,
shared tenant-wide. Fleet launches fan many scans out at once against that single budget, so
these tests pin the three defences: pace before sending, retry when throttled anyway, and never
persist a throttled scan as if it were a coverage result.

All offline — no Azure, no network.
"""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from app.azure import arg_throttle


@pytest.fixture(autouse=True)
def _clean_buckets():
    arg_throttle.reset()
    yield
    arg_throttle.reset()


# --------------------------------------------------------------------- the limiter itself
def test_limiter_paces_a_burst_beyond_the_window_budget(monkeypatch):
    """A burst larger than the window budget must be spread across windows, not sent at once.

    This is the whole point: a fleet launch used to fire every scan's queries immediately and
    discover the quota wall as a 429.
    """
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 3, 0.4))

    async def burst() -> float:
        start = time.monotonic()
        await asyncio.gather(*(arg_throttle.acquire() for _ in range(7)))
        return time.monotonic() - start

    # 7 queries at 3 per 0.4 s: 3 now, 3 at +0.4, 1 at +0.8.
    assert asyncio.run(burst()) >= 0.7


def test_limiter_does_not_tax_traffic_well_within_budget(monkeypatch):
    """Smoothing only engages once a burst forms, so a lone scan pays no latency penalty."""
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 20, 5.0))

    async def burst() -> float:
        start = time.monotonic()
        # Well under the halfway mark (10), so nothing should be spaced out.
        await asyncio.gather(*(arg_throttle.acquire() for _ in range(5)))
        return time.monotonic() - start

    assert asyncio.run(burst()) < 0.2


def test_limiter_smooths_a_burst_instead_of_releasing_the_window_at_once(monkeypatch):
    """Measured against live Azure: releasing a whole window's budget in one instant still drew
    429s, because ARG's sliding window doesn't align with ours. Spacing them fixed it."""
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 8, 1.0))

    async def burst() -> float:
        start = time.monotonic()
        await asyncio.gather(*(arg_throttle.acquire() for _ in range(8)))
        return time.monotonic() - start

    # First 4 go free; the rest are spaced by window/max = 0.125s.
    elapsed = asyncio.run(burst())
    assert 0.3 <= elapsed < 1.0, f"expected smoothing, not a burst or a full-window stall: {elapsed}"


def test_limiter_is_a_no_op_when_an_admin_disables_it(monkeypatch):
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (False, 1, 5.0))

    async def burst() -> float:
        start = time.monotonic()
        await asyncio.gather(*(arg_throttle.acquire() for _ in range(10)))
        return time.monotonic() - start

    assert asyncio.run(burst()) < 0.2


def test_one_principal_shares_a_single_budget(monkeypatch):
    """Two workloads on the SAME connection contend — Azure meters them together."""
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 1, 0.4))
    conn = {"tenant_id": "t", "auth_method": "managed_identity", "client_id": ""}

    async def run() -> float:
        async def one():
            with arg_throttle.use_principal(conn):
                await arg_throttle.acquire()

        start = time.monotonic()
        await asyncio.gather(one(), one())
        return time.monotonic() - start

    assert asyncio.run(run()) >= 0.35


def test_distinct_principals_do_not_contend(monkeypatch):
    """Different identities have separate Azure quotas, so they must not queue behind each other."""
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 1, 5.0))

    async def run() -> float:
        async def one(conn):
            with arg_throttle.use_principal(conn):
                await arg_throttle.acquire()

        start = time.monotonic()
        await asyncio.gather(
            one({"tenant_id": "t1", "auth_method": "sp", "client_id": "a"}),
            one({"tenant_id": "t2", "auth_method": "sp", "client_id": "b"}),
        )
        return time.monotonic() - start

    assert asyncio.run(run()) < 0.2


def test_unknown_identity_collapses_into_a_shared_bucket():
    """When we can't tell principals apart we must SHARE (over-pace), never split (under-pace)."""
    assert arg_throttle.principal_key(None) == "default"
    assert arg_throttle.principal_key({}) == "default"
    assert arg_throttle.principal_key({"name": "conn-a"}) == arg_throttle.principal_key({"name": "conn-b"})
    # Case differences in the same identity must not mint a second bucket.
    assert arg_throttle.principal_key({"tenant_id": "T"}) == arg_throttle.principal_key({"tenant_id": "t"})


# ------------------------------------------------------------------- quota-header feedback
def test_parse_reset_after_handles_the_arg_header_format():
    assert arg_throttle.parse_reset_after("00:00:05") == 5.0
    assert arg_throttle.parse_reset_after("00:01:30") == 90.0
    assert arg_throttle.parse_reset_after("2.5") == 2.5
    assert arg_throttle.parse_reset_after("") is None
    assert arg_throttle.parse_reset_after("garbage") is None
    assert arg_throttle.parse_reset_after(None) is None


def test_exhausted_quota_header_backs_off_before_the_next_query(monkeypatch):
    """Azure tells us the budget is gone — wait it out rather than earning a guaranteed 429."""
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 50, 5.0))

    async def run() -> float:
        arg_throttle.note_quota_headers({
            "x-ms-user-quota-remaining": "0",
            "x-ms-user-quota-resets-after": "00:00:00.4",
        })
        start = time.monotonic()
        await arg_throttle.acquire()
        return time.monotonic() - start

    assert asyncio.run(run()) >= 0.3


def test_healthy_quota_header_does_not_slow_anything_down(monkeypatch):
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (True, 50, 5.0))

    async def run() -> float:
        arg_throttle.note_quota_headers({
            "x-ms-user-quota-remaining": "7",
            "x-ms-user-quota-resets-after": "00:00:05",
        })
        start = time.monotonic()
        await arg_throttle.acquire()
        return time.monotonic() - start

    assert asyncio.run(run()) < 0.2


def test_observed_throttling_is_counted_and_backs_the_bucket_off():
    arg_throttle.note_throttled(0.2)
    assert arg_throttle.stats()["default"]["throttled"] == 1


# ------------------------------------------------------------------------- REST retry path
class _Resp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = ""

    def json(self):
        return self._payload


class _Client:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def post(self, *_a, **_kw):
        self.calls += 1
        return self._responses.pop(0)


def _patch_client(monkeypatch, responses) -> _Client:
    from app.azure import arm

    client = _Client(responses)
    monkeypatch.setattr(arm.httpx, "AsyncClient", lambda **_kw: client)
    monkeypatch.setattr(arg_throttle, "_limits", lambda: (False, 1, 1.0))
    return client


def test_single_shot_graph_query_retries_a_throttled_response(monkeypatch):
    """`query_resource_graph` had NO retry: one 429 aborted the whole calling scan."""
    from app.azure import arm

    client = _patch_client(monkeypatch, [
        _Resp(429, {"error": {"message": "RateLimiting"}}, {"retry-after": "0"}),
        _Resp(200, {"data": [{"id": "/a"}]}),
    ])

    rows, err = asyncio.run(arm.query_resource_graph("tok", "resources"))
    assert err is None
    assert rows == [{"id": "/a"}]
    assert client.calls == 2, "a 429 must be retried, not surfaced as a hard failure"


def test_single_shot_graph_query_gives_up_after_its_retry_budget(monkeypatch):
    """Fail-closed: exhausted retries must return an ERROR, never an empty (passing) result."""
    from app.azure import arm

    client = _patch_client(monkeypatch, [
        _Resp(429, {"error": {"message": "RateLimiting"}}, {"retry-after": "0"}) for _ in range(3)
    ])

    rows, err = asyncio.run(arm.query_resource_graph("tok", "resources", max_retries=2))
    assert rows == []
    assert err and "429" in err
    assert client.calls == 3


def test_single_shot_graph_query_does_not_retry_a_permission_error(monkeypatch):
    """Only throttling/transient faults are retryable — a 403 must fail fast."""
    from app.azure import arm

    client = _patch_client(monkeypatch, [_Resp(403, {"error": {"message": "AuthorizationFailed"}})])

    rows, err = asyncio.run(arm.query_resource_graph("tok", "resources"))
    assert rows == []
    assert err and "403" in err
    assert client.calls == 1


# --------------------------------------------------------------- AMBA alert-rule collection
def test_query_alerts_pages_instead_of_capping_at_one_page(monkeypatch):
    """`take 5000` was a lie: both capture paths cap a page at 1000 rows, so a large tenant
    silently lost alert rules — and every dropped rule made its resource read as MISSING."""
    from app.amba import collector
    from app.exec.command_runner import KqlResult

    seen: dict = {}

    async def fake_collect(kql, _connection, **kwargs):
        seen["kql"] = kql
        seen["max_rows"] = kwargs.get("max_rows")
        return KqlResult(ok=True, rows=[{"id": "/r1"}, {"id": "/r2"}])

    monkeypatch.setattr("app.exec.command_runner.run_kql_collect", fake_collect)

    rows = asyncio.run(collector._query_alerts(["sub-1"], None))
    assert rows == [{"id": "/r1"}, {"id": "/r2"}]
    assert "take 5000" not in seen["kql"], "the unhonoured single-page take must be gone"
    assert seen["max_rows"] == collector._ALERT_QUERY_MAX_ROWS
    assert "order by id asc" in seen["kql"], "paging needs a deterministic order"


def test_query_alerts_fails_closed_when_the_collection_fails(monkeypatch):
    from app.amba import collector
    from app.exec.command_runner import KqlResult

    async def fake_collect(*_a, **_kw):
        return KqlResult(ok=False, error="Resource Graph 429: RateLimiting")

    monkeypatch.setattr("app.exec.command_runner.run_kql_collect", fake_collect)

    with pytest.raises(RuntimeError, match="429"):
        asyncio.run(collector._query_alerts(["sub-1"], None))


def test_query_alerts_skips_azure_entirely_with_no_subscriptions():
    from app.amba import collector

    assert asyncio.run(collector._query_alerts([], None)) == []


# ------------------------------------------------------------------ throttle classification
def test_throttle_failures_are_distinguished_from_real_faults():
    from app.amba import collector

    assert collector._is_throttle_error("Resource Graph 429: RateLimiting, please provide info")
    assert collector._is_throttle_error("Too Many Requests")
    assert collector._is_throttle_error("request was throttled")
    assert not collector._is_throttle_error("AuthorizationFailed")
    assert not collector._is_throttle_error("")


def test_empty_snapshot_flags_a_throttled_scan():
    from app.amba import collector

    throttled = collector._empty_snapshot("workload", "w1", error="Resource Graph 429: RateLimiting")
    assert throttled["throttled"] is True
    assert throttled["coverage_pct"] == 0

    denied = collector._empty_snapshot("workload", "w1", error="AuthorizationFailed")
    assert denied["throttled"] is False


# ------------------------------------------------------------------------- failure caching
@pytest.mark.parametrize("module_path", [
    "app.amba.cache",
    "app.telemetry.cache",
    "app.backupdr.cache",
])
def test_purge_errored_clears_poisoned_snapshots(module_path, tmp_path, monkeypatch):
    """A throttled scan used to persist as a 0%-coverage snapshot and, because coverage GETs
    are cached-only, render as the workload's real posture until someone manually rescanned."""
    import importlib

    cache = importlib.import_module(module_path)
    path = tmp_path / "cache.json"
    path.write_text(json.dumps({
        "tenant-1": {
            "workload:good": {"coverage_pct": 82, "error": ""},
            "workload:throttled": {"coverage_pct": 0, "error": "Resource Graph 429: RateLimiting"},
            "workload:denied": {"coverage_pct": 0, "error": "AuthorizationFailed"},
        },
        "tenant-2": {"workload:fine": {"coverage_pct": 91}},
    }), encoding="utf-8")
    monkeypatch.setattr(cache, "_PATH", path)

    assert cache.purge_errored() == 2
    left = json.loads(path.read_text(encoding="utf-8"))
    assert list(left["tenant-1"]) == ["workload:good"]
    assert list(left["tenant-2"]) == ["workload:fine"]
    assert cache.purge_errored() == 0, "purge must be idempotent"


def _principal():
    from app.core.security import Principal

    return Principal(subject="tester", email="t@example.com", tenant_id="tenant-1", role="admin")


def _seed_good_snapshot(cache, path, pct=82):
    path.write_text(json.dumps({
        "tenant-1": {"subscription:sub-1": {
            "coverage_pct": pct, "error": "", "generated_at": "2000-01-01T00:00:00+00:00",
            "kpis": {}, "groups": [], "gaps": [], "all_resources": [], "excluded_resources": [],
            "suppression_rules": [],
        }},
    }), encoding="utf-8")


def test_a_throttled_refresh_does_not_overwrite_the_last_good_snapshot(tmp_path, monkeypatch):
    """The defect behind the stale '0% covered' banner: a failed scan was cached like a real
    result, and because coverage GETs are cached-only it then rendered as the workload's
    posture indefinitely."""
    from app.amba import cache as amba_cache
    from app.api import amba as amba_api

    path = tmp_path / "cache.json"
    _seed_good_snapshot(amba_cache, path)
    monkeypatch.setattr(amba_cache, "_PATH", path)

    async def throttled_scan(*_a, **_kw):
        from app.amba.collector import _empty_snapshot

        return _empty_snapshot("subscription", "sub-1", error="Resource Graph 429: RateLimiting")

    monkeypatch.setattr(amba_api, "collect_coverage", throttled_scan)
    monkeypatch.setattr(amba_api, "connection_for_scope", lambda *_a, **_kw: {}, raising=False)

    out = asyncio.run(amba_api._get_snapshot(_principal(), "subscription", "sub-1", force=True))

    # The caller is told the refresh failed, and why...
    assert out["scan_throttled"] is True
    assert "429" in out["scan_error"]
    # ...but keeps the real coverage number rather than a fabricated 0%.
    assert out["coverage_pct"] == 82
    # And the failure was never persisted.
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["tenant-1"]["subscription:sub-1"]["coverage_pct"] == 82
    assert not on_disk["tenant-1"]["subscription:sub-1"]["error"]


def test_a_successful_refresh_still_replaces_the_snapshot(tmp_path, monkeypatch):
    """Guard the other direction: the no-cache-on-failure rule must not block real results."""
    from app.amba import cache as amba_cache
    from app.api import amba as amba_api

    path = tmp_path / "cache.json"
    _seed_good_snapshot(amba_cache, path)
    monkeypatch.setattr(amba_cache, "_PATH", path)

    async def good_scan(*_a, **_kw):
        return {"coverage_pct": 95, "error": "", "generated_at": "2030-01-01T00:00:00+00:00",
                "kpis": {}, "groups": [], "gaps": [], "all_resources": [],
                "excluded_resources": [], "suppression_rules": []}

    monkeypatch.setattr(amba_api, "collect_coverage", good_scan)
    monkeypatch.setattr(amba_api, "connection_for_scope", lambda *_a, **_kw: {}, raising=False)

    out = asyncio.run(amba_api._get_snapshot(_principal(), "subscription", "sub-1", force=True))
    assert out["coverage_pct"] == 95
    assert "scan_error" not in out
    assert json.loads(path.read_text(encoding="utf-8"))["tenant-1"]["subscription:sub-1"]["coverage_pct"] == 95


def test_a_failed_first_scan_surfaces_the_error_when_there_is_nothing_to_fall_back_to(tmp_path, monkeypatch):
    from app.amba import cache as amba_cache
    from app.api import amba as amba_api

    path = tmp_path / "cache.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(amba_cache, "_PATH", path)

    async def throttled_scan(*_a, **_kw):
        from app.amba.collector import _empty_snapshot

        return _empty_snapshot("subscription", "sub-1", error="Resource Graph 429: RateLimiting")

    monkeypatch.setattr(amba_api, "collect_coverage", throttled_scan)
    monkeypatch.setattr(amba_api, "connection_for_scope", lambda *_a, **_kw: {}, raising=False)

    out = asyncio.run(amba_api._get_snapshot(_principal(), "subscription", "sub-1", force=True))
    assert out["throttled"] is True
    assert "429" in out["error"]
    assert json.loads(path.read_text(encoding="utf-8")) == {}, "a failure must never be cached"


# ------------------------------------------------------------------------- admin settings
def test_arg_pacing_settings_are_clamped_to_sane_bounds():
    from app.core.app_settings import DEFAULTS

    assert DEFAULTS["arg_max_queries_per_window"] == 12, "leave headroom under Azure's ~15/5s"
    assert DEFAULTS["arg_rate_window_seconds"] == 5
    assert DEFAULTS["arg_rate_limit_enabled"] is True


def test_limits_reader_clamps_hostile_values(monkeypatch):
    monkeypatch.setattr(
        "app.core.app_settings.load_settings",
        lambda: {"arg_rate_limit_enabled": True, "arg_max_queries_per_window": 10_000, "arg_rate_window_seconds": 0},
    )
    enabled, max_q, window = arg_throttle._limits()
    assert enabled is True
    assert max_q == 100
    assert window == 0.5
