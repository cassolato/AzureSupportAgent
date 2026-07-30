"""LIVE Azure Resource Graph throttling drill.

Deliberately saturates the ARG query quota for the signed-in principal to prove the 429
handling actually works against real Azure — not just against mocked responses.

Everything here is **read-only**: only `Resources | project id | limit 1` queries are sent. The
only side effect is briefly exhausting the ARG query budget for this identity, which Azure
resets on its own within seconds.

Phases
------
A. Limiter OFF, retries OFF   -> reproduces the original bug: 429s reach the caller as hard errors.
B. Limiter OFF, retries ON    -> proves retry/backoff recovers from those same 429s.
C. Limiter ON  (12 per 5 s)   -> proves pacing prevents the 429s in the first place.
D. Fleet simulation           -> N concurrent AMBA-shaped collections all complete.

Usage:
    python backend/scripts/arg_throttle_drill.py [--burst 45] [--fleet 4]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# The Windows console defaults to cp1252, which can't encode box-drawing/dash characters.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from app.azure import arg_throttle  # noqa: E402
from app.azure.arm import query_resource_graph  # noqa: E402

PROBE = "Resources | project id | limit 1"

_PASS = "PASS"
_FAIL = "FAIL"
_results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    _results.append((name, _PASS if ok else _FAIL, detail))
    print(f"  [{_PASS if ok else _FAIL}] {name}" + (f" - {detail}" if detail else ""))
    return ok


def arm_token() -> str:
    out = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://management.azure.com", "-o", "json"],
        capture_output=True, text=True, shell=True, check=True,
    )
    return json.loads(out.stdout)["accessToken"]


def set_limits(enabled: bool, max_q: int = 12, window: float = 5.0) -> None:
    """Override the admin-configured pacing for one phase of the drill."""
    arg_throttle._limits = lambda: (enabled, max_q, window)  # type: ignore[assignment]


async def burst(token: str, count: int, *, max_retries: int) -> tuple[int, int, float]:
    """Fire `count` concurrent ARG queries. Returns (ok, throttled_errors, seconds)."""
    arg_throttle.reset()
    start = time.monotonic()
    results = await asyncio.gather(
        *(query_resource_graph(token, PROBE, max_retries=max_retries) for _ in range(count))
    )
    elapsed = time.monotonic() - start
    ok = sum(1 for _rows, err in results if err is None)
    throttled = sum(1 for _rows, err in results if err and "429" in err)
    return ok, throttled, elapsed


async def phase_a(token: str, count: int) -> None:
    print(f"\n-- Phase A | limiter OFF, retries OFF ({count} concurrent) " + "-" * 20)
    print("   Reproducing the original defect: an unpaced, unretried burst.")
    set_limits(False)
    ok, throttled, elapsed = await burst(token, count, max_retries=0)
    print(f"   {ok} ok / {throttled} throttled in {elapsed:.2f}s")
    check(
        "A1 unpaced burst provokes real ARG throttling",
        throttled > 0,
        f"{throttled} queries returned 429 RateLimiting",
    )


async def phase_b(token: str, count: int) -> None:
    print(f"\n-- Phase B | limiter OFF, retries ON ({count} concurrent) " + "-" * 20)
    print("   Same burst, but the retry/backoff path is allowed to do its job.")
    set_limits(False)
    ok, throttled, elapsed = await burst(token, count, max_retries=5)
    print(f"   {ok} ok / {throttled} throttled in {elapsed:.2f}s")
    check("B1 retry recovers every throttled query", throttled == 0 and ok == count,
          f"{ok}/{count} succeeded")
    check("B2 recovery cost real backoff time", elapsed > 0.5, f"{elapsed:.2f}s")


async def phase_c(token: str, count: int) -> None:
    print(f"\n-- Phase C | limiter ON at 12 per 5s ({count} concurrent) " + "-" * 20)
    print("   Proactive pacing should keep us under the quota entirely.")
    set_limits(True, 12, 5.0)
    ok, throttled, elapsed = await burst(token, count, max_retries=5)
    observed = sum(int(v["throttled"]) for v in arg_throttle.stats().values())
    print(f"   {ok} ok / {throttled} throttled in {elapsed:.2f}s (bucket saw {observed} throttle events)")
    check("C1 every query succeeded", ok == count, f"{ok}/{count}")
    check("C2 pacing prevented throttling outright", observed == 0 and throttled == 0)
    # 45 queries at 12 per 5s needs at least 3 full windows to drain.
    expected_floor = ((count - 1) // 12) * 5.0
    check("C3 the burst was genuinely spread across windows", elapsed >= expected_floor * 0.8,
          f"{elapsed:.2f}s >= ~{expected_floor:.1f}s")


async def phase_d(fleet: int) -> None:
    print(f"\n-- Phase D | fleet simulation ({fleet} concurrent AMBA collections) " + "-" * 12)
    print("   The real code path: concurrent coverage scans sharing one principal's budget.")
    from app.amba.collector import collect_coverage

    set_limits(True, 12, 5.0)
    arg_throttle.reset()
    account = json.loads(
        subprocess.run(["az", "account", "show", "-o", "json"], capture_output=True, text=True,
                       shell=True, check=True).stdout
    )
    sub = account["id"]
    # "default_chain" is what the deployed Container App uses (managed identity -> REST). Local
    # dev has no managed identity, so it falls back to the az CLI token — same REST code path.
    conn = {"auth_method": "default_chain", "tenant_id": account["tenantId"]}

    start = time.monotonic()
    snaps = await asyncio.gather(*(
        collect_coverage(conn, scope_kind="subscription", scope_id=sub, workload=None)
        for _ in range(fleet)
    ))
    elapsed = time.monotonic() - start

    errored = [s for s in snaps if s.get("error")]
    throttled = [s for s in snaps if s.get("throttled")]
    for i, s in enumerate(snaps):
        kpis = s.get("kpis") or {}
        print(f"   scan {i + 1}: coverage={s.get('coverage_pct')}% "
              f"resources={kpis.get('total_resources_in_baseline')} "
              f"error={s.get('error') or 'none'}")
    print(f"   completed in {elapsed:.2f}s")
    check("D1 no concurrent scan was throttled into failure", not throttled,
          f"{len(throttled)} throttled")
    check("D2 no concurrent scan errored", not errored,
          errored[0].get("error", "")[:120] if errored else "")
    check("D3 all scans agree on the resource count (deterministic under load)",
          len({(s.get("kpis") or {}).get("total_resources_in_baseline") for s in snaps}) == 1)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--burst", type=int, default=45, help="concurrent queries per burst phase")
    ap.add_argument("--fleet", type=int, default=4, help="concurrent AMBA collections in phase D")
    args = ap.parse_args()

    print("=" * 78)
    print("LIVE ARG THROTTLING DRILL - read-only, saturates this principal's query quota")
    print("=" * 78)
    token = arm_token()

    await phase_a(token, args.burst)
    # Let Azure's own sliding window drain fully so each phase starts from a clean budget —
    # otherwise a phase inherits the previous phase's exhaustion and the result is meaningless.
    await asyncio.sleep(20)
    await phase_b(token, args.burst)
    await asyncio.sleep(20)
    await phase_c(token, args.burst)
    await asyncio.sleep(20)
    await phase_d(args.fleet)

    failed = [r for r in _results if r[1] == _FAIL]
    print("\n" + "=" * 78)
    print(f"{len(_results) - len(failed)}/{len(_results)} checks passed")
    for name, _status, detail in failed:
        print(f"  FAILED: {name} - {detail}")
    print("=" * 78)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
