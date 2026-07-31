"""Per-domain Entra collectors.

Each collector is independently permission-gated and independently refreshable, so a
missing ``AccessReview.Read.All`` degrades governance **only**. Every collector:

* returns the standard envelope from :mod:`app.entra.model` (never raises to the caller),
* names the exact missing permission when it is blind,
* reports ``truncated`` when a cap was hit rather than silently returning a short list.

Collection order matters only for cosmetics (progress readability); no collector reads
another's output. Where a collector needs group membership (role-granting groups,
Conditional-Access-referenced groups) it expands just that bounded set itself rather than
building a tenant-wide membership index that no screen would use.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Sequence

from app.entra import model
from app.entra.graphclient import GraphClient, GraphError, GraphPermissionError, GraphRequest

log = logging.getLogger("app.entra.collectors")


@dataclass
class CollectContext:
    """Everything a collector needs besides the Graph client."""

    tenant_id: str
    connection_id: str = ""
    licences: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, Any] = field(default_factory=dict)
    # Caps / windows, sourced from app settings.
    max_users: int = 250_000
    max_groups: int = 100_000
    max_apps: int = 50_000
    # 0 means NO CAP. Ownership is the input to "who is accountable for this object", and a
    # capped ownership scan reports a subset of the estate as fully covered — the exact
    # silent-incompleteness failure this product exists to surface, committed by the product
    # itself. The fan-out is batched at 20 per request with concurrent chunks, so a
    # tenant-wide scan is a few minutes rather than an afternoon.
    max_owner_lookups: int = 0
    max_group_expansions: int = 500
    expiry_window_days: int = 90
    stale_days: int = 90
    signin_lookback_days: int = 30
    # How far back activation sessions are collected. Deliberately longer than the 30 days
    # Graph retains directory audits for: the activation sources reach further back, and the
    # ledger keeps whatever we saw, so the window is not what limits history.
    activation_lookback_days: int = 90
    # Longest activation window a PIM policy may allow before the health grid marks it
    # unbounded. Mirrors ``SignalContext.max_activation_hours`` so the collector's score and
    # the signal's finding agree on what "too long" means.
    max_activation_hours: float = 8.0
    beta: bool = False
    progress: Callable[[str, str], Awaitable[None]] | None = None

    async def say(self, level: str, message: str) -> None:
        if self.progress is not None:
            try:
                await self.progress(level, message)
            except Exception:  # noqa: BLE001 - progress is cosmetic, never fail a scan
                pass

    def domain_permitted(self, domain: str) -> tuple[bool, list[str], str]:
        state = (self.permissions.get("domains") or {}).get(domain) or {}
        if not self.permissions:
            return True, [], ""
        if state.get("ok", True):
            return True, [], ""
        return False, list(state.get("missing") or []), str(state.get("reason") or "")

    def holds(self, scope: str) -> bool:
        """Does the token already carry this application permission?

        Used to tell "you have not granted this" apart from "you granted it and Microsoft
        has not applied it yet". Those are the same 403 but opposite instructions, and
        telling someone to grant a scope they just granted is how this screen loses them.
        """
        return scope in set(self.permissions.get("granted") or [])


async def guarded(
    domain: str,
    ctx: CollectContext,
    fn: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Run a collector body with the standard error boundary + timing."""
    ok, missing, reason = ctx.domain_permitted(domain)
    if not ok:
        await ctx.say("warn", f"{domain}: skipped — {reason or 'permission not granted'}")
        return model.blind_payload(domain, reason or "Permission not granted.", missing)

    started = time.monotonic()
    try:
        payload = await fn()
    except GraphPermissionError as exc:
        await ctx.say("warn", f"{domain}: forbidden — {exc.message[:160]}")
        return model.blind_payload(domain, exc.message[:400], missing or _guess_scope(domain))
    except GraphError as exc:
        await ctx.say("error", f"{domain}: {exc}")
        return model.error_payload(domain, str(exc)[:400])
    except Exception as exc:  # noqa: BLE001 - one domain must never fail the snapshot
        log.exception("entra collector %s crashed", domain)
        await ctx.say("error", f"{domain}: {type(exc).__name__}: {str(exc)[:200]}")
        return model.error_payload(domain, f"{type(exc).__name__}: {str(exc)[:300]}")
    payload["duration_ms"] = int((time.monotonic() - started) * 1000)
    return payload


def _guess_scope(domain: str) -> list[str]:
    from app.entra.permissions_probe import DOMAIN_REQUIREMENTS

    groups = DOMAIN_REQUIREMENTS.get(domain) or []
    return [" or ".join(g) for g in groups]


# --------------------------------------------------------------------------- helpers
# How many per-object sub-requests to dispatch before reporting progress. A tenant-wide
# owner fan-out is the longest single step in a collection, and a progress bar that does
# not move is indistinguishable from one that has hung.
_PROGRESS_EVERY = 2_000


async def batch_collection(
    client: GraphClient,
    ids: Sequence[str],
    url_for: Callable[[str], str],
    *,
    cap: int | None = None,
    ctx: "CollectContext | None" = None,
    label: str = "",
) -> tuple[dict[str, list[dict[str, Any]]], bool, int]:
    """Fan a per-object collection GET out through ``$batch``.

    Returns ``(by_id, truncated, forbidden_count)``. Sub-request failures are recorded, not
    raised — one 403 on an owners lookup must not lose the other 19 results.

    ``cap=None`` means *collect everything*, which is the default for a reason: a capped
    ownership scan silently reports a subset of the estate as fully covered. Pass a cap only
    where a genuine upper bound exists.
    """
    wanted = list(dict.fromkeys(i for i in ids if i))
    truncated = False
    if cap is not None and cap > 0 and len(wanted) > cap:
        wanted = wanted[:cap]
        truncated = True
    out: dict[str, list[dict[str, Any]]] = {}
    forbidden = 0
    if not wanted:
        return out, truncated, forbidden

    total = len(wanted)
    for start in range(0, total, _PROGRESS_EVERY):
        window = wanted[start:start + _PROGRESS_EVERY]
        reqs = [GraphRequest(id=str(n), url=url_for(oid)) for n, oid in enumerate(window)]
        responses = await client.batch(reqs)
        for req, resp in zip(reqs, responses):
            oid = window[int(req.id)]
            if resp.forbidden:
                forbidden += 1
                continue
            out[oid] = resp.value()
        if ctx is not None and total > _PROGRESS_EVERY:
            done = min(start + _PROGRESS_EVERY, total)
            await ctx.say("info", f"{label or 'Batch'}: {done:,}/{total:,} resolved…")
    return out, truncated, forbidden


def iso(value: Any) -> str:
    return str(value or "")


def clip(text: Any, limit: int = 160) -> str:
    """Truncate at a word boundary with an ellipsis.

    Slicing a Graph error at a fixed character count produced notes that ended mid-word
    ("...require an Entra ID Governance licen"), which reads like the product lost the rest
    of the sentence rather than chose to shorten it.
    """
    value = " ".join(str(text or "").split())
    if len(value) <= limit:
        return value
    cut = value[:limit]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" .,;:") + "…"


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
