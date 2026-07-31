"""Regression tests for the security hardening pass driven by the MDASH harness.

Each test pins a specific mechanism so a later refactor cannot quietly undo it:

- CWE-208: login must not leak "does this username exist" through response latency.
- CWE-611 / CWE-776: the Azure Updates feed parser must refuse entity expansion.
- CWE-613: changing a password must revoke the account's other live sessions.
- CWE-22:  a tenant id must not be able to steer cache writes out of the cache root.
- CWE-327: non-cryptographic SHA-1 uses must declare ``usedforsecurity=False`` so the
           app still starts on a FIPS-enforcing host.
"""
from __future__ import annotations

import hashlib
import inspect
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth.passwords import burn_password_time, hash_password, verify_password
from app.auth.service import revoke_sessions_for_user_except
from app.core.db import Base
from app.models.auth import Session, User
from app.radar.feed import _parse_rss
from app.rbac.cache import _blob_path, _safe_segment

# --------------------------------------------------------------- CWE-208 login timing


def test_burn_password_time_costs_about_the_same_as_a_real_verification():
    """The unknown-user branch must pay for an Argon2 hash like the wrong-password branch.

    Without this, "no such user" returns in microseconds while "user exists, wrong
    password" takes the full Argon2id cost, so response latency enumerates valid
    usernames even though both replies are the identical generic error.
    """
    real_hash = hash_password("correct horse battery staple")

    # Warm up: first Argon2 call in a process pays one-off setup we don't want to measure.
    verify_password(real_hash, "wrong")
    burn_password_time("wrong")

    def _median(fn, rounds=5):
        samples = []
        for _ in range(rounds):
            start = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - start)
        return sorted(samples)[len(samples) // 2]

    wrong_password = _median(lambda: verify_password(real_hash, "wrong"))
    unknown_user = _median(lambda: burn_password_time("wrong"))

    assert unknown_user > 0
    # Same order of magnitude is what defeats the oracle; exact parity is not achievable
    # and not required. A regression (an early `return` before the burn) would put the
    # unknown-user branch orders of magnitude below this floor.
    assert unknown_user > wrong_password / 5, (
        f"unknown-user branch is too cheap: {unknown_user:.4f}s vs {wrong_password:.4f}s"
    )


def test_login_burns_password_time_on_the_unknown_user_branch():
    """Pin the call site, not just the helper — the helper is useless if unused."""
    from app.api import auth as auth_api

    source = inspect.getsource(auth_api.login)
    unknown_branch = source.split('if user is None or user.status != "active":')[1]
    call = unknown_branch.split("raise fail")[0]
    assert "burn_password_time" in call, "login() no longer equalises the unknown-user path"


# ------------------------------------------------- CWE-611 / CWE-776 feed XML parsing


def test_feed_parser_refuses_entity_expansion_bomb():
    """A billion-laughs payload must never be expanded.

    The feed URL is an admin app-setting, so a misconfigured or hijacked host is in scope.
    With ``resolve_entities=False`` the parser reads the document but treats every custom
    entity as empty, so the 10^4-character expansion of ``&d;`` never materialises. The
    security property is the absence of expansion, not the rejection of the document.
    """
    bomb = """<?xml version="1.0"?>
<!DOCTYPE rss [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<rss><channel><item>
  <title>retirement &d;</title><description>&d;</description><link>https://x</link>
</item></channel></rss>"""
    items = _parse_rss(bomb)
    rendered = "".join(f"{i.get('title', '')}{i.get('summary', '')}" for i in items)
    assert "aaaaaaaaaa" not in rendered, "entity was expanded — billion laughs is reachable"
    assert len(rendered) < 200, f"output grew to {len(rendered)} chars — expansion occurred"


def test_feed_parser_refuses_external_entity():
    """Classic XXE: an external entity must never be resolved."""
    xxe = """<?xml version="1.0"?>
<!DOCTYPE rss [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<rss><channel><item>
  <title>retirement</title><description>&xxe;</description><link>https://x</link>
</item></channel></rss>"""
    items = _parse_rss(xxe)
    assert all("root:" not in (i.get("summary") or "") for i in items)


def test_feed_parser_still_reads_a_normal_retirement_item():
    """Hardening must not break the actual feature."""
    ok = """<?xml version="1.0"?>
<rss><channel><item>
  <title>Azure Front Door retirement</title>
  <description>&lt;p&gt;This service is being retired.&lt;/p&gt;</description>
  <link>https://azure.microsoft.com/updates/x</link>
</item></channel></rss>"""
    items = _parse_rss(ok)
    assert len(items) == 1
    assert items[0]["title"] == "Azure Front Door retirement"
    assert "<p>" not in items[0]["summary"]


# ----------------------------------------------------------- CWE-613 session lifetime


@pytest.mark.asyncio
async def test_password_change_revokes_other_sessions_but_keeps_the_current_one():
    """Changing a password is how a user evicts a stolen session cookie.

    If sibling sessions survive, the hijacked session outlives the credential it was
    obtained with and stays valid until its own absolute expiry.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        from datetime import datetime, timedelta, timezone

        expiry = datetime.now(timezone.utc) + timedelta(days=1)
        user_id = str(uuid.uuid4())
        other_id = str(uuid.uuid4())
        keep, sibling, unrelated = (str(uuid.uuid4()) for _ in range(3))

        async with maker() as db:
            db.add(User(id=user_id, username="victim", email="victim@example.test", status="active", auth_source="local"))
            db.add(
                User(
                    id=other_id,
                    username="bystander",
                    email="bystander@example.test",
                    status="active",
                    auth_source="local",
                )
            )
            db.add(Session(id=keep, user_id=user_id, expires_at=expiry, revoked=False))
            db.add(Session(id=sibling, user_id=user_id, expires_at=expiry, revoked=False))
            db.add(Session(id=unrelated, user_id=other_id, expires_at=expiry, revoked=False))
            await db.commit()

            revoked = await revoke_sessions_for_user_except(db, user_id, keep)
            assert revoked == 1

            assert (await db.get(Session, keep)).revoked is False, "logged the user out of their own browser"
            assert (await db.get(Session, sibling)).revoked is True, "stolen session survived"
            assert (await db.get(Session, unrelated)).revoked is False, "hit another user's session"
    finally:
        await engine.dispose()


def test_change_password_endpoint_revokes_sibling_sessions():
    """Pin the call site so the helper cannot be orphaned by a refactor."""
    from app.api import auth as auth_api

    source = inspect.getsource(auth_api.change_password)
    assert "revoke_sessions_for_user_except" in source


# ------------------------------------------------------------- CWE-22 cache path safety


@pytest.mark.parametrize(
    "hostile",
    ["../../../../etc", "..\\..\\windows\\system32", "a/b/c", "....//....//x", "/abs/path", ".."],
)
def test_blob_path_stays_inside_the_cache_root(hostile):
    """tenant_id reaches the cache from a stored connection record and is not validated
    on the way in, so it must be neutralised before it becomes a path segment."""
    root = _blob_path("00000000-0000-0000-0000-000000000000", "scope").parent.parent
    resolved = _blob_path(hostile, "some-scope").resolve()
    assert resolved.is_relative_to(root.resolve()), f"{hostile!r} escaped to {resolved}"
    assert ".." not in resolved.parts


def test_safe_segment_preserves_ordinary_tenant_guids():
    guid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    assert _safe_segment(guid) == guid
    assert _safe_segment("") == "default"
    assert _safe_segment("...") == "default"


def test_blob_paths_for_different_tenants_do_not_collide():
    a = _blob_path("tenant-a", "scope")
    b = _blob_path("tenant-b", "scope")
    assert a != b


# ------------------------------------------------------------------ CWE-327 SHA-1 usage


def test_non_cryptographic_sha1_call_sites_declare_usedforsecurity_false():
    """On a FIPS-enforcing host, hashlib.sha1() without the flag raises and the module
    fails to import — turning a cosmetic lint into an outage."""
    app_dir = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in app_dir.rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "hashlib.sha1(" in line and "usedforsecurity" not in line:
                offenders.append(f"{path.relative_to(app_dir)}:{number}")
    assert not offenders, "SHA-1 without usedforsecurity=False: " + ", ".join(offenders)


def test_usedforsecurity_flag_does_not_change_the_digest():
    """The flag is a policy declaration; existing cache keys and ids must stay stable."""
    raw = b"scope-identifier"
    assert (
        hashlib.sha1(raw, usedforsecurity=False).hexdigest()  # noqa: S324 - identity only
        == hashlib.sha1(raw).hexdigest()  # noqa: S324 - identity only
    )
