"""Guards against tenant-specific identifiers reaching shipped prompts and personas.

This is an open-source product: everything under ``backend/app`` is published, and the
starter sub-agents are seeded into every install. A subscription GUID, a tenant id, or an
Azure connection nickname in that text is meaningless to every other operator and exposes
detail about the tenant it came from.

Two rules, both structural:

- **No GUIDs** in prompt text or seeded personas. Nothing in a reusable persona should name
  a real tenant, subscription, connection or principal.
- **No named default connection.** Personas must say "the default Azure connection", never a
  nickname that only exists in one tenant.

The second rule matters as much as the first. Scrubbing GUIDs alone is not enough: a model
grounded on a real connection list will happily write the connection's *name* next to its
id, and a GUID-only scrub leaves the name behind. ``strip_tenant_specifics`` removes both.

Deliberately NOT marked slow — a leak guard that only runs in an opt-in suite is not a guard.
The rules here are structural on purpose: a denylist of the exact strings you are trying to
keep out of the repo would put them in the repo.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.automations import agents
from app.automations.agent_designer import strip_tenant_specifics

_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_APP_ROOT = Path(agents.__file__).resolve().parents[1]

# Files whose entire purpose is text sent to a model. A GUID here is always a leak: unlike
# `amba/data/amba_catalog.json` (public AMBA alert ids) or `identity/appregs.py` (well-known
# Microsoft first-party app ids), prompt text has no legitimate reason to name a real
# tenant, subscription, or principal.
_PROMPT_SURFACES = (
    "agent/prompts.py",
    "core/ai_prompts.py",
)

# Phrasings that assign a DEFAULT connection/tenant, capturing whatever is named — e.g.
# "Default tenant is `<nickname>`" or "Default to <nickname>; switch to …".
_ASSIGNS_A_DEFAULT = re.compile(
    r"default\s+(?:azure\s+)?(?:tenant|connection)\s+is\s+(?P<name>\**`?[\w-]+`?\**)"
    r"|default\s+to\s+(?P<alt>\**`?[\w-]+`?\**)\s*[;,.]",
    re.IGNORECASE,
)
# Words that make the phrase generic rather than a nickname ("is the default connection").
_GENERIC_REFERENTS = {"the", "a", "an", "your", "whichever", "whatever", "its", "this"}


def _connection_names_in(text: str) -> list[str]:
    """Connection nicknames a persona hardcodes as its default, if any."""
    names: list[str] = []
    for match in _ASSIGNS_A_DEFAULT.finditer(text or ""):
        raw = match.group("name") or match.group("alt") or ""
        token = raw.strip("*`").strip()
        if token and token.lower() not in _GENERIC_REFERENTS:
            names.append(token)
    return names


# ---------------------------------------------------------------- shipped prompt surfaces
@pytest.mark.parametrize("relative", _PROMPT_SURFACES)
def test_prompt_text_names_no_real_azure_identifier(relative):
    path = _APP_ROOT / relative
    if not path.exists():
        pytest.skip(f"{relative} not present")
    found = _GUID.findall(path.read_text(encoding="utf-8"))
    assert not found, f"{relative} hardcodes GUID(s) into prompt text: {found}"


def test_starter_agent_instructions_carry_no_guids():
    """A GUID in a reusable persona is never correct — no tenant, subscription, connection
    or principal id belongs in instructions seeded into someone else's install."""
    offenders = {
        aid: _GUID.findall(a.get("instructions", ""))
        for aid, a in agents._read_builtin_seed().items()
        if _GUID.search(a.get("instructions", ""))
    }
    assert not offenders, f"starter agents contain GUIDs: {offenders}"


def test_starter_agents_do_not_name_a_specific_connection():
    """Personas must say "the default Azure connection", never a nickname that exists in only
    one tenant — the seed ships verbatim to every install."""
    offenders = {
        aid: hits
        for aid, agent in agents._read_builtin_seed().items()
        if (hits := _connection_names_in(agent.get("instructions", "")))
    }
    assert not offenders, f"starter agents name a specific connection: {offenders}"


@pytest.mark.parametrize("named", [
    "- **Connections.** Default tenant is `acme-sp` (id). If a resource is missing, say so.",
    "- The default Azure connection is `acme-sp` unless the user names another.",
    "- **Pick the right connection.** Default to acme-sp; switch to other-sp only on request.",
    "Default Azure connection is **acme-sp**; use **other-sp** only if the user points at it.",
])
def test_guard_catches_every_connection_naming_phrasing(named):
    """These are the shapes a model reaches for when it hardcodes a default connection. A
    guard that cannot fail is worthless, so pin each one explicitly."""
    assert _connection_names_in(named), f"guard missed a naming phrasing: {named}"


@pytest.mark.parametrize("fixed", [
    "- **Connections.** Use the default Azure connection unless told otherwise.",
    "- Use the default Azure connection unless the user names another.",
    "- **Pick the right connection.** Use the default Azure connection; switch only on request.",
    "Use the default Azure connection unless the user points at another.",
    "- **Confirm scope.** If several Azure connections are configured, use the default.",
])
def test_guard_accepts_the_generic_replacements(fixed):
    assert not _connection_names_in(fixed), f"guard false-positived on: {fixed}"


# ------------------------------------------------------------------------- the scrubber
def test_scrubber_removes_a_guid_and_its_wrapper():
    out = strip_tenant_specifics("Use connection (`11111111-2222-3333-4444-555555555555`).")
    assert "11111111" not in out
    assert out == "Use connection."


def test_scrubber_removes_a_connection_name_including_bold_and_backticks():
    text = "Default to **acme-sp**; fall back to `acme-sp` only on request."
    out = strip_tenant_specifics(text, ["acme-sp"])
    assert "acme-sp" not in out
    assert out.count("the configured Azure connection") == 2


def test_scrubber_removes_the_name_left_behind_after_a_guid_is_stripped():
    """The case a GUID-only scrub misses: the nickname sits right beside the id."""
    out = strip_tenant_specifics(
        "The default tenant is **acme-sp** (`11111111-2222-3333-4444-555555555555`).",
        ["acme-sp"],
    )
    assert "acme-sp" not in out and "11111111" not in out


def test_scrubber_leaves_generic_connection_names_alone():
    """Redacting a connection literally named 'Production' would mangle the whole persona —
    worse than the leak it prevents."""
    text = "Investigate the Production subscription and compare against Dev."
    assert strip_tenant_specifics(text, ["Production", "Dev"]) == text


def test_scrubber_ignores_very_short_names():
    text = "Scale the app to 3 replicas."
    assert strip_tenant_specifics(text, ["app"]) == text


def test_scrubber_does_not_match_inside_a_longer_word():
    text = "The acme-sp-backup connection is separate."
    assert strip_tenant_specifics(text, ["acme-sp"]) == text


def test_scrubber_is_a_no_op_when_there_is_nothing_to_strip():
    text = "Use the default Azure connection and state which subscription you queried."
    assert strip_tenant_specifics(text, ["acme-sp"]) == text
    assert strip_tenant_specifics(text) == text


@pytest.mark.parametrize("value", ["", None])
def test_scrubber_tolerates_empty_input(value):
    assert strip_tenant_specifics(value or "", ["acme-sp"]) == ""
