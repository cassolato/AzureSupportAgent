"""Granted, but not yet in effect.

Entra issues the `roles` claim as soon as admin consent is recorded, but the Graph resource
can keep refusing for a few minutes. Verified live on 2026-07-31: the token carried
RoleAssignmentSchedule.Read.Directory while roleAssignmentScheduleRequests still answered
403 PermissionScopeNotGranted.

Both states are the same status code and need opposite instructions. Telling someone to grant
a permission they granted sixty seconds ago is the fastest way to make them distrust every
other instruction on the page.
"""
from __future__ import annotations

from app.entra.collectors import CollectContext
from app.entra.collectors.activations import DETAIL_SCOPE
from app.entra.collectors.pim import ACTIVATION_SCOPE


def _ctx(granted: list[str]) -> CollectContext:
    return CollectContext(tenant_id="t", permissions={"granted": granted, "domains": {}})


def test_the_two_collectors_agree_on_the_scope_name():
    """They deduplicate into one blocker row, which only works if the strings match."""
    assert DETAIL_SCOPE == ACTIVATION_SCOPE


def test_holds_is_true_when_the_token_carries_the_scope():
    assert _ctx([DETAIL_SCOPE]).holds(DETAIL_SCOPE) is True


def test_holds_is_false_when_it_does_not():
    assert _ctx(["Directory.Read.All"]).holds(DETAIL_SCOPE) is False


def test_holds_is_false_when_permissions_are_unknown():
    """An unknown permission set must not be read as 'you already have it'."""
    assert _ctx([]).holds(DETAIL_SCOPE) is False
    assert CollectContext(tenant_id="t").holds(DETAIL_SCOPE) is False
