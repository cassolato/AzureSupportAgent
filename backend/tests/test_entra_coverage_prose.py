"""Coverage prose must be readable and every fix link must work.

Two defects this pins:

* Graph answers `roleAssignmentScheduleRequests` with a JSON body, and clipping it dropped a
  truncated `{"errorCode":"PermissionScopeNotGranted"...` into the coverage banner.
* The admin-consent link was a literal `<your-app-registration-client-id>` placeholder, so
  the one action the banner kept recommending led nowhere.
"""
from __future__ import annotations

import inspect

from app.api import entra as entra_api
from app.entra.collectors import activations as activations_mod
from app.entra.collectors import governance as governance_mod
from app.entra.collectors import pim as pim_mod

TENANT = "6711ec7d-31e6-40dc-9bc9-176428a12110"
CLIENT = "318c5cc2-48b1-443d-9833-3d49556e107c"


def _source(module) -> str:
    return inspect.getsource(module)


# ------------------------------------------------------------------ no raw payloads
def test_the_activation_collector_never_echoes_the_graph_json_body():
    """Graph answers roleAssignmentScheduleRequests with JSON, never a sentence.

    Clipping it dropped a truncated `{"errorCode":"PermissionScopeNotGranted"...` into the
    coverage banner — and worse, the truncation hid the part that mattered.
    """
    src = _source(activations_mod)
    assert "clip(exc.message" not in src


def test_no_collector_asks_for_a_write_scope_to_read_activations():
    """The untruncated 403 names only WRITE scopes:

        RoleAssignmentSchedule.ReadWrite.Directory, RoleManagement.ReadWrite.Directory,
        RoleAssignmentSchedule.Remove.Directory

    There is no read-only scope for an app-only token, so asking the operator to grant
    anything here sends them to grant a permission that cannot work. This product is
    read-only and must never request directory write access.
    """
    for module in (activations_mod, pim_mod, governance_mod):
        src = _source(module)
        for scope in ("RoleAssignmentSchedule.ReadWrite", "RoleManagement.ReadWrite",
                      "RoleAssignmentSchedule.Remove"):
            assert f'"{scope}' not in src and f"'{scope}" not in src, (
                f"{module.__name__} asks for the write scope {scope}")


def test_activation_detail_comes_from_the_audit_log():
    """The read-only route to justification, using a scope the product already needs."""
    src = _source(activations_mod)
    assert "auditLogs/directoryAudits" in src
    assert "AuditLog.Read.All" in src


def test_no_collector_note_starts_by_dumping_a_json_object():
    for module in (activations_mod, pim_mod, governance_mod):
        assert '({"' not in _source(module), f"{module.__name__} pastes a JSON body into a note"


# ------------------------------------------------------------------ working fix links
def test_the_consent_url_uses_the_real_client_id():
    url = entra_api._consent_url(TENANT, CLIENT)  # noqa: SLF001 - pinning the fixed link
    assert CLIENT in url
    assert "<" not in url and ">" not in url, "no placeholder may reach a user-facing link"
    assert url.startswith(f"https://login.microsoftonline.com/{TENANT}/adminconsent")


def test_the_consent_url_is_empty_rather_than_broken_when_there_is_no_client_id():
    """A dead link is worse than no link: it teaches people the guidance is wrong."""
    assert entra_api._consent_url(TENANT, "") == ""  # noqa: SLF001


def test_the_app_registration_link_points_at_the_api_permissions_blade():
    url = entra_api._app_registration_url(TENANT, CLIENT)  # noqa: SLF001
    assert CLIENT in url
    assert "CallAnAPI" in url, "must land on API permissions, not the app overview"


def test_the_app_registration_link_is_empty_without_a_client_id():
    assert entra_api._app_registration_url(TENANT, "") == ""  # noqa: SLF001
