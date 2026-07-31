"""Signal-quality regressions found against a live tenant.

A signal that fires on objects nobody can act on trains people to ignore the whole product.
Each case here came from real output, not from imagination.
"""
from __future__ import annotations

from app.entra.signals import SignalContext
from app.entra.signal_defs.app import SPECS as APP_SPECS

_OWNERLESS = next(s for s in APP_SPECS if s.id == "app.ownerless")


def _snapshot(apps):
    return {"apps": {"applications": apps, "service_principals": [],
                     "capabilities": {"owners": True, "granted_permissions": True,
                                      "delegated_grants": True, "federated_credentials": True},
                     "counts": {}}}


def _app(name, **kw):
    base = {"object_id": f"o-{name}", "app_id": f"a-{name}", "display_name": name,
            "owner_ids": [], "owners_known": True, "credentials": [], "redirect_uris": [],
            "requested_permissions": [], "federated_credentials": [], "created_at": "",
            "sign_in_audience": "AzureADMyOrg", "multi_tenant": False, "verified_publisher": ""}
    base.update(kw)
    return base


def test_ownerless_flags_a_normal_application():
    findings = _OWNERLESS.evaluate(_snapshot([_app("Payroll Integration")]), SignalContext())
    assert [f["object_name"] for f in findings] == ["Payroll Integration"]


def test_ownerless_skips_microsoft_managed_registrations():
    """Telling an admin to assign an owner to an app Microsoft says not to modify is bad
    advice, and a wall of unactionable findings is how a signal gets ignored."""
    apps = [
        _app("aad-extensions-app. Do not modify. Used by AAD for storing user data."),
        _app("Some Connector. Do Not Modify"),
        _app("Payroll Integration"),
    ]
    findings = _OWNERLESS.evaluate(_snapshot(apps), SignalContext())
    assert [f["object_name"] for f in findings] == ["Payroll Integration"]


def test_ownerless_respects_owners_known():
    """An app whose owners were never looked up must not be reported as ownerless."""
    findings = _OWNERLESS.evaluate(
        _snapshot([_app("Unchecked", owners_known=False)]), SignalContext())
    assert findings == []


def test_ownerless_ignores_apps_that_have_owners():
    findings = _OWNERLESS.evaluate(
        _snapshot([_app("Owned", owner_ids=["u1"])]), SignalContext())
    assert findings == []


# ------------------------------------------------------------------ human-readable names
def test_a_principal_label_never_degrades_to_a_bare_guid():
    """A critical finding titled with a raw GUID is unusable: the operator cannot tell who
    it is without leaving the product, so the finding reads as noise. Seen live on
    priv.cross_plane_power."""
    from app.entra.signal_defs.priv_pim import _label

    guid = "a928ebfd-57eb-4ec2-9c64-1a70dbdda405"
    data = {
        "people": {
            "users": [{"id": "u1", "upn": "alice@x", "display_name": "Alice"}],
            "groups": [{"id": "g1", "display_name": "Tenant Admins"}],
        },
        "apps": {"service_principals": [{"object_id": "sp1", "display_name": "CI Deploy"}]},
    }
    assert _label(data, "u1") == "alice@x"
    assert _label(data, "sp1") == "CI Deploy (service principal)"
    assert _label(data, "g1") == "Tenant Admins (group)"
    assert _label(data, guid, "From RBAC") == "From RBAC"

    # The last resort still says what happened rather than presenting the id as a name.
    unresolved = _label(data, guid)
    assert guid in unresolved
    assert unresolved != guid
    assert "unresolved" in unresolved.lower()


def test_role_holders_that_are_not_users_still_get_a_name():
    """Groups and service principals hold directory roles but never appear in the people
    snapshot, so name resolution has to fall back to what the role assignment carried."""
    from app.entra.signal_defs.priv_pim import _label, entra_power

    data = {
        "people": {"users": [], "groups": []},
        "apps": {"service_principals": []},
        "roles": {
            "assignments": [{"principal_id": "g-ops", "principal_name": "Ops Admins",
                             "role_name": "Global Administrator", "role_privileged": True}],
            "group_derived": [], "eligible": [],
        },
    }
    assert _label(data, "g-ops") == "Ops Admins"
    assert entra_power(data)["g-ops"]["name"] == "Ops Admins"


def test_a_nameless_object_does_not_short_circuit_into_a_bare_guid():
    """The service-principal and group branches used to return the raw id when the object
    they matched carried no displayName, which bypassed the honest fallback below them and
    put '55ce7671-… holds a conflicting role pair' at the top of the critical queue."""
    from app.entra.signal_defs.priv_pim import _label

    for domain_data in (
        {"apps": {"service_principals": [{"object_id": "x", "display_name": ""}]}},
        {"people": {"users": [], "groups": [{"id": "x", "display_name": ""}]}},
    ):
        assert _label(domain_data, "x") == "unresolved principal x"


def test_the_id_is_never_accepted_as_its_own_name():
    """Azure role assignments carry the object id in the name field when ARM could not
    resolve the principal either. Taken as a fallback, that GUID beat every real lookup and
    was printed as though it were a name."""
    from app.entra.signal_defs.priv_pim import _label

    guid = "55ce7671-d10c-4187-bde4-275e1356dbdf"
    data = {"apps": {"service_principals": [{"object_id": guid, "display_name": "Nightly Sync"}]}}
    assert _label(data, guid, guid) == "Nightly Sync (service principal)"
    assert _label({}, guid, guid.upper()) == f"unresolved principal {guid}"


def test_separation_of_duties_names_a_service_principal():
    """The conflict signal only consulted the user index, so every non-user holder — the
    population it most wants to surface — was reported by object id."""
    from app.entra.collectors.roles import SOD_RULES
    from app.entra.signal_defs.priv import SPECS

    role_a, role_b, _ = SOD_RULES[0]
    spec = next(s for s in SPECS if s.id == "priv.sod_conflict")
    data = {
        "people": {"users": [], "groups": []},
        "apps": {"service_principals": [{"object_id": "sp1", "display_name": "Nightly Sync"}]},
        "roles": {
            "assignments": [
                {"principal_id": "sp1", "principal_name": "", "role_name": role_a,
                 "role_privileged": True},
                {"principal_id": "sp1", "principal_name": "", "role_name": role_b,
                 "role_privileged": True},
            ],
            "group_derived": [], "eligible": [],
            "capabilities": {"assignments": True, "eligible": True},
        },
    }
    findings = spec.evaluate(data, SignalContext())
    assert findings, "the conflicting pair should still be reported"
    assert findings[0]["object_name"] == "Nightly Sync (service principal)"
    assert "sp1" not in findings[0]["title"]
