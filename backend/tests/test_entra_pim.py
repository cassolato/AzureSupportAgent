"""Privileged Identity Management (P3) and Application 360 (P4).

Two areas that are easy to get subtly wrong: PIM's rule model (where the *_EndUser_Assignment
suffix decides whether a rule governs activation or administration) and the cross-plane join
(where a stale Azure RBAC cache must never be presented as current).
"""
from __future__ import annotations

import pytest

from app.entra.collectors import pim as pim_collector
from app.entra.collectors.apps import RISK_COMPONENTS, risk_score
from app.entra.signals import SignalContext, SignalUnavailable
from app.entra.signal_defs.priv_pim import SPECS as PIM_SPECS

_SPEC = {s.id: s for s in PIM_SPECS}


# ============================================================== duration + rule decoding
@pytest.mark.parametrize(("value", "hours"), [
    ("PT8H", 8.0), ("PT30M", 0.5), ("P1D", 24.0), ("PT1H30M", 1.5), ("P1DT2H", 26.0),
    ("", None), ("garbage", None),
])
def test_duration_parsing(value, hours):
    assert pim_collector.parse_duration_hours(value) == hours


def _rule(odata: str, rid: str, **kw):
    return {"@odata.type": f"#microsoft.graph.unifiedRoleManagementPolicy{odata}", "id": rid, **kw}


def test_enablement_rule_decodes_activation_controls():
    health = pim_collector._decode_rules([  # noqa: SLF001 - internal by design
        _rule("EnablementRule", "Enablement_EndUser_Assignment",
              enabledRules=["MultiFactorAuthentication", "Justification"]),
    ])
    assert health["mfa_on_activation"] is True
    assert health["justification_required"] is True
    assert health["ticket_required"] is False


def test_admin_scoped_rules_do_not_count_as_activation_controls():
    """`_Admin_*` rules govern what an administrator may configure, which is a different
    question from what a user must do to activate."""
    health = pim_collector._decode_rules([  # noqa: SLF001
        _rule("EnablementRule", "Enablement_Admin_Assignment",
              enabledRules=["MultiFactorAuthentication", "Justification"]),
    ])
    assert health["mfa_on_activation"] is False
    assert health["justification_required"] is False


def test_approval_rule_counts_approvers():
    health = pim_collector._decode_rules([  # noqa: SLF001
        _rule("ApprovalRule", "Approval_EndUser_Assignment", setting={
            "isApprovalRequired": True,
            "approvalStages": [{"primaryApprovers": [{"id": "a"}, {"id": "b"}]}],
        }),
    ])
    assert health["approval_required"] is True
    assert health["approver_count"] == 2


def test_expiration_rules_split_activation_from_eligibility():
    health = pim_collector._decode_rules([  # noqa: SLF001
        _rule("ExpirationRule", "Expiration_EndUser_Assignment", maximumDuration="PT4H"),
        _rule("ExpirationRule", "Expiration_Admin_Eligibility", isExpirationRequired=False),
        _rule("ExpirationRule", "Expiration_Admin_Assignment", isExpirationRequired=True),
    ])
    assert health["max_activation_hours"] == 4.0
    assert health["eligibility_expires"] is False
    assert health["assignment_expires"] is True


def test_authentication_context_counts_as_activation_protection():
    health = pim_collector._decode_rules([  # noqa: SLF001
        _rule("AuthenticationContextRule", "AuthenticationContext_EndUser_Assignment",
              isEnabled=True, claimValue="c1"),
    ])
    assert health["auth_context_required"] is True
    score, failed = pim_collector._score_health(health, 8.0)  # noqa: SLF001
    assert "mfa_on_activation" not in failed, "an auth context is a stronger control than MFA"


def test_health_score_is_the_fraction_of_controls_satisfied():
    perfect = {"approval_required": True, "mfa_on_activation": True, "justification_required": True,
               "max_activation_hours": 4.0, "eligibility_expires": True, "notification_recipients": 2}
    score, failed = pim_collector._score_health(perfect, 8.0)  # noqa: SLF001
    assert score == 100 and failed == []

    worst = {"approval_required": False, "mfa_on_activation": False, "justification_required": False,
             "max_activation_hours": 24.0, "eligibility_expires": False, "notification_recipients": 0}
    score, failed = pim_collector._score_health(worst, 8.0)  # noqa: SLF001
    assert score == 0 and len(failed) == 6


# =========================================================================== PIM signals
def _pim_snapshot(policy_overrides=None, *, licensed=True):
    health = {"approval_required": True, "mfa_on_activation": True, "justification_required": True,
              "ticket_required": False, "max_activation_hours": 4.0, "eligibility_expires": True,
              "assignment_expires": True, "notification_recipients": 2, "auth_context_required": False,
              "rules_seen": 10}
    health.update(policy_overrides or {})
    score, failed = pim_collector._score_health(health, 8.0)  # noqa: SLF001
    return {
        "pim": {
            "policies": [{"role_id": "rd-ga", "policy_id": "p1", "scope_id": "/", **health,
                          "score": score, "failed_controls": failed}],
            "activations": [], "group_eligibilities": [],
            "capabilities": {"policies": licensed, "activations": licensed,
                             "group_pim": licensed, "licensed": licensed},
        },
        "roles": {
            "definitions": [{"id": "rd-ga", "display_name": "Global Administrator",
                             "tier": "tier0", "privileged": True, "template_id": "t-ga"}],
            "assignments": [], "group_derived": [], "eligible": [],
        },
        "people": {"users": [], "groups": []},
    }


def test_pim_no_mfa_signal_fires_when_activation_is_unprotected():
    data = _pim_snapshot({"mfa_on_activation": False, "auth_context_required": False})
    findings = _SPEC["priv.pim_no_mfa_on_activation"].evaluate(data, SignalContext())
    assert [f["object_name"] for f in findings] == ["Global Administrator"]
    assert findings[0]["evidence"]["config_score"] < 100


def test_pim_no_mfa_signal_is_silent_when_an_auth_context_is_required():
    data = _pim_snapshot({"mfa_on_activation": False, "auth_context_required": True})
    assert _SPEC["priv.pim_no_mfa_on_activation"].evaluate(data, SignalContext()) == []


def test_pim_duration_signal_respects_the_context_threshold():
    data = _pim_snapshot({"max_activation_hours": 12.0})
    assert _SPEC["priv.pim_long_duration"].evaluate(data, SignalContext(max_activation_hours=8)) 
    assert _SPEC["priv.pim_long_duration"].evaluate(data, SignalContext(max_activation_hours=24)) == []


def test_pim_signals_report_not_measured_when_unlicensed():
    data = _pim_snapshot(licensed=False)
    with pytest.raises(SignalUnavailable):
        _SPEC["priv.pim_no_approval"].evaluate(data, SignalContext())


# ====================================================================== the Azure bridge
def test_cross_plane_reports_not_measured_without_an_rbac_scan():
    data = {"_azure_link": {"available": False, "reason": "No Azure RBAC scan has been run."},
            "roles": {"assignments": [], "group_derived": [], "eligible": [], "definitions": []},
            "apps": {"service_principals": []}}
    with pytest.raises(SignalUnavailable):
        _SPEC["priv.cross_plane_power"].evaluate(data, SignalContext())


def test_cross_plane_fires_only_when_both_planes_have_power():
    data = {
        "_azure_link": {
            "available": True, "generated_at": "2026-07-30T00:00:00+00:00", "stale": False,
            "principals": {
                "u-admin": {"powerful_roles": ["Owner"], "broad_scopes": ["Owner @ subscription"],
                            "subscriptions": ["sub-1"], "name": "Alice"},
                "u-other": {"powerful_roles": [], "broad_scopes": [], "subscriptions": []},
            },
        },
        "roles": {
            "definitions": [{"id": "rd-ga", "display_name": "Global Administrator",
                             "tier": "tier0", "privileged": True, "template_id": "t"}],
            "assignments": [
                {"role_id": "rd-ga", "role_name": "Global Administrator", "role_privileged": True,
                 "principal_id": "u-admin", "principal_type": "User"},
                {"role_id": "rd-ga", "role_name": "Global Administrator", "role_privileged": True,
                 "principal_id": "u-other", "principal_type": "User"},
            ],
            "group_derived": [], "eligible": [],
        },
        "apps": {"service_principals": []},
        "people": {"users": [{"id": "u-admin", "upn": "alice@contoso.com"},
                             {"id": "u-other", "upn": "bob@contoso.com"}]},
    }
    findings = _SPEC["priv.cross_plane_power"].evaluate(data, SignalContext())
    assert [f["object_id"] for f in findings] == ["u-admin"]
    assert findings[0]["evidence"]["azure_roles"] == ["Owner"]
    # The freshness caveat must travel with the finding.
    assert "azure_rbac_generated_at" in findings[0]["evidence"]
    assert findings[0]["evidence"]["azure_rbac_stale"] is False


def test_azure_link_marks_itself_stale_when_older_than_the_entra_snapshot():
    from app.entra import azure_link

    link = {"available": True, "generated_at": "2026-07-01T00:00:00+00:00"}
    fresh = azure_link._with_freshness(dict(link), "2026-07-30T00:00:00+00:00")  # noqa: SLF001
    assert fresh["stale"] is True
    same = azure_link._with_freshness(dict(link), "2026-06-01T00:00:00+00:00")  # noqa: SLF001
    assert same["stale"] is False


# ================================================================== application risk (P4)
def _app(**kw):
    base = {"object_id": "o1", "app_id": "a1", "display_name": "App", "owner_ids": ["u1"],
            "owners_known": True, "credentials": [], "redirect_uris": [], "multi_tenant": False,
            "verified_publisher": "Contoso", "federated_credentials": []}
    base.update(kw)
    return base


def _sp(**kw):
    base = {"object_id": "sp1", "app_id": "a1", "display_name": "App", "owner_ids": ["u1"],
            "owners_known": True, "credentials": [], "granted_app_permissions": [],
            "granted_delegated": [], "assigned_principals": 0, "is_first_party": False}
    base.update(kw)
    return base


def _perm(name, tier, **flags):
    base = {"mail": False, "files": False, "chat": False, "consent_grant": False, "directory_write": False}
    base.update(flags)
    return {"permission": name, "tier": tier, "flags": base}


def test_risk_components_are_published_and_sum_to_one_hundred():
    assert sum(c["weight"] for c in RISK_COMPONENTS) == 100
    result = risk_score(_app(), _sp())
    assert {c["key"] for c in result["components"]} == {c["key"] for c in RISK_COMPONENTS}


def test_clean_application_scores_low():
    assert risk_score(_app(), _sp())["score"] == 0


def test_consent_grant_capability_forces_a_high_score():
    """A tenant-takeover primitive is never a low-risk application, whatever else is clean."""
    sp = _sp(granted_app_permissions=[_perm("AppRoleAssignment.ReadWrite.All", "critical",
                                            consent_grant=True)])
    assert risk_score(_app(), sp)["score"] >= 80


def test_expired_credentials_and_ownerlessness_raise_the_score():
    app = _app(owner_ids=[], credentials=[
        {"kind": "secret", "expired": True, "days_left": -10, "lifetime_days": 400},
    ])
    scored = risk_score(app, _sp(owner_ids=[]))
    assert scored["score"] > 0
    by_key = {c["key"]: c for c in scored["components"]}
    assert by_key["credentials"]["points"] > 0
    assert by_key["ownership"]["points"] > 0


def test_azure_reach_contributes_to_application_risk():
    plain = risk_score(_app(), _sp())["score"]
    reaching = risk_score(_app(), _sp(), azure_roles=3)["score"]
    assert reaching > plain


def test_unknown_ownership_is_not_treated_as_ownerless():
    known_none = risk_score(_app(owner_ids=[]), _sp(owner_ids=[]))
    unknown = risk_score(_app(owner_ids=[], owners_known=False), _sp(owner_ids=[], owners_known=False))
    by_known = {c["key"]: c["points"] for c in known_none["components"]}
    by_unknown = {c["key"]: c["points"] for c in unknown["components"]}
    assert by_unknown["ownership"] < by_known["ownership"]


def test_risk_score_is_deterministic():
    sp = _sp(granted_app_permissions=[_perm("Mail.Read", "high", mail=True)], assigned_principals=200)
    assert risk_score(_app(), sp) == risk_score(_app(), sp)


def test_the_collect_context_carries_every_field_a_collector_reads():
    """Found in the live UI: the PIM collector read ``ctx.max_activation_hours``, which only
    existed on SignalContext. Every tenant that actually had PIM policies lost the whole
    domain to an AttributeError, and only tenants that were UNLICENSED looked fine — the
    worst possible failure mode, because the tenants with the feature were the ones broken.
    """
    from app.entra.collectors import CollectContext
    from app.entra import snapshot as snapshot_mod

    ctx = CollectContext(tenant_id="t1")
    assert isinstance(ctx.max_activation_hours, float)

    # And the settings dict that builds it must supply the key.
    assert "max_activation_hours" in snapshot_mod.settings()


def test_managed_identities_are_not_scored_on_ownership_or_credential_hygiene():
    """Azure owns these. They cannot be given an Entra owner and their certificates are
    platform-rotated, so scoring them there floods the top of the inventory with rows
    nobody can act on — and buries the applications that matter."""
    creds = [{"kind": "cert", "expired": True, "days_left": -5, "lifetime_days": 400}]
    mi = risk_score({}, _sp(sp_type="ManagedIdentity", owner_ids=[], credentials=creds))
    app = risk_score(_app(owner_ids=[], credentials=creds), _sp(owner_ids=[], credentials=creds))

    by_mi = {c["key"]: c for c in mi["components"]}
    assert by_mi["ownership"]["points"] == 0
    assert by_mi["credentials"]["points"] == 0
    assert by_mi["ownership"]["not_applicable"], "the exclusion must be stated, not hidden"
    assert mi["platform_managed"] is True
    assert mi["score"] < app["score"]


def test_a_managed_identity_with_real_power_is_still_ranked():
    """The exclusion must not make managed identities invisible — only quieter."""
    scored = risk_score({}, _sp(sp_type="ManagedIdentity",
                                granted_app_permissions=[_perm("Directory.ReadWrite.All", "critical",
                                                               directory_write=True)]),
                        azure_roles=3)
    assert scored["score"] > 30
