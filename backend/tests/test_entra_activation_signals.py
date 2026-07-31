"""Signals over activation sessions.

The risk with this family is confidently wrong accusations: reporting an elevation that was
refused, blaming an operator for a justification our permissions cannot see, or calling
09:00 "out of hours" because the timestamp is UTC. Each of those is pinned here.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.entra.collectors import activations as coll
from app.entra.signal_defs import activations as defs
from app.entra.signals import SignalContext, SignalUnavailable


def _data(sessions: list[dict[str, Any]], **caps: Any) -> dict[str, Any]:
    capabilities = {"entra_instances": True, "entra_requests": True, "azure_requests": True}
    capabilities.update(caps)
    return {
        "activations": {"sessions": sessions, "capabilities": capabilities},
        "people": {"users": []}, "roles": {"assignments": [], "group_derived": []},
    }


def _session(**kw: Any) -> dict[str, Any]:
    base = dict(sid="s1", plane="entra", source="entra_request", principal_id="p1",
                role_id="r1", role_name="Global Administrator",
                principal_upn="ada@example.com",
                start="2026-07-31T10:00:00Z", end="2026-07-31T18:00:00Z",
                status="Provisioned", justification="patching the exchange connector")
    base.update(kw)
    return coll.session(**base)


# --------------------------------------------------------------------------- availability
def test_no_readable_source_is_unavailable_not_clean():
    """Reporting "no problems" from a domain we cannot read is the failure mode this whole
    product exists to avoid."""
    data = _data([], entra_instances=False, entra_requests=False, azure_requests=False)
    with pytest.raises(SignalUnavailable):
        defs._sessions(data)


def test_a_source_that_cannot_record_reasons_is_not_judged_on_them():
    """The schedule-instances fallback has no justification field. Flagging those rows would
    report our own blind spot as the tenant's negligence."""
    data = _data([_session(source="entra_instance", justification="", detail_known=False)])
    with pytest.raises(SignalUnavailable):
        defs._detailed(data)
    # …but the session still counts for checks that do not need a justification.
    assert len(defs._sessions(data)) == 1


def test_failed_requests_are_not_treated_as_elevations():
    data = _data([_session(status="Failed"), _session(sid="s2", status="Denied")])
    with pytest.raises(SignalUnavailable):
        defs._sessions(data)


def test_a_mix_keeps_only_the_granted_ones():
    data = _data([_session(status="Failed"), _session(sid="s2", status="Provisioned")])
    assert [s["id"] for s in defs._sessions(data)] == ["s2"]


# --------------------------------------------------------------------------- justification
def test_a_missing_reason_is_reported():
    out = defs._no_justification(_data([_session(justification="")]), SignalContext())
    assert len(out) == 1
    assert "no reason recorded" in out[0]["title"]


def test_a_token_reason_is_reported_with_what_was_typed():
    """Seen live: 91 Azure activations justified as 'access', 't' and 'working'."""
    out = defs._weak_justification(_data([_session(justification="access")]), SignalContext())
    assert len(out) == 1
    assert "'access'" in out[0]["detail"]


def test_a_real_reason_is_left_alone():
    ctx = SignalContext()
    data = _data([_session(justification="restoring mailbox for incident 4471")])
    assert defs._no_justification(data, ctx) == []
    assert defs._weak_justification(data, ctx) == []


def test_repeat_offences_become_one_finding_with_a_count():
    """One finding per session buried the queue: 86 identical rows about five people. The
    reader needs 'this keeps happening, N times' once."""
    rows = [_session(sid=f"s{i}", justification="access",
                     start=f"2026-07-{10 + i:02d}T10:00:00Z") for i in range(12)]
    out = defs._weak_justification(_data(rows), SignalContext())
    assert len(out) == 1
    assert "12 times" in out[0]["title"]
    assert out[0]["evidence"]["occurrences"] == 12
    assert len(out[0]["evidence"]["recent_sessions"]) == 5


def test_two_roles_for_one_person_stay_separate():
    """The fingerprint includes the role, or a person's Owner and Contributor abuse collapse
    into a single inbox row."""
    rows = [_session(sid="a", justification="x", role_name="Owner"),
            _session(sid="b", justification="x", role_name="Contributor")]
    out = defs._weak_justification(_data(rows), SignalContext())
    assert len(out) == 2
    assert len({f["fingerprint"] for f in out}) == 2


# --------------------------------------------------------------------------- out of hours
def test_out_of_hours_is_judged_in_local_time_not_utc():
    """09:00 in a UTC+9 tenant is the middle of the working day. Judging the raw UTC stamp
    would report every morning as suspicious."""
    session = _session(start="2026-07-31T00:30:00Z")     # 09:30 in UTC+9
    tokyo = SignalContext(utc_offset_hours=9, business_hours_start=8, business_hours_end=18)
    assert defs._out_of_hours(_data([session]), tokyo) == []

    utc = SignalContext(utc_offset_hours=0, business_hours_start=8, business_hours_end=18)
    assert len(defs._out_of_hours(_data([session]), utc)) == 1


def test_the_timezone_used_is_stated_in_the_finding():
    out = defs._out_of_hours(_data([_session(start="2026-07-31T03:00:00Z")]),
                             SignalContext(utc_offset_hours=-5))
    assert out
    assert out[0]["evidence"]["timezone"] == "UTC-5"
    assert "UTC-5" in out[0]["detail"]


def test_a_weekend_activation_is_out_of_hours_whatever_the_clock_says():
    # 2026-08-01 is a Saturday.
    out = defs._out_of_hours(_data([_session(start="2026-08-01T12:00:00Z")]), SignalContext())
    assert len(out) == 1


def test_only_tier0_is_judged_on_timing():
    """Every routine Contributor elevation happening after six would drown the queue."""
    session = _session(role_name="Reader", start="2026-07-31T03:00:00Z")
    assert defs._out_of_hours(_data([session]), SignalContext()) == []


# --------------------------------------------------------------------------- other checks
def test_a_third_party_elevation_is_reported():
    out = defs._granted_by_other(
        _data([_session(requestor_id="p2")]), SignalContext())
    assert len(out) == 1
    assert out[0]["evidence"]["requestor_id"] == "p2"


def test_self_activation_is_normal_and_silent():
    assert defs._granted_by_other(_data([_session(requestor_id="p1")]), SignalContext()) == []


def test_a_window_longer_than_the_policy_maximum_is_reported():
    session = _session(start="2026-07-31T00:00:00Z", end="2026-08-01T00:00:00Z")   # 24h
    out = defs._long_window(_data([session]), SignalContext(max_activation_hours=8))
    assert len(out) == 1
    assert out[0]["evidence"]["hours"] == 24.0


def test_a_window_at_the_limit_is_not_reported():
    session = _session(start="2026-07-31T00:00:00Z", end="2026-07-31T08:00:00Z")
    assert defs._long_window(_data([session]), SignalContext(max_activation_hours=8)) == []


def test_a_management_group_elevation_is_flagged_as_broad():
    session = _session(plane="azure", source="azure_request", scope_type="managementGroup",
                       scope_name="Production", role_name="Owner")
    out = defs._broad_azure_scope(_data([session]), SignalContext())
    assert len(out) == 1
    assert "Production" in out[0]["title"]


def test_a_subscription_scoped_elevation_is_not_flagged_as_broad():
    session = _session(plane="azure", source="azure_request", scope_type="subscription",
                       role_name="Owner")
    assert defs._broad_azure_scope(_data([session]), SignalContext()) == []
