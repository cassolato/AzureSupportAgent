"""Users, guests and groups collector.

Two deliberate design choices:

1. **Two-pass user collection.** ``signInActivity`` cannot be freely combined with most
   ``$filter`` expressions and forces a slower query path, so the inventory is collected in
   a fast pass and last-sign-in is merged from a second, P1-gated pass. If the second pass
   fails, dormancy signals report *unknown* rather than falsely reporting *dormant* — an
   account wrongly marked stale is a support ticket, not an insight.

2. **MFA truth comes from the registration report**, not from a per-user
   ``/authentication/methods`` scan. ``/reports/authenticationMethods/userRegistrationDetails``
   returns ``isMfaRegistered`` / ``isMfaCapable`` / ``isPasswordlessCapable`` / ``methodsRegistered``
   for the entire tenant in one paged call. The existing identity collector's capped per-user
   scan is exactly the pattern this retires.
"""
from __future__ import annotations

from typing import Any

from app.entra import model
from app.entra.collectors import CollectContext, as_dict, as_list, batch_collection, clip, guarded
from app.entra.graphclient import GraphClient, GraphError, GraphPermissionError

DOMAIN = "people"

_USER_SELECT = [
    "id", "displayName", "userPrincipalName", "userType", "accountEnabled",
    "createdDateTime", "department", "companyName", "jobTitle", "employeeId",
    "onPremisesSyncEnabled", "onPremisesExtensionAttributes", "externalUserState",
    "externalUserStateChangeDateTime", "mail", "usageLocation", "assignedLicenses",
]

_GROUP_SELECT = [
    "id", "displayName", "description", "groupTypes", "securityEnabled", "mailEnabled",
    "isAssignableToRole", "membershipRule", "membershipRuleProcessingState",
    "createdDateTime", "visibility", "onPremisesSyncEnabled",
]

# Weak (phishable) authentication methods, as reported by the registration report.
_WEAK_METHODS = {"mobilePhone", "alternateMobilePhone", "officePhone", "sms", "voice", "email"}
_PHISH_RESISTANT = {"fido2SecurityKey", "windowsHelloForBusiness", "passKeyDeviceBound",
                    "passKeyDeviceBoundAuthenticator", "x509Certificate",
                    "passKeyDeviceBoundWindowsHello", "microsoftAuthenticatorPasswordless"}


async def collect(client: GraphClient, ctx: CollectContext) -> dict[str, Any]:
    async def _run() -> dict[str, Any]:
        notes: list[str] = []
        truncated = False

        # --- pass 1: inventory -------------------------------------------------
        await ctx.say("info", "People: collecting users…")
        users_raw, user_trunc = await client.get_all(
            "/users", select=_USER_SELECT, top=999, max_items=ctx.max_users
        )
        truncated = truncated or user_trunc
        if user_trunc:
            notes.append(f"User collection capped at {ctx.max_users:,} — counts are a lower bound.")
        await ctx.say("ok", f"People: {len(users_raw):,} user(s)")

        users: dict[str, dict[str, Any]] = {}
        for u in users_raw:
            u = as_dict(u)
            uid = str(u.get("id") or "")
            if not uid:
                continue
            ext = as_dict(u.get("onPremisesExtensionAttributes"))
            users[uid] = {
                "id": uid,
                "upn": u.get("userPrincipalName", "") or "",
                "display_name": u.get("displayName", "") or "",
                "mail": u.get("mail", "") or "",
                "user_type": u.get("userType", "") or "Member",
                "enabled": bool(u.get("accountEnabled")),
                "created_at": u.get("createdDateTime", "") or "",
                "department": u.get("department", "") or "",
                "company_name": u.get("companyName", "") or "",
                "job_title": u.get("jobTitle", "") or "",
                "employee_id": u.get("employeeId", "") or "",
                "usage_location": u.get("usageLocation", "") or "",
                "on_prem_synced": bool(u.get("onPremisesSyncEnabled")),
                "extension_attributes": {k: v for k, v in ext.items() if v},
                "external_user_state": u.get("externalUserState", "") or "",
                "external_state_changed_at": u.get("externalUserStateChangeDateTime", "") or "",
                "licence_count": len(as_list(u.get("assignedLicenses"))),
                # filled by later passes
                "last_signin": "",
                "last_noninteractive_signin": "",
                "signin_known": False,
                "mfa_registered": None,
                "mfa_capable": None,
                "passwordless_capable": None,
                "sspr_registered": None,
                "methods": [],
                "phishing_resistant": None,
                "is_admin_reported": None,
                "manager_id": "",
            }

        # --- pass 2: sign-in activity (P1) -------------------------------------
        signin_available = False
        try:
            await ctx.say("info", "People: merging last sign-in activity…")
            activity, act_trunc = await client.get_all(
                "/users", select=["id", "signInActivity"], top=999, max_items=ctx.max_users
            )
            truncated = truncated or act_trunc
            merged = 0
            for row in activity:
                row = as_dict(row)
                uid = str(row.get("id") or "")
                act = as_dict(row.get("signInActivity"))
                if uid in users:
                    users[uid]["last_signin"] = act.get("lastSignInDateTime", "") or ""
                    users[uid]["last_noninteractive_signin"] = act.get("lastNonInteractiveSignInDateTime", "") or ""
                    users[uid]["signin_known"] = True
                    merged += 1
            signin_available = merged > 0
            await ctx.say("ok", f"People: sign-in activity for {merged:,} user(s)")
        except GraphPermissionError as exc:
            notes.append(
                "Last sign-in activity unavailable (needs AuditLog.Read.All and Entra ID P1) — "
                f"dormancy is reported as unknown, not stale. {exc.message[:120]}"
            )
        except GraphError as exc:
            notes.append(f"Last sign-in activity unavailable: {clip(exc, 160)} — dormancy reported as unknown.")

        # --- pass 3: MFA registration report (P1) ------------------------------
        mfa_available = False
        try:
            await ctx.say("info", "People: reading the authentication-method registration report…")
            reg, _ = await client.get_all("/reports/authenticationMethods/userRegistrationDetails", top=999)
            for row in reg:
                row = as_dict(row)
                uid = str(row.get("id") or "")
                if uid not in users:
                    continue
                methods = [str(m) for m in as_list(row.get("methodsRegistered"))]
                users[uid].update({
                    "mfa_registered": bool(row.get("isMfaRegistered")),
                    "mfa_capable": bool(row.get("isMfaCapable")),
                    "passwordless_capable": bool(row.get("isPasswordlessCapable")),
                    "sspr_registered": bool(row.get("isSsprRegistered")),
                    "methods": methods,
                    "phishing_resistant": any(m in _PHISH_RESISTANT for m in methods),
                    "is_admin_reported": bool(row.get("isAdmin")),
                    # An empty method list and an absent report row look identical once
                    # merged. Without this flag a user the report has not caught up with
                    # is indistinguishable from one who has genuinely registered nothing,
                    # and the registration gap silently inflates.
                    "registration_reported": True,
                })
            mfa_available = bool(reg)
            await ctx.say("ok", f"People: registration details for {len(reg):,} user(s)")
        except GraphPermissionError as exc:
            notes.append(
                "MFA registration report unavailable (needs AuditLog.Read.All / "
                f"UserAuthenticationMethod.Read.All and Entra ID P1). {exc.message[:120]}"
            )
        except GraphError as exc:
            notes.append(f"MFA registration report unavailable: {clip(exc, 160)}")

        # --- groups -------------------------------------------------------------
        await ctx.say("info", "People: collecting groups…")
        groups_raw, grp_trunc = await client.get_all(
            "/groups", select=_GROUP_SELECT, top=999, max_items=ctx.max_groups
        )
        truncated = truncated or grp_trunc
        if grp_trunc:
            notes.append(f"Group collection capped at {ctx.max_groups:,}.")

        groups: dict[str, dict[str, Any]] = {}
        for g in groups_raw:
            g = as_dict(g)
            gid = str(g.get("id") or "")
            if not gid:
                continue
            gtypes = [str(t) for t in as_list(g.get("groupTypes"))]
            groups[gid] = {
                "id": gid,
                "display_name": g.get("displayName", "") or "",
                "description": g.get("description", "") or "",
                "group_types": gtypes,
                "dynamic": "DynamicMembership" in gtypes,
                "unified": "Unified" in gtypes,
                "security_enabled": bool(g.get("securityEnabled")),
                "mail_enabled": bool(g.get("mailEnabled")),
                "is_assignable_to_role": bool(g.get("isAssignableToRole")),
                "membership_rule": g.get("membershipRule", "") or "",
                "membership_rule_state": g.get("membershipRuleProcessingState", "") or "",
                "created_at": g.get("createdDateTime", "") or "",
                "visibility": g.get("visibility", "") or "",
                "on_prem_synced": bool(g.get("onPremisesSyncEnabled")),
                "owner_ids": [],
                "owners_known": False,
            }
        await ctx.say("ok", f"People: {len(groups):,} group(s)")

        # --- group owners (batched, uncapped) -----------------------------------
        if groups:
            await ctx.say("info", f"People: resolving owners for {len(groups):,} group(s)…")
            owners, owner_trunc, forbidden = await batch_collection(
                client,
                list(groups),
                lambda gid: f"/groups/{gid}/owners?$select=id,displayName&$top=50",
                cap=ctx.max_owner_lookups or None,
                ctx=ctx,
                label="People: group owners",
            )
            if owner_trunc:
                truncated = True
                notes.append(
                    f"Group owner lookups capped at {ctx.max_owner_lookups:,}; "
                    "ownerless detection covers that subset only."
                )
            if forbidden:
                notes.append(f"{forbidden} group owner lookup(s) were forbidden.")
            for gid, rows in owners.items():
                groups[gid]["owner_ids"] = [str(as_dict(r).get("id") or "") for r in rows if as_dict(r).get("id")]
                groups[gid]["owners_known"] = True
            await ctx.say("ok", f"People: owners resolved for {len(owners):,} group(s)")

        guests = sum(1 for u in users.values() if u["user_type"] == "Guest")
        enabled_members = sum(1 for u in users.values() if u["enabled"] and u["user_type"] == "Member")
        data = {
            "users": list(users.values()),
            "groups": list(groups.values()),
            "capabilities": {
                "signin_activity": signin_available,
                "mfa_registration_report": mfa_available,
                "group_owners": bool(groups) and any(g["owners_known"] for g in groups.values()),
            },
            "counts": {
                "users": len(users),
                "members": len(users) - guests,
                "guests": guests,
                "enabled_members": enabled_members,
                "disabled": sum(1 for u in users.values() if not u["enabled"]),
                "groups": len(groups),
                "role_assignable_groups": sum(1 for g in groups.values() if g["is_assignable_to_role"]),
            },
        }
        status = model.STATUS_PARTIAL if (notes or truncated) else model.STATUS_OK
        blockers = []
        if truncated:
            blockers.append(model.blocker(
                model.BLOCKER_CAP,
                f"User collection stopped at {ctx.max_users:,} accounts.",
                scope=f"{ctx.max_users:,} users",
                impact="Every people count is a lower bound.",
            ))
        return model.domain_payload(
            DOMAIN, data, status=status,
            item_count=len(users) + len(groups), truncated=truncated, notes=notes,
            blockers=blockers,
        )

    return await guarded(DOMAIN, ctx, _run)


# ------------------------------------------------------------------------- helpers
async def expand_groups(
    client: GraphClient, group_ids: list[str], *, cap: int = 500
) -> tuple[dict[str, list[str]], bool, list[str]]:
    """Transitive user members for a **bounded** set of groups.

    Used by the roles and Conditional Access collectors for the groups they actually
    reference (role-granting groups, policy-targeted groups) rather than building a
    tenant-wide membership index no screen would read.

    Returns ``(group_id -> [user ids], truncated, notes)``.
    """
    notes: list[str] = []
    wanted = list(dict.fromkeys(g for g in group_ids if g))
    truncated = False
    if len(wanted) > cap:
        wanted = wanted[:cap]
        truncated = True
        notes.append(f"Group membership expansion capped at {cap} group(s).")
    if not wanted:
        return {}, truncated, notes
    members, _, forbidden = await batch_collection(
        client,
        wanted,
        lambda gid: f"/groups/{gid}/transitiveMembers/microsoft.graph.user?$select=id&$top=999",
    )
    if forbidden:
        notes.append(f"{forbidden} group membership expansion(s) were forbidden.")
    return (
        {gid: [str(as_dict(m).get("id") or "") for m in rows if as_dict(m).get("id")] for gid, rows in members.items()},
        truncated,
        notes,
    )


def weak_only(methods: list[str]) -> bool:
    """True when every registered method is phishable (SMS / voice / email only)."""
    if not methods:
        return False
    return all(m in _WEAK_METHODS for m in methods)
