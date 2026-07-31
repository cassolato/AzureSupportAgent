"""Probe the entitlement and PIM-for-Groups query shapes. Usage: <connection_id>"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

EM = "/identityGovernance/entitlementManagement"
PG = "/identityGovernance/privilegedAccess/group"


async def try_one(client, label, path, **kwargs):
    try:
        rows, _ = await client.get_all(path, max_items=3, **kwargs)
        keys = ",".join(sorted(rows[0])[:8]) if rows else "(empty)"
        print(f"  OK    {label:44} {len(rows)} row(s)  {keys}")
        return rows
    except GraphError as exc:
        print(f"  FAIL  {label:44} {exc.status} {str(exc.message)[:100]}")
        return None


async def main() -> None:
    connection = resolve_connection(sys.argv[1])
    async with GraphClient(connection) as client:
        token, _ = await client.probe_token()
        if not token:
            print("no token")
            return

        print("== entitlement management")
        pkgs = await try_one(client, "accessPackages bare", f"{EM}/accessPackages", top=0)
        await try_one(client, "accessPackages expand=resourceRoleScopes",
                      f"{EM}/accessPackages", expand="resourceRoleScopes", top=0)
        await try_one(client, "accessPackages expand=accessPackageResourceRoleScopes",
                      f"{EM}/accessPackages", expand="accessPackageResourceRoleScopes", top=0)
        await try_one(client, "assignmentPolicies", f"{EM}/assignmentPolicies", top=0)
        await try_one(client, "assignmentPolicies expand=accessPackage",
                      f"{EM}/assignmentPolicies", expand="accessPackage", top=0)
        await try_one(client, "assignments", f"{EM}/assignments", top=0)
        await try_one(client, "assignments expand=target,accessPackage",
                      f"{EM}/assignments", expand="target,accessPackage", top=0)
        await try_one(client, "catalogs", f"{EM}/catalogs", top=0)
        if pkgs:
            pid = pkgs[0].get("id")
            await try_one(client, "accessPackage/{id}/resourceRoleScopes",
                          f"{EM}/accessPackages/{pid}/resourceRoleScopes", top=0)

        print("\n== PIM for groups")
        await try_one(client, "group/eligibilitySchedules bare",
                      f"{PG}/eligibilitySchedules", top=0)
        await try_one(client, "group/eligibilityScheduleInstances",
                      f"{PG}/eligibilityScheduleInstances", top=0)
        await try_one(client, "group/assignmentSchedules",
                      f"{PG}/assignmentSchedules", top=0)
        await try_one(client, "eligibilitySchedules filter=groupId",
                      f"{PG}/eligibilitySchedules",
                      filter="groupId eq '00000000-0000-0000-0000-000000000000'", top=0)

        print("\n== PIM activation history")
        await try_one(client, "roleAssignmentScheduleRequests",
                      "/roleManagement/directory/roleAssignmentScheduleRequests", top=0)


asyncio.run(main())
