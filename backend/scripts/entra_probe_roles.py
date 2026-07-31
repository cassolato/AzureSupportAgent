"""Probe which OData options the directory-role endpoints actually accept.

``/roleManagement/directory/*`` has notoriously restricted OData support and the
restrictions differ per collection, so the collector's query shape is determined by
measurement rather than by guesswork.

Usage: backend\\.venv\\Scripts\\python.exe backend\\scripts\\entra_probe_roles.py <connection-id>
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

CASES = [
    # NOTE: get_all defaults to $top=999, so "no top" must be requested explicitly.
    ("roleDefinitions no-top", "/roleManagement/directory/roleDefinitions", {"top": 0}),
    ("roleDefinitions no-top +select", "/roleManagement/directory/roleDefinitions",
     {"top": 0, "select": ["id", "templateId", "displayName", "isBuiltIn", "isEnabled"]}),
    ("roleDefinitions +top999", "/roleManagement/directory/roleDefinitions", {"top": 999}),
    ("roleDefinitions +top100", "/roleManagement/directory/roleDefinitions", {"top": 100}),
    ("directoryRoles no-top", "/directoryRoles", {"top": 0}),
    ("directoryRoleTemplates no-top", "/directoryRoleTemplates", {"top": 0}),
    ("roleAssignments +select+expand", "/roleManagement/directory/roleAssignments",
     {"select": ["id", "roleDefinitionId", "principalId", "directoryScopeId"],
      "expand": "principal($select=id,displayName,userPrincipalName,userType,accountEnabled,appId)"}),
    ("assignmentSchedules no-top", "/roleManagement/directory/roleAssignmentSchedules", {"top": 0}),
    ("eligibilitySchedules no-top", "/roleManagement/directory/roleEligibilitySchedules", {"top": 0}),
]


async def main() -> None:
    conn_id = sys.argv[1] if len(sys.argv) > 1 else ""
    conn = resolve_connection(conn_id)
    if conn is None:
        print(f"no connection resolved for {conn_id!r}")
        return
    print(f"connection {conn.get('display_name')} tenant {conn.get('tenant_id')}\n")
    async with GraphClient(conn) as gc:
        for label, path, kwargs in CASES:
            try:
                items, truncated = await gc.get_all(path, **kwargs)  # type: ignore[arg-type]
                print(f"  OK    {label:38} {len(items):>4} item(s)"
                      + (" (truncated)" if truncated else ""))
                if items and "roleDefinitions" in path and "bare" in label:
                    print(f"        sample keys: {sorted(items[0].keys())}")
            except GraphError as exc:
                print(f"  FAIL  {label:38} {exc.status} {exc.message[:110]}")


if __name__ == "__main__":
    asyncio.run(main())
