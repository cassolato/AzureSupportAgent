"""Probe roleEligibilitySchedules / roleAssignmentSchedules query shapes against a live tenant.

Graph rejects some $select/$expand/$top combinations on the PIM schedule collections with
a 400 that says "The filter is invalid" even when no $filter was sent. This finds the shape
that actually works so the collector can stop guessing.

Usage: .venv\\Scripts\\python.exe scripts\\entra_probe_pim_shapes.py <connection_id>
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

PATHS = (
    "/roleManagement/directory/roleEligibilitySchedules",
    "/roleManagement/directory/roleAssignmentSchedules",
    "/roleManagement/directory/roleEligibilityScheduleInstances",
    "/roleManagement/directory/roleAssignmentScheduleInstances",
)

SELECT = ["id", "roleDefinitionId", "principalId", "memberType", "scheduleInfo", "status"]
EXPAND = "principal($select=id,displayName,userPrincipalName,userType,accountEnabled,appId)"

VARIANTS = (
    ("bare", {}),
    ("top=999", {"top": 999}),
    ("select", {"select": SELECT, "top": 0}),
    ("expand", {"expand": EXPAND, "top": 0}),
    ("select+expand", {"select": SELECT, "expand": EXPAND, "top": 0}),
    ("select+expand+top", {"select": SELECT, "expand": EXPAND, "top": 999}),
    ("filter-all", {"filter": "assignmentType eq 'Assigned'", "top": 0}),
)


async def main() -> None:
    connection = resolve_connection(sys.argv[1] if len(sys.argv) > 1 else "")
    if not connection:
        print("no such connection")
        return
    print(f"tenant {connection.get('tenant_id')}\n")
    async with GraphClient(connection) as client:
        token, err = await client.probe_token()
        if not token:
            print("no token:", err)
            return
        for path in PATHS:
            print(f"== {path}")
            for label, kwargs in VARIANTS:
                try:
                    rows, _ = await client.get_all(path, max_items=5, **kwargs)  # type: ignore[arg-type]
                    sample = rows[0] if rows else {}
                    keys = ",".join(sorted(sample)[:6])
                    print(f"   OK    {label:22} {len(rows)} row(s)  {keys}")
                except GraphError as exc:
                    print(f"   FAIL  {label:22} {str(exc)[:110]}")
            print()


asyncio.run(main())
