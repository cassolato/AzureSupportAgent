"""Probe how assignmentPolicies expose their parent access package. Usage: <connection_id>"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

EM = "/identityGovernance/entitlementManagement"


async def try_one(client, label, **kwargs):
    try:
        rows, _ = await client.get_all(f"{EM}/assignmentPolicies", max_items=3, top=0, **kwargs)
        print(f"  OK    {label:46} {len(rows)} row(s)")
        if rows:
            print("        keys:", ",".join(sorted(rows[0])))
            pkg = rows[0].get("accessPackage")
            print("        accessPackage:", json.dumps(pkg)[:160] if pkg else "(absent)")
        return rows
    except GraphError as exc:
        print(f"  FAIL  {label:46} {exc.status} {str(exc.message)[:120]}")
        return None


async def main() -> None:
    connection = resolve_connection(sys.argv[1])
    async with GraphClient(connection) as client:
        token, _ = await client.probe_token()
        if not token:
            print("no token")
            return
        await try_one(client, "bare")
        await try_one(client, "expand=accessPackage($select=id)",
                      expand="accessPackage($select=id)")
        await try_one(client, "expand=accessPackage", expand="accessPackage")


asyncio.run(main())
