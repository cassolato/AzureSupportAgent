"""Dump one assignmentPolicy verbatim so field names can be checked. Usage: <connection_id>"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient  # noqa: E402


async def main() -> None:
    connection = resolve_connection(sys.argv[1])
    async with GraphClient(connection) as client:
        await client.probe_token()
        rows, _ = await client.get_all(
            "/identityGovernance/entitlementManagement/assignmentPolicies",
            max_items=3, top=0)
        for row in rows:
            print(json.dumps({k: v for k, v in row.items()
                              if k in ("displayName", "allowedTargetScope", "specificAllowedTargets",
                                       "requestorSettings", "requestApprovalSettings",
                                       "reviewSettings", "accessReviewSettings", "expiration")},
                             indent=2, default=str))
            print("-" * 60)


asyncio.run(main())
