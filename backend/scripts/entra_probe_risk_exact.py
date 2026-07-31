"""Probe the risk collector's EXACT queries. Usage: <connection_id>"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

SINCE = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

SIGNIN_SELECT = ["id", "createdDateTime", "userId", "userPrincipalName", "appId",
                 "appDisplayName", "clientAppUsed", "ipAddress", "status", "location",
                 "deviceDetail", "authenticationRequirement", "conditionalAccessStatus",
                 "appliedConditionalAccessPolicies", "riskLevelDuringSignIn"]

RISKY_SELECT = ["id", "userPrincipalName", "userDisplayName", "riskLevel", "riskState",
                "riskDetail", "riskLastUpdatedDateTime", "isDeleted", "isProcessing"]

DET_SELECT = ["id", "riskEventType", "riskLevel", "riskState", "userId",
              "userPrincipalName", "detectedDateTime", "ipAddress", "location",
              "activity", "detectionTimingType"]

SP_SELECT = ["id", "appId", "displayName", "riskLevel", "riskState", "riskDetail",
             "riskLastUpdatedDateTime", "isEnabled", "isProcessing", "servicePrincipalType"]


async def main() -> None:
    connection = resolve_connection(sys.argv[1] if len(sys.argv) > 1 else "")
    async with GraphClient(connection) as client:
        token, err = await client.probe_token()
        if not token:
            print("no token:", err)
            return

        cases = [
            ("signIns exact", "/auditLogs/signIns",
             {"filter": f"createdDateTime ge {SINCE}", "select": SIGNIN_SELECT, "top": 999}),
            ("signIns no-select", "/auditLogs/signIns",
             {"filter": f"createdDateTime ge {SINCE}", "top": 999}),
            ("signIns select-no-CA", "/auditLogs/signIns",
             {"filter": f"createdDateTime ge {SINCE}",
              "select": [s for s in SIGNIN_SELECT if s != "appliedConditionalAccessPolicies"],
              "top": 999}),
            ("riskyUsers exact", "/identityProtection/riskyUsers",
             {"select": RISKY_SELECT, "top": 999}),
            ("riskyUsers no-select", "/identityProtection/riskyUsers", {"top": 999}),
            ("riskDetections exact", "/identityProtection/riskDetections",
             {"select": DET_SELECT, "filter": f"detectedDateTime ge {SINCE}", "top": 999}),
            ("riskDetections no-filter", "/identityProtection/riskDetections",
             {"select": DET_SELECT, "top": 999}),
            ("riskySPs exact", "/identityProtection/riskyServicePrincipals",
             {"select": SP_SELECT, "top": 999}),
        ]
        for label, path, kwargs in cases:
            try:
                rows, trunc = await client.get_all(path, max_items=50, **kwargs)  # type: ignore[arg-type]
                print(f"  OK    {label:24} {len(rows):>4} row(s) trunc={trunc}")
            except GraphError as exc:
                print(f"  FAIL  {label:24} {exc.status} {str(exc.message)[:130]}")


asyncio.run(main())
