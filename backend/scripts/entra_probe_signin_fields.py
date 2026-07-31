"""Find which signIn $select fields this tenant accepts, and the identityProtection page cap."""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

SINCE = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

CANDIDATES = [
    "id", "createdDateTime", "userId", "userPrincipalName", "userDisplayName", "appId",
    "appDisplayName", "clientAppUsed", "ipAddress", "status", "location", "deviceDetail",
    "authenticationRequirement", "conditionalAccessStatus",
    "appliedConditionalAccessPolicies", "riskLevelDuringSignIn", "riskState",
    "isInteractive", "resourceDisplayName", "correlationId",
]


async def main() -> None:
    connection = resolve_connection(sys.argv[1] if len(sys.argv) > 1 else "")
    async with GraphClient(connection) as client:
        token, _ = await client.probe_token()
        if not token:
            print("no token")
            return

        print("== signIn $select field probe")
        good: list[str] = []
        for field in CANDIDATES:
            try:
                await client.get_all("/auditLogs/signIns",
                                     filter=f"createdDateTime ge {SINCE}",
                                     select=["id", field], top=1, max_items=1)
                good.append(field)
            except GraphError as exc:
                print(f"   REJECTED {field:36} {str(exc.message)[:80]}")
        print(f"   accepted: {good}\n")

        print("== signIn: are the fields present WITHOUT $select?")
        rows, _ = await client.get_all("/auditLogs/signIns",
                                       filter=f"createdDateTime ge {SINCE}", top=1, max_items=1)
        if rows:
            present = sorted(rows[0])
            print(f"   default payload has {len(present)} field(s)")
            for f in CANDIDATES:
                mark = "yes" if f in present else "NO "
                print(f"     {mark} {f}")
        print()

        print("== identityProtection page-size cap")
        for top in (999, 500, 250):
            try:
                rows, _ = await client.get_all("/identityProtection/riskyUsers",
                                               top=top, max_items=5)
                print(f"   OK   top={top} -> {len(rows)} row(s)")
            except GraphError as exc:
                print(f"   FAIL top={top} {str(exc.message)[:70]}")


asyncio.run(main())
