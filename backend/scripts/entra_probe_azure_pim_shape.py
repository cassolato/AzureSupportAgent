"""Show the raw Azure PIM request shape: duration encoding and justification content."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from app.azure.arm import list_subscriptions  # noqa: E402
from app.azure.credentials import get_arm_token  # noqa: E402
from app.core.azure_connections import resolve_connection  # noqa: E402

BASE = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Authorization"


async def main() -> None:
    conn = resolve_connection(sys.argv[1])
    token, _ = await get_arm_token(conn)
    subs, _ = await list_subscriptions(token)
    seen = 0
    async with httpx.AsyncClient(timeout=60) as http:
        for sub in subs:
            url = f"{BASE.format(sub['id'])}/roleAssignmentScheduleRequests"
            resp = await http.get(url, headers={"Authorization": f"Bearer {token}"},
                                  params={"api-version": "2020-10-01"})
            if resp.status_code != 200:
                continue
            for item in resp.json().get("value", []):
                p = item.get("properties", {})
                if "ctivat" not in str(p.get("requestType", "")):
                    continue
                print(f"--- {sub['name'][:40]}")
                print("  requestType :", p.get("requestType"), "| status:", p.get("status"))
                print("  scheduleInfo:", json.dumps(p.get("scheduleInfo")))
                print("  justification:", repr(p.get("justification")))
                print("  ticketInfo  :", json.dumps(p.get("ticketInfo")))
                print("  createdOn   :", p.get("createdOn"))
                seen += 1
                if seen >= 5:
                    return


if __name__ == "__main__":
    asyncio.run(main())
