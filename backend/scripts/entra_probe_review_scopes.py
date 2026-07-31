"""Print the raw scope union of every access review definition. Usage: <connection_id>

Two reviews rendered as "scope: unknown" on the live tenant, which made the governance
coverage table report 0 reviewed for every object class. Guessing at the union members is
how that happened in the first place.
"""
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
        rows, _ = await client.get_all(
            "/identityGovernance/accessReviews/definitions", top=100)
        print(f"{len(rows)} review definition(s)\n")
        for r in rows:
            print(f"{r.get('displayName')!r}  status={r.get('status')}")
            print("  scope:", json.dumps(r.get("scope"), indent=2)[:700])
            print("  instanceEnumerationScope:",
                  json.dumps(r.get("instanceEnumerationScope"), indent=2)[:400])
            print()


asyncio.run(main())
