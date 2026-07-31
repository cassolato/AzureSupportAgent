"""Probe everything the PIM Activations feature needs, on both planes.

Phase 0 of the activations build. Answers, against a live tenant:
  * does roleAssignmentScheduleRequests read at all, and what does a row carry?
  * is approval detail on the request, or only behind approvalId?
  * how far back does each source actually return? (retention is the whole reason
    the feature needs its own ledger)
  * can this connection reach ARM, list subscriptions, and read Azure PIM + Activity Log?

Usage: entra_probe_activations.py <connection_id>
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402

RM = "/roleManagement/directory"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def probe(client, label, path, **kwargs):
    try:
        rows, _ = await client.get_all(path, max_items=3, **kwargs)
        print(f"  OK    {label:52} {len(rows)} row(s)")
        if rows:
            print(f"        keys: {','.join(sorted(rows[0]))[:220]}")
        return rows
    except GraphError as exc:
        print(f"  FAIL  {label:52} {exc.status} {str(exc.message)[:110]}")
        return None


async def graph_side(connection) -> None:
    async with GraphClient(connection) as client:
        token, err = await client.probe_token()
        if not token:
            print(f"no graph token: {err}")
            return

        print("== PIM activation requests (the spine of the feature)")
        rows = await probe(client, "roleAssignmentScheduleRequests",
                           f"{RM}/roleAssignmentScheduleRequests")
        if rows:
            print("\n  --- one full row ---")
            print(json.dumps(rows[0], indent=2)[:2200])

        await probe(client, "…$expand=principal", f"{RM}/roleAssignmentScheduleRequests",
                    expand="principal")
        await probe(client, "…$filter=action eq 'selfActivate'",
                    f"{RM}/roleAssignmentScheduleRequests", filter="action eq 'selfActivate'")
        await probe(client, "…$orderby=createdDateTime desc",
                    f"{RM}/roleAssignmentScheduleRequests", orderby="createdDateTime desc")

        print("\n== approvals")
        await probe(client, "roleAssignmentApprovals", f"{RM}/roleAssignmentApprovals")
        await probe(client, "roleAssignmentScheduleInstances",
                    f"{RM}/roleAssignmentScheduleInstances")

        print("\n== retention: how far back does each source really go?")
        for days in (7, 30, 90, 180, 365):
            since = _iso(datetime.now(timezone.utc) - timedelta(days=days))
            try:
                rows, _ = await client.get_all(
                    f"{RM}/roleAssignmentScheduleRequests",
                    filter=f"createdDateTime ge {since}", max_items=1)
                print(f"  activations  >= {days:>4}d ago: {'rows' if rows else 'EMPTY'}")
            except GraphError as exc:
                print(f"  activations  >= {days:>4}d ago: FAIL {exc.status} {str(exc.message)[:70]}")
        for days in (7, 30, 90):
            since = _iso(datetime.now(timezone.utc) - timedelta(days=days))
            try:
                rows, _ = await client.get_all(
                    "/auditLogs/directoryAudits",
                    filter=f"activityDateTime ge {since}", max_items=1)
                print(f"  dirAudits    >= {days:>4}d ago: {'rows' if rows else 'EMPTY'}")
            except GraphError as exc:
                print(f"  dirAudits    >= {days:>4}d ago: FAIL {exc.status} {str(exc.message)[:70]}")

        print("\n== directory audits shape (the 'what did they do' source)")
        aud = await probe(client, "directoryAudits", "/auditLogs/directoryAudits",
                          orderby="activityDateTime desc")
        if aud:
            print(json.dumps(aud[0], indent=2)[:1400])

        print("\n== can we filter audits by the actor? (drives lazy enrichment cost)")
        if aud:
            oid = ((aud[0].get("initiatedBy") or {}).get("user") or {}).get("id") or ""
            if oid:
                await probe(client, f"audits filter initiatedBy user id",
                            "/auditLogs/directoryAudits",
                            filter=f"initiatedBy/user/id eq '{oid}'")


async def arm_side(connection) -> None:
    print("\n== Azure control plane")
    from app.azure.credentials import get_arm_token

    token, err = await get_arm_token(connection)
    if not token:
        print(f"  no ARM token: {err} -> Azure plane unavailable, Entra-only mode")
        return
    print("  ARM token acquired")

    import httpx

    from app.azure.arm import list_activity_log_events, list_subscriptions

    subs, serr = await list_subscriptions(token)
    print(f"  subscriptions: {len(subs)} {serr or ''}")
    if not subs:
        return
    sub = subs[0].get("subscriptionId") or subs[0].get("id", "").rsplit("/", 1)[-1]
    print(f"  probing subscription {sub}")

    headers = {"Authorization": f"Bearer {token}"}
    base = f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization"
    async with httpx.AsyncClient(timeout=60) as http:
        for name, api in (("roleAssignmentScheduleRequests", "2020-10-01"),
                          ("roleAssignmentScheduleInstances", "2020-10-01"),
                          ("roleEligibilityScheduleInstances", "2020-10-01")):
            r = await http.get(f"{base}/{name}", headers=headers,
                               params={"api-version": api})
            if r.status_code == 200:
                val = r.json().get("value", [])
                print(f"  OK    {name:36} {len(val)} row(s)")
                if val:
                    print(f"        keys: {','.join(sorted(val[0].get('properties', {})))[:200]}")
            else:
                print(f"  FAIL  {name:36} {r.status_code} {r.text[:120]}")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)
    events, aerr = await list_activity_log_events(token, sub, _iso(start), _iso(end),
                                                  max_events=5)
    print(f"  activity log (24h): {len(events)} event(s) {aerr or ''}")
    if events:
        e = events[0]
        print(f"        caller={e.get('caller')} op={(e.get('operationName') or {}).get('value')}")
        print(f"        claims keys: {','.join(sorted((e.get('claims') or {}))) [:200]}")


async def main() -> None:
    connection = resolve_connection(sys.argv[1])
    if not connection:
        print("connection not found")
        return
    await graph_side(connection)
    await arm_side(connection)


if __name__ == "__main__":
    asyncio.run(main())
