"""Probe the risk-domain endpoints against a live tenant and report the exact failure.

Usage: .venv\\Scripts\\python.exe scripts\\entra_probe_risk.py <connection_id>
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.azure_connections import resolve_connection  # noqa: E402
from app.entra.graphclient import GraphClient, GraphError  # noqa: E402
from app.entra.permissions_probe import decode_token_roles  # noqa: E402

SINCE = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

PROBES = (
    ("signIns (filtered)", "/auditLogs/signIns", {"filter": f"createdDateTime ge {SINCE}", "top": 5}),
    ("signIns (bare)", "/auditLogs/signIns", {"top": 5}),
    ("directoryAudits", "/auditLogs/directoryAudits", {"top": 5}),
    ("riskyUsers", "/identityProtection/riskyUsers", {"top": 5}),
    ("riskDetections", "/identityProtection/riskDetections", {"top": 5}),
    ("riskyServicePrincipals", "/identityProtection/riskyServicePrincipals", {"top": 5}),
    ("userRegistrationDetails", "/reports/authenticationMethods/userRegistrationDetails", {"top": 5}),
    ("accessReviews", "/identityGovernance/accessReviews/definitions", {"top": 5}),
    ("accessPackages", "/identityGovernance/entitlementManagement/accessPackages", {"top": 5}),
    ("lifecycleWorkflows", "/identityGovernance/lifecycleWorkflows/workflows", {"top": 5}),
)


async def main() -> None:
    connection = resolve_connection(sys.argv[1] if len(sys.argv) > 1 else "")
    if not connection:
        print("no such connection")
        return
    async with GraphClient(connection) as client:
        token, err = await client.probe_token()
        if not token:
            print("no token:", err)
            return
        roles, claim_err = decode_token_roles(token)
        print(f"tenant {connection.get('tenant_id')}")
        print(f"token application permissions ({len(roles)}): {', '.join(sorted(roles)) or '(none)'}")
        if claim_err:
            print("claim note:", claim_err)
        print()
        for label, path, kwargs in PROBES:
            try:
                rows, _ = await client.get_all(path, max_items=5, **kwargs)  # type: ignore[arg-type]
                print(f"  OK    {label:26} {len(rows)} row(s)")
            except GraphError as exc:
                print(f"  FAIL  {label:26} {exc.status} {str(exc.message)[:120]}")


asyncio.run(main())
