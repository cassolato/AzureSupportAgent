"""Live-Azure certification for AMBA coverage detection.

Deploys a throwaway resource group full of deliberately-mixed alert rules, then runs the
real collector over the payloads Azure Resource Graph actually returns and asserts every
detection path. This is the check the synthetic unit tests cannot make: that the parsing of
real ARM shapes (criteria odata types, dynamic-threshold clauses, activity-log conditions,
scheduled-query criteria, action rules, action group receivers) is correct.

The resource group is ALWAYS deleted in ``finally``. Execution is refused without the
explicit confirmation phrase.

Usage (from ``backend/``)::

    python scripts/amba_live_e2e.py --confirm CREATE_AND_DELETE_TEMP_AMBA_RESOURCES
    python scripts/amba_live_e2e.py --confirm ... --keep     # skip cleanup for debugging
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.amba.collector import (  # noqa: E402
    STATUS_MISCONFIGURED,
    STATUS_MISSING,
    STATUS_PRESENT,
    STATUS_SUPPRESSED,
    CoverageOptions,
    _describe_rule,
    _index_alerts,
    compute_coverage,
)

CONFIRMATION = "CREATE_AND_DELETE_TEMP_AMBA_RESOURCES"
BICEP = Path(__file__).resolve().parent / "amba_live_e2e.bicep"

ALERT_TYPES = (
    "microsoft.insights/metricalerts",
    "microsoft.insights/scheduledqueryrules",
    "microsoft.insights/activitylogalerts",
    "microsoft.insights/actiongroups",
    "microsoft.alertsmanagement/actionrules",
)


# --------------------------------------------------------------------------- shell
def az(*args: str, parse: bool = True) -> Any:
    proc = subprocess.run(
        ["az", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", shell=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"az {' '.join(args[:3])}… failed:\n{proc.stderr.strip()[:2000]}")
    if not parse:
        return proc.stdout
    return json.loads(proc.stdout) if proc.stdout.strip() else None


# --------------------------------------------------------------------------- assertions
class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def ok(self, condition: bool, label: str, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  PASS  {label}")
        else:
            self.failed.append(label)
            print(f"  FAIL  {label}{f'  — {detail}' if detail else ''}")

    def equal(self, actual: Any, expected: Any, label: str) -> None:
        self.ok(actual == expected, label, f"expected {expected!r}, got {actual!r}")


def find_cell(snapshot: dict[str, Any], resource_name: str, metric: str) -> dict[str, Any] | None:
    for group in snapshot["groups"]:
        for row in group["rows"]:
            if row["resource_name"].lower() != resource_name.lower():
                continue
            for cell in row["cells"]:
                if (cell["recommended"].get("metric") or "").lower() == metric.lower():
                    return cell
    return None


def find_cells(snapshot: dict[str, Any], resource_name: str, metric: str) -> list[dict[str, Any]]:
    out = []
    for group in snapshot["groups"]:
        for row in group["rows"]:
            if row["resource_name"].lower() != resource_name.lower():
                continue
            for cell in row["cells"]:
                if (cell["recommended"].get("metric") or "").lower() == metric.lower():
                    out.append(cell)
    return out


def find_activity_cell(snapshot: dict[str, Any], alert_key: str) -> dict[str, Any] | None:
    for group in snapshot["groups"]:
        for row in group["rows"]:
            for cell in row["cells"]:
                if cell["alert_key"] == alert_key:
                    return cell
    return None


# --------------------------------------------------------------------------- main
async def run(args: argparse.Namespace) -> int:
    suffix = uuid.uuid4().hex[:10]
    rg = f"rg-amba-e2e-{suffix}"
    checks = Checks()

    account = az("account", "show")
    subscription_id = account["id"]
    print(f"Subscription : {account['name']} ({subscription_id})")
    print(f"Resource group: {rg} ({args.location})")

    vault_name = ""
    try:
        print("\n[1/6] Creating resource group …")
        az("group", "create", "-n", rg, "-l", args.location, "--tags", "purpose=amba-e2e-test")

        print("[2/6] Deploying test estate (this takes a couple of minutes) …")
        result = az(
            "deployment", "group", "create",
            "-g", rg,
            "-f", str(BICEP),
            "--parameters", f"suffix={suffix}",
            "-n", f"amba-e2e-{suffix}",
        )
        outputs = result["properties"]["outputs"]
        vault_name = outputs["vaultName"]["value"]
        print(f"      deployed: storage, key vault, public IP, NSG, route table, LAW, "
              f"2 action groups, 7 metric alerts, 2 activity log alerts, 1 log alert, 1 APR")

        print("[3/6] Waiting for Azure Resource Graph to index the estate …")
        # Resource Graph indexes newly created resources asynchronously, and metric alerts /
        # scheduled query rules routinely lag the control-plane response by a minute or more.
        # Poll BOTH the resource universe and the rule set — asserting against a partial
        # index produces phantom "missing" results that look like collector bugs.
        storage_name = f"ambae2e{suffix}"
        expected_resources = {
            storage_name,
            vault_name,
            "amba-e2e-pip",
            "amba-e2e-nsg",
            "amba-e2e-rt",
            f"amba-e2e-law-{suffix}",
        }
        expected_rules = {
            "microsoft.insights/metricalerts": 9,
            "microsoft.insights/scheduledqueryrules": 1,
            "microsoft.insights/activitylogalerts": 2,
            "microsoft.insights/actiongroups": 2,
            "microsoft.alertsmanagement/actionrules": 1,
        }
        joined = ", ".join(f"'{t}'" for t in ALERT_TYPES)
        resource_query = (
            f"resources | where resourceGroup =~ '{rg}' "
            "| project id, name, type, resourceGroup, subscriptionId, location, tags"
        )
        rule_query = (
            f"resources | where type in~ ({joined}) | where resourceGroup =~ '{rg}' "
            "| project id, name, type, properties"
        )

        resources: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []
        by_type: dict[str, int] = {}
        deadline = time.monotonic() + args.index_timeout
        while True:
            resources = az("graph", "query", "-q", resource_query, "--first", "1000", "-o", "json")["data"]
            alerts = az("graph", "query", "-q", rule_query, "--first", "1000", "-o", "json")["data"]
            by_type = {}
            for row in alerts:
                key = row["type"].lower()
                by_type[key] = by_type.get(key, 0) + 1
            seen_names = {str(r.get("name", "")).lower() for r in resources}
            missing_resources = {n for n in expected_resources if n.lower() not in seen_names}
            missing_rules = {
                t: f"{by_type.get(t, 0)}/{n}" for t, n in expected_rules.items() if by_type.get(t, 0) < n
            }
            if not missing_resources and not missing_rules:
                break
            if time.monotonic() > deadline:
                print(f"      !! Resource Graph still incomplete after {args.index_timeout}s")
                print(f"         missing resources: {sorted(missing_resources)}")
                print(f"         missing rules: {missing_rules}")
                break
            print(f"      waiting … resources={sorted(missing_resources)} rules={missing_rules}")
            await asyncio.sleep(15)

        print(f"[4/6] Indexed: {len(resources)} resources, {len(alerts)} rules: {by_type}")

        # ------------------------------------------------------------ raw payload parsing
        print("\n[5/6] Verifying parsing of real ARM payloads")
        index = _index_alerts(alerts)
        checks.ok(len(index.action_groups) == 2, "both action groups indexed")
        checks.ok(
            sum(1 for usable in index.action_groups.values() if usable) == 1,
            "exactly one action group has usable receivers",
            f"{index.action_groups}",
        )
        checks.ok(len(index.suppressions) == 1, "alert processing rule parsed from ARG")
        checks.ok(
            bool(index.suppressions) and index.suppressions[0].unconditional,
            "suppression rule detected as unconditional",
        )

        log_rules = [
            d for d in (_describe_rule(r) for r in alerts) if d is not None and d.kind == "log"
        ]
        checks.ok(len(log_rules) == 1, "scheduled query rule parsed from ARG")
        if log_rules:
            checks.equal(log_rules[0].query_table, "insightsmetrics", "log query primary table extracted")
            checks.ok(
                "freespacepercentage" in log_rules[0].query_tokens,
                "log query discriminating operand extracted",
                f"tokens={sorted(log_rules[0].query_tokens)}",
            )

        dynamic_rules = [
            d for d in (_describe_rule(r) for r in alerts)
            if d is not None and "DynamicThresholdCriterion" in d.criterion_types
        ]
        checks.ok(len(dynamic_rules) == 1, "dynamic-threshold criterion parsed from ARG")
        if dynamic_rules:
            checks.equal(sorted(dynamic_rules[0].sensitivities), ["Medium"], "alert sensitivity extracted")

        activity_rules = [
            d for d in (_describe_rule(r) for r in alerts) if d is not None and d.kind == "activitylog"
        ]
        checks.ok(len(activity_rules) == 2, "activity log alerts parsed from ARG")
        categories = {c for d in activity_rules for c in d.activity.get("category", [])}
        checks.ok(
            categories == {"servicehealth", "administrative"},
            "activity log categories extracted",
            f"{categories}",
        )

        multi = [
            d for d in (_describe_rule(r) for r in alerts)
            if d is not None and d.target_resource_type
        ]
        checks.ok(len(multi) == 1, "multi-resource rule targetResourceType extracted")

        # ------------------------------------------------------------ end-to-end coverage
        print("\n[6/6] Computing coverage over the real payloads")
        snapshot = compute_coverage(
            resources,
            alerts,
            options=CoverageOptions(),
            subscriptions=[subscription_id],
        )
        kpis = snapshot["kpis"]
        print(
            f"      coverage {snapshot['coverage_pct']}% · "
            f"present {kpis['alerts_present']} · missing {kpis['alerts_missing']} · "
            f"misconfigured {kpis['alerts_misconfigured']} · suppressed {kpis['alerts_suppressed']} · "
            f"excluded {kpis['resources_excluded']}"
        )

        # Threshold-override tag: baseline wants < 100, the rule says 95, the tag says 95.
        availability_cells = find_cells(snapshot, storage_name, "Availability")
        checks.ok(len(availability_cells) == 2, "both Availability baselines scored for storage")
        for cell in availability_cells:
            checks.equal(cell["status"], STATUS_PRESENT, "storage Availability present via override tag")
            checks.equal(cell["observed"].get("effective_threshold"), 95.0, "override tag threshold applied")
            checks.equal(
                cell["observed"].get("threshold_override_tag"),
                "_amba-Availability-threshold-Override_",
                "override tag name recorded",
            )

        latency = find_cell(snapshot, vault_name, "ServiceApiHit")
        checks.ok(latency is not None, "key vault ServiceApiHit scored")
        if latency:
            checks.equal(latency["status"], STATUS_PRESENT, "RG-scoped multi-resource rule matches the vault")

        drift = find_cell(snapshot, storage_name, "SuccessE2ELatency")
        checks.ok(drift is not None, "storage SuccessE2ELatency baseline scored")
        if drift:
            checks.equal(drift["status"], STATUS_MISCONFIGURED, "threshold drift flagged")
            checks.ok(
                any("threshold differs" in i for i in drift["observed"].get("issues", [])),
                "threshold drift issue recorded",
                f"{drift['observed'].get('issues')}",
            )

        # Dimension discrimination: the AMBA "Throttling" baseline needs ResponseType AND
        # FileShare; the deployed rule carries only ResponseType, so it must not satisfy it.
        dimension_rules = [
            d for d in (_describe_rule(r) for r in alerts) if d is not None and d.dimensions
        ]
        checks.ok(len(dimension_rules) == 1, "metric dimensions parsed from ARG")
        if dimension_rules:
            checks.equal(
                sorted(dimension_rules[0].dimensions),
                [("responsetype", "success")],
                "dimension name/value pair extracted",
            )

        throttling = find_activity_cell(snapshot, "throttling")
        checks.ok(throttling is not None, "storage Throttling baseline scored")
        if throttling:
            checks.equal(
                throttling["status"], STATUS_MISSING,
                "partially-matching dimensions do not satisfy a dimension-specific baseline",
            )
            checks.ok(
                len(throttling["recommended"]["dimensions"]) == 2,
                "baseline dimensions surfaced on the cell",
            )

        file_transactions = find_activity_cell(snapshot, "fileservices_transactions")
        checks.ok(file_transactions is not None, "fileServices Transactions baseline scored")
        if file_transactions:
            checks.equal(
                file_transactions["status"], STATUS_MISSING,
                "rule with different dimensions does not satisfy a dimension-specific baseline",
            )

        api_result = find_cell(snapshot, vault_name, "ServiceApiResult")
        checks.ok(api_result is not None, "key vault ServiceApiResult scored")
        if api_result:
            checks.equal(api_result["status"], STATUS_PRESENT, "dynamic-threshold rule satisfies the dynamic baseline")
            checks.equal(
                api_result["observed"].get("observed_criterion_types"),
                ["DynamicThresholdCriterion"],
                "dynamic criterion recorded as observed",
            )

        kv_availability = find_cell(snapshot, vault_name, "Availability")
        checks.ok(kv_availability is not None, "key vault Availability scored")
        if kv_availability:
            checks.equal(kv_availability["status"], STATUS_MISCONFIGURED, "disabled rule flagged")
            checks.ok("disabled" in kv_availability["observed"].get("issues", []), "disabled issue recorded")

        saturation = find_cell(snapshot, vault_name, "SaturationShoebox")
        checks.ok(saturation is not None, "key vault SaturationShoebox scored")
        if saturation:
            checks.equal(saturation["status"], STATUS_MISCONFIGURED, "rule with no action group flagged")
            checks.ok(
                "no action group" in saturation["observed"].get("issues", []),
                "missing action group issue recorded",
            )

        kv_latency = find_cell(snapshot, vault_name, "ServiceApiLatency")
        checks.ok(kv_latency is not None, "key vault ServiceApiLatency scored")
        if kv_latency:
            checks.equal(kv_latency["status"], STATUS_MISCONFIGURED, "receiver-less action group flagged")
            checks.ok(
                "action group has no receivers" in kv_latency["observed"].get("issues", []),
                "receiver-less action group issue recorded",
                f"{kv_latency['observed'].get('issues')}",
            )

        vip = find_cell(snapshot, "amba-e2e-pip", "VipAvailability")
        checks.ok(vip is not None, "public IP VipAvailability scored")
        if vip:
            checks.equal(vip["status"], STATUS_SUPPRESSED, "alert processing rule suppression detected")
            checks.ok(bool(vip["observed"].get("suppressed_by")), "suppressing rule named on the cell")

        sh_incident = find_activity_cell(snapshot, "service_health_incident")
        checks.ok(sh_incident is not None, "Service Health Incident scored on the subscription row")
        if sh_incident:
            checks.equal(sh_incident["status"], STATUS_PRESENT, "Service Health Incident alert detected")

        sh_security = find_activity_cell(snapshot, "service_health_security")
        checks.ok(sh_security is not None, "Service Health Security scored")
        if sh_security:
            checks.equal(sh_security["status"], STATUS_MISSING, "un-deployed Service Health alert reported missing")

        kv_delete = find_activity_cell(snapshot, "activity_log_key_vault_delete")
        checks.ok(kv_delete is not None, "Key Vault delete activity log alert scored")
        if kv_delete:
            checks.equal(kv_delete["status"], STATUS_PRESENT, "Administrative activity log alert detected")

        excluded = {r["resource_name"] for r in snapshot["excluded_resources"]}
        checks.ok("amba-e2e-nsg" in excluded, "MonitorDisable-tagged NSG excluded", f"{excluded}")

        checks.equal(kpis["suppression_rules"], 1, "suppression rule counted in KPIs")
        checks.equal(kpis["action_groups"], 2, "action groups counted in KPIs")
        checks.equal(kpis["action_groups_usable"], 1, "usable action groups counted in KPIs")

        # Route table baselines are activity-log only and none were deployed.
        rt_delete = find_activity_cell(snapshot, "activity_log_route_table_deletion")
        checks.ok(rt_delete is not None, "route table activity log baseline scored")
        if rt_delete:
            checks.equal(rt_delete["status"], STATUS_MISSING, "un-deployed route table alert reported missing")

        if args.dump:
            Path(args.dump).write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
            print(f"\n      snapshot written to {args.dump}")

    finally:
        if args.keep:
            print(f"\n!! --keep set: resource group {rg} was NOT deleted. Delete it manually.")
        else:
            print(f"\nCleaning up: deleting resource group {rg} …")
            try:
                az("group", "delete", "-n", rg, "--yes", parse=False)
                print("      resource group deleted")
            except RuntimeError as exc:
                print(f"      !! cleanup failed: {exc}")
            # Key Vault soft-delete outlives the resource group; purge it so repeat runs of
            # this harness do not accumulate orphaned vaults in the tenant.
            if vault_name:
                try:
                    az("keyvault", "purge", "-n", vault_name, "-l", args.location, parse=False)
                    print(f"      key vault {vault_name} purged")
                except RuntimeError as exc:
                    print(f"      !! key vault purge failed (purge manually): {exc}")
            try:
                exists = az("group", "exists", "-n", rg, parse=False).strip().lower()
                print(f"      az group exists -> {exists}")
            except RuntimeError:
                pass

    print(f"\n{'=' * 70}")
    print(f"AMBA live E2E: {checks.passed} passed, {len(checks.failed)} failed")
    for label in checks.failed:
        print(f"  FAILED: {label}")
    print("=" * 70)
    return 1 if checks.failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True, help=f"must be exactly {CONFIRMATION}")
    parser.add_argument("--location", default="westeurope")
    parser.add_argument(
        "--index-timeout", type=int, default=300,
        help="seconds to wait for Resource Graph to index the new alert rules",
    )
    parser.add_argument("--keep", action="store_true", help="skip resource group deletion")
    parser.add_argument("--dump", default="", help="write the computed snapshot to this path")
    args = parser.parse_args()

    if args.confirm != CONFIRMATION:
        print(f"Refusing to run: --confirm must be exactly {CONFIRMATION}")
        return 2
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
