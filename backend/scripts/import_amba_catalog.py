"""Import the upstream Azure Monitor Baseline Alerts catalogue into a vendored snapshot.

Source of truth: ``services/<Provider>/<type>/alerts.yaml`` in
https://github.com/Azure/azure-monitor-baseline-alerts, pinned to a release tag so the
import is deterministic and the running app never needs outbound network access.

Usage (from ``backend/``)::

    python scripts/import_amba_catalog.py                  # re-import the pinned release
    python scripts/import_amba_catalog.py --tag 2026-06-03
    python scripts/import_amba_catalog.py --check          # fail if the vendored file is stale

Writes ``app/amba/data/amba_catalog.json``. Run it, review the diff, commit the result.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

REPO = "Azure/azure-monitor-baseline-alerts"
DEFAULT_TAG = "2026-06-03"
OUT_PATH = Path(__file__).resolve().parents[1] / "app" / "amba" / "data" / "amba_catalog.json"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "aznetagent-amba-import"})


# --------------------------------------------------------------------------- fetch
def _tree(tag: str) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{REPO}/git/trees/{tag}?recursive=1"
    resp = _SESSION.get(url, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if data.get("truncated"):
        raise RuntimeError("GitHub tree response was truncated; import would be incomplete.")
    return data.get("tree") or []


def _raw(tag: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{REPO}/{tag}/{path}"
    resp = _SESSION.get(url, timeout=60)
    resp.raise_for_status()
    return resp.text


# --------------------------------------------------------------------------- normalize
_SEV_LABEL = {0: "critical", 1: "error", 2: "warning", 3: "info", 4: "info"}

# AMBA does not publish an availability/performance/security axis; derive one so the
# existing UI grouping and finding severity mapping keep working.
#
# Matching is word-boundary based and runs over the alert NAME + METRIC + CATEGORY only.
# Descriptions are deliberately excluded: they are prose ("Supported for: Linux, Windows")
# and naive substring matching against them mislabelled large numbers of alerts — e.g.
# "Supported" contains "up", "Inodes" contains "nod".
_SECURITY_HINTS = (
    "auth", "authentication", "authorization", "unauthorized", "forbidden", "denied",
    "security", "ddos", "firewall", "threat", "certificate", "secret", "key", "keyvault",
    "delete", "deletion", "regenerate", "policy", "compliance", "waf", "azwafsecrule",
)
_AVAILABILITY_HINTS = (
    "availability", "available", "health", "healthy", "unhealthy", "heartbeat", "down",
    "failed", "failure", "failures", "error", "errors", "5xx", "4xx", "drop", "dropped",
    "disconnect", "disconnected", "unavailable", "probe", "outage", "restart", "restarts",
    "abort", "aborted", "deadletter", "deadlettered", "throttle", "throttled", "throttling",
    "quota", "exceeded", "429", "incident", "servicehealth", "resourcehealth", "status",
    "uptime", "downtime",
)

_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(\s*<?(?:https?://|mailto:)[^)]*>?\s*\)")
_MD_BARE_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MD_EMPHASIS_RE = re.compile(r"(\*\*|__|\*|_|`)")
_WS_RE = re.compile(r"\s+")


def _plain_text(value: Any) -> str:
    """Upstream prose contains Markdown; PDFs and table cells need plain text.

    The URLs are not lost — every alert's ``references`` list carries them as real links.
    """
    text = str(value or "")
    text = _MD_LINK_RE.sub(r"\1", text)
    text = _MD_BARE_LINK_RE.sub(r"\1", text)
    text = _MD_EMPHASIS_RE.sub("", text)
    return _WS_RE.sub(" ", text).strip()


def _slug(text: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")
    return out or "alert"


# Codes and acronyms that camel-case splitting destroys ("Percentage5XX" -> percentage/5/xx),
# so they are matched as substrings of the raw lowercased label instead.
_SECURITY_CODES = ("ddos", "waf", "sqli", "xss")
_AVAILABILITY_CODES = ("5xx", "4xx", "429", "503", "500", "snat")

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _words(text: str) -> set[str]:
    """Tokenize an Azure metric label, splitting camelCase and PascalCase runs."""
    spaced = _CAMEL_RE.sub(" ", text or "")
    return set(re.findall(r"[a-z0-9]+", spaced.lower()))


def _classify(alert: dict[str, Any], props: dict[str, Any]) -> str:
    label = " ".join(
        str(x)
        for x in (alert.get("name"), props.get("metricName"), props.get("category"))
        if x
    )
    blob = label.lower().replace(" ", "")
    words = _words(label)

    if words & set(_SECURITY_HINTS) or any(code in blob for code in _SECURITY_CODES):
        return "security"
    if words & set(_AVAILABILITY_HINTS) or any(code in blob for code in _AVAILABILITY_CODES):
        return "availability"
    return "performance"


def _unit_for(metric: str, description: str) -> str:
    blob = f"{metric} {description}".lower()
    if "percent" in blob or metric.endswith("Percentage") or "utilization" in blob:
        return "%"
    if "bytes per second" in blob or "bitspersecond" in blob.replace(" ", ""):
        return "bytes/s"
    if "bytes" in blob:
        return "bytes"
    if "latency" in blob or "duration" in blob or "responsetime" in blob.replace(" ", ""):
        return "ms"
    return "count"


def _alert_type(raw: str) -> str:
    value = (raw or "Metric").strip().lower()
    if value.startswith("activity"):
        return "activitylog"
    if value.startswith("log"):
        return "log"
    return "metric"


def _threshold_override_tag(alert_name: str, props: dict[str, Any]) -> str:
    """AMBA-ALZ per-resource override tag: ``_amba-<metricName|counterName>-threshold-Override_``."""
    metric = props.get("metricName") or props.get("counterName") or ""
    if not metric:
        return ""
    if str(props.get("criterionType") or "") == "DynamicThresholdCriterion":
        return ""  # dynamic-threshold alerts cannot be overridden
    return f"_amba-{metric}-threshold-Override_"


# Upstream tags that denote a workload pattern rather than curation provenance.
PATTERN_TAGS = {
    "alz": "alz",
    "hpc": "hpc",
    "avd": "avd",
    "rag": "rag",
    "avs-landingzone": "avs",
}
_PROVENANCE_TAGS = {"auto-generated", "manual", "manual-ck"}


def _normalize_alert(alert: dict[str, Any], provider: str, service: str) -> dict[str, Any] | None:
    name = str(alert.get("name") or "").strip()
    if not name:
        return None
    props = alert.get("properties") or {}
    if not isinstance(props, dict):
        props = {}

    atype = _alert_type(str(alert.get("type") or "Metric"))
    metric = str(props.get("metricName") or "")
    description = _plain_text(alert.get("description"))

    severity_num = props.get("severity")
    try:
        severity_num = int(severity_num) if severity_num is not None else 3
    except (TypeError, ValueError):
        severity_num = 3

    threshold = props.get("threshold")
    try:
        threshold = float(threshold) if threshold is not None else None
    except (TypeError, ValueError):
        threshold = None

    deployments = []
    policy_alert_name = ""
    policy_scope = ""
    for dep in alert.get("deployments") or []:
        if not isinstance(dep, dict):
            continue
        dprops = dep.get("properties") or {}
        if not isinstance(dprops, dict):
            dprops = {}
        deployments.append(
            {
                "name": str(dep.get("name") or ""),
                "template": str(dep.get("template") or ""),
                "type": str(dep.get("type") or ""),
                "tags": [str(t) for t in (dep.get("tags") or [])],
                "scope": str(dprops.get("scope") or ""),
                "policy_scope": str(dprops.get("policyScope") or ""),
                "alert_name": str(dprops.get("alertName") or ""),
                "multi_resource": bool(dprops.get("multiResource", False)),
                "enabled": bool(dprops.get("enabled", True)),
            }
        )
        if not policy_alert_name and dprops.get("alertName"):
            policy_alert_name = str(dprops["alertName"])
        if not policy_scope and dprops.get("scope"):
            policy_scope = str(dprops["scope"])

    # AMBA "Alert state": Enabled => must-have, Disabled => nice-to-have.
    default_enabled = bool(props.get("enabled", True))
    visible = bool(alert.get("visible", True))
    amba_tags = [str(t) for t in (alert.get("tags") or [])]
    patterns = sorted({PATTERN_TAGS[t] for t in amba_tags if t in PATTERN_TAGS})
    # core     = shipped in an official AMBA policy/initiative (the opinionated baseline)
    # recommended = published on the AMBA site, deploy at your discretion
    # optional = present upstream but hidden (experimental / very noisy)
    if not visible:
        tier = "optional"
    elif "alz" in amba_tags or deployments:
        tier = "core"
    else:
        tier = "recommended"

    dimensions = []
    for dim in props.get("dimensions") or []:
        if isinstance(dim, dict) and dim.get("name"):
            dimensions.append(
                {
                    "name": str(dim["name"]),
                    "operator": str(dim.get("operator") or "Include"),
                    "values": [str(v) for v in (dim.get("values") or [])],
                }
            )

    failing = props.get("failingPeriods")
    failing_periods = None
    if isinstance(failing, dict):
        failing_periods = {
            "number_of_evaluation_periods": failing.get("numberOfEvaluationPeriods"),
            "min_failing_periods_to_alert": failing.get("minFailingPeriodsToAlert"),
        }

    # Activity-log matching facts (category / incidentType / operationName / status …).
    activity: dict[str, Any] = {}
    if atype == "activitylog":
        for field in ("category", "incidentType", "operationName", "status", "level", "resourceType"):
            if props.get(field) is not None:
                activity[field] = props[field]
        for field in ("causes", "currentHealthStatus", "previousHealthStatus"):
            if props.get(field) is not None:
                activity[field] = [str(v) for v in (props.get(field) or [])]

    return {
        "guid": str(alert.get("guid") or ""),
        "key": _slug(name)[:64],
        "name": name,
        "description": description,
        "alert_type": atype,
        "visible": visible,
        "verified": bool(alert.get("verified", False)),
        "amba_tags": amba_tags,
        "patterns": patterns,
        "tier": tier,
        "default_enabled": default_enabled,
        "amba_category": _classify(alert, props),
        "severity_num": severity_num,
        "severity": _SEV_LABEL.get(severity_num, "info"),
        "metric": metric,
        "metric_namespace": str(props.get("metricNamespace") or ""),
        "counter_name": str(props.get("counterName") or ""),
        "operator": str(props.get("operator") or ""),
        "threshold": threshold,
        "unit": _unit_for(metric, description),
        "criterion_type": str(props.get("criterionType") or ""),
        "alert_sensitivity": props.get("alertSensitivity"),
        "failing_periods": failing_periods,
        "auto_mitigate": props.get("autoMitigate"),
        "time_aggregation": str(props.get("timeAggregation") or ""),
        "window_size": str(props.get("windowSize") or ""),
        "evaluation_frequency": str(props.get("evaluationFrequency") or ""),
        "dimensions": dimensions,
        "activity_log": activity,
        "log_query": str(props.get("query") or ""),
        "references": [
            {"name": _plain_text(r.get("name")), "url": str(r.get("url") or "").strip()}
            for r in (alert.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ],
        "deployments": deployments,
        "policy_alert_name": policy_alert_name,
        "policy_scope": policy_scope,
        "threshold_override_tag": _threshold_override_tag(name, props),
        "provider": provider,
        "service": service,
    }


_DISPLAY_OVERRIDES = {
    "microsoft.compute/virtualmachines": "Virtual Machine",
    "microsoft.compute/virtualmachinescalesets": "VM Scale Set",
    "microsoft.web/sites": "App Service",
    "microsoft.web/serverfarms": "App Service Plan",
    "microsoft.sql/servers": "SQL Server",
    "microsoft.sql/managedinstances": "SQL Managed Instance",
    "microsoft.storage/storageaccounts": "Storage Account",
    "microsoft.containerservice/managedclusters": "AKS Cluster",
    "microsoft.keyvault/vaults": "Key Vault",
    "microsoft.cdn/profiles": "Front Door (Standard/Premium)",
    "microsoft.network/frontdoors": "Front Door (classic)",
    "microsoft.network/loadbalancers": "Load Balancer",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB",
    "microsoft.cache/redis": "Redis Cache",
    "microsoft.network/applicationgateways": "Application Gateway",
    "microsoft.apimanagement/service": "API Management",
    "microsoft.app/containerapps": "Container App",
    "microsoft.containerregistry/registries": "Container Registry",
    "microsoft.dbforpostgresql/flexibleservers": "PostgreSQL Flexible Server",
    "microsoft.dbformysql/flexibleservers": "MySQL Flexible Server",
    "microsoft.servicebus/namespaces": "Service Bus",
    "microsoft.eventhub/namespaces": "Event Hubs",
    "microsoft.eventgrid/topics": "Event Grid",
    "microsoft.logic/workflows": "Logic App",
    "microsoft.network/azurefirewalls": "Azure Firewall",
    "microsoft.network/publicipaddresses": "Public IP",
    "microsoft.cognitiveservices/accounts": "Azure AI / OpenAI",
    "microsoft.search/searchservices": "AI Search",
    "microsoft.machinelearningservices/workspaces": "ML Workspace",
    "microsoft.datafactory/factories": "Data Factory",
    "microsoft.synapse/workspaces": "Synapse Workspace",
    "microsoft.operationalinsights/workspaces": "Log Analytics Workspace",
    "microsoft.appconfiguration/configurationstores": "App Configuration",
    "microsoft.hybridcompute/machines": "Arc-enabled Server",
    "microsoft.resources/subscriptions": "Subscription (platform)",
    "microsoft.recoveryservices/vaults": "Recovery Services Vault",
    "microsoft.storagecache/amlfilesystems": "Azure Managed Lustre",
}

# Coarse UI grouping for the coverage matrix.
_CATEGORY_BY_PROVIDER = {
    "compute": "compute", "web": "compute", "app": "containers", "containerservice": "containers",
    "containerregistry": "containers", "containerinstance": "containers", "network": "network",
    "cdn": "network", "sql": "data", "storage": "data", "documentdb": "data", "cache": "data",
    "dbformysql": "data", "dbforpostgresql": "data", "dbformariadb": "data", "netapp": "data",
    "storagesync": "data", "storagecache": "data", "keyvault": "security", "cognitiveservices": "ai",
    "search": "ai", "machinelearningservices": "ai", "datafactory": "analytics",
    "synapse": "analytics", "kusto": "analytics", "streamanalytics": "analytics",
    "powerbidedicated": "analytics", "analysisservices": "analytics", "servicebus": "integration",
    "eventhub": "integration", "eventgrid": "integration", "logic": "integration",
    "apimanagement": "integration", "appconfiguration": "integration", "devices": "integration",
    "signalrservice": "integration", "operationalinsights": "monitoring", "insights": "monitoring",
    "automation": "management", "recoveryservices": "management", "resources": "platform",
    "hybridcompute": "compute", "avs": "compute", "batch": "compute", "advisor": "management",
}


def _title(service: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", service)
    return spaced[:1].upper() + spaced[1:]


def build_catalog(tag: str) -> dict[str, Any]:
    paths = [
        node["path"]
        for node in _tree(tag)
        if node.get("type") == "blob" and re.fullmatch(r"services/[^/]+/[^/]+/alerts\.yaml", node.get("path", ""))
    ]
    paths.sort()
    print(f"  discovered {len(paths)} alerts.yaml files at tag {tag}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        documents = list(pool.map(lambda p: (p, _raw(tag, p)), paths))

    types: dict[str, Any] = {}
    total_alerts = 0
    for path, text in documents:
        _, provider, service, _ = path.split("/")
        arm_type = f"microsoft.{provider}/{service}".lower()
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:  # pragma: no cover - upstream data problem
            print(f"  !! skipping {path}: {exc}")
            continue
        if not isinstance(parsed, list):
            print(f"  !! skipping {path}: expected a list, got {type(parsed).__name__}")
            continue

        alerts: list[dict[str, Any]] = []
        used_keys: set[str] = set()
        for raw in parsed:
            if not isinstance(raw, dict):
                continue
            norm = _normalize_alert(raw, provider, service)
            if norm is None:
                continue
            key = norm["key"]
            suffix = 2
            while key in used_keys:
                key = f"{norm['key']}_{suffix}"[:64]
                suffix += 1
            used_keys.add(key)
            norm["key"] = key
            alerts.append(norm)

        if not alerts:
            continue
        total_alerts += len(alerts)
        types[arm_type] = {
            "display": _DISPLAY_OVERRIDES.get(arm_type, _title(service)),
            "category": _CATEGORY_BY_PROVIDER.get(provider.lower(), "other"),
            "provider": provider,
            "service": service,
            "source_path": path,
            "alerts": alerts,
        }

    tiers: dict[str, int] = {}
    patterns: dict[str, int] = {}
    for spec in types.values():
        for alert in spec["alerts"]:
            tiers[alert["tier"]] = tiers.get(alert["tier"], 0) + 1
            for pattern in alert["patterns"]:
                patterns[pattern] = patterns.get(pattern, 0) + 1

    print(f"  normalized {len(types)} resource types / {total_alerts} alerts")
    print(f"  tiers={tiers} patterns={patterns}")
    return {
        "amba_release": tag,
        "source": f"https://github.com/{REPO}/tree/{tag}/services",
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "type_count": len(types),
        "alert_count": total_alerts,
        "tier_counts": dict(sorted(tiers.items())),
        "pattern_counts": dict(sorted(patterns.items())),
        "types": dict(sorted(types.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"AMBA release tag (default {DEFAULT_TAG})")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if the vendored file is stale")
    args = parser.parse_args()

    print(f"Importing AMBA catalogue from {REPO}@{args.tag} …")
    catalog = build_catalog(args.tag)

    if args.check:
        if not OUT_PATH.exists():
            print("FAIL: vendored catalogue is missing.")
            return 1
        current = json.loads(OUT_PATH.read_text(encoding="utf-8"))
        if current.get("types") != catalog["types"]:
            print("FAIL: vendored catalogue differs from upstream; re-run without --check.")
            return 1
        print("OK: vendored catalogue matches upstream.")
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(catalog, indent=1, sort_keys=False), encoding="utf-8")
    size_kb = OUT_PATH.stat().st_size / 1024
    print(f"Wrote {OUT_PATH} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
