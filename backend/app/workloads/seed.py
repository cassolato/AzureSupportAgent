"""Seed-resource workload tracing — reverse-engineer ONE workload from ONE resource id.

Where :mod:`app.workloads.autopilot` works TOP-DOWN (scope → enumerate everything → group
into many workloads), this module works BOTTOM-UP: given a single ARM resource id, follow
typed relationships outward and decide which resources belong to the same workload.

The hard part isn't *finding* related resources — it's knowing **where to stop**. A shared
Log Analytics workspace or a hub VNet is referenced by half the estate; traversing through
one would drag the whole tenant into the workload. Two mechanisms prevent that:

* **hop decay + a score threshold** — every edge kind carries a weight, a resource's score
  is the best ``∏ weights × decay^hop`` path from the seed, and anything below the
  threshold is dropped;
* **shared-platform detection** — a node with high fan-in (referenced by many distinct
  resources), a well-known shared type, or a platform-managed resource group is included
  as a *dependency* but is **never traversed through**.

Everything here is PURE (no Azure, no LLM) so it's fast and fully unit-testable; the Azure
queries that feed it live in :mod:`app.workloads.seed_links`.
"""
from __future__ import annotations

import heapq
import re
from typing import Any, Iterable

from app.workloads.sculpt import DEFAULT_SYSTEM_RG_GLOBS, rg_matches_globs

# --------------------------------------------------------------------------- ARM id utils
# Matches an ARM resource id embedded anywhere in a serialized properties blob. The resource
# group segment is optional (subscription-level resources), and at least ``type/name`` must
# follow the provider namespace so bare provider paths aren't matched.
_ARM_ID_RE = re.compile(
    r"/subscriptions/[0-9a-fA-F-]{36}"
    r"(?:/resourceGroups/[A-Za-z0-9._()\-]+)?"
    r"/providers/[A-Za-z0-9.]+(?:/[A-Za-z0-9._()\-]+){2,}",
    re.IGNORECASE,
)


def top_level_id(arm_id: str) -> str:
    """Truncate an ARM id to its top-level resource (``…/providers/<ns>/<type>/<name>``).

    Child paths (``/virtualNetworks/vnet/subnets/snet``, ``/sites/app/config/web``) collapse
    onto the parent so extracted references join against Resource Graph ``Resources`` rows."""
    if not arm_id:
        return ""
    lowered = arm_id.lower()
    idx = lowered.find("/providers/")
    if idx == -1:
        return arm_id.rstrip("/")
    head = arm_id[:idx]
    tail = arm_id[idx + len("/providers/") :].strip("/").split("/")
    if len(tail) < 3:
        return arm_id.rstrip("/")
    return f"{head}/providers/{'/'.join(tail[:3])}"


def extract_arm_ids(blob: Any, *, exclude: Iterable[str] = ()) -> set[str]:
    """Every distinct top-level ARM resource id referenced inside ``blob``.

    ``blob`` is usually a resource's ``properties`` dict (it is serialized first), but any
    JSON-ish value works. Ids are lowercased and normalized to their top-level resource."""
    if blob is None:
        return set()
    if isinstance(blob, (dict, list)):
        import json

        try:
            text = json.dumps(blob)
        except (TypeError, ValueError):
            text = str(blob)
    else:
        text = str(blob)
    skip = {str(x or "").lower() for x in exclude}
    out: set[str] = set()
    for match in _ARM_ID_RE.findall(text):
        rid = top_level_id(match).lower()
        if rid and rid not in skip:
            out.add(rid)
    return out


def arm_id_parts(arm_id: str) -> dict[str, str]:
    """``{subscription_id, resource_group, resource_type, name}`` parsed from an ARM id."""
    parts = (arm_id or "").strip("/").split("/")
    out = {"subscription_id": "", "resource_group": "", "resource_type": "", "name": ""}
    lowered = [p.lower() for p in parts]
    if "subscriptions" in lowered:
        i = lowered.index("subscriptions")
        if i + 1 < len(parts):
            out["subscription_id"] = parts[i + 1]
    if "resourcegroups" in lowered:
        i = lowered.index("resourcegroups")
        if i + 1 < len(parts):
            out["resource_group"] = parts[i + 1]
    if "providers" in lowered:
        i = lowered.index("providers")
        rest = parts[i + 1 :]
        if len(rest) >= 3:
            out["resource_type"] = f"{rest[0]}/{rest[1]}"
            out["name"] = rest[2]
    return out


def parent_id(arm_id: str) -> str:
    """The immediate ARM parent of a CHILD resource id, or ``""`` when it's top level.

    After ``/providers/`` an id reads ``<ns>/<type>/<name>[/<subtype>/<subname>]…`` — so a
    parent only exists once there are at least five segments."""
    rid = (arm_id or "").rstrip("/")
    idx = rid.lower().find("/providers/")
    if idx == -1:
        return ""
    head = rid[:idx]
    tail = rid[idx + len("/providers/") :].split("/")
    if len(tail) < 5:
        return ""
    return f"{head}/providers/{'/'.join(tail[:-2])}"


# --------------------------------------------------------------------------- edge model
# Relationship kinds, strongest first. The weight is how much of the parent's score an edge
# carries to its neighbour — 1.0 means "as certain as the resource we came from".
EDGE_WEIGHTS: dict[str, float] = {
    "child": 1.0,             # ARM parent/child (disks, NICs, subnets, slots)
    "id_reference": 1.0,      # one resource embeds the other's ARM id in its properties
    "private_endpoint": 0.95, # private endpoint → the PaaS resource it fronts
    "deployment": 0.9,        # co-deployed (azd-env-name / deployment marker)
    "identity_grant": 0.85,   # managed identity of A holds an RBAC role on B
    "shared_tag": 0.8,        # same authoritative app/service/cost-center tag value
    "same_rg": 0.7,           # same resource group
    "name_token": 0.55,       # same app token in the resource name
}

EDGE_LABELS: dict[str, str] = {
    "child": "Child resource",
    "id_reference": "ARM id reference",
    "private_endpoint": "Private endpoint",
    "deployment": "Same deployment",
    "identity_grant": "Identity grant",
    "shared_tag": "Shared tag",
    "same_rg": "Same resource group",
    "name_token": "Name similarity",
}

EDGE_KINDS: tuple[str, ...] = tuple(EDGE_WEIGHTS)

# Edges that do NOT consume a hop: a disk belongs to its VM no matter how deep the VM sits.
_NO_HOP_KINDS = frozenset({"child"})

# Only these count towards a node's fan-in when detecting shared platform hubs — soft
# signals (same RG, name token) would make every resource in a big RG look like a hub.
_STRONG_KINDS = frozenset({"id_reference", "private_endpoint", "identity_grant"})

# --------------------------------------------------------------------------- tuning knobs
HOP_DECAY = 0.75          # score multiplier applied per hop away from the seed
DEFAULT_MAX_HOPS = 2
DEFAULT_THRESHOLD = 0.45  # score at/above which a resource is a workload MEMBER
BORDERLINE_BAND = 0.15    # members between (threshold - band) and threshold need a decision
DEFAULT_HUB_FANIN = 25    # distinct strong neighbours before a node is "shared platform"
MAX_MEMBERS = 400         # hard cap on proposed members
CLIQUE_CAP = 60           # groups larger than this aren't a workload boundary — no clique

# Seed-mode presets (mirror autopilot.PRESETS for the top-down flow).
SEED_PRESETS: dict[str, dict[str, Any]] = {
    "tight": {"max_hops": 1, "threshold": 0.6, "include_shared": False},
    "balanced": {"max_hops": 2, "threshold": 0.45, "include_shared": False},
    "wide": {"max_hops": 3, "threshold": 0.3, "include_shared": True},
}

# Types that are shared platform infrastructure by nature — traversing through one leaks
# into every workload in the estate. They're still surfaced as dependencies.
SHARED_TYPE_SUBSTRINGS: tuple[str, ...] = (
    "microsoft.operationalinsights/workspaces",
    "microsoft.operationsmanagement/solutions",
    "microsoft.network/dnszones",
    "microsoft.network/privatednszones",
    "microsoft.network/azurefirewalls",
    "microsoft.network/firewallpolicies",
    "microsoft.network/bastionhosts",
    "microsoft.network/expressroutecircuits",
    "microsoft.network/virtualnetworkgateways",
    "microsoft.network/virtualwans",
    "microsoft.network/virtualhubs",
    "microsoft.network/ddosprotectionplans",
    "microsoft.network/routetables",
    "microsoft.recoveryservices/vaults",
    "microsoft.automation/automationaccounts",
    "microsoft.portal/dashboards",
)

# Tag keys whose VALUE identifies a deployment/application. ``azd-env-name`` is the
# strongest (emitted by azd for exactly one deployed app) so it gets the deployment kind.
_DEPLOYMENT_TAG_KEYS = ("azd-env-name",)
_APP_TAG_KEYS = (
    "application", "app", "appname", "workload", "service", "servicename",
    "product", "project", "solution", "system", "cost-center", "costcenter",
)

# Name tokens that carry no app identity — environment markers and resource-type prefixes.
_NOISE_NAME_TOKENS = frozenset({
    "prod", "prd", "production", "dev", "development", "test", "tst", "qa", "uat",
    "stg", "stage", "staging", "sandbox", "sbx", "dr", "live", "preprod", "shared",
    "vm", "st", "sa", "stor", "kv", "asp", "plan", "app", "web", "func", "fn", "sql",
    "db", "vnet", "snet", "nsg", "pip", "nic", "law", "aks", "acr", "cosmos", "redis",
    "sb", "eh", "adf", "apim", "lb", "agw", "afw", "fw", "rg", "id", "mi", "ai", "appi",
    "azure", "microsoft", "default",
})


def _rtype(resource: dict[str, Any]) -> str:
    return str(resource.get("resource_type") or resource.get("type") or "").lower()


def app_token(name: str) -> str:
    """The first name segment that plausibly identifies the APPLICATION.

    ``func-payments-prod-01`` → ``payments``; ``st-prod`` → ``""`` (nothing app-specific)."""
    for part in re.split(r"[-_.]+", str(name or "").lower()):
        if not part or part.isdigit() or len(part) < 3:
            continue
        if part in _NOISE_NAME_TOKENS:
            continue
        if re.fullmatch(r"[a-z]{2,}\d+", part) and part[:-1] in _NOISE_NAME_TOKENS:
            continue
        return part
    return ""


def is_shared_platform(
    resource: dict[str, Any], fanin: int = 0, hub_fanin_limit: int = DEFAULT_HUB_FANIN
) -> bool:
    """True when a resource is shared infrastructure rather than part of one workload."""
    rtype = _rtype(resource)
    if any(sub in rtype for sub in SHARED_TYPE_SUBSTRINGS):
        return True
    if rg_matches_globs(str(resource.get("resource_group", "")), DEFAULT_SYSTEM_RG_GLOBS):
        return True
    return hub_fanin_limit > 0 and fanin >= hub_fanin_limit


# --------------------------------------------------------------------------- edge building
def _edge(source: str, target: str, kind: str, detail: str) -> dict[str, Any]:
    return {
        "source": source.lower(),
        "target": target.lower(),
        "kind": kind,
        "detail": detail,
        "weight": EDGE_WEIGHTS.get(kind, 0.5),
    }


def _clique_edges(
    buckets: dict[str, list[str]], kind: str, detail_of: Any, cap: int = CLIQUE_CAP
) -> list[dict[str, Any]]:
    """Connect every member of each bucket to every other. Buckets larger than ``cap`` are
    skipped — a 300-resource resource group is a container, not a workload boundary."""
    out: list[dict[str, Any]] = []
    for key, ids in buckets.items():
        uniq = sorted(set(ids))
        if len(uniq) < 2 or len(uniq) > cap:
            continue
        detail = detail_of(key) if callable(detail_of) else str(detail_of)
        for i, a in enumerate(uniq):
            for b in uniq[i + 1 :]:
                out.append(_edge(a, b, kind, detail))
    return out


def build_edges(
    resources: dict[str, dict[str, Any]], raw: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Build the weighted relationship graph over a candidate resource universe.

    ``resources`` is ``{lowercased arm id: resource dict}``. ``raw`` carries the link tables
    that need Azure to collect: ``references`` (``[{source, target}]``), ``private_endpoints``
    (``[{pe, target}]``) and ``identity_grants`` (``[{source, scope, role}]``). Everything
    else (parent/child, tags, resource group, naming) is derived from the resources."""
    raw = raw or {}
    known = set(resources)
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, target: str, kind: str, detail: str) -> None:
        s, t = source.lower(), target.lower()
        if not s or not t or s == t or s not in known or t not in known:
            return
        key = (min(s, t), max(s, t), kind)
        if key in seen:
            return
        seen.add(key)
        edges.append(_edge(s, t, kind, detail))

    def _name(rid: str) -> str:
        return str(resources.get(rid, {}).get("name", "")) or arm_id_parts(rid)["name"] or rid

    # 1. Explicit ARM-id references (both directions were collected by the caller).
    for ref in raw.get("references") or []:
        src = str(ref.get("source", "")).lower()
        tgt = str(ref.get("target", "")).lower()
        add(src, tgt, "id_reference", f"“{_name(src)}” references “{_name(tgt)}”")

    # 2. ARM parent/child — a disk/NIC/subnet always belongs with its parent.
    for rid in resources:
        pid = parent_id(rid)
        if pid and pid.lower() in known:
            add(pid, rid, "child", f"Child of “{_name(pid.lower())}”")

    # 3. Private endpoints → the PaaS resource they front.
    for link in raw.get("private_endpoints") or []:
        pe = str(link.get("pe", "")).lower()
        tgt = str(link.get("target", "")).lower()
        add(pe, tgt, "private_endpoint", f"Private endpoint into “{_name(tgt)}”")

    # 4. Managed-identity RBAC grants — A's identity can act on B.
    for grant in raw.get("identity_grants") or []:
        src = str(grant.get("source", "")).lower()
        scope = top_level_id(str(grant.get("scope", ""))).lower()
        role = str(grant.get("role", "") or "a role")
        add(src, scope, "identity_grant", f"“{_name(src)}” identity holds {role} on “{_name(scope)}”")

    # 5. Tag cliques — deployment markers first, then general application tags.
    deploy_buckets: dict[str, list[str]] = {}
    app_buckets: dict[str, list[str]] = {}
    for rid, res in resources.items():
        tags = res.get("tags") or {}
        if not isinstance(tags, dict):
            continue
        lowered = {str(k).lower(): str(v) for k, v in tags.items() if str(v or "").strip()}
        for key in _DEPLOYMENT_TAG_KEYS:
            if lowered.get(key):
                deploy_buckets.setdefault(f"{key}={lowered[key]}", []).append(rid)
                break
        for key in _APP_TAG_KEYS:
            if lowered.get(key):
                app_buckets.setdefault(f"{key}={lowered[key]}", []).append(rid)
                break
    for e in _clique_edges(deploy_buckets, "deployment", lambda k: f"Same deployment marker {k}"):
        add(e["source"], e["target"], e["kind"], e["detail"])
    for e in _clique_edges(app_buckets, "shared_tag", lambda k: f"Shared tag {k}"):
        add(e["source"], e["target"], e["kind"], e["detail"])

    # 6. Resource-group cliques.
    rg_buckets: dict[str, list[str]] = {}
    for rid, res in resources.items():
        rg = str(res.get("resource_group", "")).lower()
        sub = str(res.get("subscription_id", "")).lower()
        if rg:
            rg_buckets.setdefault(f"{sub}|{rg}", []).append(rid)
    for e in _clique_edges(rg_buckets, "same_rg", lambda k: f"Same resource group '{k.split('|')[-1]}'"):
        add(e["source"], e["target"], e["kind"], e["detail"])

    # 7. Name-token cliques.
    name_buckets: dict[str, list[str]] = {}
    for rid, res in resources.items():
        token = app_token(str(res.get("name", "")))
        if token:
            name_buckets.setdefault(token, []).append(rid)
    for e in _clique_edges(name_buckets, "name_token", lambda k: f"Name contains '{k}'"):
        add(e["source"], e["target"], e["kind"], e["detail"])

    return edges


def compute_fanin(edges: list[dict[str, Any]]) -> dict[str, int]:
    """Distinct STRONG neighbours per node — the hub signal for shared-platform detection."""
    neighbours: dict[str, set[str]] = {}
    for e in edges:
        if e["kind"] not in _STRONG_KINDS:
            continue
        neighbours.setdefault(e["source"], set()).add(e["target"])
        neighbours.setdefault(e["target"], set()).add(e["source"])
    return {k: len(v) for k, v in neighbours.items()}


# --------------------------------------------------------------------------- scoring
def score_graph(
    seed_id: str,
    resources: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    threshold: float = DEFAULT_THRESHOLD,
    decay: float = HOP_DECAY,
    hub_fanin_limit: int = DEFAULT_HUB_FANIN,
    max_nodes: int = MAX_MEMBERS,
    enabled_kinds: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Best-first expansion from the seed, returning bucketed, scored, evidenced nodes.

    A node's score is the best ``∏ edge weights × decay^hop`` path back to the seed. Nodes
    flagged as shared platform are scored and reported but never expanded through, which is
    what stops a hub VNet or a central Log Analytics workspace swallowing the estate."""
    seed = (seed_id or "").lower()
    if seed not in resources:
        return {
            "seed": seed, "nodes": [], "edges": [],
            "stats": {"members": 0, "borderline": 0, "shared": 0, "excluded": 0, "edges": 0, "hubs": 0},
        }

    allowed = set(enabled_kinds) if enabled_kinds is not None else set(EDGE_KINDS)
    live = [e for e in edges if e["kind"] in allowed and e["source"] in resources and e["target"] in resources]

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for e in live:
        adjacency.setdefault(e["source"], []).append(e)
        adjacency.setdefault(e["target"], []).append(e)

    fanin = compute_fanin(live)
    shared_ids = {
        rid for rid in resources
        if rid != seed and is_shared_platform(resources[rid], fanin.get(rid, 0), hub_fanin_limit)
    }

    floor = max(0.0, threshold - BORDERLINE_BAND) - 1e-9
    best: dict[str, dict[str, Any]] = {seed: {"score": 1.0, "hop": 0, "via": None, "parent": ""}}
    heap: list[tuple[float, str]] = [(-1.0, seed)]
    while heap:
        neg, nid = heapq.heappop(heap)
        score = -neg
        entry = best.get(nid)
        if entry is None or score < entry["score"] - 1e-9:
            continue  # stale heap entry
        if nid != seed and nid in shared_ids:
            continue  # include, but never traverse THROUGH shared platform
        hop = entry["hop"]
        for e in adjacency.get(nid, ()):
            other = e["target"] if e["source"] == nid else e["source"]
            steps = 0 if e["kind"] in _NO_HOP_KINDS else 1
            nhop = hop + steps
            if nhop > max_hops:
                continue
            cand = score * e["weight"] * (decay**steps)
            if cand < floor:
                continue
            prev = best.get(other)
            if prev is not None and cand <= prev["score"] + 1e-9:
                continue
            best[other] = {"score": cand, "hop": nhop, "via": e, "parent": nid}
            heapq.heappush(heap, (-cand, other))

    # Evidence: every edge tying a node back to something already reachable, best first.
    def _evidence(nid: str) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        seen_kinds: set[str] = set()
        for e in sorted(adjacency.get(nid, ()), key=lambda x: -x["weight"]):
            other = e["target"] if e["source"] == nid else e["source"]
            if other not in best:
                continue
            if e["kind"] in seen_kinds:
                continue
            seen_kinds.add(e["kind"])
            out.append({"kind": e["kind"], "label": EDGE_LABELS.get(e["kind"], e["kind"]), "detail": e["detail"]})
            if len(out) >= 4:
                break
        return out

    def _path(nid: str) -> list[str]:
        chain: list[str] = []
        cur = nid
        for _ in range(max_hops + 4):
            entry = best.get(cur)
            if not entry or not entry.get("via"):
                break
            chain.append(entry["via"]["kind"])
            cur = entry["parent"]
        return list(reversed(chain))

    nodes: list[dict[str, Any]] = []
    for nid, entry in best.items():
        res = resources[nid]
        shared = nid in shared_ids
        score = entry["score"]
        if nid == seed:
            bucket = "member"
        elif shared:
            bucket = "shared"
        elif score >= threshold - 1e-9:
            bucket = "member"
        elif score >= threshold - BORDERLINE_BAND - 1e-9:
            bucket = "borderline"
        else:
            bucket = "excluded"
        nodes.append({
            "id": res.get("id", nid),
            "name": res.get("name", ""),
            "resource_type": res.get("resource_type", ""),
            "resource_group": res.get("resource_group", ""),
            "subscription_id": res.get("subscription_id", ""),
            "location": res.get("location", ""),
            "score": round(score, 4),
            "hop": entry["hop"],
            "shared": shared,
            "bucket": bucket,
            "fanin": fanin.get(nid, 0),
            "is_seed": nid == seed,
            "path": _path(nid),
            "evidence": _evidence(nid),
        })

    nodes.sort(key=lambda n: (not n["is_seed"], n["hop"], -n["score"], n["name"]))

    # Hard cap on proposed members so a runaway trace can't propose thousands.
    kept = 0
    for n in nodes:
        if n["bucket"] != "member":
            continue
        kept += 1
        if kept > max_nodes:
            n["bucket"] = "excluded"
            n["capped"] = True

    reachable = set(best)
    used_edges = [e for e in live if e["source"] in reachable and e["target"] in reachable]
    counts = {"member": 0, "borderline": 0, "shared": 0, "excluded": 0}
    for n in nodes:
        counts[n["bucket"]] = counts.get(n["bucket"], 0) + 1
    return {
        "seed": seed,
        "nodes": nodes,
        "edges": used_edges,
        "stats": {
            "members": counts["member"],
            "borderline": counts["borderline"],
            "shared": counts["shared"],
            "excluded": counts["excluded"],
            "edges": len(used_edges),
            "hubs": len(shared_ids),
            "universe": len(resources),
            "max_hops": max_hops,
            "threshold": round(threshold, 3),
        },
    }


def default_name(seed: dict[str, Any], members: list[dict[str, Any]]) -> str:
    """Deterministic workload name when AI naming is unavailable/declined."""
    token = app_token(str(seed.get("name", "")))
    if token:
        return token.replace("_", " ").title()
    rg = str(seed.get("resource_group", "")).strip()
    if rg:
        return rg
    return str(seed.get("name", "")) or "Workload"


def preset_config(preset: str) -> dict[str, Any]:
    """Resolve a seed preset id into its controls (unknown ids fall back to balanced)."""
    return dict(SEED_PRESETS.get((preset or "").lower(), SEED_PRESETS["balanced"]))
