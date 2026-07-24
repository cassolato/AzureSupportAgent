"""Tests for SEED-resource workload tracing — ARM id extraction, edge building, scored
expansion, hop decay, shared-platform boundaries, buckets and caps. All offline (no Azure,
no LLM); the Azure query layer is exercised via a stubbed universe in the e2e test."""
from __future__ import annotations

import asyncio

from app.workloads import autopilot as ap
from app.workloads import seed
from app.workloads import seed_links

SUB = "11111111-2222-3333-4444-555555555555"


def _rid(rtype: str, name: str, rg: str = "rg-pay-prod") -> str:
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{rtype}/{name}"


def _r(rtype, name, rg="rg-pay-prod", tags=None, props=None, identity=None, loc="eastus"):
    rid = _rid(rtype, name, rg)
    return {
        "kind": "resource", "id": rid, "name": name, "resource_type": rtype,
        "resource_group": rg, "subscription_id": SUB, "location": loc,
        "tags": tags or {}, "properties": props or {}, "identity": identity or {},
    }


def _universe(*resources):
    return {str(r["id"]).lower(): r for r in resources}


# ------------------------------------------------------------------ ARM id extraction
def test_extract_arm_ids_finds_embedded_references():
    plan = _rid("Microsoft.Web/serverfarms", "asp-pay-prod")
    props = {"serverFarmId": plan, "siteConfig": {"appSettings": [{"value": "nothing"}]}}
    found = seed.extract_arm_ids(props)
    assert found == {plan.lower()}


def test_extract_arm_ids_normalizes_child_paths_to_parent():
    subnet = _rid("Microsoft.Network/virtualNetworks", "vnet-app") + "/subnets/snet-web"
    found = seed.extract_arm_ids({"subnet": {"id": subnet}})
    assert found == {_rid("Microsoft.Network/virtualNetworks", "vnet-app").lower()}


def test_extract_arm_ids_ignores_self_and_non_ids():
    self_id = _rid("Microsoft.Web/sites", "func-payments")
    props = {"id": self_id, "note": "/subscriptions/not-a-guid/providers/x"}
    assert seed.extract_arm_ids(props, exclude=(self_id,)) == set()


def test_extract_arm_ids_handles_subscription_level_ids():
    rid = f"/subscriptions/{SUB}/providers/Microsoft.Insights/actionGroups/ag1"
    assert seed.extract_arm_ids({"scope": rid}) == {rid.lower()}


def test_top_level_id_and_parts():
    rid = _rid("Microsoft.Sql/servers", "sql-pay") + "/databases/paydb"
    assert seed.top_level_id(rid) == _rid("Microsoft.Sql/servers", "sql-pay")
    parts = seed.arm_id_parts(rid)
    assert parts["subscription_id"] == SUB
    assert parts["resource_group"] == "rg-pay-prod"
    assert parts["resource_type"] == "Microsoft.Sql/servers"
    assert parts["name"] == "sql-pay"


def test_parent_id_only_for_child_resources():
    parent = _rid("Microsoft.Sql/servers", "sql-pay")
    assert seed.parent_id(parent + "/databases/paydb") == parent
    assert seed.parent_id(parent) == ""


# ------------------------------------------------------------------ naming
def test_app_token_skips_env_and_type_prefixes():
    assert seed.app_token("func-payments-prod-01") == "payments"
    assert seed.app_token("st-prod") == ""
    assert seed.app_token("kv-billing-dev") == "billing"
    assert seed.app_token("") == ""


# ------------------------------------------------------------------ shared platform
def test_shared_platform_by_type_rg_and_fanin():
    law = _r("microsoft.operationalinsights/workspaces", "law-hub")
    assert seed.is_shared_platform(law)
    aks_sys = _r("microsoft.compute/virtualmachinescalesets", "vmss", rg="MC_aks_rg_eastus")
    assert seed.is_shared_platform(aks_sys)
    normal = _r("microsoft.web/sites", "func-payments")
    assert not seed.is_shared_platform(normal, fanin=3)
    assert seed.is_shared_platform(normal, fanin=40)
    assert not seed.is_shared_platform(normal, fanin=40, hub_fanin_limit=0)


# ------------------------------------------------------------------ edge building
def test_build_edges_covers_every_relationship_kind():
    plan = _r("Microsoft.Web/serverfarms", "asp-payments-prod")
    site = _r("Microsoft.Web/sites", "func-payments-prod",
              props={"serverFarmId": plan["id"]},
              identity={"principalId": "p-1"})
    sql = _r("Microsoft.Sql/servers", "sql-payments-prod", tags={"application": "payments"})
    db = {**_r("Microsoft.Sql/servers", "x"), "id": sql["id"] + "/databases/paydb", "name": "paydb"}
    other = _r("Microsoft.Storage/storageAccounts", "stpayments", rg="rg-other",
               tags={"application": "payments"})
    universe = _universe(plan, site, sql, db, other)
    raw = {
        "references": [{"source": site["id"].lower(), "target": plan["id"].lower()}],
        "private_endpoints": [{"pe": plan["id"].lower(), "target": sql["id"].lower()}],
        "identity_grants": [{"source": site["id"].lower(), "scope": other["id"].lower(), "role": "Blob Contributor"}],
    }
    edges = seed.build_edges(universe, raw)
    kinds = {e["kind"] for e in edges}
    assert {"id_reference", "child", "private_endpoint", "identity_grant",
            "shared_tag", "same_rg", "name_token"} <= kinds


def test_build_edges_skips_unknown_endpoints_and_dedupes():
    a = _r("Microsoft.Web/sites", "app-one")
    b = _r("Microsoft.Web/serverfarms", "plan-one")
    universe = _universe(a, b)
    raw = {"references": [
        {"source": a["id"].lower(), "target": b["id"].lower()},
        {"source": a["id"].lower(), "target": b["id"].lower()},          # dupe
        {"source": a["id"].lower(), "target": "/subscriptions/x/nope"},  # unknown
    ]}
    edges = seed.build_edges(universe, raw)
    assert sum(1 for e in edges if e["kind"] == "id_reference") == 1


def test_build_edges_skips_oversized_cliques():
    many = [_r("Microsoft.Compute/virtualMachines", f"vm{i}", rg="rg-huge") for i in range(seed.CLIQUE_CAP + 5)]
    edges = seed.build_edges(_universe(*many), {})
    assert not [e for e in edges if e["kind"] == "same_rg"]


def test_compute_fanin_only_counts_strong_kinds():
    hub = _r("Microsoft.KeyVault/vaults", "kv-shared")
    others = [_r("Microsoft.Web/sites", f"app{i}", rg=f"rg{i}") for i in range(5)]
    universe = _universe(hub, *others)
    raw = {"references": [{"source": o["id"].lower(), "target": hub["id"].lower()} for o in others]}
    edges = seed.build_edges(universe, raw)
    fanin = seed.compute_fanin(edges)
    assert fanin[hub["id"].lower()] == 5


# ------------------------------------------------------------------ scoring
def _payments_estate():
    """A small realistic estate: a payments app plus a shared hub workspace."""
    plan = _r("Microsoft.Web/serverfarms", "asp-payments-prod")
    site = _r("Microsoft.Web/sites", "func-payments-prod", props={"serverFarmId": plan["id"]})
    storage = _r("Microsoft.Storage/storageAccounts", "stpaymentsprod")
    kv = _r("Microsoft.KeyVault/vaults", "kv-payments-prod")
    law = _r("microsoft.operationalinsights/workspaces", "law-hub", rg="rg-platform")
    stranger = _r("Microsoft.Web/sites", "func-invoices-prod", rg="rg-inv-prod")
    universe = _universe(plan, site, storage, kv, law, stranger)
    raw = {
        "references": [
            {"source": site["id"].lower(), "target": plan["id"].lower()},
            {"source": site["id"].lower(), "target": law["id"].lower()},
            {"source": stranger["id"].lower(), "target": law["id"].lower()},
        ],
    }
    edges = seed.build_edges(universe, raw)
    return site, universe, edges


def test_score_graph_buckets_members_and_shared_platform():
    site, universe, edges = _payments_estate()
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2)
    by_name = {n["name"]: n for n in result["nodes"]}

    assert by_name["func-payments-prod"]["is_seed"]
    assert by_name["asp-payments-prod"]["bucket"] == "member"
    assert by_name["stpaymentsprod"]["bucket"] == "member"   # same RG
    assert by_name["law-hub"]["bucket"] == "shared"          # never a member
    # The unrelated app is only reachable THROUGH the shared workspace, which is not
    # traversed — so it must not be pulled into the workload.
    assert "func-invoices-prod" not in by_name


def test_score_graph_respects_hop_limit():
    site, universe, edges = _payments_estate()
    one = seed.score_graph(site["id"].lower(), universe, edges, max_hops=1)
    two = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2)
    assert one["stats"]["members"] <= two["stats"]["members"]
    assert all(n["hop"] <= 1 for n in one["nodes"])


def test_score_graph_decays_with_distance():
    site, universe, edges = _payments_estate()
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=3)
    scores = {n["name"]: n["score"] for n in result["nodes"]}
    assert scores["func-payments-prod"] == 1.0
    assert scores["asp-payments-prod"] < 1.0


def test_score_graph_threshold_moves_the_boundary():
    site, universe, edges = _payments_estate()
    loose = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2, threshold=0.2)
    strict = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2, threshold=0.95)
    assert loose["stats"]["members"] > strict["stats"]["members"]


def test_score_graph_children_do_not_consume_a_hop():
    sql = _r("Microsoft.Sql/servers", "sql-payments-prod", rg="rg-a")
    db = {**sql, "id": sql["id"] + "/databases/paydb", "name": "paydb"}
    site = _r("Microsoft.Web/sites", "func-payments-prod", rg="rg-b",
              props={"connection": sql["id"]})
    universe = _universe(sql, db, site)
    edges = seed.build_edges(universe, {"references": [{"source": site["id"].lower(), "target": sql["id"].lower()}]})
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=1)
    by_name = {n["name"]: n for n in result["nodes"]}
    assert by_name["sql-payments-prod"]["hop"] == 1
    assert by_name["paydb"]["hop"] == 1          # child rides along, no extra hop
    assert by_name["paydb"]["bucket"] == "member"


def test_score_graph_borderline_band():
    """Same-RG links (0.7 x 0.75 decay = 0.525) land in the band just under a 0.6 floor."""
    site, universe, edges = _payments_estate()
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=3, threshold=0.6)
    buckets = {n["bucket"] for n in result["nodes"]}
    assert "borderline" in buckets


def test_score_graph_edge_kind_filter():
    site, universe, edges = _payments_estate()
    full = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2)
    no_rg = seed.score_graph(
        site["id"].lower(), universe, edges, max_hops=2,
        enabled_kinds=[k for k in seed.EDGE_KINDS if k != "same_rg"],
    )
    assert no_rg["stats"]["members"] < full["stats"]["members"]


def test_score_graph_caps_members():
    site = _r("Microsoft.Web/sites", "func-payments-prod")
    extras = [_r("Microsoft.Compute/virtualMachines", f"vm-payments-{i}", rg=f"rg-{i}") for i in range(10)]
    universe = _universe(site, *extras)
    raw = {"references": [{"source": site["id"].lower(), "target": e["id"].lower()} for e in extras]}
    edges = seed.build_edges(universe, raw)
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2, max_nodes=4)
    assert result["stats"]["members"] == 4
    assert any(n.get("capped") for n in result["nodes"])


def test_score_graph_is_cycle_safe_and_handles_missing_seed():
    a = _r("Microsoft.Web/sites", "a-app")
    b = _r("Microsoft.Web/serverfarms", "b-plan")
    universe = _universe(a, b)
    raw = {"references": [
        {"source": a["id"].lower(), "target": b["id"].lower()},
        {"source": b["id"].lower(), "target": a["id"].lower()},
    ]}
    edges = seed.build_edges(universe, raw)
    assert seed.score_graph(a["id"].lower(), universe, edges)["stats"]["members"] >= 2
    empty = seed.score_graph("/subscriptions/none", universe, edges)
    assert empty["nodes"] == [] and empty["stats"]["members"] == 0


def test_score_graph_reports_path_and_evidence():
    site, universe, edges = _payments_estate()
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2)
    plan = next(n for n in result["nodes"] if n["name"] == "asp-payments-prod")
    assert plan["path"] and plan["path"][0] in seed.EDGE_KINDS
    assert plan["evidence"] and all("detail" in e for e in plan["evidence"])


# ------------------------------------------------------------------ presets / naming
def test_preset_config_and_default_name():
    assert seed.preset_config("tight")["max_hops"] == 1
    assert seed.preset_config("wide")["max_hops"] == 3
    assert seed.preset_config("nonsense") == seed.preset_config("balanced")
    assert seed.default_name({"name": "func-payments-prod"}, []) == "Payments"
    assert seed.default_name({"name": "st-prod", "resource_group": "rg-x"}, []) == "rg-x"


# ------------------------------------------------------------------ link-layer purity
def test_reference_pairs_only_links_within_the_universe():
    plan = _r("Microsoft.Web/serverfarms", "asp-x")
    site = _r("Microsoft.Web/sites", "app-x", props={
        "serverFarmId": plan["id"],
        "outside": _rid("Microsoft.Web/sites", "not-in-universe", rg="rg-elsewhere"),
    })
    pairs = seed_links._reference_pairs(_universe(plan, site))
    assert pairs == [{"source": site["id"].lower(), "target": plan["id"].lower()}]


def test_resolve_seed_rejects_bad_ids():
    res, err = asyncio.run(seed_links.resolve_seed(None, "not-an-id"))
    assert res is None and "resource id" in err
    res, err = asyncio.run(seed_links.resolve_seed(None, f"/subscriptions/{SUB}/resourceGroups/rg1"))
    assert res is None and "individual resource" in err


# ------------------------------------------------------------------ autopilot integration
def test_resolve_subs_supports_resource_scope():
    subs, err = asyncio.run(ap._resolve_subs(None, "resource", _rid("Microsoft.Web/sites", "a")))
    assert subs == [SUB] and not err
    subs, err = asyncio.run(ap._resolve_subs(None, "resource", "garbage"))
    assert subs == [] and err


def test_seed_evidence_summarizes_the_trace():
    site, universe, edges = _payments_estate()
    result = seed.score_graph(site["id"].lower(), universe, edges, max_hops=2)
    members = [n for n in result["nodes"] if n["bucket"] == "member"]
    ev = ap._seed_evidence(site, members)
    assert ev[0]["kind"] == "seed"
    assert any(e["kind"] in seed.EDGE_KINDS for e in ev[1:])


def test_trace_cache_roundtrip():
    key = ap._trace_key("t1", "c1", "/Sub/RES", 2)
    assert ap._trace_cache_get(key) is None
    ap._trace_cache_put(key, {"edges": []}, {"a": {}})
    hit = ap._trace_cache_get(key)
    assert hit is not None and hit[1] == {"a": {}}
    ap._trace_cache.pop(key, None)


def test_seed_discovery_end_to_end_without_azure_or_ai(monkeypatch):
    """Full discover_from_seed flow with the Azure + LLM layers stubbed out."""
    site, universe, _edges = _payments_estate()
    seed_res = universe[site["id"].lower()]

    async def fake_resolve(_conn, _rid, **_kw):
        return seed_res, ""

    async def fake_universe(_conn, _seed, _subs, **_kw):
        raw = {
            "references": [
                {"source": site["id"].lower(), "target": _rid("Microsoft.Web/serverfarms", "asp-payments-prod").lower()},
            ],
            "private_endpoints": [], "identity_grants": [],
        }
        return universe, raw, ["stubbed universe"]

    monkeypatch.setattr(seed_links, "resolve_seed", fake_resolve)
    monkeypatch.setattr(seed_links, "gather_universe", fake_universe)
    ap._trace_cache.clear()

    async def _run():
        events = []
        async for ev in ap.discover_from_seed(
            {"tenant_id": "t", "id": "c"}, site["id"], preset="balanced", use_ai=False
        ):
            events.append(ev)
        return events

    events = asyncio.run(_run())
    kinds = [e["type"] for e in events]
    assert "candidate" in kinds and "done" in kinds
    cand = next(e["candidate"] for e in events if e["type"] == "candidate")
    names = {n["name"] for n in cand["nodes"]}
    assert "func-payments-prod" in names           # the seed
    assert "asp-payments-prod" in names            # linked by id reference
    assert "law-hub" not in names                  # shared platform stays out
    assert cand["name"] == "Payments"              # deterministic naming (no AI)
    assert cand["evidence"][0]["kind"] == "seed"
    done = next(e for e in events if e["type"] == "done")
    assert done["meta"]["used_ai"] is False
    assert done["meta"]["seed"] == site["id"]


def test_seed_trace_stream_emits_a_trace_event(monkeypatch):
    site, universe, _edges = _payments_estate()
    seed_res = universe[site["id"].lower()]

    async def fake_resolve(_conn, _rid, **_kw):
        return seed_res, ""

    async def fake_universe(_conn, _seed, _subs, **_kw):
        return universe, {"references": [], "private_endpoints": [], "identity_grants": []}, []

    monkeypatch.setattr(seed_links, "resolve_seed", fake_resolve)
    monkeypatch.setattr(seed_links, "gather_universe", fake_universe)
    ap._trace_cache.clear()

    async def _run():
        return [ev async for ev in ap.trace_from_seed({"tenant_id": "t", "id": "c"}, site["id"])]

    events = asyncio.run(_run())
    trace = next(e for e in events if e["type"] == "trace")
    assert trace["seed"]["name"] == "func-payments-prod"
    assert trace["stats"]["members"] >= 1
    assert {k["kind"] for k in trace["edge_kinds"]} == set(seed.EDGE_KINDS)


def test_seed_trace_reports_bad_seed(monkeypatch):
    async def fake_resolve(_conn, _rid, **_kw):
        return None, "That resource wasn't found."

    monkeypatch.setattr(seed_links, "resolve_seed", fake_resolve)

    async def _run():
        return [ev async for ev in ap.trace_from_seed({"tenant_id": "t", "id": "c"}, "/subscriptions/x/providers/a/b/c")]

    events = asyncio.run(_run())
    assert events[-1]["type"] == "error"
