"""Tests for the deterministic parts of the harness: no network, no model calls."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mdash import dedupe, sarif
from mdash.agents import (
    AUTHN,
    DEBATE_SCHEMA,
    ESCALATION_SCHEMA,
    FINDINGS_SCHEMA,
    SUPPLY,
    select,
)
from mdash.config import Config
from mdash.findings import Finding, ProofState, Verdict, security_severity, severity_rank
from mdash.panel import Panel, extract_json, normalise_endpoint
from mdash.prepare import collect
from mdash.scan import _coerce, _relevant


# --------------------------------------------------------------------------------- findings
def test_severity_normalisation_and_ordering():
    assert severity_rank("CRITICAL") > severity_rank("high") > severity_rank("info")
    # Anything unrecognised must land on a safe middle value, never crash.
    assert Finding(path="a.py", title="t", severity="bogus").severity == "medium"
    assert float(security_severity("critical")) >= 9.0
    assert float(security_severity("high")) >= 7.0


def test_line_end_never_precedes_line_start():
    f = Finding(path="a.py", title="t", line_start=40, line_end=2)
    assert f.line_end == 40


def test_rule_id_prefers_cwe():
    assert Finding(path="a.py", title="X", cwe="CWE-611").rule_id == "mdash/cwe-611"
    assert Finding(path="a.py", title="Some Bug", cwe="").rule_id == "mdash/some-bug"
    # A malformed CWE must fall back to the slug rather than producing a broken id.
    assert Finding(path="a.py", title="Some Bug", cwe="CWE-abc").rule_id == "mdash/some-bug"


def test_fingerprint_is_line_independent():
    """Unrelated edits above a finding must not re-open the alert."""
    a = Finding(path="a.py", title="Same bug", cwe="CWE-79", line_start=10)
    b = Finding(path="a.py", title="Same bug", cwe="CWE-79", line_start=400)
    assert a.fingerprint == b.fingerprint
    c = Finding(path="other.py", title="Same bug", cwe="CWE-79")
    assert c.fingerprint != a.fingerprint


# ------------------------------------------------------------------------------------ panel
@pytest.mark.parametrize(
    "raw",
    [
        '[{"title": "x"}]',
        '```json\n[{"title": "x"}]\n```',
        'Sure, here you go:\n[{"title": "x"}]\nHope that helps!',
        '```\n[{"title": "x"}]\n```',
    ],
)
def test_extract_json_survives_model_wrapping(raw):
    assert extract_json(raw) == [{"title": "x"}]


def test_extract_json_returns_none_on_garbage():
    assert extract_json("not json at all") is None
    assert extract_json("") is None


# ------------------------------------------------------------------------------------- scan
def test_coerce_skips_malformed_entries():
    target = type("T", (), {"path": "a.py"})()
    raw = [
        {"title": "Real finding", "severity": "high", "confidence": 0.8},
        {"no_title": "ignored"},
        "not a dict",
        {"title": "", "severity": "high"},
    ]
    out = _coerce(raw, agent=AUTHN, target=target, model="m")
    assert len(out) == 1
    assert out[0].title == "Real finding"


def test_coerce_unwraps_object_wrapper():
    target = type("T", (), {"path": "a.py"})()
    out = _coerce({"findings": [{"title": "Wrapped"}]}, agent=AUTHN, target=target, model="m")
    assert len(out) == 1


def test_coerce_clamps_confidence():
    target = type("T", (), {"path": "a.py"})()
    out = _coerce(
        [{"title": "x", "confidence": 5.0}, {"title": "y", "confidence": "bad"}],
        agent=AUTHN, target=target, model="m",
    )
    assert out[0].confidence == 1.0
    assert out[1].confidence == 0.5


def test_agent_file_type_routing():
    """The infra auditor must not be spent on application Python, and vice versa."""
    py = type("T", (), {"path": "backend/app/auth/saml.py"})()
    compose = type("T", (), {"path": "docker-compose.yml"})()
    dockerfile = type("T", (), {"path": "Dockerfile"})()
    assert _relevant(AUTHN, py) and not _relevant(AUTHN, compose)
    assert _relevant(SUPPLY, compose) and not _relevant(SUPPLY, py)
    assert _relevant(SUPPLY, dockerfile)


def test_select_rejects_unknown_agent():
    assert len(select(None)) == 5
    assert [a.name for a in select(["injection"])] == ["injection"]
    with pytest.raises(ValueError, match="Unknown agent"):
        select(["nope"])


# ----------------------------------------------------------------------------------- dedupe
def _f(**kw):
    return Finding(**{"path": "a.py", "title": "t", **kw})


def test_dedupe_merges_same_cwe_in_same_region():
    out = dedupe.run([
        _f(title="Secret in argv", cwe="CWE-214", line_start=10, line_end=12,
           agent="secrets-crypto", severity="medium", confidence=0.6),
        _f(title="Credential exposed via process args", cwe="CWE-214", line_start=11,
           line_end=13, agent="injection", severity="high", confidence=0.5),
    ])
    assert len(out) == 1
    # The strongest instance survives, and the weaker agent is recorded as corroboration.
    assert out[0].severity == "high"
    assert out[0].agent == "injection"
    assert out[0].corroborations == ["secrets-crypto"]
    assert out[0].confidence > 0.5


def test_dedupe_keeps_distinct_bugs_apart():
    out = dedupe.run([
        _f(title="XXE in parser", cwe="CWE-611", line_start=10, agent="injection"),
        _f(title="Hardcoded password", cwe="CWE-798", line_start=300, agent="secrets-crypto"),
    ])
    assert len(out) == 2


def test_dedupe_does_not_merge_across_files():
    out = dedupe.run([
        Finding(path="a.py", title="Same bug", cwe="CWE-79", line_start=5, agent="x"),
        Finding(path="b.py", title="Same bug", cwe="CWE-79", line_start=5, agent="y"),
    ])
    assert len(out) == 2


def test_dedupe_confidence_never_exceeds_one():
    findings = [
        _f(title="Same bug", cwe="CWE-89", line_start=5, agent=f"agent-{i}", confidence=0.9)
        for i in range(8)
    ]
    out = dedupe.run(findings)
    assert len(out) == 1
    assert out[0].confidence <= 1.0


def test_dedupe_empty():
    assert dedupe.run([]) == []


# ------------------------------------------------------------------------------------ sarif
def test_sarif_shape_and_required_properties():
    findings = [
        _f(title="XXE", cwe="CWE-611", severity="high", line_start=10, line_end=12,
           agent="injection", model="gpt-5.3-codex", confidence=0.9,
           verdict=Verdict.UPHELD, remediation="Disable entity resolution."),
    ]
    doc = sarif.build(findings, usage={"gpt-5.4": {"calls": 2}})
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert len(run["results"]) == 1

    result = run["results"][0]
    assert result["ruleId"] == "mdash/cwe-611"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    # GitHub tracks alerts by this, not by line number.
    assert result["partialFingerprints"]["mdashFindingV1"]

    rule = run["tool"]["driver"]["rules"][0]
    # GitHub ranks by security-severity, not by SARIF level.
    assert float(rule["properties"]["security-severity"]) >= 7.0
    assert "external/cwe/cwe-611" in rule["properties"]["tags"]


def test_sarif_message_reports_the_reasoning_chain():
    f = _f(title="X", severity="high", agent="injection", model="m",
           hypothesis="Attacker controls input.", verdict=Verdict.UPHELD,
           debate_rationale="Guard is bypassable.", proof_state=ProofState.PROVEN,
           remediation="Escape it.")
    f.corroborations = ["secrets-crypto"]
    msg = sarif.build([f])["runs"][0]["results"][0]["message"]["text"]
    assert "injection" in msg and "secrets-crypto" in msg
    assert "upheld" in msg and "Guard is bypassable." in msg
    assert "Proof of concept executed successfully" in msg
    assert "Escape it." in msg


def test_sarif_rule_dedup_keeps_highest_severity():
    doc = sarif.build([
        _f(title="A", cwe="CWE-611", severity="low", line_start=1),
        _f(path="b.py", title="B", cwe="CWE-611", severity="critical", line_start=1),
    ])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert float(rules[0]["properties"]["security-severity"]) >= 9.0


def test_sarif_empty_is_valid(tmp_path: Path):
    out = tmp_path / "n" / "mdash.sarif"
    sarif.write([], out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------------- prepare
def test_prepare_ranks_security_code_above_inert_code(tmp_path: Path):
    (tmp_path / "backend" / "app" / "auth").mkdir(parents=True)
    (tmp_path / "backend" / "app" / "auth" / "saml.py").write_text(
        "import jwt\ndef verify(t):\n    return jwt.decode(t, verify_signature=False)\n",
        encoding="utf-8",
    )
    (tmp_path / "plain.py").write_text("X = 1\nY = 2\n", encoding="utf-8")

    targets = collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                      max_file_bytes=100_000)
    paths = [t.path for t in targets]
    assert "backend/app/auth/saml.py" in paths
    assert paths[0] == "backend/app/auth/saml.py"


def test_prepare_honours_excludes_and_budget(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.py").write_text("import subprocess", encoding="utf-8")
    for i in range(5):
        (tmp_path / f"m{i}.py").write_text("import subprocess\npassword='x'", encoding="utf-8")

    targets = collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=3,
                      max_file_bytes=100_000)
    assert len(targets) == 3
    assert all("node_modules" not in t.path for t in targets)


def test_prepare_skips_oversized_and_empty(tmp_path: Path):
    (tmp_path / "big.py").write_text("import subprocess\n" + ("# pad\n" * 5000), encoding="utf-8")
    (tmp_path / "empty.py").write_text("   \n", encoding="utf-8")
    targets = collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                      max_file_bytes=1000)
    assert targets == []


def test_prepare_explicit_paths_cannot_escape_root(tmp_path: Path):
    """A diff-supplied path must not pull in files outside the repository."""
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "in.py").write_text("import subprocess", encoding="utf-8")
    (tmp_path / "outside.py").write_text("import subprocess", encoding="utf-8")
    targets = collect(tmp_path / "repo", include=["**/*.py"], exclude=[], max_targets=10,
                      max_file_bytes=100_000, paths=["in.py", "../outside.py"])
    assert [t.path for t in targets] == ["in.py"]


def test_prepare_keeps_unremarkable_files_in_diff_mode(tmp_path: Path):
    """A PR can introduce a bug into a file with no pre-existing security markers."""
    (tmp_path / "plain.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    # Whole-repo sweep: the score floor rations budget, so an inert file is skipped.
    assert collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                   max_file_bytes=100_000) == []
    # Diff mode: the caller already chose the file, so it must still be scanned.
    explicit = collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                       max_file_bytes=100_000, paths=["plain.py"])
    assert [t.path for t in explicit] == ["plain.py"]


def test_prepare_excludes_apply_at_the_repository_root(tmp_path: Path):
    """Vendored code at the root must not consume the scan budget."""
    from mdash.prepare import _matches_any

    assert _matches_any("node_modules/dep.py", ["**/node_modules/**"])
    assert _matches_any("frontend/node_modules/dep.py", ["**/node_modules/**"])
    assert _matches_any("bundle.min.js", ["**/*.min.js"])
    assert not _matches_any("app/models.py", ["**/node_modules/**"])

    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text("password = 'x'", encoding="utf-8")
    assert collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                   max_file_bytes=100_000) == []


def test_prepare_still_excludes_vendored_paths_in_diff_mode(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text("password = 'x'", encoding="utf-8")
    targets = collect(tmp_path, include=["**/*.py"], exclude=[], max_targets=10,
                      max_file_bytes=100_000, paths=["node_modules/dep.py"])
    assert targets == []


def test_target_numbering_and_truncation_is_announced():
    from mdash.prepare import Target

    t = Target(path="a.py", text="alpha\nbeta\ngamma\n", score=1.0, reasons=[], line_count=3)
    assert "    1 | alpha" in t.numbered(max_chars=10_000)
    assert "truncated" in t.numbered(max_chars=30)


# ----------------------------------------------------------------------------------- config
def test_config_defaults_match_the_documented_panel():
    cfg = Config()
    assert cfg.auditor.deployment == "gpt-5.3-codex"
    assert cfg.debater.deployment == "gpt-5.4-mini"
    assert cfg.escalation.deployment == "gpt-5.4"
    # gpt-5.3-codex reports chatCompletion=false, so only /responses will work.
    assert cfg.api_version == "2025-04-01-preview"
    # Executing generated code must never be the default.
    assert cfg.prove is False
    assert cfg.debate is True


def test_config_rejects_bad_reasoning_effort():
    Config().merge({"panel": {"auditor": {"deployment": "d", "reasoning_effort": "high"}}})
    with pytest.raises(ValueError, match="reasoning_effort"):
        Config().merge({"panel": {"auditor": {"deployment": "d", "reasoning_effort": "turbo"}}})


# --------------------------------------------------------------- endpoint + request shaping
@pytest.mark.parametrize(
    "given",
    [
        "https://res.cognitiveservices.azure.com/",
        "https://res.services.ai.azure.com/",
        "https://res.openai.azure.com/",
        "res.cognitiveservices.azure.com",
    ],
)
def test_endpoint_is_normalised_to_the_host_that_serves_responses(given):
    """Only the OpenAI host routes /responses; the others 404."""
    assert normalise_endpoint(given) == "https://res.openai.azure.com/"


def test_endpoint_leaves_unrelated_hosts_alone():
    assert normalise_endpoint("https://my-proxy.internal.example/") == (
        "https://my-proxy.internal.example/"
    )


def test_request_kwargs_match_the_verified_responses_contract():
    cfg = Config()
    cfg.endpoint = "https://res.cognitiveservices.azure.com/"
    panel = Panel.__new__(Panel)  # no client, no network
    panel.cfg = cfg
    panel._quirks = {}

    kwargs = panel._kwargs(cfg.auditor, "sys", "user", FINDINGS_SCHEMA)
    assert kwargs["model"] == "gpt-5.3-codex"
    assert kwargs["instructions"] == "sys" and kwargs["input"] == "user"
    # max_tokens is rejected outright by these deployments.
    assert "max_tokens" not in kwargs
    assert kwargs["max_output_tokens"] == cfg.auditor.max_output_tokens
    # Source code is the payload: it must not persist in server-side response state.
    assert kwargs["store"] is False
    assert kwargs["reasoning"] == {"effort": "medium"}
    fmt = kwargs["text"]["format"]
    assert fmt["type"] == "json_schema" and fmt["strict"] is True


def test_request_kwargs_respect_learned_quirks():
    cfg = Config()
    panel = Panel.__new__(Panel)
    panel.cfg = cfg
    panel._quirks = {"gpt-5.4": {"no_reasoning", "no_schema", "no_temperature"}}
    cfg.escalation.temperature = 0.1
    kwargs = panel._kwargs(cfg.escalation, "s", "u", ESCALATION_SCHEMA)
    assert "reasoning" not in kwargs
    assert "text" not in kwargs
    assert "temperature" not in kwargs


# ---------------------------------------------------------------------- structured schemas
@pytest.mark.parametrize(
    "schema", [FINDINGS_SCHEMA, DEBATE_SCHEMA, ESCALATION_SCHEMA], ids=lambda s: s["type"]
)
def test_schemas_satisfy_strict_structured_output_rules(schema):
    """Strict mode rejects any object that omits additionalProperties:false or under-declares
    `required`, and the failure surfaces as an opaque 400 at scan time."""

    def check(node):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False
            assert set(node.get("required", [])) == set(node.get("properties", {}))
            for child in node.get("properties", {}).values():
                check(child)
        if node.get("type") == "array":
            check(node["items"])

    check(schema)


def test_escalation_cannot_return_uncertain():
    """The arbiter exists to end the debate; leaving it undecided would loop."""
    assert ESCALATION_SCHEMA["properties"]["verdict"]["enum"] == ["upheld", "refuted"]
    assert "uncertain" in DEBATE_SCHEMA["properties"]["verdict"]["enum"]


def test_findings_schema_shape_is_what_coerce_expects():
    target = type("T", (), {"path": "a.py"})()
    sample = {"findings": [{"title": "x", "severity": "high", "cwe": "CWE-79",
                            "line_start": 1, "line_end": 2, "hypothesis": "h",
                            "evidence": "e", "remediation": "r", "confidence": 0.8}]}
    assert set(sample["findings"][0]) == set(
        FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]
    )
    assert len(_coerce(sample, agent=AUTHN, target=target, model="m")) == 1


def test_config_merge_overrides_panel_and_scope():
    cfg = Config().merge({
        "panel": {"auditor": "my-model", "debater": {"deployment": "cheap", "max_output_tokens": 99}},
        "scope": {"include": ["x/**/*.py"], "agents": ["injection"]},
        "limits": {"max_targets": 7, "min_confidence": 0.9},
        "stages": {"prove": True, "debate": False},
    })
    assert cfg.auditor.deployment == "my-model"
    assert cfg.debater.max_output_tokens == 99
    assert cfg.include == ["x/**/*.py"]
    assert cfg.agents == ["injection"]
    assert cfg.max_targets == 7 and cfg.min_confidence == 0.9
    assert cfg.prove is True and cfg.debate is False


def test_config_rejects_role_without_deployment():
    with pytest.raises(ValueError, match="missing 'deployment'"):
        Config().merge({"panel": {"auditor": {"max_output_tokens": 10}}})


def test_config_missing_file_falls_back_to_defaults(tmp_path: Path):
    assert Config.load(root=tmp_path).auditor.deployment == "gpt-5.3-codex"
    with pytest.raises(FileNotFoundError):
        Config.load(tmp_path / "nope.toml")


def test_repo_config_parses_and_is_consistent():
    """The committed mdash.toml must actually load."""
    root = Path(__file__).resolve().parents[3]
    cfg = Config.load(root / "mdash.toml")
    assert cfg.auditor.deployment and cfg.debater.deployment and cfg.escalation.deployment
    assert cfg.include, "scope.include must not be empty"
    assert cfg.prove is False
