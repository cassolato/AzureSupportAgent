"""SARIF 2.1.0 output for GitHub code scanning.

Findings are only useful where reviewers already work, so the harness emits SARIF and the
workflow uploads it to the Security tab. Three details make the difference between alerts
that get triaged and alerts that get dismissed wholesale:

* `security-severity` - GitHub ranks alerts by this numeric property, not by SARIF `level`.
* `partialFingerprints` - lets GitHub track an alert across runs instead of closing and
  re-opening it every time an unrelated edit shifts line numbers.
* the full reasoning chain in the message - which agent found it, whether an independent
  agent corroborated it, how the debate resolved, and whether a PoC actually executed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .findings import Finding, ProofState, Verdict, security_severity, severity_rank

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/schemas/sarif-schema-2.1.0.json"
TOOL_NAME = "MDASH-style agentic scanner"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _level(finding: Finding) -> str:
    return _LEVEL[finding.severity]


def _message(finding: Finding) -> str:
    parts = [finding.hypothesis or finding.title]

    provenance = f"Found by the `{finding.agent}` auditor ({finding.model})"
    if finding.corroborations:
        others = ", ".join(f"`{a}`" for a in finding.corroborations)
        provenance += f", independently corroborated by {others}"
    parts.append(provenance + ".")

    if finding.verdict is not Verdict.NOT_RUN:
        line = f"Adversarial review: **{finding.verdict.value}** (confidence {finding.confidence:.2f})"
        if finding.escalated:
            line += ", escalated to the senior arbiter after the panel disagreed"
        if finding.debate_rationale:
            line += f" - {finding.debate_rationale}"
        parts.append(line)

    if finding.proof_state is ProofState.PROVEN:
        parts.append("**Proof of concept executed successfully - the mechanism is confirmed.**")
    elif finding.proof_state is ProofState.DISPROVEN:
        parts.append("A proof of concept was executed and did NOT reproduce the defect.")
    elif finding.proof_state is ProofState.INCONCLUSIVE:
        parts.append(f"Proof attempt was inconclusive: {finding.proof_detail[:200]}")

    if finding.remediation:
        parts.append(f"**Remediation.** {finding.remediation}")
    return "\n\n".join(p for p in parts if p)


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.rule_id in rules:
            # Keep the highest severity seen for the rule so the rule-level default is not
            # set by whichever instance happened to be encountered first.
            existing = rules[finding.rule_id]["properties"]["security-severity"]
            if float(security_severity(finding.severity)) > float(existing):
                existing_props = rules[finding.rule_id]["properties"]
                existing_props["security-severity"] = security_severity(finding.severity)
                rules[finding.rule_id]["defaultConfiguration"]["level"] = _level(finding)
            continue
        tags = ["security", "mdash"]
        if finding.cwe:
            tags.append(f"external/cwe/{finding.cwe.lower()}")
        if finding.agent:
            tags.append(f"mdash/agent/{finding.agent}")
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.rule_id.replace("/", "-"),
            "shortDescription": {"text": finding.title[:120]},
            "fullDescription": {"text": (finding.hypothesis or finding.title)[:900]},
            "help": {
                "text": finding.remediation or "Review the finding and apply an appropriate fix.",
                "markdown": f"**Remediation.** {finding.remediation}"
                if finding.remediation
                else "Review the finding and apply an appropriate fix.",
            },
            "defaultConfiguration": {"level": _level(finding)},
            "properties": {
                "tags": tags,
                "security-severity": security_severity(finding.severity),
                "precision": "high" if finding.confidence >= 0.8 else "medium",
            },
        }
    return list(rules.values())


def _result(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    if finding.line_start:
        region["startLine"] = finding.line_start
        region["endLine"] = max(finding.line_start, finding.line_end)
    return {
        "ruleId": finding.rule_id,
        "level": _level(finding),
        "message": {"text": _message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    **({"region": region} if region else {}),
                }
            }
        ],
        "partialFingerprints": {"mdashFindingV1": finding.fingerprint},
        "properties": {
            "agent": finding.agent,
            "model": finding.model,
            "confidence": round(finding.confidence, 3),
            "verdict": finding.verdict.value,
            "escalated": finding.escalated,
            "proofState": finding.proof_state.value,
            "corroborations": finding.corroborations,
            "cwe": finding.cwe,
        },
    }


def build(findings: list[Finding], *, usage: dict[str, Any] | None = None) -> dict[str, Any]:
    ordered = sorted(
        findings, key=lambda f: (-severity_rank(f.severity), -f.confidence, f.path, f.line_start)
    )
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": "https://github.com/cassolato/AzureSupportAgent/tree/main/tools/mdash",
                "rules": _rules(ordered),
            }
        },
        "results": [_result(f) for f in ordered],
        "columnKind": "utf16CodeUnits",
    }
    if usage:
        run["properties"] = {"modelUsage": usage}
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def write(findings: list[Finding], path: Path, *, usage: dict[str, Any] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(findings, usage=usage), indent=2), encoding="utf-8")
