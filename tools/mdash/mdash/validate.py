"""Validate stage: adversarial debate, with escalation on disagreement.

This is the stage that separates a finding from a triage backlog. A candidate is cross-
examined by a *different* model than the one that produced it - self-review mostly produces
agreement - and the reviewer is asked to argue both sides before committing to a verdict.

Escalation is where the cost tiering pays off. The cheap seat settles the clear cases; only
genuine disagreement (an `uncertain` verdict, or a confident auditor refuted by a hesitant
debater) reaches the expensive reasoner. Spend therefore tracks difficulty, not repo size.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from .agents import (
    DEBATE_SCHEMA,
    DEBATER_SYSTEM,
    ESCALATION_SCHEMA,
    ESCALATION_SYSTEM,
)
from .config import Config
from .findings import Finding, Verdict, normalize_severity
from .panel import Panel

log = logging.getLogger("mdash.validate")

_CONTEXT_LINES = 45


def _context(source: str, finding: Finding) -> str:
    """Lines around the finding, so the reviewer sees guards the auditor may have missed."""
    lines = source.splitlines()
    if not lines:
        return ""
    start = max(0, (finding.line_start or 1) - 1 - _CONTEXT_LINES)
    end = min(len(lines), (finding.line_end or finding.line_start or 1) + _CONTEXT_LINES)
    return "\n".join(f"{i:5d} | {lines[i - 1]}" for i in range(start + 1, end + 1))


def _prompt(finding: Finding, source: str) -> str:
    return (
        f"## Candidate finding\n"
        f"- File: {finding.path}\n"
        f"- Lines: {finding.line_start}-{finding.line_end}\n"
        f"- Title: {finding.title}\n"
        f"- Severity claimed: {finding.severity}\n"
        f"- CWE claimed: {finding.cwe or 'unspecified'}\n"
        f"- Reported by: {finding.agent} (confidence {finding.confidence:.2f})\n\n"
        f"### Hypothesis\n{finding.hypothesis or '(none given)'}\n\n"
        f"### Evidence cited\n```\n{finding.evidence or '(none given)'}\n```\n\n"
        f"### Surrounding source\n```\n{_context(source, finding)}\n```\n\n"
        "Cross-examine this finding."
    )


def _apply(finding: Finding, data: dict[str, Any], *, escalated: bool) -> None:
    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict in {v.value for v in Verdict}:
        finding.verdict = Verdict(verdict)
    else:
        finding.verdict = Verdict.UNCERTAIN

    try:
        confidence = float(data.get("confidence", finding.confidence))
    except (TypeError, ValueError):
        confidence = finding.confidence
    finding.confidence = min(1.0, max(0.0, confidence))

    if data.get("severity"):
        finding.severity = normalize_severity(str(data["severity"]))
    finding.debate_for = str(data.get("argument_for", ""))[:3000]
    finding.debate_against = str(data.get("argument_against", ""))[:3000]
    finding.debate_rationale = str(data.get("rationale", ""))[:1500]
    if escalated:
        finding.escalated = True


def _needs_escalation(finding: Finding) -> bool:
    """Disagreement, not difficulty, is the escalation trigger."""
    if finding.verdict is Verdict.UNCERTAIN:
        return True
    # A confident auditor overturned by a hesitant reviewer is exactly the case where the
    # cheap seat is least trustworthy.
    return finding.verdict is Verdict.REFUTED and finding.confidence < 0.5


async def run(
    panel: Panel,
    cfg: Config,
    findings: list[Finding],
    sources: dict[str, str],
) -> list[Finding]:
    """Debate every candidate, escalate the contested ones, and drop the refuted."""
    if not findings:
        return []
    log.info("Validate: debating %d candidate(s) on %s", len(findings), cfg.debater.deployment)

    async def debate(finding: Finding) -> None:
        source = sources.get(finding.path, "")
        try:
            _, parsed = await panel.complete(
                "debater", DEBATER_SYSTEM, _prompt(finding, source), schema=DEBATE_SCHEMA
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("debate failed for %s: %s", finding.title[:60], exc)
            finding.verdict = Verdict.UNCERTAIN
            return
        if isinstance(parsed, dict):
            _apply(finding, parsed, escalated=False)
        else:
            finding.verdict = Verdict.UNCERTAIN

    await asyncio.gather(*(debate(f) for f in findings))

    contested = [f for f in findings if _needs_escalation(f)]
    if contested:
        log.info(
            "Validate: escalating %d/%d contested finding(s) to %s",
            len(contested),
            len(findings),
            cfg.escalation.deployment,
        )

        async def escalate(finding: Finding) -> None:
            source = sources.get(finding.path, "")
            prompt = (
                f"{_prompt(finding, source)}\n\n"
                f"## Prior review (unresolved)\n"
                f"For: {finding.debate_for or '(none)'}\n\n"
                f"Against: {finding.debate_against or '(none)'}\n\n"
                "The panel could not settle this. Make the final decision."
            )
            try:
                _, parsed = await panel.complete(
                    "escalation", ESCALATION_SYSTEM, prompt, schema=ESCALATION_SCHEMA
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("escalation failed for %s: %s", finding.title[:60], exc)
                return
            if isinstance(parsed, dict):
                _apply(finding, parsed, escalated=True)

        await asyncio.gather(*(escalate(f) for f in contested))

    survivors = [
        f
        for f in findings
        if f.verdict is not Verdict.REFUTED and f.confidence >= cfg.min_confidence
    ]
    log.info(
        "Validate complete: %d upheld, %d refuted or below confidence floor",
        len(survivors),
        len(findings) - len(survivors),
    )
    return survivors
