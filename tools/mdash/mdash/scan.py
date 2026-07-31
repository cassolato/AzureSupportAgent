"""Scan stage: run specialised auditor agents over the ranked targets.

Each (agent, target) pair is one independent job. Agents are matched to targets by file type
and then ordered by affinity, so the authn auditor is spent on `auth/saml.py` before it is
spent on a utility module, and the infra auditor never sees application Python at all.

Running several narrow agents over the same file is deliberate. Independent agreement between
agents that were not told about each other is real evidence, and the dedupe stage promotes it.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from .agents import FINDINGS_SCHEMA, Agent, auditor_system
from .config import Config
from .findings import Finding
from .panel import Panel
from .prepare import Target

log = logging.getLogger("mdash.scan")

# Excerpt budget per request. Kept well inside the model context so the system prompt,
# instructions and response all fit alongside it.
_MAX_EXCERPT_CHARS = 48_000


def _relevant(agent: Agent, target: Target) -> bool:
    suffix = "." + target.path.rsplit(".", 1)[-1] if "." in target.path.rsplit("/", 1)[-1] else ""
    if suffix in agent.extensions:
        return True
    # An empty string in `extensions` means "also extensionless files" (Dockerfile, Makefile).
    return "" in agent.extensions and suffix == ""


def _affinity(agent: Agent, target: Target) -> float:
    lowered = target.path.lower()
    return sum(2.0 for frag in agent.affinities if frag in lowered)


def _user_prompt(target: Target) -> str:
    return (
        f"File: {target.path}\n"
        f"Lines: {target.line_count}\n"
        f"Flagged during attack-surface analysis because: {', '.join(target.reasons[:6])}\n\n"
        "Audit the following excerpt. Line numbers are shown to the left of each line and are "
        "the numbers you must cite.\n\n"
        f"{target.numbered(max_chars=_MAX_EXCERPT_CHARS)}"
    )


def _coerce(raw: Any, *, agent: Agent, target: Target, model: str) -> list[Finding]:
    """Turn a model response into Findings, discarding anything malformed."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        # Models occasionally wrap the array in an object despite instructions.
        for key in ("findings", "results", "issues", "vulnerabilities"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raw = [raw]
    if not isinstance(raw, list):
        return []

    out: list[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        try:
            confidence = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        out.append(
            Finding(
                path=target.path,
                title=title[:300],
                severity=str(item.get("severity", "medium")),
                cwe=str(item.get("cwe", "")).strip(),
                hypothesis=str(item.get("hypothesis", ""))[:4000],
                evidence=str(item.get("evidence", ""))[:4000],
                remediation=str(item.get("remediation", ""))[:2000],
                line_start=_int(item.get("line_start")),
                line_end=_int(item.get("line_end")),
                agent=agent.name,
                model=model,
                confidence=min(1.0, max(0.0, confidence)),
            )
        )
    return out


def _int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


async def run(
    panel: Panel,
    cfg: Config,
    targets: list[Target],
    agents: list[Agent],
) -> list[Finding]:
    """Execute every relevant (agent, target) pair and collect candidate findings."""
    jobs: list[tuple[Agent, Target]] = []
    for target in targets:
        for agent in agents:
            if _relevant(agent, target):
                jobs.append((agent, target))
    jobs.sort(key=lambda pair: -(pair[1].score + _affinity(*pair)))

    if not jobs:
        log.warning("No (agent, target) pairs matched - nothing to scan.")
        return []
    log.info("Scan: %d audit jobs across %d targets", len(jobs), len(targets))

    async def one(agent: Agent, target: Target) -> list[Finding]:
        deployment = cfg.auditor.deployment
        try:
            _, parsed = await panel.complete(
                "auditor",
                auditor_system(agent),
                _user_prompt(target),
                schema=FINDINGS_SCHEMA,
            )
        except Exception as exc:  # noqa: BLE001 - one agent failing must not abort the scan
            log.warning("auditor %s failed on %s: %s", agent.name, target.path, exc)
            return []
        found = _coerce(parsed, agent=agent, target=target, model=deployment)
        if found:
            log.info("  %-18s %-56s %d finding(s)", agent.name, target.path[-56:], len(found))
        return found

    results = await asyncio.gather(*(one(a, t) for a, t in jobs))
    findings = [f for group in results for f in group]
    log.info("Scan complete: %d candidate finding(s)", len(findings))
    return findings
