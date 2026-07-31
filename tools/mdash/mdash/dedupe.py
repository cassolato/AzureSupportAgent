"""Dedupe stage: collapse semantically equivalent findings.

Running five narrow auditors over the same file means the same defect can be reported more
than once - the injection auditor and the secrets auditor will both notice a credential
interpolated into a shell command. Reporting that twice trains reviewers to skim.

Independent rediscovery is nonetheless the strongest credibility signal the harness has: two
agents that were never told about each other reached the same conclusion. So duplicates are
merged rather than discarded, the surviving record keeps the richest text and the highest
severity, and corroboration raises confidence on the survivor.
"""
from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

from .findings import Finding, severity_rank

log = logging.getLogger("mdash.dedupe")

# Titles above this similarity, in the same file and overlapping region, are the same bug.
_TITLE_SIMILARITY = 0.72
# Findings within this many lines of each other are treated as the same region: agents often
# cite the call site and the definition of the same defect.
_LINE_PROXIMITY = 25

_STOPWORDS = frozenset(
    {"the", "a", "an", "in", "on", "of", "to", "for", "and", "or", "is", "are", "via", "with"}
)


def _canonical(title: str) -> str:
    words = re.findall(r"[a-z0-9]+", (title or "").lower())
    return " ".join(w for w in words if w not in _STOPWORDS)


def _same_region(a: Finding, b: Finding) -> bool:
    if not (a.line_start and b.line_start):
        return True  # No location from one side: fall back to title similarity alone.
    if a.line_start <= b.line_end and b.line_start <= a.line_end:
        return True
    return min(
        abs(a.line_start - b.line_start),
        abs(a.line_end - b.line_end),
        abs(a.line_start - b.line_end),
        abs(b.line_start - a.line_end),
    ) <= _LINE_PROXIMITY


def _equivalent(a: Finding, b: Finding) -> bool:
    if a.path != b.path:
        return False
    if not _same_region(a, b):
        return False
    if a.cwe and b.cwe and a.cwe.upper() == b.cwe.upper():
        return True
    return SequenceMatcher(None, _canonical(a.title), _canonical(b.title)).ratio() >= _TITLE_SIMILARITY


def _merge(primary: Finding, other: Finding) -> Finding:
    """Fold `other` into `primary`, keeping the strongest claim from each."""
    if severity_rank(other.severity) > severity_rank(primary.severity):
        primary.severity = other.severity
    if not primary.cwe and other.cwe:
        primary.cwe = other.cwe
    for attr in ("hypothesis", "evidence", "remediation", "debate_rationale"):
        if len(getattr(other, attr) or "") > len(getattr(primary, attr) or ""):
            setattr(primary, attr, getattr(other, attr))
    if primary.line_start and other.line_start:
        primary.line_start = min(primary.line_start, other.line_start)
        primary.line_end = max(primary.line_end, other.line_end)
    elif other.line_start:
        primary.line_start, primary.line_end = other.line_start, other.line_end

    if other.agent and other.agent != primary.agent:
        if other.agent not in primary.corroborations:
            primary.corroborations.append(other.agent)
        # Independent agreement is evidence. Move a fraction of the remaining distance to
        # certainty rather than adding a flat bonus, so repeats cannot push past 1.0.
        primary.confidence = min(0.99, primary.confidence + (1.0 - primary.confidence) * 0.35)
    primary.escalated = primary.escalated or other.escalated
    return primary


def run(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return []
    # Strongest first, so the survivor of each cluster is the best-argued instance.
    ordered = sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), -f.confidence, f.path, f.line_start),
    )

    clusters: list[Finding] = []
    for candidate in ordered:
        for existing in clusters:
            if _equivalent(existing, candidate):
                _merge(existing, candidate)
                break
        else:
            clusters.append(candidate)

    collapsed = len(findings) - len(clusters)
    if collapsed:
        corroborated = sum(1 for f in clusters if f.corroborations)
        log.info(
            "Dedupe: %d finding(s) collapsed into %d; %d independently corroborated",
            collapsed,
            len(clusters),
            corroborated,
        )
    return clusters
