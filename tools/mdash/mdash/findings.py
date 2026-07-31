"""Finding model shared by every stage of the harness.

A finding accretes state as it moves down the pipeline: an auditor agent creates it with a
hypothesis and evidence, the debate stage attaches a verdict and adjusts confidence, dedupe
collapses equivalents, and prove attaches an execution result. Keeping one mutable record
(rather than a new type per stage) is what lets the SARIF writer report *how* a finding was
reached, which is the part reviewers actually use to decide whether to trust it.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Ordered low -> high so comparisons and sorting work directly.
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

# GitHub renders code-scanning alerts by the numeric `security-severity` property, not by
# the SARIF `level`. These are the documented cut points (>=9.0 critical, >=7.0 high,
# >=4.0 medium, >=0.1 low).
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.5",
}


class Verdict(str, Enum):
    """Outcome of the debate stage."""

    UPHELD = "upheld"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"
    NOT_RUN = "not_run"


class ProofState(str, Enum):
    """Outcome of the prove stage."""

    PROVEN = "proven"
    DISPROVEN = "disproven"
    NOT_ATTEMPTED = "not_attempted"
    INCONCLUSIVE = "inconclusive"


def normalize_severity(value: str | None) -> str:
    out = (value or "").strip().lower()
    return out if out in _SEVERITY_ORDER else "medium"


def severity_rank(value: str | None) -> int:
    return _SEVERITY_ORDER.index(normalize_severity(value))


def security_severity(value: str | None) -> str:
    return _SECURITY_SEVERITY[normalize_severity(value)]


def _slug(text: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return out or "finding"


@dataclass
class Finding:
    """One candidate vulnerability, from hypothesis through to proof."""

    path: str
    title: str
    severity: str = "medium"
    cwe: str = ""
    # Why the auditor believes this is a bug, and the concrete code it is pointing at.
    hypothesis: str = ""
    evidence: str = ""
    remediation: str = ""
    line_start: int = 0
    line_end: int = 0
    # Which specialised auditor produced it, and which model backed that agent.
    agent: str = ""
    model: str = ""

    confidence: float = 0.5
    verdict: Verdict = Verdict.NOT_RUN
    debate_for: str = ""
    debate_against: str = ""
    debate_rationale: str = ""
    escalated: bool = False

    proof_state: ProofState = ProofState.NOT_ATTEMPTED
    proof_detail: str = ""

    # Populated by the dedupe stage: agents that independently reported the same issue.
    corroborations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.line_start = max(0, int(self.line_start or 0))
        self.line_end = max(self.line_start, int(self.line_end or self.line_start))

    @property
    def rule_id(self) -> str:
        """Stable rule identifier, preferring the CWE so alerts group sensibly."""
        cwe = (self.cwe or "").strip().upper().replace(" ", "")
        if cwe.startswith("CWE-") and cwe[4:].isdigit():
            return f"mdash/{cwe.lower()}"
        return f"mdash/{_slug(self.title)[:60]}"

    @property
    def fingerprint(self) -> str:
        """Stable across runs so GitHub can track an alert rather than re-open it.

        Deliberately excludes line numbers: unrelated edits above a finding shift them and
        would otherwise present the same issue as a brand-new alert on every scan.
        """
        basis = f"{self.path}|{self.rule_id}|{_slug(self.title)[:60]}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]

    @property
    def dedupe_key(self) -> tuple[str, str]:
        return (self.path, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "hypothesis": self.hypothesis,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "agent": self.agent,
            "model": self.model,
            "confidence": round(self.confidence, 3),
            "verdict": self.verdict.value,
            "debate_rationale": self.debate_rationale,
            "escalated": self.escalated,
            "proof_state": self.proof_state.value,
            "proof_detail": self.proof_detail,
            "corroborations": self.corroborations,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
        }
