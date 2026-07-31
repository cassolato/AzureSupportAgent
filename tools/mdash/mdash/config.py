"""Configuration for the harness: model panel, scope, and budget.

The panel is the part worth understanding. MDASH's published design runs a *configurable*
panel rather than one model, because no single model is best at every stage: a code-heavy
model audits, a cheap high-volume model debates, and an expensive reasoner is reserved for
the cases where the first two disagree. The roles below are that structure; which concrete
deployment backs each role is configuration, so the harness survives model changes.

MAI-Cyber-1-Flash is the intended auditor/debater tier in Microsoft's own deployment. It is
not available as a standalone Azure AI Foundry endpoint (private preview, usable only inside
MDASH), so the default panel substitutes generally available models. Swap the deployment
names in mdash.toml if you are granted access - nothing else needs to change.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_NAME = "mdash.toml"

_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high"})


@dataclass
class RoleConfig:
    """One seat on the model panel."""

    deployment: str
    max_output_tokens: int = 8000
    temperature: float | None = None
    # Reasoning deployments spend hidden tokens before answering. Effort is the main quality
    # and cost dial on this panel, so each seat sets its own.
    reasoning_effort: str | None = None

    @classmethod
    def parse(cls, raw: Any, *, role: str) -> RoleConfig:
        if isinstance(raw, str):
            return cls(deployment=raw)
        if not isinstance(raw, dict):
            # ValueError, not TypeError: this is invalid *configuration*, and the CLI
            # reports every config problem through the same handler.
            raise ValueError(  # noqa: TRY004
                f"[panel.{role}] must be a deployment name or a table"
            )
        deployment = str(raw.get("deployment", "")).strip()
        if not deployment:
            raise ValueError(f"[panel.{role}] is missing 'deployment'")
        temp = raw.get("temperature")
        effort = raw.get("reasoning_effort")
        if effort is not None and str(effort) not in _EFFORTS:
            raise ValueError(
                f"[panel.{role}] reasoning_effort must be one of {sorted(_EFFORTS)}"
            )
        return cls(
            deployment=deployment,
            max_output_tokens=int(raw.get("max_output_tokens", 8000)),
            temperature=None if temp is None else float(temp),
            reasoning_effort=None if effort is None else str(effort),
        )


@dataclass
class Config:
    endpoint: str = ""
    # The Responses API is required: gpt-5.3-codex and similar reasoning deployments report
    # chatCompletion=false. This api-version is the oldest verified to route /responses.
    api_version: str = "2025-04-01-preview"

    # Panel roles. `auditor` scans, `debater` cross-examines with an independent model, and
    # `escalation` breaks ties - the expensive seat, deliberately reached least often.
    auditor: RoleConfig = field(
        default_factory=lambda: RoleConfig("gpt-5.3-codex", reasoning_effort="medium")
    )
    debater: RoleConfig = field(
        default_factory=lambda: RoleConfig("gpt-5.4-mini", reasoning_effort="low")
    )
    escalation: RoleConfig = field(
        default_factory=lambda: RoleConfig("gpt-5.4", reasoning_effort="high")
    )

    include: list[str] = field(default_factory=lambda: ["**/*.py"])
    exclude: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)

    max_targets: int = 40
    max_file_bytes: int = 120_000
    concurrency: int = 6
    request_timeout: int = 240
    max_retries: int = 3

    # Findings at or below this confidence after debate are dropped rather than reported.
    min_confidence: float = 0.35
    # Debate is what separates a finding from a triage backlog, so it is on by default.
    debate: bool = True
    # Executing generated code is opt-in; see prove.py for the sandbox contract.
    prove: bool = False
    prove_timeout: int = 20

    @classmethod
    def load(cls, path: Path | None = None, *, root: Path | None = None) -> Config:
        """Load config from a TOML file, falling back to built-in defaults."""
        cfg = cls()
        candidate = path or ((root or Path.cwd()) / DEFAULT_CONFIG_NAME)
        if not candidate.is_file():
            if path is not None:
                raise FileNotFoundError(f"Config not found: {candidate}")
            return cfg
        raw = tomllib.loads(candidate.read_text(encoding="utf-8"))
        return cfg.merge(raw)

    def merge(self, raw: dict[str, Any]) -> Config:
        panel = raw.get("panel") or {}
        for role in ("auditor", "debater", "escalation"):
            if role in panel:
                setattr(self, role, RoleConfig.parse(panel[role], role=role))
        if "endpoint" in panel:
            self.endpoint = str(panel["endpoint"])
        if "api_version" in panel:
            self.api_version = str(panel["api_version"])

        scope = raw.get("scope") or {}
        if "include" in scope:
            self.include = [str(p) for p in scope["include"]]
        if "exclude" in scope:
            self.exclude = [str(p) for p in scope["exclude"]]
        if "agents" in scope:
            self.agents = [str(a) for a in scope["agents"]]

        limits = raw.get("limits") or {}
        for key in (
            "max_targets",
            "max_file_bytes",
            "concurrency",
            "request_timeout",
            "max_retries",
            "prove_timeout",
        ):
            if key in limits:
                setattr(self, key, int(limits[key]))
        if "min_confidence" in limits:
            self.min_confidence = float(limits["min_confidence"])

        stages = raw.get("stages") or {}
        if "debate" in stages:
            self.debate = bool(stages["debate"])
        if "prove" in stages:
            self.prove = bool(stages["prove"])
        return self

    def role(self, name: str) -> RoleConfig:
        return {
            "auditor": self.auditor,
            "debater": self.debater,
            "escalation": self.escalation,
        }[name]
