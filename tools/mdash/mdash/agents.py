"""Specialised auditor roles.

MDASH's stated reason for many narrow agents over one general prompt: "An auditor does not
reason like a debater, which does not reason like a prover. Each pipeline stage has its own
role, prompt regime, tools, and stop criteria."

The same applies within the scan stage. A single "find security bugs" prompt regresses to the
mean - it reports the same shallow set every time. Each agent below gets one threat model, an
explicit non-goal list to suppress the categories other agents own, and file-path affinities
so it is only spent on code where its class of bug can actually live.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Agent:
    name: str
    focus: str
    # Bug classes this agent must ignore because another agent owns them. Without this the
    # agents produce heavily overlapping findings and the dedupe stage does all the work.
    non_goals: str
    # Substrings that make a path especially relevant to this agent.
    affinities: tuple[str, ...] = ()
    extensions: tuple[str, ...] = (".py",)
    guidance: str = ""


AUTHN = Agent(
    name="authn-authz",
    focus=(
        "Authentication and authorization defects: missing or bypassable auth dependencies on "
        "routes, broken session lifecycle (fixation, missing revocation, absent expiry), "
        "privilege escalation, IDOR / missing per-object ownership checks, tenant isolation "
        "failures, unsafe token validation (unverified signatures, unpinned algorithms, missing "
        "audience/issuer/expiry checks), SAML and OIDC assertion handling flaws, and "
        "authentication bypasses arising from XML or text parsing quirks."
    ),
    non_goals="Do not report injection, SSRF, secrets, crypto primitives, or container issues.",
    affinities=("auth", "api/", "session", "login", "oidc", "saml", "rbac", "token", "identity"),
    guidance=(
        "Trace whether a guard is enforced at the dispatch site or merely declared. A check "
        "that a caller may skip is not a control. For assertion parsing, consider whether "
        "attacker-injected structure (comments, nested nodes, duplicate elements) can change "
        "the value the application ultimately trusts."
    ),
)

INJECTION = Agent(
    name="injection",
    focus=(
        "Injection and unsafe interpretation of untrusted input: SQL/NoSQL injection, command "
        "and argument injection, path traversal, unsafe deserialization (pickle, yaml.load), "
        "eval/exec on attacker-influenced data, template injection, XXE and entity expansion, "
        "log/header injection via unstripped CRLF, and prompt injection that reaches a tool "
        "with real side effects."
    ),
    non_goals="Do not report auth, SSRF, secrets management, or infrastructure issues.",
    affinities=("exec", "command", "query", "db", "sql", "parse", "template", "agent", "tool"),
    guidance=(
        "Establish the taint path explicitly: name the entry point, the transformations, and "
        "the sink. If a sink is reached only through an allowlist you can see enforced in this "
        "file, say so and lower the severity rather than reporting it as exploitable."
    ),
)

SSRF = Agent(
    name="ssrf-egress",
    focus=(
        "Outbound request safety: SSRF via user- or model-controlled URLs, missing egress "
        "validation, cloud metadata endpoint (169.254.169.254) reachability, DNS-rebinding "
        "TOCTOU between a resolve-time check and the actual connect, redirect following that "
        "escapes the original validation, and unvalidated webhook or callback targets."
    ),
    non_goals="Do not report auth, injection, secrets, or container issues.",
    affinities=("http", "client", "fetch", "connector", "webhook", "url", "request", "proxy"),
    guidance=(
        "The decisive question is whether the address that was *validated* is the address that "
        "is ultimately *connected to*. If the code validates a hostname then hands that same "
        "hostname to the HTTP client, the second resolution is attacker-controllable."
    ),
)

SECRETS = Agent(
    name="secrets-crypto",
    focus=(
        "Credential and cryptographic handling: hardcoded or committed secrets, credentials "
        "passed via argv or environment where other processes can read them, secrets reaching "
        "logs or error responses, weak or misused primitives (ECB, static IV/nonce, weak KDF), "
        "insecure randomness for security-relevant values, missing TLS verification, and unsafe "
        "temporary-file permissions for credential material."
    ),
    non_goals="Do not report auth logic, injection, SSRF, or container issues.",
    affinities=("crypto", "secret", "cred", "key", "password", "token", "cipher", "hash", "tls"),
    guidance=(
        "Distinguish cryptographic use from non-cryptographic use. A hash used to build a cache "
        "key or a display identifier is not a vulnerability; say so explicitly instead of "
        "reporting it. Reserve findings for values that guard a trust boundary."
    ),
)

SUPPLY = Agent(
    name="infra-supplychain",
    focus=(
        "Deployment and supply-chain posture: containers running as root, mutable or unpinned "
        "base images, build steps that ignore lockfiles, secrets baked into image layers or "
        "build args, over-permissive network exposure (0.0.0.0 binds, permissive firewall "
        "rules), predictable or defaulted credentials in IaC, public network access left on, "
        "and CI workflows with excessive permissions or untrusted input in privileged contexts."
    ),
    non_goals="Do not report application-level auth, injection, or SSRF issues.",
    affinities=("docker", "compose", "deploy", "bicep", "workflow", "pipeline", ".github", "infra"),
    extensions=(".yml", ".yaml", ".bicep", ".json", ".tf", ""),
    guidance=(
        "Judge the default configuration, since that is what most deployments run. A risky "
        "option that is off by default is worth less than one that is on by default. Name the "
        "specific directive and what an operator must change."
    ),
)

ALL_AGENTS: tuple[Agent, ...] = (AUTHN, INJECTION, SSRF, SECRETS, SUPPLY)
_BY_NAME = {a.name: a for a in ALL_AGENTS}


def select(names: list[str] | None) -> list[Agent]:
    """Resolve configured agent names, defaulting to the full cohort."""
    if not names:
        return list(ALL_AGENTS)
    unknown = [n for n in names if n not in _BY_NAME]
    if unknown:
        raise ValueError(
            f"Unknown agent(s): {', '.join(unknown)}. Available: {', '.join(_BY_NAME)}"
        )
    return [_BY_NAME[n] for n in names]


# --------------------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------------------

_SHARED_RULES = """\
Report only defects you can justify from the code shown. Follow these rules strictly:

- Every finding must name a concrete attacker, an entry point, and the consequence. If you
  cannot describe how untrusted input reaches the defect, do not report it.
- Quote the exact vulnerable code in `evidence`, copied verbatim from the excerpt.
- `line_start`/`line_end` must refer to the line numbers shown in the excerpt.
- Prefer a small number of well-argued findings. A speculative finding is worse than none:
  it consumes review time that should go to real bugs.
- Do not report style, formatting, performance, missing tests, or general "best practice"
  advice. Only report security defects.
- Do not report a defect that the code shown already mitigates. If a guard is present,
  either explain why it is insufficient or stay silent.
- `confidence` is your honest probability (0.0-1.0) that a security engineer would agree
  this is a real, reachable defect worth fixing."""

_SCHEMA = """\
Respond with a JSON object: {"findings": [ ... ]}. No prose, no markdown fence.
Each element of `findings`:

{
  "title": "short specific description of the defect",
  "severity": "critical|high|medium|low|info",
  "cwe": "CWE-###",
  "line_start": 12,
  "line_end": 18,
  "hypothesis": "attacker, entry point, path to the sink, and the impact",
  "evidence": "verbatim vulnerable code from the excerpt",
  "remediation": "the specific change that fixes it",
  "confidence": 0.75
}

If the excerpt contains no security defect, respond with exactly: {"findings": []}"""

_SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Strict structured output makes the response shape a service-side guarantee rather than a
# prompt-time request. Strict mode requires additionalProperties:false and demands that every
# property appear in `required`, so genuinely optional fields are typed as nullable instead.
FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "title", "severity", "cwe", "line_start", "line_end",
                    "hypothesis", "evidence", "remediation", "confidence",
                ],
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": _SEVERITIES},
                    "cwe": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "hypothesis": {"type": "string"},
                    "evidence": {"type": "string"},
                    "remediation": {"type": "string"},
                    "confidence": {"type": "number"},
                },
            },
        }
    },
}

DEBATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "argument_for", "argument_against", "verdict", "confidence", "severity", "rationale",
    ],
    "properties": {
        "argument_for": {"type": "string"},
        "argument_against": {"type": "string"},
        "verdict": {"type": "string", "enum": ["upheld", "refuted", "uncertain"]},
        "confidence": {"type": "number"},
        "severity": {"type": "string", "enum": _SEVERITIES},
        "rationale": {"type": "string"},
    },
}

# The arbiter exists to end the debate, so "uncertain" is absent from its enum by design.
ESCALATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "confidence", "severity", "rationale"],
    "properties": {
        "verdict": {"type": "string", "enum": ["upheld", "refuted"]},
        "confidence": {"type": "number"},
        "severity": {"type": "string", "enum": _SEVERITIES},
        "rationale": {"type": "string"},
    },
}


def auditor_system(agent: Agent) -> str:
    return (
        f"You are a specialist application-security auditor. Your sole focus is:\n{agent.focus}\n\n"
        f"Out of scope for you: {agent.non_goals}\n\n"
        f"{agent.guidance}\n\n{_SHARED_RULES}\n\n{_SCHEMA}"
    )


DEBATER_SYSTEM = """\
You are an adversarial reviewer of security findings. Another agent has reported a candidate
defect. Your job is to determine whether it survives cross-examination.

Argue both sides honestly before deciding:
- `argument_for`: the strongest case that this is real, reachable, and exploitable.
- `argument_against`: the strongest case that it is a false positive - already mitigated,
  unreachable from untrusted input, a misreading of the code, or not a security issue.

Then decide. Weight these heavily:
- Is there a guard in the shown code that already prevents it?
- Can untrusted input actually reach this location?
- Does the claimed impact follow from the mechanism described?
- Is the code being flagged for a non-security reason dressed up as one?

Be willing to refute. Confirming a false positive is a worse outcome than rejecting a real
finding, because a scanner that produces noise gets ignored entirely.

Respond with a JSON object only:

{
  "argument_for": "...",
  "argument_against": "...",
  "verdict": "upheld|refuted|uncertain",
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|info",
  "rationale": "one or two sentences explaining the decision"
}
Use "uncertain" only when the excerpt genuinely lacks the context needed to decide - it
routes the finding to a stronger model, which costs real money, so do not use it to avoid
committing."""

ESCALATION_SYSTEM = """\
You are the senior arbiter on a security review panel. A specialist auditor reported a
finding and an adversarial reviewer could not settle it. You have the final decision.

You are the most capable and most expensive model on the panel and are consulted only for
genuinely hard cases. Reason carefully about reachability, the trust boundary being crossed,
and whether the described mechanism actually produces the claimed impact. Then commit to a
clear verdict - "uncertain" is not available to you.

Respond with a JSON object only:

{
  "verdict": "upheld|refuted",
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|info",
  "rationale": "the decisive reasoning, in two or three sentences"
}"""

PROVER_SYSTEM = """\
You construct minimal proof-of-concept tests for security findings.

Write a single self-contained Python script that demonstrates the defect. The script:
- must print exactly "VULNERABLE" to stdout if the defect is demonstrated, and "SAFE" if it
  is not,
- must be entirely self-contained: standard library only, plus any third-party module the
  target file already imports,
- must NOT make network calls, spawn shells, read or write outside a temp directory, or
  modify the repository,
- must terminate quickly, well under the execution timeout,
- must reproduce the *mechanism* in isolation. Copy the relevant logic into the script; do
  not attempt to import the application, which will not be installed.

If the defect cannot be demonstrated this way - it needs a live service, a race window, a
specific deployment, or privileged access - respond with exactly: NOT_PROVABLE

Otherwise respond with the raw Python source only. No markdown fence, no commentary."""
