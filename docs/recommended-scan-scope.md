---
layout: default
title: Recommended MDASH scan scope
nav_exclude: true
---

# Recommended MDASH scan scope — Azure Support Agent

A ranked, evidence-based scan plan for Codename MDASH agentic code scanning. Targets are
prioritised by the consequence of a vulnerability, not by file count.

Companion documents: [mdash-readiness.md](mdash-readiness.md) ·
[ai-security-threat-model.md](ai-security-threat-model.md) ·
[security-review.md](security-review.md)

---

## 1. Ranking method

Each target is rated on four axes, then assigned an overall priority.

| Axis | Question |
|---|---|
| **Security impact** | What does a vulnerability here compromise? |
| **Azure impact** | Can it cause an unintended Azure control-plane change? |
| **AI impact** | Can model output or injected content influence it? |
| **Exposure** | Is it reachable from untrusted input? |

| Priority | Meaning |
|---|---|
| **Critical** | Untrusted input can reach privileged Azure operations or credentials through this code |
| **High** | Guards a trust boundary: authentication, authorisation, credentials, or execution |
| **Medium** | Broad surface or infrastructure posture; consequence is real but bounded |
| **Low** | Limited blast radius, or non-executing content |

MDASH ranks files internally using call-graph analysis and complexity. This document
supplies the *business* context that ranking cannot infer — which paths hold credentials
and which reach ARM.

---

## 2. Repository inventory

Tracked files: **651 Python**, **158 frontend sources**, **176 Markdown**. Measured on the
PR #4 branch.

| Area | Files | LOC | Role | Priority |
|---|---:|---:|---|---|
| `backend/app/agent` | 21 | 6,497 | Orchestration, prompts, builtins, VM tools | **Critical** |
| `backend/app/mcp` | 2 | 609 | MCP client, read/write classification | **Critical** |
| `backend/app/exec` | 3 | 1,465 | Command validation and execution | **Critical** |
| `backend/app/azure` | 5 | 1,246 | Credential resolution, MCP env injection | **Critical** |
| `backend/app/auth` | 9 | 1,251 | Local, OIDC, SAML authentication | **High** |
| `backend/app/core` | 26 | 6,081 | Crypto, settings, security dependencies, connections | **High** |
| `backend/app/api` | 47 | 27,935 | Entire REST surface | **High** |
| `backend/app/rbac` | 13 | 2,535 | Azure RBAC access review | **High** |
| `backend/app/identity` | 9 | 2,047 | Identity posture analysis | **Medium** |
| `backend/app/graph` | 8 | 1,602 | Microsoft Graph integration | **Medium** |
| `backend/app/automations` | 9 | 2,246 | Custom agents, scheduled tasks | **High** |
| `backend/app/radar` | 10 | 1,480 | Service Health, Advisor, external feed | **Medium** |
| `deploy` | 2 | 1,150 | Bicep and ARM templates | **High** |
| `third_party` | 27 | 6,056 | Vendored Entra MCP server | **Medium** |
| `frontend/src` | 158 | 102,422 | React SPA | **Medium** |

---

## 3. Critical targets

### C-1 · `backend/app/agent/orchestrator.py`

**Why it matters.** The ReAct loop. Assembles the system prompt, resolves the write
policy, classifies calls, dispatches tools, and decides whether a mutation is gated. Every
agent-initiated Azure action passes through this file.

| Axis | Assessment |
|---|---|
| Security | Central authorisation decision point for tool execution |
| Azure | Directly dispatches control-plane mutations |
| AI | Consumes model output and untrusted tool results |
| Exposure | Reachable from any authenticated chat message |

**Findings expected:** [AI-01](ai-security-threat-model.md#ai-01),
[AI-09](ai-security-threat-model.md#ai-09),
[AI-13](ai-security-threat-model.md#ai-13),
[AI-15](ai-security-threat-model.md#ai-15).

**Validation approach.** Trace `write_policy_override` from parameter to dispatch. Confirm
`approval_required` is emitted for every write under the gated policy. Verify tool results
pass through `sanitize_tool_result` before entering the message list. Check that the
write-policy directive is positioned last in the assembled prompt.

---

### C-2 · `backend/app/mcp/client.py`

**Why it matters.** Two security-critical behaviours in 609 lines: the read/write
classifier that decides whether the approval gate applies, and the consent-elicitation
callback that answers the MCP server's destructive-operation prompts.

| Axis | Assessment |
|---|---|
| Security | Sole classification boundary between read and write |
| Azure | Misclassification means an ungated control-plane mutation |
| AI | The model supplies the argument string being classified |
| Exposure | Every tool call |

**Findings expected:** [AI-02](ai-security-threat-model.md#ai-02),
[AI-05](ai-security-threat-model.md#ai-05).

**Validation approach.** Enumerate the Azure MCP tool catalogue and assert `classify_call`
returns `"write"` for every destructive command. Confirm the fail-safe default is preserved
on every path, including the tool-name fallback. Review whether auto-accepting consent is
appropriate given the application gate can be disabled.

---

### C-3 · `backend/app/exec/command_runner.py`

**Why it matters.** Executes `az`, `azd`, and `kubectl` commands. Already well hardened —
`argv` parsing with `shell=False`, a binary allow-list, quote-aware shell-operator
rejection, mutating-verb detection, output caps, and credential scrubbing. PR #4
strengthened it further.

| Axis | Assessment |
|---|---|
| Security | Command injection would be immediately exploitable |
| Azure | Executes real Azure CLI commands |
| AI | Command text can originate from model output |
| Exposure | Reachable through agent tool calls |

**Findings expected:** Edge cases in the quote-state machine
(`_has_unquoted_shell_operator`) — nested quotes, escapes, Unicode; allow-list bypass via
path or casing; argument injection where a permitted binary accepts a dangerous flag
(for example `az ... --query` with a script-bearing value, or `kubectl --kubeconfig`).

**Validation approach.** Fuzz `validate_command` with quoting and escaping variants.
Confirm `AZURE_CLIENT_SECRET` and `AZURE_CLIENT_CERTIFICATE_PATH` are stripped on every
spawn path. Test whether a permitted binary can be induced to execute arbitrary code
through its own flags.

---

### C-4 · `backend/app/agent/builtins.py`

**Why it matters.** Network-reaching tools — `web_fetch`, `dns_query`, `tcp_probe`,
`nslookup`, `traceroute` — invoked with model-chosen targets. Hardened in PR #4 with SSRF
protections and configurable egress lists.

| Axis | Assessment |
|---|---|
| Security | SSRF, and the primary outbound exfiltration channel |
| Azure | Can reach instance metadata and private endpoints |
| AI | Target URL is chosen by the model |
| Exposure | Any chat turn |

**Findings expected:** [AI-10](ai-security-threat-model.md#ai-10). Specifically: DNS
rebinding (validate the hostname, resolve, then connect to a different address), redirect
following to a non-allow-listed host, IPv6 and decimal/octal IP encodings, and `169.254.169.254`
reachability.

**Validation approach.** Attempt to reach instance metadata directly and via redirect and
rebinding. Confirm allow-list enforcement happens **after** DNS resolution and again on
each redirect hop. Verify response size caps.

---

### C-5 · `backend/app/agent/vm_tools.py`

**Why it matters.** Executes commands and reads files on registered sandbox VMs, with a
per-VM `strict_mode` flag that can disable approval for mutating commands.

| Axis | Assessment |
|---|---|
| Security | Remote command execution driven by model output |
| Azure | VM identity may reach Azure; metadata endpoint is local |
| AI | Command text is model-generated; file contents return to the model |
| Exposure | Agent tool calls |

**Findings expected:** [AI-06](ai-security-threat-model.md#ai-06). Also command
construction, path traversal in `_vm_read_file`, and completeness of `_redact_secrets`.

**Validation approach.** Confirm mutating commands are gated when `strict_mode` is true and
verify what happens when it is false. Test path traversal on the read path. Assess whether
redaction is applied before persistence as well as before display.

---

### C-6 · `backend/app/azure/credentials.py` + `backend/app/core/crypto.py` + `backend/app/core/azure_connections.py`

**Why it matters.** The credential store. Fernet encryption, key resolution, decryption,
and injection of live service principal secrets into MCP child process environments.

| Axis | Assessment |
|---|---|
| Security | Highest-value asset in the system |
| Azure | Compromise means full tenant compromise at the principal's scope |
| AI | Indirect — the target of exfiltration attempts |
| Exposure | Not directly model-reachable, which is why it is C-6 not C-1 |

**Findings expected:** [AI-07](ai-security-threat-model.md#ai-07),
[SEC-05](security-review.md#sec-05). Also: key-derivation weaknesses, temporary
certificate file permissions and cleanup, secrets reaching logs or exception traces,
timing issues in decryption.

**Validation approach.** Confirm the encryption key never appears in logs or API
responses. Verify temporary certificate files are `0600` and deterministically removed.
Check that decrypted values are not retained longer than needed. Confirm masked API
responses cannot be induced to reveal plaintext.

---

### C-7 · `backend/app/api/chats.py`

**Why it matters.** The chat entry point, and where the autonomous write-policy override is
set — the single line that disables the approval gate.

| Axis | Assessment |
|---|---|
| Security | Sets the security policy for the turn |
| Azure | Determines whether mutations require approval |
| AI | Directly feeds the orchestration loop |
| Exposure | Primary authenticated entry point |

**Findings expected:** [AI-01](ai-security-threat-model.md#ai-01). Also authorisation on
chat and turn endpoints, and whether one user can subscribe to another's turn stream.

**Validation approach.** Trace every caller that can set `run_mode`. Confirm SSE
subscription is authorised per chat. Verify cancellation and reconnection cannot be used to
replay or resume another user's turn.

---

## 4. High targets

### H-1 · `backend/app/auth/`

Local password auth, OIDC, and SAML. PR #4 fixed a SAML comment-splitting authentication
bypass (CVE-2017-11427 class) by switching to `"".join(el.itertext())` at Issuer,
AudienceRestriction, NameID, and AttributeValue.

**Expect:** residual XML signature-wrapping variants, OIDC state/nonce/PKCE handling,
JWKS caching and key-rotation handling, `id_token` audience and issuer validation, timing
side channels in password comparison, and completeness of lockout counters.

**Validate:** signature wrapping against all four assertion reads; OIDC replay via reused
`state`; group-claim to role mapping under attacker-controlled claim values.

---

### H-2 · `backend/app/core/security.py` + `backend/app/auth/permissions.py`

Principal resolution and the `require_permission` dependency enforcing 40+ permissions
across 47 routers.

**Expect:** routes missing a permission dependency, over-broad permissions
([SEC-10](security-review.md#sec-10)), allow-list bypasses in the forced-password-change
and `noaccess` interceptors, and role-downscoping errors.

**Validate:** enumerate every route and assert each declares an explicit permission or is
a justified member of the unauthenticated allow-list. This is a good candidate for an
automated test rather than review alone.

---

### H-3 · `backend/app/api/` (remaining 46 routers, ~28k LOC)

The largest single surface. Includes routers that mutate Azure through subsystem
change-request flows: `alerts_manager`, `backup_manager`, `policy`, `automations`,
`assessments`, `tagintel`, `connections`.

**Expect:** IDOR on resource identifiers, missing permission checks, SSRF in
connector-configuration endpoints, injection in query-building endpoints, mass assignment,
and unbounded responses.

**Validate:** scan as a unit so cross-router patterns surface. Prioritise `connections.py`
(credential CRUD), `admin.py` (settings, approvals, audit), and `automations.py` (agent
creation).

---

### H-4 · `backend/app/automations/` + `backend/app/agent/agent_designer.py`

Custom agent definitions, scheduled tasks, and the LLM-driven agent designer that can emit
`run_mode: "autonomous"`.

**Expect:** [AI-04](ai-security-threat-model.md#ai-04). Also scheduled-task authorisation,
whether a task runs as its creator or as a service identity, and persistence of
`allowed_tools`.

**Validate:** attempt to obtain an autonomous agent through natural-language request.
Confirm the tool allow-list is enforced at dispatch, not only at display.

---

### H-5 · `deploy/main.bicep` + `deploy/main.json`

Infrastructure definition. PR #4 already made `postgresAdminPassword` a required
`@secure()` parameter.

**Expect:** [SEC-01](security-review.md#sec-01),
[SEC-02](security-review.md#sec-02),
[SEC-03](security-review.md#sec-03). Also secret leakage through outputs, over-permissive
role assignments, missing TLS enforcement, and drift between the Bicep and the generated
ARM JSON.

**Validate:** confirm `main.json` is regenerated from `main.bicep` and that no parameter
is `@secure()` in one and plaintext in the other. Run `az deployment group what-if`
against a disposable resource group.

---

### H-6 · `backend/app/rbac/`

Reads and evaluates Azure RBAC and Entra directory roles, composing effective access
including group inheritance and PIM. Documented read-only.

**Expect:** confirmation that no write path exists; cache poisoning where a stale or
attacker-influenced scan hides a privileged assignment; injection in Resource Graph query
construction.

**Validate:** confirm no role-assignment create or delete call exists. Review cache keying
and TTL, and behaviour on partial scan failure — a failed scan must not be cached as a
clean result.

---

## 5. Medium targets

| ID | Path | Rationale | Expect |
|---|---|---|---|
| M-1 | `backend/app/radar/` | Ingests an external RSS feed | [AI-11](ai-security-threat-model.md#ai-11); XML parsing, host validation, field length caps |
| M-2 | `backend/app/graph/`, `backend/app/identity/` | Microsoft Graph queries at directory scope | Over-broad Graph permissions, injection in filter construction |
| M-3 | `third_party/entraid-mcp-server` | Vendored, outside dependency management | [SEC-07](security-review.md#sec-07); upstream advisories, Graph scope |
| M-4 | `frontend/src` | 102k LOC rendering agent output | XSS via `dangerouslySetInnerHTML`, unsanitised Markdown, token handling in browser storage |
| M-5 | `backend/app/main.py` | App wiring, CORS, middleware ordering | Permissive CORS, middleware ordering that skips auth, error handlers leaking traces |
| M-6 | `Dockerfile`, `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` | Container posture; hardened in PR #4 | Residual root usage, build-time secrets in layers, unpinned base images |
| M-7 | `backend/app/connectors/` | Outbound webhooks to Teams, Slack, Jira, Grafana | SSRF, webhook URL validation, secret handling |
| M-8 | `backend/app/notifications/` | Outbound message delivery | Injection into message bodies, secret leakage in delivery logs |

---

## 6. Low targets

| Path | Rationale |
|---|---|
| `docs/` | Documentation. Scan only for accidentally committed secrets or real identifiers |
| `**/demo*.py`, `backend/app/demo_catalog.py` | Demo data. Verify it contains no real tenant identifiers |
| `frontend/public`, `docs/assets` | Static assets |
| `docs/*_TEST_PLAN.md`, `BUG_HUNTING_PLAN.md` | Planning documents, excluded from the docs site |
| `RELEASE`, `LICENSE`, `CODE_OF_CONDUCT.md` | Metadata |

---

## 7. Scan waves

Agentic scans are slower and more expensive than static analysis. Sequence for signal
density.

| Wave | Scope | Rationale |
|---|---|---|
| 1 | `backend/app/agent`, `backend/app/mcp`, `backend/app/exec` | Highest consequence, ~8.5k LOC — fast, dense signal |
| 2 | `backend/app/auth`, `backend/app/core`, `backend/app/azure` | Trust boundaries and credentials |
| 3 | `backend/app/api` | Largest surface; benefits from wave 1–2 context |
| 4 | `deploy`, Dockerfiles, `docker-compose.yml` | Infrastructure posture |
| 5 | `frontend/src` | Client-side; XSS on agent-rendered output |
| 6 | `third_party` | Supply chain |
| 7 | `backend/app` (whole tree) | Baseline pass to catch cross-module taint paths |

Wave 7 matters. Several findings — notably
[AI-01](ai-security-threat-model.md#ai-01), where configuration in `api/chats.py` flows
into dispatch in `agent/orchestrator.py` — are **cross-file** and invisible to a
directory-scoped scan. Run the full-tree pass at least once per release.

```powershell
# Wave 1
defender scan ai-scan submit ./backend/app/agent
defender scan ai-scan submit ./backend/app/mcp
defender scan ai-scan submit ./backend/app/exec

# Wave 7 — full backend, async
defender scan ai-scan submit ./backend
defender status wait <JOB_ID> -o results-backend.sarif
```

`mai-augmented-profile` is unavailable in `swedencentral` because `MAI-Cyber-1-Flash` is
not offered there. Use the default `gpt-general-profile`.

---

## 8. Exclusions

Excluded from early waves to control cost and noise. Not excluded from the wave 7
baseline.

| Excluded | Reason |
|---|---|
| `docs/` | Non-executing content |
| `frontend/public`, `docs/assets` | Static assets |
| `**/node_modules`, `**/.venv`, `**/__pycache__` | Build artefacts |
| `frontend/package-lock.json`, `backend/uv.lock` | Covered by dependency review and Dependabot |
| `**/*.png`, `**/*.svg` | Binary assets |

Do **not** exclude `third_party/`. Vendored code is outside dependency management and is
the least-monitored executable code in the repository.

---

## 9. Triage guidance

MDASH scores findings on a ten-level confidence hierarchy from UNLIKELY to PROVEN.
Suggested handling for this repository:

| Confidence | Action |
|---|---|
| PROVEN / high | Triage within one working day if in a Critical target; treat as a release blocker |
| Medium | Confirm manually against the threat model; a matching entry raises priority |
| UNLIKELY / low | Batch review; look for clusters in one file, which often indicate a real design weakness |

Cross-reference every finding against
[ai-security-threat-model.md](ai-security-threat-model.md) and
[security-review.md](security-review.md) before triage. A finding that matches a known
entry should inherit that entry's priority. A finding in a Critical target that matches
**no** existing entry is the most valuable output of the scan and should be reviewed
first.

`defender fix` can generate fixes from results. Every Critical and High target here
touches an agent, credential, or Azure control-plane path — apply generated fixes only
through normal pull-request review, never automatically.

> The exact `defender fix` argument syntax is not published on Microsoft Learn. See
> [mdash-readiness.md](mdash-readiness.md#9-running-an-mdash-scan) — marked
> **Documentation Required**.
