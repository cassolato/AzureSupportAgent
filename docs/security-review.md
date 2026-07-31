---
layout: default
title: Security review
nav_exclude: true
---

# Security review — Azure Support Agent

Conventional application and infrastructure security review, produced as part of MDASH
readiness preparation. AI- and agent-specific risks are in
[ai-security-threat-model.md](ai-security-threat-model.md); scan prioritisation is in
[recommended-scan-scope.md](recommended-scan-scope.md).

---

## 1. Executive summary

This review is a static, source-derived assessment. No exploitation was attempted and no
runtime testing was performed. It complements — and does not replace — the MDASH scan,
whose purpose is to find what human review misses.

### Existing posture

The codebase shows a deliberate and, in most places, well-executed security design:

| Control | Implementation |
|---|---|
| Secrets at rest | Fernet (AES-128-CBC + HMAC-SHA256) via `backend/app/core/crypto.py`; key from `SECRETS_ENCRYPTION_KEY` or a `0600` local file |
| Password storage | Argon2 with per-account lockout and per-IP rate limiting |
| Sessions | Server-side, database-backed; HttpOnly/Secure/SameSite cookies; idle and absolute lifetimes |
| Authorisation | 40+ fine-grained permissions enforced by FastAPI dependencies; `noaccess` default for JIT-provisioned SSO users |
| Command execution | `argv` parsing with `shell=False`, binary allow-list, shell-operator rejection, credential scrubbing |
| Write operations | Read/write classification with a fail-safe default to write, plus an approval gate |
| MCP posture | Azure MCP server spawned `--read-only` by default; no remote MCP servers |
| Proxy headers | `X-Forwarded-For` trusted only when explicitly configured |
| Private networking | Optional VNet injection with private endpoints for storage and PostgreSQL |

PR #4 — the branch this change extends — already remediated 13 findings, including a
committed database credential, a SAML assertion comment-splitting authentication bypass
(CVE-2017-11427 class), a predictable `uniqueString()`-derived database password, and
several npm transitive advisories. That work is not repeated here.

### This review

Ten findings remain, none of which duplicate PR #4:

| Severity | Count |
|---|---|
| High | 3 |
| Medium | 4 |
| Low | 3 |

The dominant theme is **identity architecture**: the application authenticates to Azure
with stored service principal secrets rather than managed identity, which makes the
credential store the single highest-value asset in the system.

---

## 2. Findings

| ID | Title | Severity | Affected path |
|---|---|---|---|
| [SEC-01](#sec-01) | Container App has no managed identity | High | `deploy/main.bicep` |
| [SEC-02](#sec-02) | PostgreSQL `0.0.0.0` firewall rule in public mode | High | `deploy/main.bicep:340-351` |
| [SEC-03](#sec-03) | Mutable `:latest` container image tag | High | `deploy/main.bicep:12` |
| [SEC-04](#sec-04) | No Key Vault for `SECRETS_ENCRYPTION_KEY` | Medium | Deployment / environment |
| [SEC-05](#sec-05) | Encryption key auto-generated to disk on first run | Medium | `backend/app/core/crypto.py` |
| [SEC-06](#sec-06) | No CI/CD security gates | Medium | *(repository)* |
| [SEC-07](#sec-07) | Vendored third-party MCP server | Medium | `third_party/entraid-mcp-server` |
| [SEC-08](#sec-08) | `Microsoft.DBforPostgreSQL` provider not registered | Low | Environment |
| [SEC-09](#sec-09) | Storage account key-based access for file mount | Low | `deploy/main.bicep` |
| [SEC-10](#sec-10) | Broad in-app permission surface | Low | `backend/app/auth/permissions.py` |

---

### SEC-01 {#sec-01}
**Container App has no managed identity** — **High**

**Description.** `deploy/main.bicep` provisions the Container App with no `identity`
block. The application therefore holds no Azure identity of its own and authenticates to
Azure exclusively through service principal credentials stored in the connections registry
and injected as environment variables (`backend/app/azure/credentials.py`).

**Why the design exists.** Multi-tenancy. The application acts as a *different* principal
per connected tenant, which a single managed identity cannot express. That rationale is
sound for tenant operations.

**Why it is still a finding.** It is not sound for the application's *own* operations.
With no managed identity there is no keyless path to Key Vault, storage, Log Analytics, or
its own telemetry. Every secret must be delivered as configuration, which is what makes
SEC-04 and [AI-07](ai-security-threat-model.md) severe.

**Impact.** Long-lived client secrets are the only credential mechanism; rotation requires
redeployment or manual re-entry; there is no keyless path for platform access.

**Remediation.**
1. Add a system-assigned (or user-assigned) identity to the Container App.
2. Grant it `Key Vault Secrets User` and read `SECRETS_ENCRYPTION_KEY` at startup.
3. Use it for storage and Log Analytics access, replacing account keys (SEC-09).
4. Keep per-tenant service principals for tenant operations, and prefer workload identity
   federation over client secrets where supported.

**Validation.**
- `az containerapp show --query identity` returns a principal ID.
- The application starts with no `SECRETS_ENCRYPTION_KEY` in its environment.

---

### SEC-02 {#sec-02}
**PostgreSQL `0.0.0.0` firewall rule in public mode** — **High**

**Description.** In the default public deployment mode the template creates Azure's
"allow all Azure services" firewall rule:

```bicep
// deploy/main.bicep:340-351
// SECURITY (CWE-284): the special 0.0.0.0-0.0.0.0 rule is Azure's "Allow public access
// from any Azure service ..."
startIpAddress: '0.0.0.0'
endIpAddress:   '0.0.0.0'
```

The template already carries an in-line warning, so the risk is acknowledged.

**Impact.** The database accepts connections from **any** Azure tenant's resources, not
only this subscription's. Combined with credentials obtained elsewhere, this is a direct
data-plane path from outside the customer's boundary. CWE-284, improper access control.

**Remediation.**
1. Prefer `privateNetworking = 'Yes'`, which sets `publicNetworkAccess: 'Disabled'` and
   provisions a private endpoint. Document it as the recommended production mode.
2. If public mode must remain, replace the rule with the Container Apps environment's
   outbound IPs.
3. Enable Entra authentication for PostgreSQL and disable password auth.
4. Enforce TLS.

**Validation.**
- `az postgres flexible-server firewall-rule list` shows no `0.0.0.0` rule.
- Connection attempts from an unrelated Azure subscription fail.

---

### SEC-03 {#sec-03}
**Mutable `:latest` container image tag** — **High**

**Description.**

```bicep
// deploy/main.bicep:11-12
@description('... SECURITY: a mutable :latest tag means the deployed code can change
without a template change and cannot be attested; for production, pin an immutable digest')
param containerImage string = 'docker.io/zmustafa/azure-support-agent:latest'
```

The risk is documented in the parameter description, but `:latest` remains the default and
therefore what the one-click deployment path uses.

**Impact.** The deployed code can change without any template change. There is no
attestation, no reproducibility, and a registry compromise or tag overwrite propagates to
every deployment on the next revision. For an application that holds tenant credentials
and can mutate Azure, this is a serious supply-chain exposure. Public Docker Hub also
widens the trust boundary relative to a customer-controlled ACR.

**Remediation.**
1. Default to an immutable digest: `docker.io/zmustafa/azure-support-agent@sha256:...`.
2. Publish to GHCR or a customer ACR and document pull authentication.
3. Sign images and verify signatures at deployment.
4. Generate and publish an SBOM per release.
5. Enable Defender for Containers registry scanning — the `Containers` plan is already on
   Standard in the target subscription.

**Validation.**
- `az containerapp show --query "properties.template.containers[].image"` returns a digest.
- The digest matches a signed, published release artefact.

---

### SEC-04 {#sec-04}
**No Key Vault for `SECRETS_ENCRYPTION_KEY`** — **Medium**

**Description.** `backend/app/core/crypto.py` reads `SECRETS_ENCRYPTION_KEY` from the
environment; the deployment supplies it as a Container Apps secret. Validation confirmed
**no Key Vault exists** in `rg-ip-mdash-AzureSupportAgent`.

**Impact.** This key protects every stored service principal credential. Held only as a
deployment parameter it cannot be rotated without redeployment, has no access audit trail,
and no HSM protection. Anyone who can read the Container App configuration can read it.

**Remediation.**
1. Create a Key Vault with Azure RBAC authorisation and purge protection.
2. Store `SECRETS_ENCRYPTION_KEY` there and reference it via Container Apps Key Vault
   secret references (requires SEC-01).
3. Document the rotation runbook — note that changing the key without migrating data makes
   existing encrypted values unreadable, as
   [credential-handling.md](security/credential-handling.md) already warns.
4. Enable diagnostic logging on the vault.

**Validation.**
- `K1` in the validation script passes.
- The Container App references the secret from Key Vault, not as a literal.

---

### SEC-05 {#sec-05}
**Encryption key auto-generated to disk on first run** — **Medium**

**Description.**

```python
# backend/app/core/crypto.py
if _KEY_PATH.exists():
    return _KEY_PATH.read_text(encoding="utf-8").strip().encode("utf-8")
# Generate and persist (dev only)
key = Fernet.generate_key()
_KEY_PATH.write_text(key.decode("utf-8"), encoding="utf-8")
```

The fallback is intended for development and the file is created with restricted
permissions.

**Impact.** The fallback is silent. If `SECRETS_ENCRYPTION_KEY` is unset or malformed in
production the application starts normally and writes a key to `backend/.data/secret.key`
— on a mounted Azure Files share in the deployed topology. The key then sits beside the
ciphertext it protects, defeating the encryption at rest. Silent degradation makes this a
configuration error that no one notices.

**Remediation.**
1. Gate the fallback on an explicit development flag; in production, fail fast and loudly
   when the key is absent.
2. Log (without the value) which key source was selected at startup.
3. Expose the key source on an admin health page.
4. Exclude `backend/.data/` from backups and image layers.

**Validation.**
- Start with `SECRETS_ENCRYPTION_KEY` unset and a production flag; expect a clean startup
  failure and no generated key file.

---

### SEC-06 {#sec-06}
**No CI/CD security gates** — **Medium**

**Description.** Before this change the repository had **no `.github/` directory**: no
workflows, no CodeQL, no dependency review, no Dependabot.

**Impact.** No automated static analysis, no dependency vulnerability gate, no secret
scanning enforcement in pull requests. For a repository handling credentials and Azure
control-plane operations, every regression depends on human review. It also means MDASH
would have nowhere to publish SARIF alongside existing results.

**Remediation.** Added by this change:

| File | Purpose |
|---|---|
| `.github/workflows/codeql.yml` | CodeQL for Python and TypeScript, `security-extended` queries, weekly plus PR runs |
| `.github/workflows/dependency-review.yml` | Fails PRs introducing high-severity vulnerable dependencies |
| `.github/dependabot.yml` | Weekly updates for pip, npm, Docker, and GitHub Actions |

All three require only `GITHUB_TOKEN`. The MDASH pipeline workflow needs secrets and is
provided as a documented opt-in template in
[mdash-readiness.md](mdash-readiness.md#10-cicd-integration) rather than committed active.

Still recommended, as repository settings:

1. Enable secret scanning and push protection.
2. Enable Dependabot security updates.
3. Branch protection on `main`: required reviews, required status checks, no force push.
4. `CODEOWNERS` for `backend/app/agent`, `backend/app/mcp`, `backend/app/exec`,
   `backend/app/auth`, `deploy/`.

**Validation.**
- CodeQL and dependency-review appear as checks on a pull request.
- Both are configured as required status checks.

---

### SEC-07 {#sec-07}
**Vendored third-party MCP server** — **Medium**

**Description.** `third_party/entraid-mcp-server` is a vendored Python MCP server that
performs Microsoft Graph operations against the directory.

**Impact.** Vendored code is outside the normal dependency update path — Dependabot will
not raise advisories for it, and it does not appear in a lockfile. It runs in-process
context with directory access, so a vulnerability there is a directory-scope issue. Its
provenance and update cadence are not documented in the repository.

**Remediation.**
1. Record upstream source, commit, and licence in a `third_party/README`.
2. Include `third_party/` in every MDASH scan (see
   [recommended-scan-scope.md](recommended-scan-scope.md), wave 6).
3. Subscribe to upstream advisories and document a re-vendoring procedure.
4. Constrain the Graph permissions it is granted to the minimum the features require.

**Validation.**
- Upstream commit is recorded and matches the vendored tree.
- The scan covers `third_party/`.

---

### SEC-08 {#sec-08}
**`Microsoft.DBforPostgreSQL` provider not registered** — **Low**

**Description.** Validation found the provider in `NotRegistered` state in
`MCAPS-Hybrid-rafaelcas`, while `deploy/main.bicep` provisions a PostgreSQL flexible
server.

**Impact.** Deployment fails at resource-creation time with an error that is easy to
misread as a template problem. Availability, not confidentiality.

**Remediation.**

```bash
az provider register --namespace Microsoft.DBforPostgreSQL \
  --subscription 4bd56768-1b2f-4c85-951f-68ce70b7c999
```

Registration is asynchronous; poll until `Registered`.

**Validation.** Check `D-PG` in the validation script, or:

```bash
az provider show --namespace Microsoft.DBforPostgreSQL --query registrationState -o tsv
```

---

### SEC-09 {#sec-09}
**Storage account key-based access for file mount** — **Low**

**Description.** The Container Apps environment mounts an Azure Files share using storage
account keys.

**Impact.** Account keys grant full control of the storage account and do not expire.
The mounted share holds `backend/.data/`, which contains the encrypted connections
registry — and, under SEC-05, potentially the encryption key itself. This is a low finding
only because Container Apps file mounts have limited identity-based alternatives today.

**Remediation.**
1. Rotate account keys on a schedule.
2. Enable `allowSharedKeyAccess: false` where the platform permits identity-based mounts.
3. Keep the private-endpoint configuration used in private networking mode.
4. Enable Defender for Storage — the `StorageAccounts` plan is already on Standard.
5. Ensure `SECRETS_ENCRYPTION_KEY` never lands on the share (SEC-04, SEC-05).

**Validation.**
- Key rotation is documented and scheduled.
- Public network access to the storage account is disabled.

---

### SEC-10 {#sec-10}
**Broad in-app permission surface** — **Low**

**Description.** `backend/app/auth/permissions.py` defines 40+ fine-grained permissions
across agent, automation, governance, observability, and incident-response features. The
model is well designed — the concern is operational.

**Impact.** With this many permissions, role definitions drift toward "grant everything"
for convenience. `chat.use` alone is broad: it grants access to the agent loop and, with
it, the entire tool surface. There is no separation between "chat read-only" and "chat
with write tools".

**Remediation.**
1. Split `chat.use` into `chat.use` and `chat.write_tools`, and require the latter for any
   turn that may reach a gated write.
2. Add a distinct `agents.autonomous` permission for
   [AI-04](ai-security-threat-model.md).
3. Ship least-privilege starter roles (`viewer`, `operator`, `approver`) rather than
   leaving composition to administrators.
4. Report on users holding admin, and review periodically.

**Validation.**
- A user with `chat.use` but not `chat.write_tools` cannot trigger a write gate.
- Starter roles exist and are documented.

---

## 3. Remediation backlog

| Priority | ID | Item | Effort |
|---|---|---|---|
| P0 | SEC-01 | Add managed identity to the Container App | Medium |
| P0 | SEC-02 | Remove the `0.0.0.0` PostgreSQL rule; default to private networking | Low |
| P1 | SEC-03 | Pin an immutable image digest; sign and publish an SBOM | Medium |
| P1 | SEC-04 | Key Vault for `SECRETS_ENCRYPTION_KEY` | Medium |
| P1 | SEC-05 | Fail fast when the encryption key is absent in production | Low |
| P1 | SEC-06 | Branch protection and required checks | Low |
| P2 | SEC-07 | Document and monitor vendored third-party code | Low |
| P2 | SEC-09 | Storage key rotation and identity-based access | Medium |
| P2 | SEC-10 | Split `chat.use`; ship least-privilege starter roles | Medium |
| P3 | SEC-08 | Register `Microsoft.DBforPostgreSQL` | Trivial |

Cross-cutting: the AI findings in
[ai-security-threat-model.md](ai-security-threat-model.md) carry two **Critical** items
(AI-01, AI-02) that outrank everything above.

---

## 4. Security review checklist

For reviewers of changes to this repository. Anything touching the paths in
[recommended-scan-scope.md](recommended-scan-scope.md) warrants a second reviewer.

### Agent and orchestration

- [ ] No new path can set `write_policy_override = "off"`.
- [ ] New tools are classified correctly by `classify_call`, with tests.
- [ ] New tool output flows through `sanitize_tool_result`.
- [ ] Prompt additions are appended **before** the write-policy directive, never after.
- [ ] No new autonomous execution path bypasses approvals.

### Azure integration

- [ ] No new use of long-lived client secrets where managed identity or federation works.
- [ ] Secrets are never logged, echoed, or returned in an API response.
- [ ] New Azure calls respect the connection's tenant scope.
- [ ] Subprocess spawns strip credential environment variables.

### Authentication and authorisation

- [ ] Every new route declares `require_permission(...)`.
- [ ] New permissions are added to the catalogue and documented.
- [ ] No route is added to the unauthenticated allow-list without justification.
- [ ] Session and cookie attributes are unchanged unless deliberately reviewed.

### Infrastructure

- [ ] No new public ingress without justification.
- [ ] New secret parameters are `@secure()`.
- [ ] Container images are pinned by digest.
- [ ] No new `0.0.0.0` firewall rule.

### Dependencies

- [ ] New dependencies are pinned and have a known-good licence.
- [ ] Dependency review passes.
- [ ] Vendored code is recorded with upstream provenance.

### Secrets

- [ ] No credential, token, connection string, or key in source, tests, fixtures, docs, or
      commit messages.
- [ ] `.env.example` contains placeholders only.
- [ ] Secret scanning and push protection are enabled.

---

## 5. Related documentation

Existing security documentation in this repository:

- [Security overview](security/index.md)
- [Data flow](security/data-flow.md)
- [Access control](security/access-control.md)
- [Approvals](security/approvals.md)
- [Credential handling](security/credential-handling.md)
- [Auditing](security/auditing.md)

Added by this change:

- [MDASH readiness](mdash-readiness.md)
- [Azure validation](azure-validation.md)
- [AI security threat model](ai-security-threat-model.md)
- [Recommended scan scope](recommended-scan-scope.md)

Report product vulnerabilities through the process in `SECURITY.md`, not a public issue.
