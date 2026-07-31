# mdash — agentic security scanning harness

A multi-model, multi-agent security review pipeline that runs against Azure AI Foundry
deployments and reports into GitHub code scanning.

It is a working reimplementation of the pipeline Microsoft describes for **MDASH**
(the AI-driven Scanning Harness behind Project Ithaca / Project Perception). The design
premise, in Microsoft's words, is that *"the harness does the work, and the model is one
input"* — the stages are model-agnostic by construction.

---

## Why this exists (and the MAI-Cyber-1-Flash question)

Microsoft's MDASH announcement pairs the harness with **MAI-Cyber-1-Flash**. Neither is
generally available:

| Thing | Status |
| --- | --- |
| MDASH | Limited **private preview**, Microsoft-operated. Signup: <https://aka.ms/AI-drivenScanningHarness> |
| MAI-Cyber-1-Flash | Azure AI Foundry **private preview**, usable *only inside MDASH*. Explicitly **"not exposed as a public endpoint."** |
| Project Perception | Gated preview in Microsoft Defender |

So you cannot deploy MDASH + MAI-Cyber-1-Flash into your own subscription today.

What makes substitution reasonable is Microsoft's own benchmark. On CyberGym:

| Configuration | Score |
| --- | --- |
| MDASH + MAI-Cyber-1-Flash + GPT-5.4 | 96.00% |
| MDASH + GPT-5.4 panel (no Cyber model) | 95.95% |

The specialised model's contribution is roughly a **50% cost reduction, not a capability
gain**. The capability is in the harness. This tool is that harness, wired to models you
can actually deploy — swap a deployment name in `mdash.toml` if you are granted access.

---

## Pipeline

```
prepare  ->  scan  ->  validate  ->  dedupe  ->  prove  ->  report
   |          |           |            |          |          |
 rank      5 narrow    adversarial   merge     execute     SARIF +
 attack    auditors    debate on a   equivalent a real     findings.json +
 surface   in         *different*    findings   trigger    job summary
           parallel    model                    (opt-in)
```

**prepare** — ranks files by attack surface rather than scanning everything: path signals
(`auth/`, `exec/`, `crypto/`), risky constructs in the source, and git churn over the last
180 days. Recently-churned security-relevant code is where bugs are. The ranking makes
`max_targets` a budget rather than an arbitrary truncation.

**scan** — five specialist auditors, each with an explicit `non_goals` list so they do not
all report the same thing:

| Agent | Owns |
| --- | --- |
| `authn-authz` | authentication, sessions, tokens, access control, IDOR |
| `injection` | SQL/command/template/XML/deserialisation sinks |
| `ssrf-egress` | outbound requests, URL handling, redirect and rebind attacks |
| `secrets-crypto` | credential handling, key management, weak primitives |
| `infra-supplychain` | Dockerfiles, compose, IaC, CI workflows, dependency pinning |

Narrow agents beat one general prompt: a single "find all vulnerabilities" pass reliably
under-reports whole classes because the model settles on the first few it notices.

**validate** — the stage that separates a finding from a triage backlog. Every candidate is
cross-examined by a **different deployment**, which must argue both `argument_for` and
`argument_against` before ruling. This is not optional rigour: a model reviewing its own
output overwhelmingly agrees with itself. Only genuine disagreement (`uncertain`, or a
low-confidence refutation) escalates to the expensive reasoner — so **spend tracks
difficulty, not repository size**.

**dedupe** — merges rather than discards. Two agents that were never told about each other
reaching the same conclusion is the strongest credibility signal available, so corroboration
*raises* confidence on the survivor and is marked with ⭐ in the report.

**prove** — opt-in. Writes and executes a proof-of-concept in a scrubbed subprocess sandbox.
Off by default; see the warning below.

**report** — SARIF 2.1.0 with `security-severity` (GitHub ranks by that, not SARIF `level`),
CWE tags, and `partialFingerprints` computed **without line numbers** so alerts track across
unrelated edits instead of re-opening.

---

## Quick start

```bash
pip install ./tools/mdash
az login

export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com/"
python -m mdash --root . --out mdash-results --max-targets 10
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--diff origin/main` | scan only changed files (pull-request mode) |
| `--agents injection,secrets-crypto` | run a subset of auditors |
| `--max-targets N` | budget cap; files are ranked, so N picks the most interesting |
| `--fail-on high` | non-zero exit when a finding meets that severity |
| `--prove` | enable proof-of-concept execution (read the warning) |
| `--no-debate` | skip validation — faster, noisier, not recommended |

Outputs land in `--out`: `mdash.sarif`, `findings.json` (full reasoning chain, including
refuted candidates' rationale), and `summary.md`.

Configuration lives in [`mdash.toml`](../../mdash.toml) at the repository root.

---

## Model panel

| Seat | Default | Reasoning effort | Called |
| --- | --- | --- | --- |
| `auditor` | `gpt-5.3-codex` | medium | once per (agent × file) |
| `debater` | `gpt-5.4-mini` | low | once per candidate finding |
| `escalation` | `gpt-5.4` | high | only on disagreement |

Two constraints are load-bearing and worth not "simplifying" away:

1. **The debater must be a different deployment from the auditor.** Independence is the
   whole point of the stage.
2. **The harness uses the Responses API, not Chat Completions.** This is a hard requirement:
   `gpt-5.3-codex` reports `chatCompletion: false` and serves only `/responses`. Responses
   also accepts a strict `json_schema`, which makes the output shape a service-side
   guarantee instead of a prompt-time request. Verify any model you swap in with:

   ```bash
   az cognitiveservices account deployment show \
     -g <rg> -n <account> --deployment-name <deployment> \
     --query properties.capabilities
   ```

Note that only the `*.openai.azure.com` hostname routes `/responses`; the
`cognitiveservices.azure.com` and `services.ai.azure.com` hosts answer 404. The harness
rewrites the host for you, so any endpoint form for the resource works.

Requests are sent with `store: false` — the payload is your source code and it should not
persist in server-side response state.

---

## CI setup

[`.github/workflows/mdash-scan.yml`](../../.github/workflows/mdash-scan.yml) runs on pull
requests, weekly, and on demand. It authenticates with **workload identity federation** — no
client secret, no API key.

One-time setup:

```bash
# 1. App registration + service principal
az ad app create --display-name mdash-scanner
APP_ID=$(az ad app list --display-name mdash-scanner --query "[0].appId" -o tsv)
az ad sp create --id "$APP_ID"

# 2. Federated credential for this repository (branch-scoped)
az ad app federated-credential create --id "$APP_ID" --parameters '{
  "name": "mdash-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<owner>/<repo>:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'
# Add a second credential with subject "repo:<owner>/<repo>:pull_request" for PR runs.

# 3. Least privilege: inference only, scoped to the one Foundry account
az role assignment create \
  --assignee "$APP_ID" \
  --role "Cognitive Services OpenAI User" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<account>"
```

Then set four repository **variables** (not secrets — none of these are sensitive):
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_OPENAI_ENDPOINT`.

Pull requests **from forks** are skipped: a fork cannot mint an OIDC token for your tenant,
so the run would fail on credentials rather than on findings. The scheduled sweep covers
those changes after merge.

---

## ⚠️ The prove stage executes model-generated code

`--prove` asks a model to write a proof-of-concept and then **runs it**. Mitigations: a
scrubbed environment allowlist, an isolated temporary working directory, no stdin, a hard
timeout, and `python -I -S`. These are defence in depth, **not a security boundary**.

Enable it in disposable CI runners or containers. Do not enable it on a workstation holding
credentials. It is off by default and stays off unless you pass `--prove`.

---

## Limitations

Worth stating plainly, because a scanner that oversells itself gets ignored:

- **Single-file context.** Auditors reason about one file at a time. Vulnerabilities that
  only exist in the interaction between modules are largely out of reach.
- **Non-deterministic.** Two runs will not produce identical findings. Treat it as a review
  partner, not a gate you can diff.
- **False negatives are unmeasured.** The debate stage is tuned to suppress false positives,
  which necessarily costs recall. It complements CodeQL, bandit, and dependency scanning —
  it does not replace any of them.
- **Costs real money per run.** `max_targets` and the escalation-on-disagreement routing are
  the two controls that matter.

## Development

```bash
pip install -e "./tools/mdash[dev]"
python -m pytest tools/mdash/tests -q
python -m ruff check tools/mdash
```

The test suite is deliberately network-free: it covers ranking, agent routing, dedupe
clustering, SARIF shape, request construction, and the strict-schema invariants that
otherwise only surface as an opaque HTTP 400 mid-scan.
