---
layout: default
title: Backup Manager
parent: Coverage
grand_parent: User guide
nav_order: 5
description: Manage Azure Backup and Site Recovery — protection inventory, job triage, policies, vault posture, DR drills, real cost, and approval-gated changes.
permalink: /user-guide/coverage/backup-manager/
feature_ids: [PROACTIVE_NAV:backup-manager, BACKUP_MANAGER_NAV:overview, BACKUP_MANAGER_NAV:flow, BACKUP_MANAGER_NAV:inventory, BACKUP_MANAGER_NAV:jobs, BACKUP_MANAGER_NAV:policies, BACKUP_MANAGER_NAV:vaults, BACKUP_MANAGER_NAV:gaps, BACKUP_MANAGER_NAV:dr, BACKUP_MANAGER_NAV:cost, BACKUP_MANAGER_NAV:changes]
---

# Backup Manager

**Product permissions:** `backup_manager.read`; write actions use `backup_manager.protect_write`, `backup_manager.policy_write`, `backup_manager.vault_write`, `backup_manager.ondemand`, `backup_manager.drill_write`, and `backup_manager.reference_write` according to the action. `backup_manager.approve` decides and applies managed changes.

## Purpose

**App routes:** `/backup-manager` and `/backup-manager/:tab`

Backup Manager is the operational management plane for Azure Backup and Azure Site Recovery. It is the sibling of Alerts Manager: there the inbox is fired alerts, here it is failed backup jobs; there the rules are alert rules, here they are backup policies; and the destinations are vaults rather than action groups. Backup & DR Coverage remains the separate read-only scoring view, and its findings can be ingested here as a remediation queue.

Some actions mutate Azure. Availability depends on both the signed-in user's permission and the connection's read-only policy.

## What this module deliberately does not do

Two whole classes of operation are absent by design rather than unimplemented, and the module reports the omission instead of hiding it. `GET /api/backup-manager/refusals` lists them, and the capability flags `can_restore` and `can_delete_backup_data` are always `false`.

- **Restore of any kind.** There is no restore target type in the change model. Restores are performed in the Azure portal by the team that owns the workload, under their own change control.
- **Destructive backup operations:** deleting backup data, purging soft-deleted items, locking immutability, disabling soft delete, and unregistering a container. These cannot be rolled back, so they stay in the portal.

Only **stop protection with data retained** exists. A request to stop protection in any other mode is refused by the apply path, not merely hidden in the UI.

## Prerequisites and data sources

### Prerequisites

- An Azure connection that can read the Resource Graph `recoveryservicesresources` table across the selected scope.
- Reader access to Recovery Services vaults and Backup vaults for the per-vault configuration reads (soft delete, storage redundancy, Resource Guard, diagnostic settings).
- `Microsoft.CostManagement/query/action` on the in-scope subscriptions for actual spend. Without it the Cost tab still reports list-price estimates and says why actuals are missing.
- A Log Analytics workspace receiving vault diagnostics for long-horizon Backup Reports. Pasted-token connections cannot query Log Analytics because the token audience differs; use a service-principal or managed-identity connection.
- Target-specific ARM write access on the connection at apply time, plus the matching product permission to draft the change.

### Data sources

- **Azure Resource Graph** is the spine: protected items, backup instances, policies, jobs, Site Recovery replicated items, and recovery plans, collected from nine independent queries.
- **ARM configuration reads**, one per vault, for the facts Resource Graph does not expose.
- **Azure Cost Management** for invoiced spend, and the **Azure Retail Prices** API for list prices.
- **Log Analytics** for job history beyond the Resource Graph window.

Every source is fail-soft. A permission gap or unsupported table degrades that one section and is recorded in `errors` rather than failing the analysis.

## Tabs and actions

- **Overview** is the scorecard: protected items, job success in the last 24 hours, RPO attainment, ransomware readiness, chronic failures, Site Recovery health, estimated monthly cost, and the count of changes awaiting a decision.
- **Protection flow** renders the estate as a Sankey: which subscription, workload, resource type, policy and vault each item flows through, and how it ends up. Columns are configurable, flows can be weighted by item count or by real money, and unprotected resources are drawn as their own branch.
- **Protection** lists every protected item with its vault, policy, state and latest recovery point, and flags orphaned and stopped items.
- **Job inbox** clusters failures by root cause against a knowledge base of Azure Backup error codes rather than listing every job, and surfaces chronic failures and backup-window congestion.
- **Policies** analyses sprawl, drift and retention floors, and models the exact recovery-point impact of a proposed retention change before anything is submitted.
- **Vaults** scores ransomware readiness per vault and offers the hardening controls that are safe to automate.
- **Gaps** detects backup-eligible resources with no protection and ingests findings from Backup & DR Coverage, then plans protection for the selected ones.
- **DR & drills** reports Site Recovery readiness and RPO attainment, and maintains the recovery drill register.
- **Cost & waste** layers list prices, measured consumption and invoiced spend, and prices recoverable waste.
- **Managed changes** is the approval ledger: pending, approved, applying, applied, failed, rejected and rolled-back requests.

Tab controls are permission- and capability-dependent. A read-only connection disables every write control even when the signed-in user holds the permission.

## Freshness and scope behavior

Backup Manager does **not** read Azure on page load, on tab switch, or when the scope changes. A full estate sweep is expensive, and numbers that move while an operator is working a decision are worse than numbers that are slightly old. Reading Azure happens only when **Analyze backups** is clicked.

One analysis produces the data for every tab, so the job count on the Overview is by construction the same set of rows the Job inbox lists. Until a scope has been analyzed, every tab shows the same prompt to analyze rather than silently starting a sweep.

The analysis runs on the server and survives navigation: closing the tab or moving elsewhere in the app does not abandon it, and returning reconnects to its progress. Progress is reported per phase — resolving scope, reading Resource Graph, checking for orphans, reading vault configuration, analyzing, pricing, saving — with the row count each of the nine Resource Graph sources returned. Starting an analysis for a scope that is already analyzing re-attaches to the running job instead of launching a second sweep.

Results are stored per tenant, connection and scope, and survive a restart. Row lists are bounded — 2,000 jobs, 5,000 protected items and 2,000 gaps — and a truncated section says so. The 24 most recently analyzed scopes are retained.

If **every** Resource Graph source fails — an expired token or a revoked role — the analysis is reported as failed and the previous result is kept. An empty estate would otherwise be indistinguishable from a genuine "nothing is protected" answer and would overwrite a good analysis. A partial failure still saves and is flagged.

Demo workloads are synthetic and are composed on read, so they need no analysis and offer no Analyze button.

Backup job history from Resource Graph covers a rolling window of approximately **seven days**. Longer horizons require vault diagnostics shipping to Log Analytics.

## Workflow overview

### Triage failing backups

1. Analyze the scope, then open **Job inbox**.
2. Work the failure clusters rather than individual jobs: each cluster carries the Azure error code, its cause, and the documented remediation.
3. Check **chronic failures** — items with no recent recovery point are a protection outage even when today's job succeeded.
4. Where a retry is appropriate, draft an on-demand backup; it enters the ledger as a change rather than running immediately.

### Close a protection gap

1. Open **Gaps**. Live detection and findings ingested from Backup & DR Coverage are listed separately.
2. Select the resources to protect, then choose a target vault and policy.
3. Preview. Blocked items state why — for example, cross-subscription protection is not supported, so the vault must be in the resource's subscription.
4. Submit. Each ready item becomes a pending change; nothing reaches Azure yet.

### Harden a vault

1. Open **Vaults** and review the per-vault score and its failing controls.
2. Select the controls to apply. Controls that cannot be automated safely are reported as portal-only and are never offered as an action.
3. Submit, then approve and apply from **Managed changes**.

Storage redundancy is locked by Azure once a vault holds its first protected item, so that action is withdrawn rather than offered and failed.

### Understand what backup actually costs

1. Open **Cost & waste**. The default period is the last complete month.
2. Compare the list-price estimate with invoiced spend, and read the variance.
3. Use the meter breakdown to see what is actually billed, and the per-item table for the apportioned figures.
4. Review recoverable waste, which is priced from actual spend when actuals are available and from list prices otherwise.

Changing the period or the cost type is an explicit action and fetches that period on demand.

### Read the protection flow

1. Open **Protection flow**. The default chain runs subscription → workload → resource type → policy → vault → outcome.
2. Switch the weighting between **Items** and **Cost**. The same estate answers a different question: where the machines are, versus where the money goes.
3. Click any bar or ribbon to highlight its complete paths; each node also shows its own weight.
4. Use a preset, or build a chain and save it as a named perspective for later. Perspectives are stored per browser.

Selecting a node offers the matching action — the unprotected terminal opens Gaps with those resources preselected, a vault opens its posture, a policy opens retention modelling.

## Interpretation of results

- An **orphaned** item is a protected item whose source resource no longer exists; it is still billing. Orphan detection fails open: if the resource sweep cannot run, nothing is reported as orphaned rather than everything.
- **RPO attainment** is measured against the retention tier configured in the editable reference, not an Azure setting.
- **Ransomware readiness** is a weighted score over vault controls. Controls that are portal-only are scored but never offered as an action.
- **Estimated cost** is a list price. It is not a bill, and it will usually differ from invoiced spend because it assumes a full month at the current footprint.
- **Applied** means the request completed. Only a fresh analysis proves Azure converged.

### How backup cost is attributed

Azure Cost Management attributes backup charges to the **vault**, never to the individual protected item. This was established by querying live billing data, not assumed. Per-item cost therefore cannot be read directly.

The Cost tab apportions each vault's actual spend across its items, weighting by measured consumption where Log Analytics provides it, then by estimated cost, then equally. The apportioned figures reconcile back to the vault total exactly, and each row states which basis it used. Any spend that cannot be attributed to an in-scope vault is reported as unattributed rather than being spread silently.

List prices come from the Azure Retail Prices API in the tenant's **billing currency**, so the estimate and the invoice are comparable. Protected instances are a flat monthly rate per datasource type, not a size band. Managed disks have no protected-instance meter at all — Azure Disk Backup is snapshot-billed outside the Backup service — and are priced as zero and flagged, rather than being silently under-reported.

Variance refuses to compare a partial period, such as month-to-date, or two periods in different currencies, and says which it is rather than showing a misleading delta.

## Approval, apply, and rollback

Every write drafts a managed change. Submission and approval do not touch Azure; only **Apply to Azure** does.

High-risk targets require **two distinct approvers**. The first approval records the approver and returns the change as awaiting a second; the same person cannot supply both. Such rows are excluded from bulk approval and must be approved individually.

Azure Backup writes are long-running. Apply parks the row in an `applying` state with the operation URL, and a dedicated poller drives it to applied or failed, with a 120-minute deadline. A row that is still applying is not lost if the browser closes.

Optimistic concurrency compares a hash of the target's state captured at draft time. If Azure changed in the meantime, the row is marked stale and must be re-drafted rather than forced.

Where a rollback is supported it is prepared as a new reviewed request. Rollback is not available for operations the module refuses to perform in the first place.

## Exports, evidence, and the editable reference

Protected items, jobs, policies, gaps, posture and drills each export to CSV. Export is read-only and audited.

Applying a change and recording a drill outcome both capture an Evidence Locker snapshot.

The failure knowledge base, vault checks, retention tiers, service limits and cost rates live in a versioned, editable reference document with bounded revision history. Editing requires `backup_manager.reference_write`; a revision can be restored, and the whole document can be reset to the shipped seed.

## Safety and limitations

- Restores and destructive backup operations are unavailable by design. Do not plan a recovery procedure around this module.
- Resource Graph job history is a rolling window of about seven days. Absence of a job in this view is not proof it never ran.
- A collector that fails records an error and degrades one section. Treat an incomplete analysis as incomplete evidence, not as a clean result.
- Truncated sections are flagged. Do not read a bounded list as a complete inventory.
- Cost figures are apportioned, not per-item billing records. They reconcile to the vault total, which is the level Azure actually bills.
- A vault's storage redundancy cannot be changed after its first protected item; the module withdraws the action rather than failing the apply.
- Backup Reports require vault diagnostics and a queryable workspace. A pasted-token connection cannot read Log Analytics.
- Saved Protection flow perspectives are stored per browser. They do not follow a user to another machine and cannot be shared.
- Approving is not applying, and applying is not converging. Verify against Azure after apply.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| Every tab asks me to analyze | This is intended. The module never reads Azure on its own. Click **Analyze backups**. |
| The analysis failed and my old data is still shown | Every Resource Graph source failed, most often an expired or revoked credential. The previous analysis was deliberately kept. Refresh the connection credential and analyze again. |
| Analysis reports zero of everything but no error | Check the connection's Reader access at the selected scope and the reported `errors`. A permission gap degrades a section rather than failing the sweep. |
| A tab shows stale numbers | Nothing refreshes automatically. Click **Analyze again**; the header shows when the current analysis was taken. |
| Cost shows an estimate but no actuals | The connection lacks Cost Management query rights on the in-scope subscriptions, or the period has no billed backup usage. The reported reason states which. |
| Actual spend and the estimate disagree sharply | Expected. The estimate assumes a full month at the current footprint; a vault populated part-way through the month bills less. Confirm with the meter breakdown. |
| Per-item cost looks approximate | It is apportioned. Azure bills backup to the vault, not the item. The rows reconcile to the vault total exactly and each states its basis. |
| Backup Reports are unavailable | Enable vault diagnostics to a Log Analytics workspace, and use a service-principal or managed-identity connection — pasted tokens cannot query Log Analytics. |
| A write button is disabled | Check the specific product permission, the connection's `read_only` state, and the capability matrix. |
| A change is stuck in **applying** | Azure Backup writes are long-running. The poller has a 120-minute deadline; after that the row is marked timed out and must be re-drafted. |
| A change is marked **stale** | Azure changed after the request was drafted. Analyze again and create a new request instead of forcing the original payload. |
| I approved a change but it will not apply | It is a high-risk target requiring two distinct approvers. A second, different approver must approve it, and it cannot be approved in bulk. |
| Restore is not offered anywhere | Intentional and permanent. Perform restores in the Azure portal under the owning team's change control. |
| A gap cannot be remediated | The preview states why. The most common cause is a target vault in a different subscription from the resource. |
| A vault redundancy action disappeared | The vault already holds a protected item, after which Azure locks redundancy. |
| Saved flow perspectives vanished | They are stored per browser. A different browser, machine, or a cleared cache has no access to them. |

## Related pages

- [Backup & DR Coverage]({{ site.baseurl }}/user-guide/coverage/backup-dr-coverage/)
- [Alerts Manager]({{ site.baseurl }}/user-guide/coverage/alerts-manager/)
- [Connection Capability]({{ site.baseurl }}/user-guide/coverage/connection-capability/)
