"""Built-in Backup Manager baselines: failure knowledge base, posture checks, limits, rates.

Everything here is a *seed*.  :mod:`app.backup_manager.reference` persists an editable,
versioned copy under ``backend/.data/`` so an operator can correct a remediation hint, adjust
a compliance retention floor, or update a price without a code change — the same pattern the
AMBA / Telemetry / Backup-DR reference sets use.

Prices and service limits are deliberately marked as estimates with an ``as_of`` date.  They
drive planning views, never billing.
"""
from __future__ import annotations

from typing import Any

SEED_VERSION = 1

# --------------------------------------------------------------------------- failure KB
# Azure Backup surfaces a stable error code on every failed job.  Mapping code -> cause ->
# remediation is what turns a wall of red rows into an actionable queue.  ``auto_fix`` marks
# the codes where re-running the backup after the stated fix is the correct next step, which
# is the only automated action Backup Manager offers (it never restores or deletes).
FAILURE_KB: list[dict[str, Any]] = [
    # -- Azure VM / guest agent ------------------------------------------------------
    {
        "code": "UserErrorGuestAgentStatusUnavailable",
        "title": "VM agent is not responding",
        "category": "guest_agent",
        "severity": "error",
        "cause": "The Azure VM guest agent is missing, stopped, or out of date, so the backup extension cannot be reached.",
        "remediation": "Confirm the VM is running, then restart the Azure guest agent (waagent on Linux, WindowsAzureGuestAgent service on Windows) and upgrade it to the latest version.",
        "auto_fix": True,
    },
    {
        "code": "GuestAgentSnapshotTaskStatusError",
        "title": "Guest agent could not report snapshot status",
        "category": "guest_agent",
        "severity": "error",
        "cause": "The guest agent could not communicate the snapshot task result, usually due to blocked outbound access to Azure storage or a stalled agent.",
        "remediation": "Allow outbound HTTPS to Azure Storage and the AzureBackup service tag (or add a private endpoint), then restart the guest agent and retry.",
        "auto_fix": True,
    },
    {
        "code": "ExtensionSnapshotFailedNoSecureNetwork",
        "title": "Snapshot blocked by network restrictions",
        "category": "network",
        "severity": "error",
        "cause": "The backup extension could not establish a secure channel to the backup service because outbound traffic is blocked by an NSG, firewall, or proxy.",
        "remediation": "Permit outbound 443 to the AzureBackup, Storage, and AzureActiveDirectory service tags, or deploy a private endpoint on the Recovery Services vault.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorVmNotInDesirableState",
        "title": "VM is not in a state that allows backup",
        "category": "resource_state",
        "severity": "error",
        "cause": "The virtual machine was deallocated, failed provisioning, or was mid-operation when the backup ran.",
        "remediation": "Bring the VM to a Running or Stopped (allocated) state and clear any failed provisioning state, then trigger an on-demand backup.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorPreCheckVmNotInDesirableState",
        "title": "Pre-check found the VM in an unhealthy state",
        "category": "resource_state",
        "severity": "warning",
        "cause": "The backup pre-check detected a VM configuration issue (deallocated, failed extension, unsupported state).",
        "remediation": "Resolve the pre-check warning shown on the VM's Backup blade, then retry the backup.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorCrpReportedUserErrorForVMSnapshot",
        "title": "Compute platform rejected the snapshot",
        "category": "resource_state",
        "severity": "error",
        "cause": "The compute resource provider refused the snapshot, commonly because of an in-progress disk operation, an unsupported disk configuration, or an attached disk in a failed state.",
        "remediation": "Wait for any in-flight disk operation to finish, verify every attached disk is healthy and supported, then retry.",
        "auto_fix": True,
    },
    {
        "code": "ExtensionStuckInDeletionState",
        "title": "Backup extension stuck deleting",
        "category": "extension",
        "severity": "error",
        "cause": "A previous extension operation left the VMSnapshot extension in a transient deletion state.",
        "remediation": "Remove the VMSnapshot / VMSnapshotLinux extension from the VM, allow it to be reinstalled by the next backup, then retry.",
        "auto_fix": True,
    },
    {
        "code": "ExtensionStateInvalid",
        "title": "Backup extension is in an invalid state",
        "category": "extension",
        "severity": "error",
        "cause": "The snapshot extension is present but reporting an invalid or failed provisioning state.",
        "remediation": "Uninstall the VMSnapshot extension and run an on-demand backup so it is redeployed cleanly.",
        "auto_fix": True,
    },
    {
        "code": "ExtensionConfigParsingFailure",
        "title": "Extension configuration could not be parsed",
        "category": "extension",
        "severity": "error",
        "cause": "Permissions on the VM's extension configuration directory prevent the backup extension from reading its settings.",
        "remediation": "Reset permissions on the extension config folder (Windows: C:\\Packages\\Plugins; Linux: /var/lib/waagent) and retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorFsFreezeFailed",
        "title": "Linux file-system freeze failed",
        "category": "guest_os",
        "severity": "error",
        "cause": "The guest could not freeze one or more mounted file systems, so an application-consistent snapshot was not possible.",
        "remediation": "Unmount or exclude problematic mounts (duplicate mount points, network shares), verify no long-running I/O holds the file system, then retry.",
        "auto_fix": True,
    },
    {
        "code": "ExtensionFailedVssWriterInBadState",
        "title": "Windows VSS writer in a bad state",
        "category": "guest_os",
        "severity": "error",
        "cause": "One or more VSS writers were failed or unstable when the snapshot was requested.",
        "remediation": "Run `vssadmin list writers`, restart the services owning any failed writer (or reboot the VM), then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorKeyvaultPermissionsNotConfigured",
        "title": "Vault cannot read the disk-encryption key",
        "category": "encryption",
        "severity": "error",
        "cause": "The Recovery Services vault identity lacks Key Vault permissions for an Azure Disk Encryption protected VM.",
        "remediation": "Grant the vault's managed identity get/list on keys and secrets in the Key Vault holding the BEK/KEK, then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorKeyVaultNotFound",
        "title": "Encryption key vault not found",
        "category": "encryption",
        "severity": "error",
        "cause": "The Key Vault referenced by the encrypted VM no longer exists or was moved.",
        "remediation": "Restore or recreate the Key Vault and its BEK/KEK, or re-encrypt the VM against a reachable Key Vault.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorBackupOperationFailedAsDiskExcluded",
        "title": "Disk exclusion left nothing to back up",
        "category": "configuration",
        "severity": "warning",
        "cause": "The selective-disk configuration excluded every disk, or referenced a LUN that no longer exists.",
        "remediation": "Review the selective-disk backup settings on the protected item and include at least the OS disk.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorInvalidDiskLunList",
        "title": "Selective-disk LUN list is invalid",
        "category": "configuration",
        "severity": "error",
        "cause": "A LUN listed in the selective-disk configuration is not attached to the VM any more.",
        "remediation": "Update the disk inclusion/exclusion list on the protected item to match the current disk layout.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorRequestDisallowedByPolicy",
        "title": "Azure Policy blocked the backup operation",
        "category": "governance",
        "severity": "error",
        "cause": "A deny policy assignment blocked a resource the backup service needed to create (typically the restore-point collection or a snapshot).",
        "remediation": "Review the deny assignment named in the error and add an exemption for the backup service's resource group.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorSubscriptionStateNotRegistered",
        "title": "Subscription is not registered for backup",
        "category": "governance",
        "severity": "error",
        "cause": "The Microsoft.RecoveryServices (or Microsoft.DataProtection) resource provider is not registered on the subscription.",
        "remediation": "Register the required resource provider on the subscription, then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorRpCollectionLimitReached",
        "title": "Restore-point collection limit reached",
        "category": "capacity",
        "severity": "error",
        "cause": "The instant-restore snapshot limit for the VM was reached, usually because older restore points were not cleaned up.",
        "remediation": "Lower the instant-restore retention on the policy or clear stale restore-point collections, then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorBackupOperationInProgress",
        "title": "Another backup is already running",
        "category": "transient",
        "severity": "info",
        "cause": "A backup or restore job for the same item was still running when this one was queued.",
        "remediation": "No action required — wait for the in-flight job to finish. Persistent overlap means the job duration exceeds the schedule interval.",
        "auto_fix": False,
    },
    # -- SQL / SAP HANA in Azure VM ---------------------------------------------------
    {
        "code": "UserErrorSQLNoSysadminMembership",
        "title": "Backup identity lacks SQL sysadmin",
        "category": "workload",
        "severity": "error",
        "cause": "The NT Service\\AzureWLBackupPluginSvc account is not a sysadmin on the SQL instance.",
        "remediation": "Grant sysadmin to the backup plugin account on the SQL instance (or re-run the SQL discovery/enable flow), then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorSQLPodNotReachable",
        "title": "SQL instance unreachable from the backup agent",
        "category": "workload",
        "severity": "error",
        "cause": "The workload backup agent could not connect to the SQL instance (stopped service, network, or authentication).",
        "remediation": "Confirm the SQL service is running and reachable from the VM, then re-run discovery and retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorSQLLSNValidationFailure",
        "title": "SQL log chain is broken",
        "category": "workload",
        "severity": "error",
        "cause": "Another backup product truncated the SQL log chain, so the log backup LSN no longer matches.",
        "remediation": "Stop competing SQL backup products or switch them to COPY_ONLY, then trigger a full backup to re-seed the chain.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorAutoProtectionCancelledAsDBBeingProtected",
        "title": "Auto-protection skipped an already-protected database",
        "category": "workload",
        "severity": "info",
        "cause": "Auto-protection tried to enrol a database that is already protected by another policy.",
        "remediation": "No action required, unless the database should move to the auto-protection policy.",
        "auto_fix": False,
    },
    # -- Azure Files -------------------------------------------------------------------
    {
        "code": "UserErrorAzureFileShareNotFound",
        "title": "File share no longer exists",
        "category": "resource_state",
        "severity": "error",
        "cause": "The protected Azure file share was deleted or renamed.",
        "remediation": "Recreate the share, or stop protection for the item if the share was retired deliberately (use the Azure portal for data deletion).",
        "auto_fix": False,
    },
    {
        "code": "UserErrorStorageAccountNotFound",
        "title": "Storage account no longer exists",
        "category": "resource_state",
        "severity": "error",
        "cause": "The storage account holding the protected share was deleted or moved to another subscription.",
        "remediation": "Restore or re-register the storage account, or retire the protected item in the Azure portal.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorFileShareSnapshotLimitReached",
        "title": "File share snapshot limit reached",
        "category": "capacity",
        "severity": "error",
        "cause": "The share reached the maximum number of snapshots, so no new recovery point could be created.",
        "remediation": "Delete unmanaged manual snapshots on the share or reduce policy retention, then retry.",
        "auto_fix": True,
    },
    # -- Blobs / disks / PostgreSQL (Backup vault) --------------------------------------
    {
        "code": "UserErrorMaxRestorePointCount",
        "title": "Maximum restore points reached",
        "category": "capacity",
        "severity": "error",
        "cause": "The datasource already holds the maximum number of restore points allowed by the service.",
        "remediation": "Reduce the retention rule on the backup policy so older recovery points age out, then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorMissingRoleAssignment",
        "title": "Backup vault identity is missing a role assignment",
        "category": "rbac",
        "severity": "error",
        "cause": "The Backup vault's managed identity lacks the role required on the datasource (for example Disk Snapshot Contributor, Storage Account Backup Contributor, or Reader).",
        "remediation": "Grant the vault identity the role listed in the error on the datasource and its snapshot resource group, then retry.",
        "auto_fix": True,
    },
    {
        "code": "UserErrorDatasourceUnavailable",
        "title": "Datasource is unavailable",
        "category": "resource_state",
        "severity": "error",
        "cause": "The protected datasource is stopped, deleted, or otherwise unreachable by the backup service.",
        "remediation": "Bring the datasource back online, or retire the backup instance in the Azure portal if it was decommissioned.",
        "auto_fix": False,
    },
    {
        "code": "UserErrorDataSourceNotSupported",
        "title": "Datasource configuration is not supported",
        "category": "configuration",
        "severity": "error",
        "cause": "The datasource uses a SKU, size, or feature combination the backup service does not support.",
        "remediation": "Check the supported-scenarios matrix for this datasource type and adjust the resource, or use a native protection mechanism instead.",
        "auto_fix": False,
    },
    # -- AKS -----------------------------------------------------------------------------
    {
        "code": "UserErrorBackupExtensionNotPresent",
        "title": "AKS backup extension not installed",
        "category": "extension",
        "severity": "error",
        "cause": "The Backup extension is missing from the AKS cluster, or trusted access to the Backup vault was removed.",
        "remediation": "Install the Backup extension on the cluster and re-enable the trusted-access role binding to the Backup vault, then retry.",
        "auto_fix": True,
    },
    {
        "code": "AksClusterUnreachable",
        "title": "AKS cluster is unreachable",
        "category": "network",
        "severity": "error",
        "cause": "The backup service could not reach the cluster API server (stopped cluster, private cluster without trusted access, or network restriction).",
        "remediation": "Start the cluster, verify the API server allowlist, and re-establish trusted access to the Backup vault.",
        "auto_fix": True,
    },
    # -- Site Recovery ---------------------------------------------------------------------
    {
        "code": "ReplicationHealthCritical",
        "title": "Replication health is critical",
        "category": "site_recovery",
        "severity": "critical",
        "cause": "Site Recovery reports a critical replication error for the protected item, so the recovery point is not usable.",
        "remediation": "Open the replicated item's health errors, resolve the underlying agent/network/disk issue, and confirm RPO returns within target.",
        "auto_fix": False,
    },
]

# --------------------------------------------------------------------------- posture checks
# Vault-level ransomware / recoverability controls.  ``weight`` feeds the readiness score;
# ``portal_only`` marks controls Backup Manager will never change automatically (irreversible
# or data-destructive), which the UI renders as guidance instead of an action.
VAULT_CHECKS: list[dict[str, Any]] = [
    {
        "id": "soft_delete",
        "label": "Soft delete enabled",
        "weight": 20,
        "severity": "critical",
        "why": "Soft delete is the primary defence against an attacker (or a mistake) permanently destroying backup data.",
        "manageable": True,
        "portal_only": False,
    },
    {
        "id": "soft_delete_retention",
        "label": "Soft-delete retention >= 14 days",
        "weight": 8,
        "severity": "warning",
        "why": "A short undelete window can expire before anyone notices the deletion.",
        "manageable": True,
        "portal_only": False,
    },
    {
        "id": "immutability",
        "label": "Immutability configured",
        "weight": 12,
        "severity": "warning",
        "why": "Immutable vaults stop retention being shortened or recovery points being deleted early.",
        "manageable": False,
        "portal_only": True,
        "portal_reason": "Locking a vault's immutability is irreversible. Backup Manager reports the state but never changes it — use the Azure portal.",
    },
    {
        "id": "mua",
        "label": "Multi-user authorisation (Resource Guard)",
        "weight": 15,
        "severity": "warning",
        "why": "MUA forces a second identity to approve destructive vault operations.",
        "manageable": False,
        "portal_only": True,
        "portal_reason": "Associating a Resource Guard changes who can operate the vault — configure it in the Azure portal with the guard owner.",
    },
    {
        "id": "redundancy",
        "label": "Geo- or zone-redundant backup storage",
        "weight": 12,
        "severity": "warning",
        "why": "Locally redundant backup storage does not survive a zone or regional failure.",
        "manageable": True,
        "portal_only": False,
        "note": "Storage redundancy can only be changed before the first item is protected.",
    },
    {
        "id": "cross_region_restore",
        "label": "Cross Region Restore enabled",
        "weight": 8,
        "severity": "warning",
        "why": "Without CRR a regional outage leaves geo-redundant backup data unrestorable until the region returns.",
        "manageable": True,
        "portal_only": False,
    },
    {
        "id": "cmk",
        "label": "Customer-managed key encryption",
        "weight": 6,
        "severity": "info",
        "why": "CMK gives you control of the key protecting backup data at rest.",
        "manageable": False,
        "portal_only": True,
        "portal_reason": "Enabling CMK requires key-vault access policies and cannot be safely rolled back — configure it in the Azure portal.",
    },
    {
        "id": "private_endpoint",
        "label": "Private endpoint / public access restricted",
        "weight": 6,
        "severity": "info",
        "why": "Private connectivity keeps backup traffic off the public internet.",
        "manageable": False,
        "portal_only": True,
        "portal_reason": "Private endpoint wiring involves DNS and networking outside this module's blast radius.",
    },
    {
        "id": "monitor_alerts",
        "label": "Built-in Azure Monitor alerts enabled",
        "weight": 8,
        "severity": "warning",
        "why": "Without built-in alerts a silent backup failure can persist for weeks.",
        "manageable": True,
        "portal_only": False,
    },
    {
        "id": "diagnostics",
        "label": "Diagnostic settings send backup reports to Log Analytics",
        "weight": 5,
        "severity": "info",
        "why": "Vault diagnostics unlock long-horizon job history, storage consumption, and cost reporting.",
        "manageable": True,
        "portal_only": False,
    },
]

# --------------------------------------------------------------------------- compliance floors
# Minimum acceptable protection per workload criticality tier.  Purely a planning baseline —
# operators are expected to edit these to match their own BCDR standard.
TIERS: list[dict[str, Any]] = [
    {"id": "mission_critical", "label": "Mission critical", "rpo_hours": 4, "retention_days": 90, "require_offsite": True, "drill_days": 90},
    {"id": "business_critical", "label": "Business critical", "rpo_hours": 12, "retention_days": 60, "require_offsite": True, "drill_days": 180},
    {"id": "standard", "label": "Standard", "rpo_hours": 24, "retention_days": 30, "require_offsite": False, "drill_days": 365},
    {"id": "low", "label": "Low", "rpo_hours": 72, "retention_days": 14, "require_offsite": False, "drill_days": 0},
]
DEFAULT_TIER = "standard"

# --------------------------------------------------------------------------- service limits
LIMITS: dict[str, Any] = {
    "rsv_protected_items_per_vault": 2000,
    "rsv_policies_per_vault": 200,
    "rsv_vaults_per_subscription_per_region": 500,
    "backup_vault_instances_per_vault": 5000,
    "backup_vaults_per_subscription_per_region": 500,
    "warn_at_pct": 80,
    "source": "Azure Backup published service limits — edit if Microsoft revises them.",
}

# --------------------------------------------------------------------------- cost model
# Planning estimates only. Protected-instance pricing is tiered by source size; backup storage
# is charged per consumed GB by redundancy.  All values are list prices in USD.
COST_RATES: dict[str, Any] = {
    "currency": "USD",
    "as_of": "2026-07",
    "estimate_only": True,
    "source": "Seeded fallback list prices. Live rates come from the Azure Retail Prices API.",
    # Region whose list prices to quote. Empty means "infer from where the vaults live".
    "price_region": "",
    "protected_instance": {
        "under_50gb": 5.0,
        "50_to_500gb": 10.0,
        "per_additional_500gb": 10.0,
    },
    "storage_gb_month": {
        "lrs": 0.0224,
        "zrs": 0.0280,
        "grs": 0.0448,
        "archive_lrs": 0.0022,
        "archive_grs": 0.0044,
    },
    "snapshot_gb_month": 0.05,
    "site_recovery_instance_month": 25.0,
    "assumed_instance_gb": 200.0,
}

# --------------------------------------------------------------------------- auto-protect policy
# Built-in Azure Policy definitions used for at-scale onboarding.  Definition ids are tenant
# independent (they live under the built-in provider path).
AUTO_PROTECT_POLICIES: list[dict[str, Any]] = [
    {
        "id": "vm_backup_by_tag",
        "label": "Configure backup on VMs with a given tag to an existing Recovery Services vault",
        "definition_id": "/providers/Microsoft.Authorization/policyDefinitions/09ce66bc-1220-4153-8104-e3f51c936913",
        "effect": "DeployIfNotExists",
        "datasource": "microsoft.compute/virtualmachines",
        "parameters": ["vaultLocation", "backupPolicyId", "inclusionTagName", "inclusionTagValue"],
    },
    {
        "id": "vm_backup_audit",
        "label": "Audit: Azure Backup should be enabled for Virtual Machines",
        "definition_id": "/providers/Microsoft.Authorization/policyDefinitions/013e242c-8828-4970-87b3-ab247555486d",
        "effect": "AuditIfNotExists",
        "datasource": "microsoft.compute/virtualmachines",
        "parameters": [],
    },
]

# --------------------------------------------------------------------------- refusals
# Operations Backup Manager will never perform. Surfaced to the UI so the reason is explicit
# rather than the feature simply appearing to be missing.
PORTAL_ONLY_OPERATIONS: list[dict[str, str]] = [
    {
        "id": "restore",
        "label": "Restore data",
        "reason": "Backup Manager never restores data. Restores are performed in the Azure portal by the team that owns the workload, with their own change control.",
    },
    {
        "id": "delete_backup_data",
        "label": "Stop protection and delete backup data",
        "reason": "Deleting recovery points is irreversible and cannot be rolled back. Backup Manager can stop protection while retaining data; permanent deletion must be done in the Azure portal.",
    },
    {
        "id": "purge_soft_deleted",
        "label": "Permanently purge soft-deleted items",
        "reason": "Purging destroys the last copy of the data. Use the Azure portal.",
    },
    {
        "id": "lock_immutability",
        "label": "Lock vault immutability",
        "reason": "A locked immutable vault can never be unlocked. Backup Manager reports the state but will not set it.",
    },
    {
        "id": "disable_soft_delete",
        "label": "Disable soft delete",
        "reason": "Disabling soft delete removes the main ransomware safeguard. Backup Manager can only strengthen it.",
    },
    {
        "id": "unregister_container",
        "label": "Unregister a protection container",
        "reason": "Unregistering can orphan backup data. Use the Azure portal.",
    },
]


def seed_reference() -> dict[str, Any]:
    """The complete built-in reference document persisted on first load."""
    return {
        "seed_version": SEED_VERSION,
        "failure_kb": [dict(item) for item in FAILURE_KB],
        "vault_checks": [dict(item) for item in VAULT_CHECKS],
        "tiers": [dict(item) for item in TIERS],
        "default_tier": DEFAULT_TIER,
        "limits": dict(LIMITS),
        "cost_rates": {
            **COST_RATES,
            "protected_instance": dict(COST_RATES["protected_instance"]),
            "storage_gb_month": dict(COST_RATES["storage_gb_month"]),
        },
        "auto_protect_policies": [dict(item) for item in AUTO_PROTECT_POLICIES],
        "sla": {
            "job_sla_hours": 24,
            "chronic_failure_days": 3,
            "stale_recovery_point_hours": 36,
            "drill_stale_days": 180,
        },
    }
