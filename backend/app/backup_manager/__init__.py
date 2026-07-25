"""Backup Manager — the approval-gated management plane for Azure Backup and Site Recovery.

Sibling of :mod:`app.alerts_manager`.  Where :mod:`app.backupdr` is the read-only WAF
coverage *detector*, this package is the operational plane: live protection inventory, the
backup job inbox, policy and vault administration, DR readiness, and an encrypted managed
change ledger whose Azure writes are long-running operations tracked by a dedicated poller.

Deliberately **not** implemented (product decision, enforced in :mod:`app.backup_manager.changes`):

* restores of any kind — the module never calls a restore API;
* destructive backup operations (delete backup data, purge soft-deleted items, lock vault
  immutability, disable soft delete). These are refused with portal guidance instead.
"""
