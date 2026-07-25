"""add Backup Manager change ledger and drill register

Revision ID: 0004_backup_manager
Revises: 0003_alerts_manager_changes
Create Date: 2026-07-25
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_backup_manager"
down_revision: str | None = "0003_alerts_manager_changes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "backup_manager_changes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("connection_id", sa.String(36), nullable=False),
        sa.Column("target_type", sa.String(40), nullable=False),
        sa.Column("target_id", sa.String(1024), nullable=False),
        sa.Column("operation", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("risk", sa.String(16), nullable=False),
        sa.Column("summary_json", sa.JSON(), nullable=False),
        sa.Column("desired_encrypted", sa.Text(), nullable=False),
        sa.Column("before_encrypted", sa.Text(), nullable=False),
        sa.Column("after_encrypted", sa.Text(), nullable=False),
        sa.Column("expected_state_hash", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("requires_dual_approval", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("second_approver", sa.String(128), nullable=True),
        sa.Column("second_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_by", sa.String(128), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("rollback_of", sa.String(36), nullable=True),
        sa.Column("evidence_id", sa.String(36), nullable=True),
        sa.Column("plan_id", sa.String(36), nullable=True),
        sa.Column("depends_on", sa.JSON(), nullable=False),
        sa.Column("operation_url", sa.Text(), nullable=True),
        sa.Column("azure_job_id", sa.String(1024), nullable=True),
        sa.Column("poll_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("poll_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("poll_deadline", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_backup_manager_changes_tenant_id", "backup_manager_changes", ["tenant_id"])
    op.create_index("ix_backup_manager_changes_connection_id", "backup_manager_changes", ["connection_id"])
    op.create_index("ix_backup_manager_changes_target_id", "backup_manager_changes", ["target_id"])
    op.create_index("ix_backup_manager_changes_status", "backup_manager_changes", ["status"])
    op.create_index("ix_backup_manager_changes_rollback_of", "backup_manager_changes", ["rollback_of"])
    op.create_index("ix_backup_manager_changes_plan_id", "backup_manager_changes", ["plan_id"])
    op.create_index("ix_backup_changes_tenant_requested", "backup_manager_changes", ["tenant_id", "requested_at"])
    op.create_index("ix_backup_changes_tenant_status", "backup_manager_changes", ["tenant_id", "status"])
    op.create_index("ix_backup_changes_status_poll", "backup_manager_changes", ["status", "poll_after"])

    op.create_table(
        "backup_drills",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("connection_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("scope_kind", sa.String(24), nullable=False),
        sa.Column("scope_id", sa.String(256), nullable=False),
        sa.Column("target_id", sa.String(1024), nullable=False),
        sa.Column("target_name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("cadence_days", sa.Integer(), nullable=False, server_default="180"),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_by", sa.String(128), nullable=True),
        sa.Column("outcome_notes", sa.Text(), nullable=True),
        sa.Column("rto_minutes", sa.Integer(), nullable=True),
        sa.Column("change_id", sa.String(36), nullable=True),
        sa.Column("evidence_id", sa.String(36), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_backup_drills_tenant_id", "backup_drills", ["tenant_id"])
    op.create_index("ix_backup_drills_connection_id", "backup_drills", ["connection_id"])
    op.create_index("ix_backup_drills_status", "backup_drills", ["status"])
    op.create_index("ix_backup_drills_tenant_status", "backup_drills", ["tenant_id", "status"])
    op.create_index("ix_backup_drills_tenant_due", "backup_drills", ["tenant_id", "due_at"])


def downgrade() -> None:
    op.drop_table("backup_drills")
    op.drop_table("backup_manager_changes")
