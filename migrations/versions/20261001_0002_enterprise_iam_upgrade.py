"""enterprise iam upgrade

Revision ID: 20261001_0002
Revises: 20261001_0001
Create Date: 2026-10-01 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20261001_0002"
down_revision: Union[str, None] = "20261001_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Upgrade users table with account lockout & login tracking columns
    op.add_column(
        "users",
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. Upgrade audit_logs table with event_type, description, user_agent, and JSON metadata
    op.add_column(
        "audit_logs",
        sa.Column(
            "event_type",
            sa.String(length=100),
            nullable=False,
            server_default=sa.text("'SECURITY_EVENT'"),
        ),
    )
    op.add_column(
        "audit_logs",
        sa.Column("description", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("user_agent", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("metadata", sa.JSON(), nullable=True),
    )
    op.create_index(op.f("ix_audit_logs_event_type"), "audit_logs", ["event_type"], unique=False)

    # 3. Create sessions table
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("session_token_hash", sa.String(length=255), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=True),
        sa.Column("refresh_jti", sa.String(length=64), nullable=True),
        sa.Column(
            "device_name",
            sa.String(length=255),
            nullable=False,
            server_default=sa.text("'Chrome Windows'"),
        ),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column(
            "last_activity",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
    )
    op.create_index(op.f("ix_sessions_id"), "sessions", ["id"], unique=False)
    op.create_index(op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False)
    op.create_index(
        op.f("ix_sessions_session_token_hash"),
        "sessions",
        ["session_token_hash"],
        unique=True,
    )
    op.create_index(op.f("ix_sessions_jti"), "sessions", ["jti"], unique=False)
    op.create_index(op.f("ix_sessions_refresh_jti"), "sessions", ["refresh_jti"], unique=False)

    # 4. Create email_verifications table
    op.create_table(
        "email_verifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_email_verifications_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_verifications")),
    )
    op.create_index(op.f("ix_email_verifications_id"), "email_verifications", ["id"], unique=False)
    op.create_index(
        op.f("ix_email_verifications_user_id"),
        "email_verifications",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_email_verifications_token_hash"),
        "email_verifications",
        ["token_hash"],
        unique=True,
    )

    # 5. Create password_reset_tokens table
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_password_reset_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_password_reset_tokens")),
    )
    op.create_index(
        op.f("ix_password_reset_tokens_id"),
        "password_reset_tokens",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_password_reset_tokens_user_id"),
        "password_reset_tokens",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_password_reset_tokens_token_hash"),
        "password_reset_tokens",
        ["token_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_password_reset_tokens_token_hash"),
        table_name="password_reset_tokens",
    )
    op.drop_index(op.f("ix_password_reset_tokens_user_id"), table_name="password_reset_tokens")
    op.drop_index(op.f("ix_password_reset_tokens_id"), table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")

    op.drop_index(op.f("ix_email_verifications_token_hash"), table_name="email_verifications")
    op.drop_index(op.f("ix_email_verifications_user_id"), table_name="email_verifications")
    op.drop_index(op.f("ix_email_verifications_id"), table_name="email_verifications")
    op.drop_table("email_verifications")

    op.drop_index(op.f("ix_sessions_refresh_jti"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_jti"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_session_token_hash"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_user_id"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_id"), table_name="sessions")
    op.drop_table("sessions")

    op.drop_index(op.f("ix_audit_logs_event_type"), table_name="audit_logs")
    op.drop_column("audit_logs", "metadata")
    op.drop_column("audit_logs", "user_agent")
    op.drop_column("audit_logs", "description")
    op.drop_column("audit_logs", "event_type")

    op.drop_column("users", "last_login_at")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
