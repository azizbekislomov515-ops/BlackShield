"""crash_reports

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-14 18:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "crash_reports",
        sa.Column(
            "id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), sa.Identity(), nullable=False
        ),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("app_version", sa.String(length=32), nullable=False),
        sa.Column("version_code", sa.Integer(), nullable=False),
        sa.Column("android_sdk", sa.Integer(), nullable=False),
        sa.Column("exception", sa.String(length=256), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("stack", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_crash_reports")),
    )
    op.create_index("ix_crash_reports_received_at", "crash_reports", ["received_at"], unique=False)
    op.create_index("ix_crash_reports_fingerprint", "crash_reports", ["fingerprint"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_crash_reports_fingerprint", table_name="crash_reports")
    op.drop_index("ix_crash_reports_received_at", table_name="crash_reports")
    op.drop_table("crash_reports")
