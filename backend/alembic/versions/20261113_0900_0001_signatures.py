"""signatures and signature_versions

Revision ID: 0001
Revises:
Create Date: 2026-11-13 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "signatures",
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("algorithm", sa.String(length=8), nullable=False),
        sa.Column("family", sa.String(length=128), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("removed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint(
            "algorithm IN ('md5', 'sha1', 'sha256')", name=op.f("ck_signatures_algorithm")
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_signatures_severity"),
        ),
        sa.PrimaryKeyConstraint("hash", name=op.f("pk_signatures")),
    )
    op.create_index("ix_signatures_version_hash", "signatures", ["version", "hash"], unique=False)

    op.create_table(
        "signature_versions",
        sa.Column("version", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("version", name=op.f("pk_signature_versions")),
    )


def downgrade() -> None:
    op.drop_table("signature_versions")
    op.drop_index("ix_signatures_version_hash", table_name="signatures")
    op.drop_table("signatures")
