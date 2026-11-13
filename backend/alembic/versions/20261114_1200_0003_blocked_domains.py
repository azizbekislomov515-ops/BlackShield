"""blocked_domains and domain_versions

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-14 12:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "blocked_domains",
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("removed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint(
            "category IN ('malware', 'phishing')", name=op.f("ck_blocked_domains_category")
        ),
        sa.PrimaryKeyConstraint("domain", name=op.f("pk_blocked_domains")),
    )
    op.create_index(
        "ix_blocked_domains_version_domain", "blocked_domains", ["version", "domain"], unique=False
    )
    op.create_index("ix_blocked_domains_source", "blocked_domains", ["source"], unique=False)

    op.create_table(
        "domain_versions",
        sa.Column("version", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("version", name=op.f("pk_domain_versions")),
    )


def downgrade() -> None:
    op.drop_table("domain_versions")
    op.drop_index("ix_blocked_domains_source", table_name="blocked_domains")
    op.drop_index("ix_blocked_domains_version_domain", table_name="blocked_domains")
    op.drop_table("blocked_domains")
