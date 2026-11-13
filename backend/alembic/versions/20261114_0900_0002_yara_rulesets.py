"""yara_rulesets

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-14 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "yara_rulesets",
        sa.Column("version", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("rules", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version > 0", name=op.f("ck_yara_rulesets_version_positive")),
        sa.PrimaryKeyConstraint("version", name=op.f("pk_yara_rulesets")),
    )


def downgrade() -> None:
    op.drop_table("yara_rulesets")
