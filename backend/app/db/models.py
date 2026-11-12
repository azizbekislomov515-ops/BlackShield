"""Import every ORM model here so Alembic autogenerate sees it in Base.metadata."""

from app.db.base import Base

__all__ = ["Base"]
