from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ORM models. Import models in app/db/models.py for Alembic."""
