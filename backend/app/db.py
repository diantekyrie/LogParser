from __future__ import annotations

from sqlmodel import SQLModel, Session, create_engine

DATABASE_URL = "sqlite:///./parsecat.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def init_db() -> None:
    # Import models so their tables register with SQLModel.metadata before create_all.
    from app.models import db_models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
