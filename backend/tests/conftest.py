"""Shared test fixtures.

Database tests run against the real Postgres service (the same one
docker-compose wires up for the api container) rather than a separate test
database, but every test gets full isolation: each test opens its own
connection, starts an outer transaction, and binds its Session to that
connection with join_transaction_mode="create_savepoint" -- so even when
application code calls session.commit() (as the CRUD layer does), that
only releases a SAVEPOINT, never the outer transaction. Rolling back the
outer transaction at teardown undoes everything the test did, so nothing
ever lands in real dev data.
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

import app.models  # noqa: F401 -- populates Base.metadata before create_all
from app.core.config import get_settings
from app.core.db import Base, get_db
from app.main import app as fastapi_app


@pytest.fixture(scope="session")
def db_engine() -> Generator[Engine, None, None]:
    engine = create_engine(get_settings().database_url)
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Generator[Session, None, None]:
    connection = db_engine.connect()
    outer_transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    yield session

    session.close()
    outer_transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        yield db_session

    fastapi_app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.clear()
