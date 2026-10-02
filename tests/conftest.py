from collections.abc import AsyncGenerator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.config import settings
from app.database.database import Base
from app.database.session import ResilientRedisClient, get_db, get_redis
from app.main import app
from app.middleware import rate_limit as rate_limit_module

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create a fresh in-memory async SQLite database engine for each test."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated SQLAlchemy AsyncSession per test."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def test_redis() -> AsyncGenerator[ResilientRedisClient, None]:
    """Provide a fresh, loop-bound Redis client for each test.

    The client is created *inside* the test's own pytest-asyncio event loop and is
    closed again before that loop is destroyed. The module-level production client
    (``app.database.session.redis_client``) is never used here: it is built once at
    import time, so its pooled connection would stay bound to the event loop of the
    first test that touched it and raise
    ``RuntimeError: ... got Future ... attached to a different loop`` in every test
    after that.
    """
    test_redis_client = ResilientRedisClient(settings.REDIS_URL)

    await test_redis_client.flushdb()

    try:
        yield test_redis_client
    finally:
        await test_redis_client.flushdb()
        await test_redis_client.close()


@pytest_asyncio.fixture(scope="function")
async def client(
    db_session: AsyncSession,
    test_redis: ResilientRedisClient,
) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTPX AsyncClient wired to the FastAPI app with test dependencies."""
    settings.RATE_LIMIT_ENABLED = True
    settings.RATE_LIMIT_REQUESTS = 5
    settings.RATE_LIMIT_WINDOW_SECONDS = 60

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    async def override_get_redis() -> ResilientRedisClient:
        return test_redis

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    # RateLimitMiddleware resolves its client from the module global, so point that
    # reference at this test's client for the duration of the test; without it the
    # middleware would still use the import-time client and re-trigger the cross-loop
    # reuse this fixture exists to prevent. Production wiring is restored afterwards.
    original_middleware_redis = rate_limit_module.redis_client
    rate_limit_module.redis_client = test_redis

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac
    finally:
        rate_limit_module.redis_client = original_middleware_redis
        app.dependency_overrides.clear()
