import fnmatch
import time
from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.database.database import engine

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class InMemoryRedisStore:
    """TTL-aware async in-memory Redis store used in isolated test environments or fallback."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._expires_at: dict[str, float] = {}

    def _purge_if_expired(self, key: str) -> None:
        exp = self._expires_at.get(key)
        if exp is not None and time.time() >= exp:
            self._data.pop(key, None)
            self._expires_at.pop(key, None)

    async def get(self, key: str) -> str | None:
        self._purge_if_expired(key)
        return self._data.get(key)

    async def set(
        self,
        key: str,
        value: str | int,
        ex: int | None = None,
        nx: bool = False,
    ) -> bool:
        self._purge_if_expired(key)
        if nx and key in self._data:
            return False
        self._data[key] = str(value)
        if ex is not None:
            if ex <= 0:
                self._data.pop(key, None)
                self._expires_at.pop(key, None)
                return True
            self._expires_at[key] = time.time() + ex
        else:
            self._expires_at.pop(key, None)
        return True

    async def setex(self, key: str, seconds: int, value: str | int) -> bool:
        return await self.set(key, value, ex=seconds)

    async def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            self._purge_if_expired(key)
            if key in self._data:
                self._data.pop(key, None)
                self._expires_at.pop(key, None)
                deleted += 1
        return deleted

    async def exists(self, *keys: str) -> int:
        count = 0
        for key in keys:
            self._purge_if_expired(key)
            if key in self._data:
                count += 1
        return count

    async def incr(self, key: str) -> int:
        self._purge_if_expired(key)
        current = int(self._data.get(key, "0")) + 1
        self._data[key] = str(current)
        return current

    async def expire(self, key: str, seconds: int) -> bool:
        self._purge_if_expired(key)
        if key not in self._data:
            return False
        if seconds <= 0:
            self._data.pop(key, None)
            self._expires_at.pop(key, None)
            return True
        self._expires_at[key] = time.time() + seconds
        return True

    async def ttl(self, key: str) -> int:
        self._purge_if_expired(key)
        if key not in self._data:
            return -2
        exp = self._expires_at.get(key)
        if exp is None:
            return -1
        return max(0, int(exp - time.time()))

    async def keys(self, pattern: str = "*") -> list[str]:
        all_keys = list(self._data.keys())
        for k in all_keys:
            self._purge_if_expired(k)
        return [k for k in self._data if fnmatch.fnmatch(k, pattern)]

    async def flushdb(self) -> bool:
        self._data.clear()
        self._expires_at.clear()
        return True

    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


class ResilientRedisClient:
    """Async Redis client that uses Redis 7 in production and falls back cleanly in local test runs."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._fallback = InMemoryRedisStore()
        self._use_memory_only = redis_url.startswith("memory://")
        self._client: aioredis.Redis | None = None
        if not self._use_memory_only:
            self._client = aioredis.from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )

    async def _exec(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        if self._use_memory_only or self._client is None:
            return await getattr(self._fallback, method_name)(*args, **kwargs)
        try:
            method = getattr(self._client, method_name)
            return await method(*args, **kwargs)
        except (RedisError, OSError):
            return await getattr(self._fallback, method_name)(*args, **kwargs)

    async def get(self, key: str) -> str | None:
        return await self._exec("get", key)

    async def set(
        self,
        key: str,
        value: str | int,
        ex: int | None = None,
        nx: bool = False,
    ) -> Any:
        return await self._exec("set", key, value, ex=ex, nx=nx)

    async def setex(self, key: str, seconds: int, value: str | int) -> Any:
        return await self._exec("setex", key, seconds, value)

    async def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        return int(await self._exec("delete", *keys))

    async def exists(self, *keys: str) -> int:
        if not keys:
            return 0
        return int(await self._exec("exists", *keys))

    async def incr(self, key: str) -> int:
        return int(await self._exec("incr", key))

    async def expire(self, key: str, seconds: int) -> bool:
        return bool(await self._exec("expire", key, seconds))

    async def ttl(self, key: str) -> int:
        return int(await self._exec("ttl", key))

    async def keys(self, pattern: str = "*") -> list[str]:
        result = await self._exec("keys", pattern)
        return [str(k) for k in result]

    async def flushdb(self) -> Any:
        await self._fallback.flushdb()
        return await self._exec("flushdb")

    async def ping(self) -> bool:
        return bool(await self._exec("ping"))

    async def close(self) -> None:
        """Disconnect the underlying redis.asyncio client and release its connection pool.

        Must be awaited from the same event loop that performed the Redis calls, so the
        pool's sockets are torn down while that loop is still running. If the loop has
        already been destroyed, the sockets are abandoned to the garbage collector
        instead of being touched from a dead loop (which raises
        ``RuntimeError: Event loop is closed``).
        """
        client = self._client
        if client is None:
            return
        try:
            # Explicitly release the pool: some redis-py versions only close it when
            # ``auto_close_connection_pool`` is enabled.
            await client.aclose(close_connection_pool=True)
        except TypeError:
            # Older/newer redis-py builds without the ``close_connection_pool`` keyword.
            try:
                await client.aclose()
            except (RedisError, OSError, RuntimeError):
                pass
        except (RedisError, OSError, RuntimeError):
            # Redis already gone, or the owning event loop is closed: nothing left to
            # disconnect safely, so teardown must not raise.
            pass

    async def aclose(self) -> None:
        """Backward-compatible alias for :meth:`close`."""
        await self.close()


redis_client = ResilientRedisClient(settings.REDIS_URL)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency providing a scoped SQLAlchemy AsyncSession per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_redis() -> ResilientRedisClient:
    """FastAPI dependency returning the shared async Redis client."""
    return redis_client
