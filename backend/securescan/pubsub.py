from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator

from .config import settings

logger = logging.getLogger("securescan.pubsub")


class PubSubBackend(ABC):
    @abstractmethod
    async def publish(self, channel: str, payload: dict) -> None:
        """Publish an event to a channel."""

    @abstractmethod
    async def subscribe(self, channel: str) -> AsyncGenerator[dict, None]:
        """Subscribe to a channel and yield events."""

    @abstractmethod
    async def add_to_replay(self, channel: str, payload: dict, cap: int) -> None:
        """Add an event to the replay buffer for a channel."""

    @abstractmethod
    async def fetch_replay(self, channel: str) -> list[dict]:
        """Fetch the replay buffer for a channel."""

    @abstractmethod
    async def clear_replay(self, channel: str) -> None:
        """Clear the replay buffer for a channel."""


class InProcessBackend(PubSubBackend):
    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue]] = {}
        self._replays: dict[str, list[dict]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, channel: str, payload: dict) -> None:
        async with self._lock:
            queues = list(self._queues.get(channel, []))
        for q in queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, channel: str) -> AsyncGenerator[dict, None]:
        # Larger maxsize than ScanEventBus.QUEUE_CAP so we don't drop
        # events here before the bus can apply its own eviction logic.
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._queues.setdefault(channel, []).append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if channel in self._queues:
                    self._queues[channel].remove(q)
                    if not self._queues[channel]:
                        del self._queues[channel]

    async def add_to_replay(self, channel: str, payload: dict, cap: int) -> None:
        async with self._lock:
            buf = self._replays.setdefault(channel, [])
            buf.append(payload)
            if len(buf) > cap:
                del buf[: len(buf) - cap]

    async def fetch_replay(self, channel: str) -> list[dict]:
        async with self._lock:
            return list(self._replays.get(channel, []))

    async def clear_replay(self, channel: str) -> None:
        async with self._lock:
            self._replays.pop(channel, None)


class RedisBackend(PubSubBackend):
    def __init__(self, redis_url: str, prefix: str = "ss:") -> None:
        import redis.asyncio as redis

        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.prefix = prefix

    async def publish(self, channel: str, payload: dict) -> None:
        full_channel = f"{self.prefix}events:{channel}"
        await self.redis.publish(full_channel, json.dumps(payload))

    async def subscribe(self, channel: str) -> AsyncGenerator[dict, None]:
        full_channel = f"{self.prefix}events:{channel}"
        async with self.redis.pubsub() as pubsub:
            await pubsub.subscribe(full_channel)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield json.loads(message["data"])

    async def add_to_replay(self, channel: str, payload: dict, cap: int) -> None:
        key = f"{self.prefix}replay:{channel}"
        async with self.redis.pipeline() as pipe:
            pipe.rpush(key, json.dumps(payload))
            pipe.ltrim(key, -cap, -1)
            # 1 hour default expiry for replay buffers, can be adjusted by caller if terminal
            pipe.expire(key, 3600)
            await pipe.execute()

    async def fetch_replay(self, channel: str) -> list[dict]:
        key = f"{self.prefix}replay:{channel}"
        items = await self.redis.lrange(key, 0, -1)
        return [json.loads(item) for item in items]

    async def clear_replay(self, channel: str) -> None:
        key = f"{self.prefix}replay:{channel}"
        await self.redis.delete(key)


_backend: PubSubBackend | None = None


def get_pubsub_backend() -> PubSubBackend:
    global _backend
    if _backend is not None:
        return _backend

    if settings.redis_url:
        logger.info("Using Redis pubsub backend")
        _backend = RedisBackend(settings.redis_url, settings.redis_key_prefix)
    else:
        logger.info("Using in-process pubsub backend")
        _backend = InProcessBackend()
    return _backend


def get_redis_client():
    """Return the underlying redis.asyncio client if Redis is active."""
    backend = get_pubsub_backend()
    if isinstance(backend, RedisBackend):
        return backend.redis
    return None
