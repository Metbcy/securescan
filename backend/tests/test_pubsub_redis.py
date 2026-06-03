import asyncio
import os

import pytest

from securescan.pubsub import RedisBackend

REDIS_URL = os.environ.get("SECURESCAN_REDIS_URL")


@pytest.mark.skipif(not REDIS_URL, reason="SECURESCAN_REDIS_URL not set")
@pytest.mark.asyncio
async def test_redis_round_trip():
    backend = RedisBackend(REDIS_URL, prefix="ss-test:")
    try:
        # Check connectivity
        await backend.redis.ping()
    except Exception as e:
        pytest.skip(f"Redis unreachable: {e}")

    received = []

    async def subscriber():
        async for msg in backend.subscribe("test-chan"):
            received.append(msg)
            if msg == {"done": True}:
                break

    task = asyncio.create_task(subscriber())
    await asyncio.sleep(0.1)  # let task start and subscribe

    await backend.publish("test-chan", {"foo": "bar"})
    await backend.publish("test-chan", {"done": True})

    await asyncio.wait_for(task, timeout=2.0)
    assert received == [{"foo": "bar"}, {"done": True}]
    await backend.redis.close()


@pytest.mark.skipif(not REDIS_URL, reason="SECURESCAN_REDIS_URL not set")
@pytest.mark.asyncio
async def test_redis_cross_instance_fanout():
    # Simulate two workers
    b1 = RedisBackend(REDIS_URL, prefix="ss-test-cross:")
    b2 = RedisBackend(REDIS_URL, prefix="ss-test-cross:")

    received = []

    async def sub2():
        async for msg in b2.subscribe("chan"):
            received.append(msg)
            break

    task = asyncio.create_task(sub2())
    await asyncio.sleep(0.1)

    await b1.publish("chan", {"hello": "world"})
    await asyncio.wait_for(task, timeout=2.0)
    assert received == [{"hello": "world"}]

    await b1.redis.close()
    await b2.redis.close()
