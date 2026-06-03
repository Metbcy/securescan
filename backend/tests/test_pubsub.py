import asyncio

import pytest

from securescan.pubsub import InProcessBackend


@pytest.mark.asyncio
async def test_in_process_round_trip():
    backend = InProcessBackend()
    received = []

    async def subscriber():
        async for msg in backend.subscribe("test-chan"):
            received.append(msg)
            if msg == {"done": True}:
                break

    task = asyncio.create_task(subscriber())
    await asyncio.sleep(0.01)  # let task start

    await backend.publish("test-chan", {"foo": "bar"})
    await backend.publish("test-chan", {"done": True})

    await asyncio.wait_for(task, timeout=1.0)
    assert received == [{"foo": "bar"}, {"done": True}]


@pytest.mark.asyncio
async def test_in_process_replay():
    backend = InProcessBackend()
    await backend.add_to_replay("chan1", {"id": 1}, cap=2)
    await backend.add_to_replay("chan1", {"id": 2}, cap=2)
    await backend.add_to_replay("chan1", {"id": 3}, cap=2)

    replays = await backend.fetch_replay("chan1")
    assert replays == [{"id": 2}, {"id": 3}]

    await backend.clear_replay("chan1")
    assert await backend.fetch_replay("chan1") == []
