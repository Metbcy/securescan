import asyncio
import pytest
from securescan.events import ScanEventBus
from securescan.pubsub import InProcessBackend

@pytest.mark.asyncio
async def test_events_multi_instance_in_process_isolation():
    """In-process backend should be isolated per instance."""
    bus1 = ScanEventBus(backend=InProcessBackend())
    bus2 = ScanEventBus(backend=InProcessBackend())
    
    q1 = await bus1.subscribe("scan-1")
    q2 = await bus2.subscribe("scan-1")
    await asyncio.sleep(0.1) # Wait for forwarders to register
    
    await bus1.publish("scan-1", "event", {"val": 1})
    await asyncio.sleep(0.1)
    
    assert q1.qsize() == 1
    assert q2.qsize() == 0 # Isolated
