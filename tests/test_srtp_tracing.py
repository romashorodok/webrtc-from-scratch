import asyncio

import pytest

from webrtc import Runtime
from webrtc.srtp.session import Session, SessionKeys


def keys():
    return SessionKeys(b"a" * 16, b"b" * 14, b"a" * 16, b"b" * 14)

def rtp(sequence=1):
    return b"\x80\x60" + sequence.to_bytes(2, "big") + b"\x00\x00\x00\x01\x12\x34\x56\x78payload"


def test_srtp_crypto_is_metaclass_offloaded_and_aggregated():
    async def scenario():
        runtime = Runtime(scope_id="srtp")
        session = Session(keys())
        async def owner():
            encrypted = await session.encrypt(rtp())
            assert await session.decrypt(encrypted) == rtp()
        async with runtime:
            trace_id = runtime.root_context.trace_id
            await owner()
        groups = runtime.activity_groups.snapshots()
        operations = {item.operation for item in groups}
        assert operations == {"srtp.encrypt", "srtp.decrypt"}
        assert all(item.total_worker_ns > 0 for item in groups)
        assert all(item.total_queue_ns >= 0 for item in groups)
        assert all(item.trace_id == trace_id for item in groups)
    asyncio.run(scenario())


def test_srtp_failure_is_recorded_and_original_exception_is_reraised():
    async def scenario():
        runtime = Runtime(scope_id="srtp"); sender = Session(keys())
        async def owner():
            encrypted = bytearray(await sender.encrypt(rtp())); encrypted[-1] ^= 1
            with pytest.raises(Exception): await sender.decrypt(bytes(encrypted))
        async with runtime:
            await owner()
        failed = next(item for item in runtime.activity_groups.snapshots()
                      if item.operation == "srtp.decrypt")
        assert failed.errors == 1 and failed.latest_failure_class
    asyncio.run(scenario())


def test_packet_rate_calls_do_not_create_task_nodes():
    async def scenario():
        runtime = Runtime(scope_id="srtp"); session = Session(keys())
        gate = asyncio.Event()
        async def owner():
            for index in range(100): await session.encrypt(rtp(index))
            gate.set(); await asyncio.sleep(0)
        async with runtime:
            await owner()
        group = next(item for item in runtime.activity_groups.snapshots() if item.operation == "srtp.encrypt")
        assert group.calls == 100
        assert runtime.task_registry.task_ids() == ()
    asyncio.run(scenario())
