import asyncio

import pytest

from webrtc import Runtime
from webrtc.srtp.session import Session, SessionKeys


def keys():
    return SessionKeys(b"a" * 16, b"b" * 14, b"a" * 16, b"b" * 14)

def rtp(sequence=1):
    return b"\x80\x60" + sequence.to_bytes(2, "big") + b"\x00\x00\x00\x01\x12\x34\x56\x78payload"


def bind_session(runtime, session, entity_id):
    runtime.register_owner(entity_id, epoch=1)
    runtime.bind_observation(
        session, entity_id=entity_id, role="srtp-session", owner_epoch=1,
    )


def test_srtp_crypto_is_offloaded_without_packet_rate_operation_groups():
    async def scenario():
        runtime = Runtime(scope_id="srtp")
        session = Session(keys())
        async def owner():
            encrypted = await session.encrypt(rtp())
            assert await session.decrypt(encrypted) == rtp()
        async with runtime:
            bind_session(runtime, session, "srtp:test")
            await owner()
        groups = runtime.activity_groups.snapshots()
        assert groups == ()
    asyncio.run(scenario())


def test_srtp_failure_is_reraised_without_packet_rate_operation_group():
    async def scenario():
        runtime = Runtime(scope_id="srtp"); sender = Session(keys())
        async def owner():
            encrypted = bytearray(await sender.encrypt(rtp())); encrypted[-1] ^= 1
            with pytest.raises(Exception): await sender.decrypt(bytes(encrypted))
        async with runtime:
            bind_session(runtime, sender, "srtp:test")
            await owner()
        assert runtime.activity_groups.snapshots() == ()
    asyncio.run(scenario())


def test_packet_rate_calls_do_not_create_task_nodes():
    async def scenario():
        runtime = Runtime(scope_id="srtp"); session = Session(keys())
        gate = asyncio.Event()
        async def owner():
            for index in range(100): await session.encrypt(rtp(index))
            gate.set(); await asyncio.sleep(0)
        async with runtime:
            bind_session(runtime, session, "srtp:test")
            await owner()
        assert runtime.activity_groups.snapshots() == ()
        assert runtime.task_registry.task_ids() == ()
    asyncio.run(scenario())
