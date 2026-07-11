import asyncio

import pytest

from webrtc.srtp import Session, SessionKeys
from webrtc.tracing import PerformanceRecorder, use_performance_recorder


def _keys() -> SessionKeys:
    return SessionKeys(bytes(16), bytes(14), bytes(16), bytes(14))


def _rtp(ssrc: int = 0x12345678, sequence_number: int = 1) -> bytes:
    return bytes([
        0x80, 0x60, sequence_number >> 8, sequence_number & 0xFF,
        0, 0, 0, 1,
        *ssrc.to_bytes(4, "big"),
        0xDE, 0xAD, 0xBE, 0xEF,
    ])


def _rtcp() -> bytes:
    return bytes([
        0x80, 0xC8, 0x00, 0x06,
        0x12, 0x34, 0x56, 0x78,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0x10,
    ])


def _events(recorder: PerformanceRecorder, name: str):
    return [event for event in recorder.events() if event.name == name]


def test_srtp_rtp_crypto_events_include_packet_metadata_and_counters():
    session = Session(_keys(), is_rtp=True)
    packet = _rtp()
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        encrypted = session.encrypt(packet)
        assert session.decrypt(encrypted) == packet

    encrypted_event = _events(recorder, "srtp.rtp_encrypt.completed")[0]
    decrypted_event = _events(recorder, "srtp.rtp_decrypt.completed")[0]
    assert encrypted_event.metadata["packet_kind"] == "rtp"
    assert encrypted_event.metadata["flow_direction"] == "tx"
    assert encrypted_event.metadata["ssrc"] == 0x12345678
    assert encrypted_event.metadata["sequence_number"] == 1
    assert encrypted_event.metadata["plaintext_size_bytes"] == len(packet)
    assert encrypted_event.metadata["ciphertext_size_bytes"] == len(encrypted)
    assert encrypted_event.metadata["counter.srtp.rtp_encrypted"] == 1
    assert decrypted_event.metadata["plaintext_size_bytes"] == len(packet)
    assert decrypted_event.metadata["counter.srtp.rtp_decrypted"] == 1


def test_srtp_rtcp_crypto_events_are_separate_from_rtp():
    session = Session(_keys(), is_rtp=False)
    packet = _rtcp()
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        encrypted = session.encrypt(packet)
        assert session.decrypt(encrypted) == packet

    assert _events(recorder, "srtp.rtcp_encrypt.completed")[0].metadata["counter.srtp.rtcp_encrypted"] == 1
    assert _events(recorder, "srtp.rtcp_decrypt.completed")[0].metadata["counter.srtp.rtcp_decrypted"] == 1
    assert not _events(recorder, "srtp.rtp_encrypt.completed")


def test_srtp_decrypt_failure_is_traced():
    sender = Session(_keys(), is_rtp=True)
    receiver = Session(_keys(), is_rtp=True)
    corrupted = bytearray(sender.encrypt(_rtp()))
    corrupted[-1] ^= 0xFF
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        with pytest.raises(Exception):
            receiver.decrypt(bytes(corrupted))

    failed = _events(recorder, "srtp.rtp_decrypt.failed")[0]
    assert failed.metadata["packet_kind"] == "rtp"
    assert failed.metadata["error_stage"] == "srtp_decrypt"
    assert failed.metadata["counter.srtp.rtp_decrypt_failed"] == 1
    assert failed.metadata["exception_class"]


def test_srtp_stream_creation_delivery_and_drop_are_traced():
    sender = Session(_keys(), is_rtp=True)
    receiver = Session(_keys(), is_rtp=True)
    recorder = PerformanceRecorder()

    async def exercise() -> None:
        with use_performance_recorder(recorder):
            await receiver.write_incoming(sender.encrypt(_rtp(sequence_number=1)))
            stream = await receiver.get_stream(0x12345678)
            assert stream is not None
            stream._queue = asyncio.Queue(maxsize=1)
            await receiver.write_incoming(sender.encrypt(_rtp(sequence_number=2)))
            await receiver.write_incoming(sender.encrypt(_rtp(sequence_number=3)))

    asyncio.run(exercise())

    created = _events(recorder, "srtp.stream.created")
    delivered = _events(recorder, "srtp.stream.delivered")
    dropped = _events(recorder, "srtp.stream.dropped")
    assert created[0].metadata["ssrc"] == 0x12345678
    assert created[0].metadata["packet_kind"] == "rtp"
    assert created[0].metadata["is_new"] is True
    assert delivered[0].metadata["counter.srtp.stream_packets_delivered"] == 1
    assert dropped[0].metadata["counter.srtp.stream_packets_dropped"] == 1
    assert dropped[0].metadata["drop_reason"] == "stream_queue_full_or_closed"


def test_srtp_session_close_does_not_deadlock_with_active_streams():
    session = Session(_keys(), is_rtp=True)

    async def exercise() -> None:
        await session.open_stream(0x12345678)
        await asyncio.wait_for(session.close(), timeout=0.1)
        assert await session.get_stream(0x12345678) is None

    asyncio.run(exercise())
