import asyncio

import pytest

from webrtc.config import DebugConfig, LogLevel
from webrtc.dtls.dtlstransport import DTLSTransport
from webrtc.lifecycle import TransportCondition
from webrtc.logger import get_logger
from webrtc.peer_connection import ICEGatherer, PeerConnection
from webrtc.session_description import SessionDescription, SessionDescriptionType
from webrtc.signaling import SignalingStateTransitionError


@pytest.fixture(autouse=True)
def quiet_webrtc_logger():
    config = DebugConfig.get()
    previous_levels = (
        config.ice_log_level,
        config.dtls_log_level,
        config.srtp_log_level,
        config.rtp_log_level,
        config.rtcp_log_level,
        config.transceiver_log_level,
        config.peer_connection_log_level,
        config.opus_log_level,
    )
    get_logger().config.set_all_log_levels(LogLevel.SILENT)
    yield
    (
        config.ice_log_level,
        config.dtls_log_level,
        config.srtp_log_level,
        config.rtp_log_level,
        config.rtcp_log_level,
        config.transceiver_log_level,
        config.peer_connection_log_level,
        config.opus_log_level,
    ) = previous_levels


def test_invalid_signaling_state_raises_immediately(capsys):
    async def scenario():
        pc = PeerConnection()

        with pytest.raises(SignalingStateTransitionError):
            await pc.set_local_description(
                SessionDescriptionType.Answer,
                SessionDescription(),
            )

    asyncio.run(scenario())

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_ice_gather_failure_raises(monkeypatch, capsys):
    async def scenario():
        gatherer = ICEGatherer()

        async def fail_create_agent(*args, **kwargs):
            raise RuntimeError("bind failed")

        monkeypatch.setattr(gatherer, "_ICEGatherer__create_agent", fail_create_agent)

        with pytest.raises(RuntimeError, match="bind failed"):
            await gatherer.gather()

    asyncio.run(scenario())

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_dtls_wait_handshake_raises_stored_failure():
    async def scenario():
        transport = DTLSTransport.__new__(DTLSTransport)
        failure = RuntimeError("handshake failed")
        transport._DTLSTransport__handshake_complete = asyncio.Event()
        transport._DTLSTransport__handshake_complete.set()
        transport._DTLSTransport__handshake_failed = failure

        with pytest.raises(RuntimeError, match="handshake failed"):
            await transport.wait(TransportCondition.HANDSHAKE_COMPLETE, timeout=0.05)

    asyncio.run(scenario())


def test_dtls_start_without_transport_raises(capsys):
    transport = DTLSTransport.__new__(DTLSTransport)
    transport._DTLSTransport__handshake_complete = asyncio.Event()
    transport._DTLSTransport__dtls_conn = None
    transport._DTLSTransport__transport = None

    from webrtc.dtls import DTLSRole

    with pytest.raises(RuntimeError, match="No transport bound"):
        transport.start(DTLSRole.Client)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
