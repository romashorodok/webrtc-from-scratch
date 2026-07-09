import asyncio

import pytest
import webrtc_rs

from webrtc.dtls.dtlstransport import DTLSLocal, DTLSTransport, DTLSRole
from webrtc.ice.agent import Agent, AgentOptions
from webrtc.ice.candidate_base import CandidateBase
from webrtc.ice.net.types import CandidateType, LocalCandidate, NetworkType
from webrtc.peer_connection import PeerConnection
from webrtc.session_description import SessionDescription, SessionDescriptionType
from webrtc.tracing import PerformanceRecorder, use_performance_recorder


class _FakeUDP:
    def inbound_handlers(self):
        return {}


class _FakeMux:
    def intercept(self, remote):
        raise AssertionError("not needed")


class _FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data):
        self.sent.append(data)


class _FakeSrtpSession:
    pass


def _event_names(recorder: PerformanceRecorder) -> list[str]:
    return [event.name for event in recorder.events()]


def test_sdp_create_and_set_description_events_are_decorated(monkeypatch):
    async def scenario():
        pc = PeerConnection()
        recorder = PerformanceRecorder()

        async def generate_unmatched_sdp(transceivers):
            return SessionDescription()

        monkeypatch.setattr(pc, "_generate_unmatched_sdp", generate_unmatched_sdp)

        with use_performance_recorder(recorder):
            desc = await pc.create_offer()
            await pc.set_local_description(SessionDescriptionType.Offer, desc)

        assert _event_names(recorder) == [
            "sdp.create_offer.started",
            "sdp.create_offer.completed",
            "sdp.set_local_offer.started",
            "sdp.set_local_offer.completed",
        ]

    asyncio.run(scenario())


def test_ice_gather_and_candidate_events_are_emitted():
    async def scenario():
        agent = Agent(AgentOptions([], _FakeUDP(), []))
        candidate = CandidateBase()
        candidate.set_address("127.0.0.1")
        candidate.set_port(5000)
        candidate.set_network_type(NetworkType.UDP)
        candidate.set_candidate_type(CandidateType.Host)
        recorder = PerformanceRecorder()

        with use_performance_recorder(recorder):
            await agent.gather_candidates()
            await agent._add_local_candidate(LocalCandidate(candidate, _FakeMux()))
            agent.set_remote_credentials("remoteUfrag", "remotePassword")

        names = _event_names(recorder)
        assert names[:2] == ["ice.gather.started", "ice.gather.completed"]
        assert "ice.candidate.gathered" in names
        assert "ice.remote_credentials.set" in names
        candidate_event = next(event for event in recorder.events() if event.name == "ice.candidate.gathered")
        assert candidate_event.metadata["counter.ice.candidates"] == 1

    asyncio.run(scenario())


def test_dtls_start_failure_and_record_tx_events_are_emitted():
    async def scenario():
        recorder = PerformanceRecorder()

        with use_performance_recorder(recorder):
            transport = DTLSTransport(certificate=webrtc_rs.Certificate())
            with pytest.raises(RuntimeError):
                transport.start(DTLSRole.Client)
            await DTLSLocal(_FakeTransport()).sendto(b"not-a-dtls-record")

        names = _event_names(recorder)
        assert names[:3] == [
            "dtls.start.started",
            "dtls.role.selected",
            "dtls.start.failed",
        ]
        assert "dtls.record.tx" in names
        record_event = next(event for event in recorder.events() if event.name == "dtls.record.tx")
        assert record_event.metadata["counter.dtls.records_tx"] == 1

    asyncio.run(scenario())


def test_srtp_ready_events_are_decorated(monkeypatch):
    async def scenario():
        transport = DTLSTransport(certificate=webrtc_rs.Certificate())
        keys = type(
            "Keys",
            (),
            {
                "client_write_key": b"c" * 16,
                "client_write_salt": b"c" * 14,
                "server_write_key": b"s" * 16,
                "server_write_salt": b"s" * 14,
            },
        )()
        transport._srtp_keying_material = keys
        recorder = PerformanceRecorder()

        monkeypatch.setattr(
            "webrtc.dtls.dtlstransport.SrtpSession.from_keying_material",
            lambda **kwargs: _FakeSrtpSession(),
        )

        with use_performance_recorder(recorder):
            await transport._init_srtp(is_client=True)

        assert _event_names(recorder)[:4] == [
            "srtp.ready.started",
            "srtp.rtp_session.ready",
            "srtp.rtcp_session.ready",
            "srtp.ready.completed",
        ]

    asyncio.run(scenario())
