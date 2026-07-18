import asyncio
from types import SimpleNamespace

import pytest

from webrtc import Runtime
from webrtc.ice.agent import Agent, AgentOptions, AgentRole
from webrtc.peer_connection import ICETransport
from webrtc.srtp import Session, SessionKeys
from webrtc.state_machine import StaleMachineAccess, TransitionCommit
from webrtc.transceiver import (
    MediaCaps, RTPCodecKind, RTPCodecParameters, RTPTransceiver,
    RTPTransceiverDirection,
)


class _Gatherer:
    entity_id = "ice-gatherer:authority"

    def get_role(self):
        return AgentRole.Controlling


class _PairTransport:
    def __init__(self, entity_id):
        self.entity_id = entity_id
        self.closed = False

    async def aclose(self):
        self.closed = True


class _UDP:
    async def aclose(self):
        return None


def test_ice_agent_credentials_role_and_lifecycle_use_one_protocol_snapshot():
    async def scenario():
        async with Runtime(scope_id="stage6-agent"):
            agent = Agent(
                AgentOptions([], _UDP(), []),
                owner=SimpleNamespace(entity_id="peer:authority"),
            )
            while agent.protocol_snapshot().state == "new":
                await asyncio.sleep(0)
            initial = agent.protocol_snapshot()
            agent.set_remote_credentials("remote-user", "remote-password")
            credentials = agent.protocol_snapshot()
            assert initial.remote_credentials is None
            assert credentials.remote_credentials == (
                "remote-user", "remote-password",
            )
            agent.connect(True)
            while agent.protocol_snapshot().state == "waiting-remote":
                await asyncio.sleep(0)
            checking = agent.protocol_snapshot()
            assert checking.role is AgentRole.Controlling
            assert agent.get_role() is checking.role
            await agent.aclose()
            assert agent.protocol_snapshot().state == "closed"

    asyncio.run(scenario())


def test_selected_transport_commits_binding_and_provenance_as_one_snapshot():
    async def scenario():
        async with Runtime(scope_id="stage6-selected"):
            selected = ICETransport(_Gatherer())
            pair = _PairTransport("candidate-pair:authoritative")
            nomination = TransitionCommit(
                pair.entity_id, "candidate-pair", "succeeded", "nominated",
                7, "nomination", 1, 3,
            )
            before = selected.authoritative_snapshot()
            await selected.bind(pair, nomination)
            committed = selected.authoritative_snapshot()

            assert before.state == "new" and before.transport is None
            assert committed.ready and committed.transport is pair
            assert selected.selected_snapshot() is committed
            assert committed.transport is pair
            assert not hasattr(committed, "nomination_entity_id")
            assert not hasattr(committed, "revision")

            with pytest.raises(RuntimeError, match="already bound"):
                await selected.bind(_PairTransport("candidate-pair:stale"), nomination)

            await selected.aclose()
            terminal = selected.authoritative_snapshot()
            assert terminal.state == "closed" and terminal.transport is None
            assert pair.closed

    asyncio.run(scenario())


def test_srtp_admission_snapshot_rejects_after_atomic_drain():
    async def scenario():
        keys = SessionKeys(bytes(16), bytes(14), bytes(16), bytes(14))
        async with Runtime(scope_id="stage6-srtp"):
            session = Session(keys, observability_id="srtp:authority")
            await session.wait_ready()
            ready = session.admission_snapshot()
            assert ready.keys_ready and ready.accepting_packets
            stream = await session.open_stream(1234)
            admitted = session.admission_snapshot()
            assert admitted.stream_count == 1
            assert ready.stream_count == 0  # retained snapshots never mutate

            await session.close()
            closed = session.admission_snapshot()
            assert closed.state == "closed"
            assert not closed.accepting_packets and not closed.accepting_streams
            with pytest.raises(RuntimeError, match="admission rejected"):
                await session.open_stream(5678)
            with pytest.raises(RuntimeError, match="admission rejected"):
                await session.accept_stream()
            with pytest.raises(RuntimeError, match="admission rejected"):
                await session.encrypt(b"packet")
            assert stream.closed

    asyncio.run(scenario())


def test_transceiver_snapshot_is_the_read_authority_and_stale_cas_is_rejected():
    async def scenario():
        async with Runtime(scope_id="stage6-transceiver"):
            transceiver = RTPTransceiver(
                object(), MediaCaps(), RTPCodecKind.Audio,
                RTPTransceiverDirection.Sendonly,
                observability_id="transceiver:authority",
            )
            await transceiver.wait_active()
            codec = RTPCodecParameters("audio/opus", 48000, 50, 2, "", 111, "opus")
            await transceiver.set_prefered_codec(codec)
            await transceiver.set_mid("audio-0")
            authority = transceiver.negotiated_snapshot
            machine = transceiver._runner.snapshot()

            assert transceiver.direction is authority.direction
            assert transceiver.mid.value == authority.mid == "audio-0"
            assert authority.codecs == (codec,)

            with pytest.raises(StaleMachineAccess):
                await transceiver.apply_negotiated_snapshot(
                    authority,
                    expected_snapshot=type(authority)(
                        authority.direction, authority.mid, authority.codecs,
                        authority.sender_config, authority.receiver_config,
                        authority.sender, authority.receiver,
                    ),
                )
            assert transceiver.negotiated_snapshot is authority
            await transceiver.aclose()

    asyncio.run(scenario())
