import asyncio
from dataclasses import fields
from types import SimpleNamespace

from webrtc import Runtime
from webrtc.dtls import DTLSTransport, DTLSTransportSnapshot, DTLSRole
from webrtc.ice.agent import (
    Agent, AgentProtocolSnapshot, CandidatePair, CandidatePairController,
    CandidatePairRegistry, CandidatePairControllerSnapshot,
    CandidatePairSnapshot, CandidatePairState, _ControllerCommand,
)
from webrtc.peer_connection import (
    PeerAuthoritySnapshot, PeerConnection,
    SelectedTransportSnapshot,
    SignalingSnapshot,
)
from webrtc.srtp import (
    Session, SessionAdmissionSnapshot, SessionKeys, SessionReadinessSnapshot,
)
from webrtc.transceiver import (
    MediaCaps,
    NegotiatedTransceiverSnapshot,
    RTPCodecKind, RTPCodecParameters, RTPDecodingParameters,
    RTPReceiver,
    RTPReceiverSnapshot,
    RTPRtxParameters, RTPTransceiverDirection, TrackLocal,
)


def _field_names(snapshot_type) -> set[str]:
    return {field.name for field in fields(snapshot_type)}


def test_stage1_domain_snapshots_exclude_observation_infrastructure() -> None:
    forbidden = {
        "entity_id", "observability_id", "owner_entity_id", "epoch",
        "machine_epoch", "machine_type", "cause_id", "operation_id",
        "sender_id", "receiver_id", "selected_pair_id",
        "nomination_entity_id", "nomination_epoch", "nomination_revision",
        "srtp_rtp_revision", "srtp_rtcp_revision",
    }
    snapshots = (
        PeerAuthoritySnapshot,
        SelectedTransportSnapshot,
        AgentProtocolSnapshot,
        CandidatePairSnapshot,
        CandidatePairControllerSnapshot,
        DTLSTransportSnapshot,
        SessionAdmissionSnapshot,
        SessionReadinessSnapshot,
        RTPReceiverSnapshot,
        NegotiatedTransceiverSnapshot,
    )
    for snapshot_type in snapshots:
        assert _field_names(snapshot_type).isdisjoint(forbidden), snapshot_type
        assert "revision" not in _field_names(snapshot_type), snapshot_type

    # Signaling alone owns an explicit optimistic-concurrency contract: offer
    # generation rejects a commit prepared from an older signaling snapshot.
    assert "revision" in _field_names(SignalingSnapshot)
    assert _field_names(SignalingSnapshot).isdisjoint(forbidden)


def test_stage1_receiver_reads_one_immutable_domain_snapshot() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage1-receiver"):
            receiver = RTPReceiver(MediaCaps(), RTPCodecKind.Audio)
            initial = receiver.receiver_snapshot
            transport = object()
            receiver.bind(transport)
            bound = receiver.receiver_snapshot

            assert initial.state == "new" and initial.transport is None
            assert bound.state == "bound" and bound.transport is transport
            assert receiver.track is bound.track is None
            assert initial is not bound

            await receiver.aclose()
            assert receiver.receiver_snapshot.state == "stopped"
            assert receiver.receiver_snapshot.transport is None

    asyncio.run(scenario())


def test_stage1_srtp_wait_and_close_use_admission_authority() -> None:
    async def scenario() -> None:
        keys = SessionKeys(bytes(16), bytes(14), bytes(16), bytes(14))
        async with Runtime(scope_id="stage1-srtp-readiness"):
            session = Session(keys, observability_id="stage1:srtp")
            machine_snapshot = session._runner.snapshot
            session._runner.snapshot = lambda: (
                machine_snapshot()
                if session.admission_snapshot().state == "closed"
                else (_ for _ in ()).throw(AssertionError(
                    "SRTP domain lifecycle gate read MachineSnapshot"
                ))
            )
            await session.wait_ready()
            readiness = session.lifecycle_snapshot()
            assert readiness.ready
            assert _field_names(type(readiness)) == {
                "state", "keys_ready", "accepting_packets", "accepting_streams",
            }
            await session.close()
            assert session.admission_snapshot().state == "closed"

    asyncio.run(scenario())


def test_stage1_add_transceiver_accepts_injected_receiver_authority() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage1-injected-receiver") as runtime:
            peer = PeerConnection()
            peer.__compose_runtime__(runtime)
            codec = RTPCodecParameters(
                "audio/opus", 48000, 0.02, 2, "", 111, "opus",
            )
            local = TrackLocal("local", "stream", RTPCodecKind.Audio, codec)
            receiver = RTPReceiver(MediaCaps(), RTPCodecKind.Audio)
            receiver.receive(RTPDecodingParameters(
                "remote", 77, 111, RTPRtxParameters(78),
            ))
            injected_track = receiver.track
            assert injected_track is not None and "_track" not in receiver.__dict__

            transceiver = await peer.add_transceiver_from_track(
                local, RTPTransceiverDirection.Recvonly, receiver=receiver,
            )
            assert transceiver.receiver is receiver
            assert receiver.receiver_snapshot.track is injected_track
            await transceiver.aclose()

    asyncio.run(scenario())


def test_stage1_dtls_admission_and_start_read_domain_snapshots() -> None:
    async def scenario() -> None:
        transport = DTLSTransport.__new__(DTLSTransport)
        admission = SessionAdmissionSnapshot(
            state="ready", keys_ready=True, accepting_packets=True,
            accepting_streams=True,
        )
        session = SimpleNamespace(
            admission_snapshot=lambda: admission,
            lifecycle_snapshot=lambda: (_ for _ in ()).throw(AssertionError(
                "DTLS readiness read a generic SRTP machine snapshot"
            )),
        )
        transport._srtp_keying_material = object()
        transport._srtp_rtp = session
        transport._srtp_rtcp = session
        transport._authority = DTLSTransportSnapshot(
            state="connected", role=DTLSRole.Client, transport=object(),
            handshake_ready=True, srtp_rtp_ready=True, srtp_rtcp_ready=True,
        )
        transport._runner = SimpleNamespace(
            snapshot=lambda: (_ for _ in ()).throw(AssertionError(
                "DTLS start read the generic machine snapshot"
            ))
        )

        transport._require_connected_readiness()
        await transport.start(DTLSRole.Client)

    asyncio.run(scenario())


def test_stage1_receiver_gates_ignore_machine_snapshot_and_duplicate_fields() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage1-receiver-authority"):
            receiver = RTPReceiver(MediaCaps(), RTPCodecKind.Audio)
            receiver._runner.snapshot = lambda: (_ for _ in ()).throw(
                AssertionError("receiver gate read generic machine snapshot")
            )
            transport = object()
            receiver.bind(transport)
            assert receiver.receiver_snapshot.state == "bound"
            assert receiver.receiver_snapshot.transport is transport
            receiver.stop()
            assert receiver.receiver_snapshot.state == "stopping"
            await receiver.aclose()
            assert receiver.receiver_snapshot.state == "stopped"
            assert {"_dtls", "_track", "_kind", "_pending_receive"}.isdisjoint(
                receiver.__dict__
            )

    asyncio.run(scenario())


def test_stage1_ice_admission_reads_typed_pair_and_controller_snapshots() -> None:
    pair = CandidatePair.__new__(CandidatePair)
    pair._authority = SimpleNamespace(state="succeeded")
    pair._runner = SimpleNamespace(
        snapshot=lambda: (_ for _ in ()).throw(
            AssertionError("generic pair machine snapshot was read")
        )
    )
    pair.get_pair_priority = lambda _controlling: 1

    assert pair.state is CandidatePairState.SUCCEEDED
    registry = CandidatePairRegistry()
    registry._check_list["pair"] = pair
    assert registry.best_pair_priority(True) is pair

    controller = CandidatePairController.__new__(CandidatePairController)
    controller._authority = SimpleNamespace(nominated=True)
    controller._runner = SimpleNamespace(
        snapshot=lambda: (_ for _ in ()).throw(
            AssertionError("generic controller machine snapshot was read")
        )
    )
    assert controller.nominated
    agent = Agent.__new__(Agent)
    agent._protocol = SimpleNamespace(
        candidate_pairs=(pair,), selected_transports=(),
    )
    agent._controller_registry = SimpleNamespace(
        controllers=lambda: (controller,),
    )
    assert agent._has_succeeded_candidate_pair()


def test_stage1_controller_receive_failure_gate_uses_typed_authority() -> None:
    class Selector:
        def start(self) -> None:
            return None

    class FailingConnection:
        async def recvfrom(self):
            raise RuntimeError("receive failed")

    async def scenario() -> None:
        submitted = []
        controller = CandidatePairController.__new__(CandidatePairController)
        controller._authority = SimpleNamespace(state="checking")
        controller._pair = SimpleNamespace(entity_id="pair:stage1")
        controller.entity_id = "controller:stage1"
        controller._command_id = 0
        controller._CandidatePairController__selector = Selector()
        controller._CandidatePairController__conn = FailingConnection()
        controller._runner = SimpleNamespace(
            epoch=1,
            try_submit=submitted.append,
            snapshot=lambda: (_ for _ in ()).throw(AssertionError(
                "receive failure gate read generic controller snapshot"
            )),
        )

        async def no_ping() -> None:
            return None

        controller.ping_remote_candidate = no_ping
        await controller._receive_loop()
        assert len(submitted) == 1
        assert submitted[0].kind is _ControllerCommand.FAIL

    asyncio.run(scenario())


def test_stage1_peer_compatibility_lifecycle_reads_peer_authority() -> None:
    peer = object.__new__(PeerConnection)
    peer._peer_runner = SimpleNamespace(
        authority=PeerAuthoritySnapshot(state="closing"),
        snapshot=lambda: (_ for _ in ()).throw(
            AssertionError("generic peer machine snapshot was read")
        ),
    )
    assert peer._closing
    assert peer._started
    assert not peer.closed
