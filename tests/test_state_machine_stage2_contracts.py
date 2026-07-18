import asyncio
from types import SimpleNamespace

import pytest
import webrtc_rs

from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtlstransport import (
    DTLSTransport, DTLSRole, RECORD_INGRESS_CAPACITY,
)
from webrtc.dtls.flight_state import Flight
from webrtc.dtls.fsm import (
    FLIGHT_TRANSITIONS, FSM, FSMState, MAX_PENDING_ENCRYPTED_RECORDS,
)
from webrtc.dtls.handshake_reconstructor import (
    HandshakeReconstructor, HandshakeReconstructionOverflow,
    MAX_FRAGMENTED_HANDSHAKES,
)
from webrtc.dtls.dtls_record import HandshakeMessageType
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.runtime import Runtime
from webrtc.srtp.session import Session, SessionKeys, MAX_SRTP_STREAMS


class _Remote:
    async def sendto(self, data: bytes) -> None:
        return None


class _PairTransport:
    def __init__(self) -> None:
        self.ingress_started = asyncio.Event()
        self.rtp_started = asyncio.Event()
        self.rtcp_started = asyncio.Event()
        self.dtls: DTLSTransport | None = None

    async def recv_dtls(self):
        self.ingress_started.set()
        await asyncio.Event().wait()

    async def recv_rtp(self):
        assert self.dtls is not None
        assert self.dtls.authoritative_snapshot().media_ready
        self.rtp_started.set()
        await asyncio.Event().wait()

    async def recv_rtcp(self):
        assert self.dtls is not None
        assert self.dtls.authoritative_snapshot().media_ready
        self.rtcp_started.set()
        await asyncio.Event().wait()


def _keys() -> SessionKeys:
    return SessionKeys(b"a" * 16, b"b" * 14, b"c" * 16, b"d" * 14)


def test_stage2_machine_catalog_separates_public_dtls_from_internal_phases() -> None:
    public = MACHINE_SPECS["dtls-transport"]
    phase = MACHINE_SPECS["dtls-handshake-phase"]
    assert public.states.isdisjoint({"preparing", "sending", "waiting", "finished"})
    assert {"preparing", "sending", "waiting", "finished"} <= phase.states
    assert public.machine_type != phase.machine_type


def test_stage2_runtime_registers_distinct_bounded_dtls_machines() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2") as runtime:
            transport = DTLSTransport(webrtc_rs.Certificate())
            fsm = FSM(
                _Remote(), Certificate(webrtc_rs.Certificate()),
                asyncio.Queue(maxsize=64), Flight.FLIGHT1,
            )
            assert transport.entity_id == "dtls-transport:stage2"
            assert fsm.entity_id == "dtls-handshake-phase:stage2"
            assert transport.record_layer_chan.maxsize == RECORD_INGRESS_CAPACITY
            queue_entity = f"{transport.entity_id}:record-ingress"
            queue_telemetry_entity = runtime.telemetry_entity_id("queue", queue_entity)
            # Queue admission/close is owned by the primitive; it has no
            # permanent mailbox task or observational lifecycle machine.
            assert runtime.projection.machines.get(queue_entity) is None
            assert "_runner" not in transport.record_layer_chan.__dict__
            queue_facets = {
                item.facet_id.rsplit(":", 1)[-1]: item
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == queue_telemetry_entity
            }
            assert {item.observer_meta for item in queue_facets.values()} == {"aggregate"}
            assert queue_facets["capacity"].value == RECORD_INGRESS_CAPACITY
            assert fsm.commands.capacity == 16
            assert runtime.projection.machines.get(transport.entity_id).state == "new"
            assert runtime.projection.machines.get(fsm.entity_id).state == "preparing"
            with pytest.raises(RuntimeError, match="No transport bound"):
                await transport.start(DTLSRole.Client)
            await transport.aclose()
            await fsm.aclose()
            assert runtime.projection.machines.get(queue_entity) is None

    asyncio.run(scenario())


def test_stage2_runtime_owned_flight_parse_uses_failure_policy(monkeypatch) -> None:
    class ParsedFlight:
        async def parse(self, _state, _messages):
            return Flight.FLIGHT2

    monkeypatch.setitem(FLIGHT_TRANSITIONS, Flight.FLIGHT1, ParsedFlight())

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-flight-parse"):
            fsm = FSM(
                _Remote(), Certificate(webrtc_rs.Certificate()),
                asyncio.Queue(maxsize=64), Flight.FLIGHT1,
            )
            assert await fsm.wait() is FSMState.Preparing
            await fsm.aclose()

    asyncio.run(scenario())


def test_stage2_flight_programming_failure_is_not_retried(monkeypatch) -> None:
    class BrokenFlight:
        async def parse(self, _state, _messages):
            raise NameError("broken flight dependency")

    monkeypatch.setitem(FLIGHT_TRANSITIONS, Flight.FLIGHT1, BrokenFlight())

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-flight-failure"):
            fsm = FSM(
                _Remote(), Certificate(webrtc_rs.Certificate()),
                asyncio.Queue(maxsize=64), Flight.FLIGHT1,
            )
            with pytest.raises(NameError, match="broken flight dependency"):
                await fsm.wait()
            await fsm.aclose()

    asyncio.run(scenario())


def test_stage2_srtp_keys_and_sessions_are_ready_before_transport_connected() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-srtp") as runtime:
            rtp = Session(_keys(), is_rtp=True, observability_id="srtp:rtp")
            rtcp = Session(_keys(), is_rtp=False, observability_id="srtp:rtcp")
            await rtp.wait_ready()
            await rtcp.wait_ready()
            assert rtp.lifecycle_snapshot().state == "ready"
            assert rtcp.lifecycle_snapshot().state == "ready"
            assert runtime.projection.machines.get("srtp:rtp").state == "ready"
            assert runtime.projection.machines.get("srtp:rtcp").state == "ready"
            assert not hasattr(rtp, "_streams_lock")
            assert rtp._new_stream_queue.maxsize == MAX_SRTP_STREAMS
            await rtcp.close()
            await rtp.close()

    asyncio.run(scenario())


def test_stage2_connected_is_ordered_after_keys_sessions_and_revision_facets(monkeypatch) -> None:
    async def fake_handshake(self, is_client: bool) -> None:
        del is_client
        self._srtp_keying_material = SRTPKeyingMaterial(
            b"a" * 16, b"c" * 16, b"b" * 14, b"d" * 14,
        )
        self._srtp_rtp = Session(_keys(), True, observability_id="ordered:rtp")
        self._srtp_rtcp = Session(_keys(), False, observability_id="ordered:rtcp")

    monkeypatch.setattr(DTLSTransport, "_run_handshake", fake_handshake)

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-order") as runtime:
            transport = DTLSTransport(webrtc_rs.Certificate())
            pair = _PairTransport()
            pair.dtls = transport
            await transport.start(DTLSRole.Client, pair)
            snapshot = runtime.projection.machines.get(transport.entity_id)
            assert snapshot.state == "connected"
            assert transport.authoritative_snapshot().media_ready
            assert pair.ingress_started.is_set()
            await asyncio.wait_for(pair.rtp_started.wait(), 1.0)
            await asyncio.wait_for(pair.rtcp_started.wait(), 1.0)
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item.value
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == transport.entity_id
            }
            assert facets["srtp_keys_ready"] is True
            assert facets["srtp_rtp_ready"] is True
            assert facets["srtp_rtcp_ready"] is True
            provenance = [
                item for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == transport.entity_id
            ]
            assert {item.source_revision for item in provenance} == {snapshot.revision}
            await transport.aclose()

    asyncio.run(scenario())


def test_stage2_duplicate_start_shares_reply_and_close_wakes_handshake(monkeypatch) -> None:
    release = asyncio.Event()

    async def blocked_handshake(self, is_client: bool) -> None:
        del self, is_client
        await release.wait()

    monkeypatch.setattr(DTLSTransport, "_run_handshake", blocked_handshake)

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-close"):
            transport = DTLSTransport(webrtc_rs.Certificate())
            pair = _PairTransport()
            first = asyncio.create_task(transport.start(DTLSRole.Client, pair))
            await pair.ingress_started.wait()
            second = asyncio.create_task(transport.start(DTLSRole.Client, pair))
            await transport.aclose()
            results = await asyncio.gather(first, second, return_exceptions=True)
            assert all(isinstance(item, RuntimeError) for item in results)
            assert transport._runner.snapshot().state == "closed"
            assert all(handle.done() for handle in transport._child_handles())

    asyncio.run(scenario())


def test_stage2_fragment_and_pending_encrypted_budgets_are_explicit() -> None:
    reconstructor = HandshakeReconstructor()
    for sequence in range(MAX_FRAGMENTED_HANDSHAKES):
        handshake = SimpleNamespace(
            header=SimpleNamespace(
                handshake_type=HandshakeMessageType.ClientHello,
                message_sequence=sequence, length=2,
                fragment_offset=0, fragment_length=1,
            ),
            message=SimpleNamespace(marshal=lambda: b"x"),
        )
        assert reconstructor._complete_fragmented(None, handshake) is None
    overflow = SimpleNamespace(
        header=SimpleNamespace(
            handshake_type=HandshakeMessageType.ClientHello,
            message_sequence=MAX_FRAGMENTED_HANDSHAKES, length=2,
            fragment_offset=0, fragment_length=1,
        ),
        message=SimpleNamespace(marshal=lambda: b"x"),
    )
    with pytest.raises(HandshakeReconstructionOverflow, match="too many"):
        reconstructor._complete_fragmented(None, overflow)
    assert MAX_PENDING_ENCRYPTED_RECORDS == 64


def test_stage2_srtp_rejects_stream_admission_after_drain() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-admission"):
            session = Session(_keys(), observability_id="admission:rtp")
            await session.close()
            with pytest.raises(RuntimeError, match="admission rejected while closed"):
                await session.open_stream(123)

    asyncio.run(scenario())
