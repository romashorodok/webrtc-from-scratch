import asyncio
from types import SimpleNamespace
from typing import NoReturn

import pytest

from webrtc.dtls import DTLSRole
from webrtc.dtls.dtlstransport import DTLSLocal
from webrtc.ice import AgentRole, CandidatePairControllerEvent
from webrtc.ice.agent import CandidatePairController
from webrtc.peer_connection import PeerConnection
from webrtc.peer_connection_types import ConnectionRole
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc import Runtime
from webrtc.runtime_services import FailurePolicy
from webrtc.session_description import (
    MediaDescription,
    SessionDescription,
    SessionDescriptionAttr,
    SessionDescriptionAttrKey,
)


class FakeGatherer:
    def __init__(self, role=AgentRole.Controlling):
        self.role = role

    def get_role(self):
        return self.role


class FakeDTLSTransport:
    def __init__(self):
        self.starts = []
        self.enqueued = []

    def start(self, role, transport):
        self.starts.append((role, transport))

    async def enqueue_record(self, data):
        self.enqueued.append(data)


class FakePairTransport:
    def __init__(self):
        self.sent = []
        self._dtls_packet_ready = asyncio.Event()

    async def recv_dtls(self):
        await self._dtls_packet_ready.wait()
        return SimpleNamespace(data=b"\x16\xfe\xfd")

    def sendto(self, data):
        self.sent.append(data)


class FakePairController(ObservedComponent):
    def __init__(self):
        self.handlers = {}

    @event_loop
    def remove_all_listeners(self):
        pass

    @event_loop
    def on(self, event):
        def decorator(handler):
            self.handlers[event] = handler
            return handler

        return decorator

    @task(
        name="ice:candidate-pair-controller",
        kind="ice",
        metadata={"expected_long_running": True, "loop_role": "controller"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def start(self):
        await asyncio.Event().wait()

    async def start_managed(self):
        self._task_handle = self.start()
        return self._task_handle


def make_peer_connection_subject(role=AgentRole.Controlling):
    pc = PeerConnection.__new__(PeerConnection)
    pc.gatherer = FakeGatherer(role)
    pc._dtls_transport = FakeDTLSTransport()
    pc._transport = None
    pc._transport_ready = asyncio.Event()
    pc._current_remote_description = None
    pc._pending_remote_description = None
    return pc


def remote_description_with_setup(role: ConnectionRole) -> SessionDescription:
    desc = SessionDescription()
    media = MediaDescription("video", 9, ["UDP", "TLS", "RTP", "SAVPF"])
    media.add_attribute(
        SessionDescriptionAttr(SessionDescriptionAttrKey.ConnectionSetup, role.value)
    )
    desc.media_descriptions.append(media)
    return desc


def running_trace_by_name(runtime):
    return {trace["name"]: trace for trace in runtime.trace_live_running()}


def test_dtls_local_sends_records_through_ice_transport_sendto():
    async def scenario():
        transport = FakePairTransport()
        local = DTLSLocal(transport)

        await local.sendto(b"dtls-record")

        assert transport.sent == [b"dtls-record"]

    asyncio.run(scenario())


def test_nomination_startup_excludes_obsolete_dequeue_bridge_and_marks_long_running_tasks():
    async def scenario():
        runtime = Runtime(max_workers=1)
        pc = make_peer_connection_subject()
        controller = FakePairController()
        transport = FakePairTransport()

        async with runtime:
            await pc._PeerConnection__on_ice_pair_controller(controller)
            await controller.handlers[
                CandidatePairControllerEvent.NOMINATE_TRANSPORT
            ](transport)
            await asyncio.sleep(0)

            traces = running_trace_by_name(runtime)

            assert pc._dtls_transport.starts == [(DTLSRole.Client, transport)]
            assert "dtls:ice-pair-dequeue-handshake" not in traces
            assert {
                "ice:candidate-pair-controller",
                "dtls:ice-pair-queue-handshake",
            }.issubset(traces)

            controller_metadata = traces["ice:candidate-pair-controller"]["metadata"]
            queue_metadata = traces["dtls:ice-pair-queue-handshake"]["metadata"]
            assert controller_metadata["expected_long_running"] is True
            assert controller_metadata["loop_role"] == "controller"
            assert queue_metadata["expected_long_running"] is True
            assert queue_metadata["loop_role"] == "receive"

        assert runtime.trace_live_running() == []

    asyncio.run(scenario())


def test_candidate_pair_controller_close_owns_start_handle_and_is_retryable():
    class Selector:
        def __init__(self):
            self.close_entered = asyncio.Event()
            self.close_release = asyncio.Event()

        async def aclose(self):
            self.close_entered.set()
            await self.close_release.wait()

    class Subject(CandidatePairController):
        def __init__(self):
            super(CandidatePairController, self).__init__()
            self._task_handle = None
            self._close_task = None
            self._closing = False
            self._closed = False
            self._CandidatePairController__selector = Selector()
            self.started = asyncio.Event()
            self.stopped = asyncio.Event()

        @task(name="test:candidate-controller", kind="ice")
        async def start(self) -> NoReturn:
            self.started.set()
            try:
                await asyncio.Event().wait()
                raise AssertionError("unreachable")
            finally:
                self.stopped.set()

    async def scenario():
        async with Runtime() as runtime:
            controller = Subject()
            task_handle = await controller.start_managed()
            assert controller._task_handle is task_handle
            await controller.started.wait()

            first_close = asyncio.create_task(controller.aclose())
            await controller._CandidatePairController__selector.close_entered.wait()
            first_close.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first_close

            assert controller.stopped.is_set()
            controller._CandidatePairController__selector.close_release.set()
            await controller.aclose()
            assert controller._closed
            assert controller._task_handle is None
            assert task_handle.done()
            assert runtime.root_context is not None
            assert runtime.task_registry.get(runtime.root_context.task_id) is not None

    asyncio.run(scenario())


def test_sdp_setup_role_matches_dtls_start_role_for_ice_role():
    controlling_pc = make_peer_connection_subject(AgentRole.Controlling)
    controlled_pc = make_peer_connection_subject(AgentRole.Controlled)

    assert controlling_pc._PeerConnection__get_sdp_role() is ConnectionRole.Actpass
    controlled_pc._pending_remote_description = remote_description_with_setup(
        ConnectionRole.Actpass
    )
    assert controlled_pc._PeerConnection__get_sdp_role() is ConnectionRole.Passive


def test_dtls_role_uses_remote_sdp_setup_attribute():
    pc = make_peer_connection_subject(AgentRole.Controlling)

    pc._current_remote_description = remote_description_with_setup(ConnectionRole.Active)
    assert pc._PeerConnection__get_dtls_role() is DTLSRole.Server

    pc._current_remote_description = remote_description_with_setup(ConnectionRole.Passive)
    assert pc._PeerConnection__get_dtls_role() is DTLSRole.Client
