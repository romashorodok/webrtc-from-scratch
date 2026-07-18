import asyncio
import inspect
from types import SimpleNamespace

import pytest

from webrtc.dtls import DTLSRole
from webrtc.dtls.dtlstransport import DTLSLocal
from webrtc.ice import AgentRole
from webrtc.ice.agent import CandidatePairController
from webrtc.peer_connection import PeerConnection
from webrtc.peer_connection_types import ConnectionRole
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc import Runtime
from webrtc.runtime_services import FailurePolicy
from webrtc.state_machine import TransitionCommit
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

    async def start(self, role, transport):
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


def running_trace_by_name(runtime):
    return {trace["name"]: trace for trace in runtime.trace_live_running()}


def test_dtls_local_sends_records_through_ice_transport_sendto():
    async def scenario():
        transport = FakePairTransport()
        local = DTLSLocal(transport)

        await local.sendto(b"dtls-record")

        assert transport.sent == [b"dtls-record"]

    asyncio.run(scenario())


def test_candidate_pair_controller_close_owns_start_handle_and_is_retryable():
    source = inspect.getsource(CandidatePairController)
    assert "start_pump" in source
    assert "_receive_handle" in source
    assert "_close_task" not in source
    assert "asyncio.create_task" not in source
