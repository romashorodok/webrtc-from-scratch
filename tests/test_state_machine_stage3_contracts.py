import asyncio
import socket
import time
from types import SimpleNamespace

import pytest

from webrtc import Runtime
from webrtc.ice.agent import (
    BindingRequestCacheRegistry, CandidatePair, CandidatePairController,
    CandidatePairTransport, ControllingSelector, ControlledSelector, Agent, AgentOptions,
    CandidatePairRegistry,
)
from webrtc.ice import stun
from webrtc.ice.candidate_base import CandidateBase
from webrtc.peer_connection import ICEGatherer, ICETransport, PeerConnection
from webrtc.ice.net.types import Address, LocalCandidate, Packet, RemoteCandidate
from webrtc.ice.net.udp_mux import Interceptor, MultiUDPMux
from webrtc.state_machine import TransitionCommit
from webrtc.state_machine import TransitionController
from webrtc.runtime_services import Borrowed


class _FakeAgent:
    def __init__(self, release: asyncio.Event | None = None) -> None:
        self.release = release
        self.gather_calls = 0
        self.closed = False
        self.dialed = False

    async def gather_candidates(self) -> None:
        self.gather_calls += 1
        if self.release is not None:
            await self.release.wait()

    def get_local_credentials(self):
        return "ufrag", "password"

    def get_role(self):
        return None

    def dial(self) -> None:
        self.dialed = True

    async def aclose(self) -> None:
        self.closed = True

    async def aclose_controllers(self) -> None:
        return None


def test_controller_start_waits_for_receive_effect_not_machine_revision() -> None:
    class Conn:
        def __init__(self) -> None:
            self.release = asyncio.Event()

        def sendto(self, _data) -> None:
            return None

        async def recvfrom(self):
            await self.release.wait()
            raise RuntimeError("released")

    class Mux:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def intercept(self, _remote):
            return self.conn

    class Owner:
        async def _controller_failed(self, error, commit):
            del error, commit

        async def _controller_nominated(self, transport, commit):
            del transport, commit

    async def scenario() -> None:
        transition_controller = TransitionController(timeout=1)
        transition_controller.pause_at(
            "candidate-pair-controller", to_state="checking",
            phase="after_commit",
        )
        async with Runtime(
            scope_id="controller-receive-ready",
            transition_controller=Borrowed(transition_controller),
        ):
            conn = Conn()
            local_raw, remote_raw = CandidateBase(), CandidateBase()
            local_raw.set_address("127.0.0.1")
            local_raw.set_port(5000)
            local_raw.set_priority(100)
            remote_raw.set_address("127.0.0.2")
            remote_raw.set_port(5001)
            remote_raw.set_priority(90)
            pair = CandidatePair(
                "local", "local-password", "remote", "remote-password",
                LocalCandidate(local_raw, Mux(conn)),
                RemoteCandidate(remote_raw, conn),
            )
            snapshot = pair._runner.snapshot()
            while snapshot.state != "waiting":
                snapshot = await pair._runner.wait_for_revision(snapshot.revision)
            registry = CandidatePairRegistry()
            registry.append(pair)
            controller = CandidatePairController(
                pair, ControlledSelector(registry, 1), 1, owner=Owner(),
            )

            starting = asyncio.create_task(controller.start_managed())
            checkpoint = await transition_controller.wait_until(
                "candidate-pair-controller", "checking", phase="after_commit",
            )
            assert controller._runner.snapshot().state == "checking"
            assert controller._receive_handle is None
            assert not starting.done()

            transition_controller.release(checkpoint.checkpoint_id)
            handle = await asyncio.wait_for(starting, 1)
            assert handle is controller._receive_handle
            await controller.aclose()
            await pair.aclose()

    asyncio.run(scenario())


def test_stage3_gather_is_one_runtime_owned_command_with_shared_completion() -> None:
    async def scenario() -> None:
        release = asyncio.Event()
        async with Runtime(scope_id="stage3-gather") as runtime:
            gatherer = ICEGatherer()
            fake = _FakeAgent(release)

            async def create_agent(*args, **kwargs):
                return fake

            gatherer._ICEGatherer__create_agent = create_agent
            first = asyncio.create_task(gatherer.gather())
            second = asyncio.create_task(gatherer.gather())
            while fake.gather_calls == 0:
                await asyncio.sleep(0)
            assert gatherer._runner.snapshot().state == "gathering"
            assert gatherer._gather_handle is not None
            assert gatherer._gather_handle.owner_entity_id == gatherer.entity_id
            release.set()
            await asyncio.gather(first, second)
            snapshot = runtime.projection.machines.get(gatherer.entity_id)
            assert fake.gather_calls == 1
            assert snapshot.state == "complete"
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item.value
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == gatherer.entity_id
            }
            assert facets == {}  # lifecycle exists only on the machine
            await gatherer.aclose()
            assert fake.closed

    asyncio.run(scenario())


def test_stage3_gather_failure_commits_gatherer_and_public_ice_failure() -> None:
    class FailingAgent(_FakeAgent):
        def __init__(self, owner) -> None:
            super().__init__()
            self.owner = owner
            self.entity_id = "ice-agent:stage3-gather-failure"

        async def gather_candidates(self) -> None:
            raise OSError("candidate bind failed")

        async def fail(self, error, *, cause_id=None):
            commit = TransitionCommit(
                self.entity_id, "ice-agent", "waiting-remote", "failed",
                1, cause_id, 1,
            )
            await self.owner._on_agent_failure(error, commit)
            return commit

    async def scenario() -> None:
        observed: list[TransitionCommit] = []

        class Owner:
            async def _ice_failed(self, error, commit):
                assert isinstance(error, OSError)
                observed.append(commit)

        async with Runtime(scope_id="stage3-gather-failure") as runtime:
            gatherer = ICEGatherer(owner=Owner())

            async def create_agent(*args, **kwargs):
                return FailingAgent(gatherer)

            gatherer._ICEGatherer__create_agent = create_agent
            with pytest.raises(OSError, match="candidate bind failed"):
                await gatherer.gather()
            assert runtime.projection.machines.get(gatherer.entity_id).state == "failed"
            assert observed[0].machine_type == "ice-agent"
            assert observed[0].to_state == "failed"
            await gatherer.aclose()

    asyncio.run(scenario())


def test_stage3_nomination_is_the_only_selected_transport_cause_and_facets_agree() -> None:
    async def scenario() -> None:
        selected = []

        class Owner:
            async def _ice_nominated(self, transport, commit):
                selected.append((transport, commit))

        async with Runtime(scope_id="stage3-nominate") as runtime:
            gatherer = ICEGatherer(owner=Owner())
            fake = _FakeAgent()
            gatherer._ICEGatherer__agent = fake
            await gatherer.dial()
            pair_entity = "candidate-pair:exact"
            pair = CandidatePair.__new__(CandidatePair)
            pair.entity_id = pair_entity
            transport = CandidatePairTransport(
                SimpleNamespace(sendto=lambda *_: None), pair,
            )
            nomination = TransitionCommit(
                pair_entity, "candidate-pair", "succeeded", "nominated",
                3, "use-candidate:1", 1,
            )
            await gatherer._on_nominated(transport, nomination)
            assert len(selected) == 1
            assert selected[0][0] is transport
            assert selected[0][1] is nomination
            await gatherer.aclose()

    asyncio.run(scenario())


def test_stage3_packet_overflow_is_bounded_and_class_specific() -> None:
    async def scenario() -> None:
        queue = Interceptor(maxsize=1)
        queue.put_nowait(Packet(Address("127.0.0.1", 1), b"\x80\x60media"))
        queue.put_nowait(Packet(Address("127.0.0.1", 1), b"\x80\x61fresh"))
        assert queue._queue.qsize() == 1
        assert queue.dropped_media == 1
        stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42"
        with pytest.raises(asyncio.QueueFull):
            queue.put_nowait(Packet(Address("127.0.0.1", 1), stun))
        assert queue.rejected_control == 1
        with pytest.raises(asyncio.QueueFull, match="control ingress overflow"):
            await queue.get()

    asyncio.run(scenario())


def test_stage3_controlled_use_candidate_commits_success_before_nomination() -> None:
    class Conn:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def sendto(self, data) -> None:
            self.sent.append(bytes(data))

    class Mux:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def intercept(self, _remote):
            return self.conn

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-controlled-nomination") as runtime:
            conn = Conn()
            local_raw, remote_raw = CandidateBase(), CandidateBase()
            local_raw.set_address("127.0.0.1")
            local_raw.set_port(5000)
            local_raw.set_priority(100)
            remote_raw.set_address("127.0.0.2")
            remote_raw.set_port(5001)
            remote_raw.set_priority(90)
            pair = CandidatePair(
                "local", "local-password", "remote", "remote-password",
                LocalCandidate(local_raw, Mux(conn)), RemoteCandidate(remote_raw, conn),
            )
            while pair._runner.snapshot().state != "waiting":
                await asyncio.sleep(0)
            registry = CandidatePairRegistry()
            registry.append(pair)
            observed: list[TransitionCommit] = []

            async def nominated(candidate, success):
                assert candidate is pair
                assert success.to_state == "succeeded"
                observed.append(await pair.mark_nominated(success))

            selector = ControlledSelector(registry, 1, nominated)
            request = stun.Message(stun.MessageType(
                stun.Method.Binding, stun.MessageClass.Request,
            ))
            request.add_attribute(stun.UseCandidate())
            await selector.on_binding_success(pair, conn, request)

            transitions = [
                item.to_state for item in runtime.projection.machines.transition_snapshots()
                if item.entity_id == pair.entity_id
            ]
            assert transitions[-3:] == ["in-progress", "succeeded", "nominated"]
            assert observed[0].entity_id == pair.entity_id
            assert observed[0].revision == pair._runner.snapshot().revision
            await pair.aclose()

    asyncio.run(scenario())


def test_stage3_stun_overflow_causally_fails_controller_and_pair() -> None:
    class Conn:
        def __init__(self) -> None:
            self.ingress = Interceptor(maxsize=1)

        def sendto(self, _data) -> None:
            return None

        async def recvfrom(self):
            return await self.ingress.get()

    class Mux:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def intercept(self, _remote):
            return self.conn

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-stun-overflow"):
            conn = Conn()
            local_raw, remote_raw = CandidateBase(), CandidateBase()
            local_raw.set_address("127.0.0.1")
            local_raw.set_port(5000)
            local_raw.set_priority(100)
            remote_raw.set_address("127.0.0.2")
            remote_raw.set_port(5001)
            remote_raw.set_priority(90)
            pair = CandidatePair(
                "local", "local-password", "remote", "remote-password",
                LocalCandidate(local_raw, Mux(conn)), RemoteCandidate(remote_raw, conn),
            )
            while pair._runner.snapshot().state != "waiting":
                await asyncio.sleep(0)
            registry = CandidatePairRegistry()
            registry.append(pair)
            failure = asyncio.Event()

            class Owner:
                async def _controller_failed(self, error, commit):
                    assert isinstance(error, asyncio.QueueFull)
                    assert commit.to_state == "failed"
                    failure.set()

                async def _controller_nominated(self, transport, commit):
                    del transport, commit

            controller = CandidatePairController(
                pair, ControlledSelector(registry, 1), 1, owner=Owner(),
            )
            await controller.start_managed()
            conn.ingress.put_nowait(Packet(Address("127.0.0.2", 5001), b"media"))
            with pytest.raises(asyncio.QueueFull):
                conn.ingress.put_nowait(Packet(
                    Address("127.0.0.2", 5001),
                    b"\x00\x01\x00\x00\x21\x12\xa4\x42",
                ))
            await asyncio.wait_for(failure.wait(), 1.0)
            while controller._runner.snapshot().state != "stopped":
                await asyncio.sleep(0)
            assert pair._runner.snapshot().state == "failed"
            await controller.aclose()
            await pair.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("nominate", [False, True], ids=["post-success", "post-nomination"])
def test_stage3_receive_failure_propagates_after_pair_success_or_nomination(
    nominate: bool,
) -> None:
    class Conn:
        def __init__(self) -> None:
            self.release = asyncio.Event()

        def sendto(self, _data) -> None:
            return None

        async def recvfrom(self):
            await self.release.wait()
            raise ValueError("inbound STUN failure")

    class Mux:
        def __init__(self, conn: Conn) -> None:
            self.conn = conn

        def intercept(self, _remote):
            return self.conn

    class Selector:
        _nominate = None

        def start(self) -> None:
            return None

        async def send_ping_stun_message(self, pair, conn) -> None:
            return None

        async def aclose(self) -> None:
            return None

    async def scenario() -> None:
        async with Runtime(scope_id=f"stage3-post-{'nomination' if nominate else 'success'}") as runtime:
            conn = Conn()
            local_raw, remote_raw = CandidateBase(), CandidateBase()
            local_raw.set_address("127.0.0.1")
            local_raw.set_port(5000)
            local_raw.set_priority(100)
            remote_raw.set_address("127.0.0.2")
            remote_raw.set_port(5001)
            remote_raw.set_priority(90)
            pair = CandidatePair(
                "local", "local-password", "remote", "remote-password",
                LocalCandidate(local_raw, Mux(conn)), RemoteCandidate(remote_raw, conn),
            )
            while pair._runner.snapshot().state != "waiting":
                await asyncio.sleep(0)
            success = await pair.mark_succeeded("connectivity-success")
            observed: list[tuple[BaseException, TransitionCommit]] = []

            class Owner:
                async def _controller_failed(self, error, commit):
                    observed.append((error, commit))

                async def _controller_nominated(self, transport, commit):
                    del transport, commit

            selector = Selector()
            controller = CandidatePairController(
                pair, selector, 1, owner=Owner(),
            )
            await controller.start_managed()
            if nominate:
                assert selector._nominate is not None
                await selector._nominate(pair, success)
                while controller._runner.snapshot().state != "forwarding":
                    await asyncio.sleep(0)
                pair_nomination = pair._nomination_commit
                assert pair_nomination is not None
                controller_nomination = next(
                    item for item in runtime.projection.machines.transition_snapshots()
                    if item.entity_id == controller.entity_id
                    and item.to_state == "nominated"
                )
                assert controller_nomination.revision != pair_nomination.revision
                controller_facets = {
                    item.facet_id.rsplit(":", 1)[-1]: item.value
                    for item in runtime.projection.facets.snapshots()
                    if item.owner_entity_id == controller.entity_id
                }
                assert controller_facets["nomination_entity_id"] == pair.entity_id
                assert controller_facets["nomination_revision"] == pair_nomination.revision

            conn.release.set()
            while controller._runner.snapshot().state != "stopped":
                await asyncio.sleep(0)
            assert pair._runner.snapshot().state == "failed"
            assert isinstance(observed[0][0], ValueError)
            assert observed[0][1].to_state == "failed"
            await controller.aclose()
            await pair.aclose()

    asyncio.run(scenario())


def test_stage3_selected_transport_preserves_nomination_cause_and_terminal_order() -> None:
    class Gatherer:
        def get_role(self):
            return None

    class Transport:
        entity_id = "pair"
        closed = False

        async def aclose(self):
            self.closed = True

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-selected") as runtime:
            selected = ICETransport(Gatherer())
            transport = Transport()
            from webrtc.state_machine import TransitionCommit
            nomination = TransitionCommit(
                "pair", "candidate-pair", "succeeded", "nominated",
                4, "nomination-7", 1,
            )
            await selected.bind(transport, nomination)
            snapshot = runtime.projection.machines.get(selected.entity_id)
            assert snapshot.state == "ready"
            assert [
                op.to_state for op in runtime.projection.machines.transition_snapshots()
                if op.entity_id == selected.entity_id
            ] == ["selecting", "ready"]
            assert all(
                op.cause_id == "nomination-7"
                for op in runtime.projection.machines.transition_snapshots()
                if op.entity_id == selected.entity_id
            )
            await selected.aclose()
            assert transport.closed
            assert runtime.projection.machines.get(selected.entity_id) is None

    asyncio.run(scenario())


def test_stage3_udp_terminal_commit_waits_for_connection_lost() -> None:
    class Transport:
        def __init__(self, protocol):
            self.protocol = protocol

        def get_extra_info(self, name):
            if name == "sockname":
                return ("127.0.0.1", 4567)
            return None

        def close(self):
            asyncio.get_running_loop().call_soon(self.protocol.connection_lost, None)

    class EndpointLoop:
        def create_datagram_endpoint(self, factory, *, local_addr):
            async def create():
                protocol = factory()
                transport = Transport(protocol)
                protocol.connection_made(transport)
                return transport, protocol
            return create()

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-socket") as runtime:
            interface = SimpleNamespace(address=SimpleNamespace(value="127.0.0.1"))
            mux = MultiUDPMux([interface], EndpointLoop())
            await mux.accept()
            assert runtime.projection.machines.get(mux.entity_id).state == "active"
            await mux.aclose()
            transitions = [
                item.to_state
                for item in runtime.projection.machines.transition_snapshots()
                if item.entity_id == mux.entity_id
            ]
            assert transitions[-2:] == ["draining", "closed"]

    asyncio.run(scenario())


def test_stage3_dns_timeout_cancels_runtime_owned_worker(monkeypatch) -> None:
    class UDP:
        async def aclose(self):
            return None

    def slow_lookup(hostname):
        time.sleep(0.02)
        return "127.0.0.1"

    monkeypatch.setattr(socket, "gethostbyname", slow_lookup)

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-dns") as runtime:
            agent = Agent(AgentOptions([], UDP(), []), owner=SimpleNamespace())
            with pytest.raises(TimeoutError, match="timed out"):
                await agent._resolve_mdns("peer.local", timeout=0.001)
            assert runtime.projection.machines.get(agent.entity_id).state == "waiting-remote"
            await agent.aclose()

    asyncio.run(scenario())


def test_stage3_dns_success_reads_immutable_worker_outcome(monkeypatch) -> None:
    class UDP:
        async def aclose(self):
            return None

    monkeypatch.setattr(socket, "gethostbyname", lambda _hostname: "127.0.0.1")

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-dns-success"):
            agent = Agent(AgentOptions([], UDP(), []), owner=SimpleNamespace())
            assert await agent._resolve_mdns("peer.local") == "127.0.0.1"
            await agent.aclose()

    asyncio.run(scenario())


def test_stage3_udp_bind_failure_maps_to_failed_before_close() -> None:
    class EndpointLoop:
        def create_datagram_endpoint(self, factory, *, local_addr):
            async def create():
                raise OSError("bind refused")
            return create()

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-bind-failure") as runtime:
            interface = SimpleNamespace(address=SimpleNamespace(value="127.0.0.1"))
            mux = MultiUDPMux([interface], EndpointLoop())
            with pytest.raises(OSError, match="bind refused"):
                await mux.accept()
            assert runtime.projection.machines.get(mux.entity_id).state == "failed"
            await mux.aclose()
            assert runtime.projection.machines.get(mux.entity_id) is None

    asyncio.run(scenario())


def test_stage3_udp_partial_multibind_closes_and_awaits_created_socket() -> None:
    class Transport:
        def __init__(self, protocol) -> None:
            self.protocol = protocol
            self.closed = False

        def get_extra_info(self, name):
            if name == "sockname":
                return ("127.0.0.1", 4567)
            return None

        def close(self) -> None:
            self.closed = True
            asyncio.get_running_loop().call_soon(
                self.protocol.connection_lost, None,
            )

    class EndpointLoop:
        def __init__(self) -> None:
            self.calls = 0
            self.created: list[Transport] = []

        def create_datagram_endpoint(self, factory, *, local_addr):
            async def create():
                self.calls += 1
                if self.calls == 2:
                    raise OSError("second bind refused")
                protocol = factory()
                transport = Transport(protocol)
                self.created.append(transport)
                protocol.connection_made(transport)
                return transport, protocol
            return create()

    async def scenario() -> None:
        async with Runtime(scope_id="stage3-partial-bind") as runtime:
            loop = EndpointLoop()
            interfaces = [
                SimpleNamespace(address=SimpleNamespace(value="127.0.0.1")),
                SimpleNamespace(address=SimpleNamespace(value="127.0.0.2")),
            ]
            mux = MultiUDPMux(interfaces, loop)
            with pytest.raises(OSError, match="second bind refused"):
                await mux.accept()
            assert loop.created[0].closed
            assert loop.created[0].protocol._closed.done()
            assert not mux._socket_resources
            assert runtime.projection.machines.get(mux.entity_id).state == "failed"
            await mux.aclose()

    asyncio.run(scenario())


def test_stage3_runtime_owned_resource_closes_and_awaits_barrier() -> None:
    async def scenario() -> None:
        runtime = Runtime(scope_id="stage3-owned-resource")
        automatic_closed = asyncio.Event()
        automatic_close_calls = 0
        async with runtime:
            runtime.register_owner("resource-owner", epoch=1)
            closed = asyncio.Event()
            close_calls = 0

            def close() -> None:
                nonlocal close_calls
                close_calls += 1
                asyncio.get_running_loop().call_soon(closed.set)

            resource = runtime.register_owned_resource(
                close=close, wait_closed=closed.wait,
                owner_entity_id="resource-owner", owner_epoch=1,
                name="test-socket",
            )
            with pytest.raises(AssertionError, match="resource"):
                runtime.remove_owner("resource-owner", 1)
            await asyncio.gather(resource.aclose(), resource.aclose())
            assert resource.status == "closed"
            assert close_calls == 1
            runtime.remove_owner("resource-owner", 1)

            runtime.register_owner("automatic-owner", epoch=1)

            def automatic_close() -> None:
                nonlocal automatic_close_calls
                automatic_close_calls += 1
                asyncio.get_running_loop().call_soon(automatic_closed.set)

            runtime.register_owned_resource(
                close=automatic_close, wait_closed=automatic_closed.wait,
                owner_entity_id="automatic-owner", owner_epoch=1,
                name="automatic-socket",
            )
        assert automatic_closed.is_set()
        assert automatic_close_calls == 1

    asyncio.run(scenario())


def test_stage3_peer_close_terminates_selected_transport_before_nomination() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage3-pre-nomination-close") as runtime:
            peer = PeerConnection()
            selected_entity = peer._ice_transport.entity_id
            assert runtime.projection.machines.get(selected_entity).state == "new"
            await peer.aclose()
            assert runtime.projection.machines.get(selected_entity) is None

    asyncio.run(scenario())
