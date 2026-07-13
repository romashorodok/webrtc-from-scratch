from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from webrtc.peer_connection import PeerConnection, PeerConnectionTaskFailed
from webrtc.performance import ObservedComponent, task
from webrtc import Runtime
from webrtc.runtime_services import FailurePolicy, ScopeState


class FakeGatherer:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    def on(self, *_args) -> None:
        pass

    async def start(self) -> None:
        self.order.append("ice.start")

    async def dial(self) -> None:
        self.order.append("ice.dial")

    async def accept(self) -> None:
        self.order.append("ice.accept")

    async def aclose(self) -> None:
        self.order.append("ice.close")

    async def aclose_controllers(self) -> None:
        self.order.append("ice.controllers.close")


class FakeDtls:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    async def aclose(self) -> None:
        self.order.append("dtls.close")


class FakeAttachment:
    def __init__(self, name: str, order: list[str]) -> None:
        self.name = name
        self.order = order

    async def start(self) -> None:
        self.order.append(f"{self.name}.start")

    async def stop(self) -> None:
        self.order.append(f"{self.name}.stop")

    async def aclose(self) -> None:
        self.order.append(f"{self.name}.close")


class FailingProtocol(ObservedComponent):
    @task(name="protocol.fail", kind="protocol", failure=FailurePolicy.FAIL_CONNECTION)
    async def run(self) -> None:
        raise LookupError("protocol failed")


def _subject(order: list[str]) -> PeerConnection:
    pc = PeerConnection()
    pc.gatherer = FakeGatherer(order)
    pc._dtls_transport = FakeDtls(order)
    return pc


def test_nested_lifetime_keeps_runtime_active_for_ordered_domain_cleanup(monkeypatch):
    async def scenario() -> None:
        order: list[str] = []
        pc = _subject(order)
        pc.attach_signaling(FakeAttachment("signaling", order))
        pc.attach_media_source(FakeAttachment("media", order))
        runtime = Runtime(scope_id=pc.id)

        class Logger:
            def write_events_sync(self, events) -> None:
                assert runtime.state is ScopeState.ACTIVE
                order.append(f"log.flush:{len(events)}")

        monkeypatch.setattr("webrtc.peer_components.get_logger", lambda: Logger())
        async with runtime:
            async with pc:
                pc.log_inbox.put_nowait(SimpleNamespace(message="last"))

        assert runtime.state is ScopeState.CLOSED
        assert order.index("signaling.stop") < order.index("dtls.close")
        assert order.index("media.stop") < order.index("dtls.close")
        assert order.index("ice.controllers.close") < order.index("dtls.close")
        assert order.index("dtls.close") < order.index("ice.close")
        assert order.index("ice.close") < order.index("log.flush:1")

    asyncio.run(scenario())


def test_peer_iteration_gets_one_terminal_event_and_waiters_wake():
    async def scenario() -> None:
        order: list[str] = []
        pc = _subject(order)
        events = []

        async def consume() -> None:
            async for event in pc:
                events.append(event)

        async with Runtime(scope_id=pc.id):
            async with pc:
                consumer = asyncio.create_task(consume())
            await pc.wait_closed()
            await consumer
            await pc.aclose()

        terminal = [event for event in events if isinstance(event, dict) and event.get("type") == "closed"]
        assert len(terminal) == 1

    asyncio.run(scenario())


def test_fail_connection_observer_preserves_original_task_exception():
    async def scenario() -> None:
        pc = _subject([])
        protocol = FailingProtocol()
        async with Runtime(scope_id=pc.id):
            async with pc:
                failed = protocol.run()
                with pytest.raises(LookupError, match="protocol failed"):
                    await failed
                assert isinstance(failed.exception(), LookupError)
                await asyncio.wait_for(pc.wait_closed(), 1.0)
                events = [event async for event in pc]
                assert any(isinstance(event, PeerConnectionTaskFailed) for event in events)
                assert pc.state == "error"

    asyncio.run(scenario())


def test_peer_cleanup_failure_is_truthful_retryable_and_preserves_body_error():
    class FlakyDtls(FakeDtls):
        def __init__(self, order):
            super().__init__(order)
            self.attempts = 0

        async def aclose(self) -> None:
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("cleanup failed")
            await super().aclose()

    async def scenario() -> None:
        pc = _subject([])
        pc._dtls_transport = FlakyDtls([])
        async with Runtime(scope_id=pc.id):
            with pytest.raises(BaseExceptionGroup) as caught:
                async with pc:
                    raise ValueError("body failed")
            flattened = caught.value.exceptions
            assert any(isinstance(error, ValueError) for error in flattened)
            assert any(isinstance(error, OSError) for error in flattened)
            assert pc.closed is False
            assert pc._closing is True
            assert not pc._closed_event.is_set()
            assert pc.event_inbox.closed is False

            await pc.aclose("retry")
            assert pc.closed is True
            assert pc._dtls_transport.attempts == 2
            assert pc._closed_event.is_set()

    asyncio.run(scenario())
