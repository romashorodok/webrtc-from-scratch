from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from queue import Empty, Full, Queue
import asyncio
import threading
from typing import Any, Protocol

from .runtime_services import ExecutionContext, current_execution_context


@dataclass(frozen=True, slots=True)
class DomainEvent:
    context: ExecutionContext
    timestamp: float = field(default_factory=time.time)

@dataclass(frozen=True, slots=True)
class IcePairNominated(DomainEvent):
    local_address: str | None = None
    remote_address: str | None = None
    pair_id: str | None = None

@dataclass(frozen=True, slots=True)
class SrtpKeysReady(DomainEvent):
    # The current SRTP implementation always uses the one profile selected by
    # the server hello.  Keep the semantic event useful instead of publishing
    # an unexplained null after key derivation succeeds.
    profile: str = "SRTP_AES128_CM_HMAC_SHA1_80"

@dataclass(frozen=True, slots=True)
class SrtpSessionReady(DomainEvent):
    protocol: str = "rtp"
    session_id: str | None = None

@dataclass(frozen=True, slots=True)
class SrtpStreamCreated(DomainEvent):
    ssrc: int = 0
    protocol: str = "rtp"
    session_id: str | None = None
    stream_id: str | None = None
    ssrc_id: str | None = None
    stream_count: int = 1

@dataclass(frozen=True, slots=True)
class SrtpPacketDelivery(DomainEvent):
    ssrc: int = 0
    protocol: str = "rtp"
    delivered: bool = True
    failure_reason: str | None = None
    session_id: str | None = None
    stream_id: str | None = None


@dataclass(frozen=True, slots=True)
class PeerStateChanged(DomainEvent):
    lifecycle: str = "new"
    signaling: str = "stable"
    connection: str = "new"


@dataclass(frozen=True, slots=True)
class IceStateChanged(DomainEvent):
    gathering: str = "new"
    connection: str = "new"


@dataclass(frozen=True, slots=True)
class TransportStateChanged(DomainEvent):
    lifecycle: str = "new"
    selected: bool = False
    pair_id: str | None = None


@dataclass(frozen=True, slots=True)
class DtlsStateChanged(DomainEvent):
    state: str = "new"
    revision: int = 0


@dataclass(frozen=True, slots=True)
class TransceiverStateChanged(DomainEvent):
    transceiver_id: str = "default"
    direction: str = "inactive"
    active: bool = False
    lifecycle: str = "inactive"


@dataclass(frozen=True, slots=True)
class MediaStateChanged(DomainEvent):
    media_id: str = "default"
    direction: str = "recv"
    active: bool = False
    lifecycle: str = "inactive"


@dataclass(frozen=True, slots=True)
class QueueStateChanged(DomainEvent):
    queue_id: str = "default"
    queue_instance_id: str | None = None
    depth: int = 0
    high_water: int = 0


@dataclass(frozen=True, slots=True)
class WorkerLaneStateChanged(DomainEvent):
    lane_id: str = "default"
    lane_instance_id: str | None = None
    queued: int = 0
    running: bool = False


@dataclass(frozen=True, slots=True)
class TraceHealthChanged(DomainEvent):
    admitted: bool = True
    subscriber_count: int = 0
    journal_depth: int = 0
    dispatcher_drops: int = 0
    dispatcher_observer_failures: int = 0

class DomainEventObserver(Protocol):
    def on_domain_event(self, event: DomainEvent) -> None: ...


class DomainEventDispatcher:
    """Bounded synchronous fan-out; publishing never waits or affects protocol work."""
    def __init__(self, observers=(), *, capacity: int = 1024) -> None:
        self.observers = list(observers)
        self.capacity = max(1, capacity)
        self.diagnostics = Counter()
        self._diagnostic_sinks: list[Counter[str]] = []
        self._owner_thread: int | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ingress: Queue[DomainEvent] = Queue(maxsize=self.capacity)
        self._drain_scheduled = False
        self._delivery_depth = 0

    def publish(self, event: DomainEvent) -> bool:
        current = threading.get_ident()
        if self._owner_thread is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = None
            self._owner_thread = current
        if current == self._owner_thread:
            if self._delivery_depth >= self.capacity:
                self._diagnostic("dropped")
                return False
            self._delivery_depth += 1
            try:
                self._deliver(event)
            finally:
                self._delivery_depth -= 1
            return True
        # Exceptional external-thread producers enqueue only immutable events.
        # Queue/wakeup internals may lock; projection records never do.
        if self._loop is None or self._loop.is_closed():
            self._diagnostic("external_without_loop")
            return False
        try:
            self._ingress.put_nowait(event)
        except Full:
            self._diagnostic("dropped")
            return False
        if not self._drain_scheduled:
            self._drain_scheduled = True
            self._loop.call_soon_threadsafe(self._drain_ingress)
        return True

    def _deliver(self, event: DomainEvent) -> None:
        for observer in tuple(self.observers):
            try:
                observer.on_domain_event(event)
            except Exception:
                self._diagnostic("observer_failures")

    def _diagnostic(self, name: str) -> None:
        self.diagnostics[name] += 1
        exported_name = f"domain_dispatcher_{name}"
        for sink in tuple(self._diagnostic_sinks):
            sink[exported_name] += 1

    def add_diagnostic_sink(self, diagnostics: Counter[str]) -> None:
        if not any(sink is diagnostics for sink in self._diagnostic_sinks):
            self._diagnostic_sinks.append(diagnostics)

    def remove_diagnostic_sink(self, diagnostics: Counter[str]) -> None:
        for index, sink in enumerate(self._diagnostic_sinks):
            if sink is diagnostics:
                del self._diagnostic_sinks[index]
                break

    def add_observer(self, observer: DomainEventObserver) -> None:
        if observer not in self.observers:
            self.observers.append(observer)

    def remove_observer(self, observer: DomainEventObserver) -> None:
        try:
            self.observers.remove(observer)
        except ValueError:
            pass

    def _drain_ingress(self) -> None:
        self._drain_scheduled = False
        while True:
            try:
                event = self._ingress.get_nowait()
            except Empty:
                return
            self._deliver(event)


_default_dispatcher = DomainEventDispatcher()

def emit_domain_event(event_type, **values: Any) -> bool:
    context = current_execution_context()
    if context is None: return False
    return _default_dispatcher.publish(event_type(context=context, **values))

def get_domain_event_dispatcher() -> DomainEventDispatcher:
    return _default_dispatcher
