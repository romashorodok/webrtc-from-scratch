from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from queue import Full, Queue
from threading import RLock
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

@dataclass(frozen=True, slots=True)
class SrtpKeysReady(DomainEvent):
    profile: str | None = None

@dataclass(frozen=True, slots=True)
class SrtpSessionReady(DomainEvent):
    protocol: str = "rtp"

@dataclass(frozen=True, slots=True)
class SrtpStreamCreated(DomainEvent):
    ssrc: int = 0
    protocol: str = "rtp"

@dataclass(frozen=True, slots=True)
class SrtpPacketDelivery(DomainEvent):
    ssrc: int = 0
    protocol: str = "rtp"
    delivered: bool = True

class DomainEventObserver(Protocol):
    def on_domain_event(self, event: DomainEvent) -> None: ...


class DomainEventDispatcher:
    """Bounded synchronous fan-out; publishing never waits or affects protocol work."""
    def __init__(self, observers=(), *, capacity: int = 1024) -> None:
        self.observers = list(observers)
        self.capacity = max(1, capacity)
        self.diagnostics = Counter()
        self._inflight = 0
        self._lock = RLock()

    def publish(self, event: DomainEvent) -> bool:
        with self._lock:
            if self._inflight >= self.capacity:
                self.diagnostics["dropped"] += 1
                return False
            self._inflight += 1
        try:
            for observer in tuple(self.observers):
                try: observer.on_domain_event(event)
                except Exception: self.diagnostics["observer_failures"] += 1
            return True
        finally:
            with self._lock: self._inflight -= 1


_default_dispatcher = DomainEventDispatcher()

def emit_domain_event(event_type, **values: Any) -> bool:
    context = current_execution_context()
    if context is None: return False
    return _default_dispatcher.publish(event_type(context=context, **values))

def get_domain_event_dispatcher() -> DomainEventDispatcher:
    return _default_dispatcher
