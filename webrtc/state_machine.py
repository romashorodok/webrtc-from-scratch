"""Neutral, single-writer async state-machine execution primitives.

This module intentionally has no dependency on tracing or WebRTC component
policy.  Components propose states; one runner validates and commits them at an
async safe point.  Observability may consume the immutable commit afterwards.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Generic, TypeVar

C = TypeVar("C")


class InvalidTransition(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MachineSpec:
    machine_type: str
    initial: str
    transitions: Mapping[str, frozenset[str]]
    terminal: frozenset[str]
    test_actions: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        transitions = {
            state: frozenset(destinations)
            for state, destinations in self.transitions.items()
        }
        states = set(transitions)
        for destinations in transitions.values():
            states.update(destinations)
        if not self.machine_type or self.initial not in states:
            raise ValueError("machine type and initial state must be declared")
        if not self.terminal <= states:
            raise ValueError("terminal states must be declared")
        object.__setattr__(self, "transitions", MappingProxyType(transitions))

    @property
    def states(self) -> frozenset[str]:
        result = set(self.transitions)
        for destinations in self.transitions.values():
            result.update(destinations)
        return frozenset(result)

    def validate(self, current: str, proposed: str) -> None:
        if proposed not in self.transitions.get(current, frozenset()):
            raise InvalidTransition(
                f"invalid {self.machine_type} transition: {current!r} -> {proposed!r}"
            )


@dataclass(frozen=True, slots=True)
class TransitionCommit:
    entity_id: str
    machine_type: str
    from_state: str
    to_state: str
    revision: int
    cause: object | None
    monotonic_ns: int


@dataclass(frozen=True, slots=True)
class TransitionOp:
    entity_id: str
    machine_type_id: int
    from_state_id: int
    to_state_id: int
    producer_id: int
    producer_seq: int
    cause_id: int | None
    monotonic_ns: int


@dataclass(frozen=True, slots=True)
class TransitionCheckpoint:
    checkpoint_id: int
    entity_id: str
    machine_type: str
    from_state: str
    to_state: str
    revision: int
    phase: str
    allowed_actions: frozenset[str] = frozenset()


class InjectedTransitionFailure(RuntimeError):
    pass


class NullTransitionController:
    """Production controller: calls are constant-time no-ops and never pause."""

    async def before_commit(self, checkpoint: TransitionCheckpoint) -> None:
        return None

    async def after_commit(self, checkpoint: TransitionCheckpoint) -> None:
        return None

    async def terminal(self, checkpoint: TransitionCheckpoint) -> None:
        return None

    def cancel_owner(self, entity_id: str) -> int:
        return 0

    def release_all(self) -> None:
        return None


@dataclass(slots=True)
class _PauseRule:
    machine_type: str
    to_state: str
    phase: str
    entity_id: str | None
    action: str | None
    reached: asyncio.Queue[TransitionCheckpoint] = field(default_factory=asyncio.Queue)


class TransitionController(NullTransitionController):
    """Deterministic test-only checkpoints around atomic transition commits.

    Pauses occur only where a runner explicitly awaits this controller.  The
    synchronous commit itself contains no await, so application invariants are
    never suspended halfway through mutation.
    """

    _PHASES = frozenset({"before_commit", "after_commit", "terminal"})

    def __init__(self, *, timeout: float = 5.0) -> None:
        self.timeout = timeout
        self._next_id = 1
        self._rules: list[_PauseRule] = []
        self._releases: dict[int, asyncio.Event] = {}
        self._active: dict[int, TransitionCheckpoint] = {}
        self._failures: dict[int, BaseException] = {}

    def pause_at(
        self,
        machine_type: str,
        *,
        to_state: str,
        phase: str = "before_commit",
        entity_id: str | None = None,
        action: str | None = None,
    ) -> None:
        if phase not in self._PHASES:
            raise ValueError(f"unsupported checkpoint phase: {phase}")
        self._rules.append(_PauseRule(machine_type, to_state, phase, entity_id, action))

    async def wait_until(
        self, machine_type: str, to_state: str, *, phase: str | None = None
    ) -> TransitionCheckpoint:
        for rule in self._rules:
            if (rule.machine_type == machine_type and rule.to_state == to_state
                    and (phase is None or rule.phase == phase)):
                return await asyncio.wait_for(rule.reached.get(), self.timeout)
        raise LookupError(f"no pause registered for {machine_type} -> {to_state}")

    def release(self, checkpoint_id: int) -> None:
        event = self._releases.get(checkpoint_id)
        if event is not None:
            event.set()

    def inject_failure(
        self, checkpoint_id: int, error: BaseException | None = None
    ) -> None:
        checkpoint = self._active.get(checkpoint_id)
        if checkpoint is None:
            raise LookupError(f"checkpoint {checkpoint_id} is not active")
        if "inject_failure" not in checkpoint.allowed_actions:
            raise PermissionError("machine does not permit failure injection")
        self._failures[checkpoint_id] = error or InjectedTransitionFailure(
            f"injected failure at checkpoint {checkpoint_id}"
        )
        self.release(checkpoint_id)

    def cancel_owner(self, entity_id: str) -> int:
        released = 0
        for checkpoint_id, event in tuple(self._releases.items()):
            checkpoint = self._active.get(checkpoint_id)
            if (checkpoint is not None and checkpoint.entity_id == entity_id
                    and "cancel_owner" in checkpoint.allowed_actions):
                event.set()
                released += 1
        return released

    def release_all(self) -> None:
        for event in tuple(self._releases.values()):
            event.set()

    async def _checkpoint(self, checkpoint: TransitionCheckpoint) -> None:
        for rule in self._rules:
            if not (
                rule.machine_type == checkpoint.machine_type
                and rule.to_state == checkpoint.to_state
                and rule.phase == checkpoint.phase
                and (rule.entity_id is None or rule.entity_id == checkpoint.entity_id)
            ):
                continue
            event = asyncio.Event()
            self._releases[checkpoint.checkpoint_id] = event
            self._active[checkpoint.checkpoint_id] = checkpoint
            await rule.reached.put(checkpoint)
            try:
                await asyncio.wait_for(event.wait(), self.timeout)
                failure = self._failures.pop(checkpoint.checkpoint_id, None)
                if failure is not None:
                    raise failure
            finally:
                self._releases.pop(checkpoint.checkpoint_id, None)
                self._active.pop(checkpoint.checkpoint_id, None)
            return

    async def before_commit(self, checkpoint: TransitionCheckpoint) -> None:
        await self._checkpoint(checkpoint)

    async def after_commit(self, checkpoint: TransitionCheckpoint) -> None:
        await self._checkpoint(checkpoint)

    async def terminal(self, checkpoint: TransitionCheckpoint) -> None:
        await self._checkpoint(checkpoint)

    def checkpoint(
        self, *, entity_id: str, machine_type: str, from_state: str,
        to_state: str, revision: int, phase: str,
        allowed_actions: frozenset[str] = frozenset(),
    ) -> TransitionCheckpoint:
        checkpoint = TransitionCheckpoint(
            self._next_id, entity_id, machine_type, from_state, to_state, revision, phase,
            allowed_actions,
        )
        self._next_id += 1
        return checkpoint


class AsyncStateMachineRunner(ABC, Generic[C]):
    """One-coroutine state owner with typed commands and atomic commits."""

    def __init__(
        self,
        spec: MachineSpec,
        *,
        entity_id: str,
        controller: NullTransitionController | None = None,
        projector: Callable[[TransitionCommit], None] | None = None,
    ) -> None:
        self.spec = spec
        self.entity_id = entity_id
        self.state = spec.initial
        self.revision = 0
        self.commands: asyncio.Queue[C] = asyncio.Queue()
        self.controller = controller or NullTransitionController()
        self.projector = projector

    async def next_cause(self) -> C:
        return await self.commands.get()

    @abstractmethod
    async def step(self, cause: C) -> str:
        """Handle one command and propose, but do not publish, the next state."""

    def commit(self, proposed: str, cause: C | None) -> TransitionCommit:
        """Validate and mutate synchronously in one event-loop turn."""
        previous = self.state
        self.spec.validate(previous, proposed)
        self.state = proposed
        self.revision += 1
        return TransitionCommit(
            self.entity_id, self.spec.machine_type, previous, proposed,
            self.revision, cause, time.monotonic_ns(),
        )

    def _checkpoint(self, commit: TransitionCommit, phase: str) -> TransitionCheckpoint:
        factory = getattr(self.controller, "checkpoint", None)
        if factory is not None:
            return factory(
                entity_id=commit.entity_id, machine_type=commit.machine_type,
                from_state=commit.from_state, to_state=commit.to_state,
                revision=commit.revision, phase=phase,
                allowed_actions=self.spec.test_actions,
            )
        return TransitionCheckpoint(
            0, commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.revision, phase, self.spec.test_actions,
        )

    async def reconcile_terminal(self, committed: TransitionCommit) -> None:
        """Join owned children/barriers before exposing a terminal checkpoint."""
        return None

    async def run(self) -> None:
        while self.state not in self.spec.terminal:
            cause = await self.next_cause()
            proposed = await self.step(cause)
            preview = TransitionCommit(
                self.entity_id, self.spec.machine_type, self.state, proposed,
                self.revision + 1, cause, 0,
            )
            self.spec.validate(self.state, proposed)
            await self.controller.before_commit(self._checkpoint(preview, "before_commit"))
            committed = self.commit(proposed, cause)
            if self.projector is not None:
                self.projector(committed)
            await self.controller.after_commit(self._checkpoint(committed, "after_commit"))
            if committed.to_state in self.spec.terminal:
                await self.reconcile_terminal(committed)
                await self.controller.terminal(self._checkpoint(committed, "terminal"))
