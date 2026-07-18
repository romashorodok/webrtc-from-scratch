"""Neutral, single-writer async state-machine execution primitives.

This module intentionally has no dependency on tracing or WebRTC component
policy.  Components propose states; one runner validates and commits them at an
async safe point.  Observability may consume the immutable commit afterwards.
"""

from __future__ import annotations

import asyncio
import time
from contextvars import ContextVar
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Generic, TypeVar

C = TypeVar("C")
P = TypeVar("P")
E = TypeVar("E")
R = TypeVar("R")
_observation_dispatch_active: ContextVar[bool] = ContextVar(
    "state_machine_observation_dispatch_active", default=False,
)


class ObservationReentrancy(RuntimeError):
    pass


def begin_observation_dispatch():
    return _observation_dispatch_active.set(True)


def end_observation_dispatch(token) -> None:
    _observation_dispatch_active.reset(token)


def _reject_observation_reentrancy() -> None:
    if _observation_dispatch_active.get():
        raise ObservationReentrancy(
            "observation dispatch cannot commit protocol state re-entrantly"
        )


def _dispatch_transition_sink(sink: Any, commit: Any, effects: Any) -> None:
    if getattr(sink, "__accepts_effects__", False):
        sink(commit, effects)
    else:
        sink(commit)


class InvalidTransition(ValueError):
    pass


class StaleMachineAccess(RuntimeError):
    pass


class WrongEventLoop(RuntimeError):
    pass


class MailboxClosed(RuntimeError):
    pass


class MailboxFull(RuntimeError):
    pass


class TerminalChildrenAlive(AssertionError):
    pass


class ReplyPort(Generic[R]):
    """Loop-owned, write-once reply used by retryable machine commands."""

    __slots__ = ("_future",)

    def __init__(self) -> None:
        self._future: asyncio.Future[R] = asyncio.get_running_loop().create_future()

    @property
    def done(self) -> bool:
        return self._future.done()

    def resolve(self, value: R) -> bool:
        if self._future.done():
            return False
        self._future.set_result(value)
        return True

    def reject(self, error: BaseException) -> bool:
        if self._future.done():
            return False
        self._future.set_exception(error)
        return True

    async def wait(self) -> R:
        return await asyncio.shield(self._future)


@dataclass(frozen=True, slots=True)
class MachineCommand(Generic[P, R]):
    kind: object
    command_id: int
    expected_epoch: int
    payload: P
    reply: ReplyPort[R] | None = None
    expected_revision: int | None = None
    producer_id: int | None = None
    producer_seq: int | None = None
    cause_id: int | str | None = None

    def __post_init__(self) -> None:
        if (self.producer_id is None) != (self.producer_seq is None):
            raise ValueError("producer_id and producer_seq must be supplied together")

    @property
    def deduplication_key(self) -> tuple[int, int, int] | None:
        """Return retry identity only when the caller explicitly supplied it.

        ``command_id`` is useful for local diagnostics and replies, but it is
        not retry evidence.  Treating every local command as retryable retains
        payload/results unnecessarily and can make a later, unrelated local
        command look like a duplicate after an owner restart.
        """
        if self.producer_id is None:
            return None
        return (self.expected_epoch, self.producer_id, self.producer_seq)


@dataclass(frozen=True, slots=True)
class _CachedFailure:
    """Traceback-free duplicate-command failure evidence."""

    error_type: type[BaseException]
    args: tuple[object, ...]
    text: str

    @classmethod
    def from_error(cls, error: BaseException) -> _CachedFailure:
        return cls(type(error), error.args, str(error))

    def materialize(self) -> BaseException:
        try:
            return self.error_type(*self.args)
        except Exception:
            return RuntimeError(self.text)


@dataclass(frozen=True, slots=True)
class PreparedTransition(Generic[E]):
    expected_state: str
    proposed_state: str
    effects: E
    cause_id: int | str | None = None
    expected_epoch: int | None = None
    expected_revision: int | None = None


@dataclass(frozen=True, slots=True)
class MachineSnapshot:
    entity_id: str
    machine_type: str
    epoch: int
    revision: int
    state: str
    terminal: bool


class BoundedMailbox(Generic[C]):
    """A close-aware bounded mailbox whose blocked producers are always woken."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("mailbox capacity must be positive")
        self.capacity = capacity
        self._items: deque[C] = deque()
        self._closed = False
        self._changed = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def depth(self) -> int:
        return len(self._items)

    def _signal(self) -> None:
        changed, self._changed = self._changed, asyncio.Event()
        changed.set()

    async def submit(self, item: C) -> None:
        while True:
            if self._closed:
                raise MailboxClosed("mailbox is closed")
            if len(self._items) < self.capacity:
                self._items.append(item)
                self._signal()
                return
            changed = self._changed
            await changed.wait()

    def try_submit(self, item: C) -> None:
        if self._closed:
            raise MailboxClosed("mailbox is closed")
        if len(self._items) >= self.capacity:
            raise MailboxFull(f"mailbox capacity {self.capacity} exceeded")
        self._items.append(item)
        self._signal()

    async def receive(self) -> C:
        while True:
            if self._items:
                item = self._items.popleft()
                self._signal()
                return item
            if self._closed:
                raise MailboxClosed("mailbox is closed")
            changed = self._changed
            await changed.wait()

    def close(self) -> tuple[C, ...]:
        if self._closed:
            return ()
        self._closed = True
        rejected = tuple(self._items)
        self._items.clear()
        self._signal()
        return rejected


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
    epoch: int = 1


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
        epoch: int = 1,
        mailbox_capacity: int = 32,
        dedupe_capacity: int = 128,
        controller: NullTransitionController | None = None,
        transition_sink: Callable[[TransitionCommit], None] | None = None,
    ) -> None:
        self.spec = spec
        self.entity_id = entity_id
        if epoch < 1:
            raise ValueError("machine epoch must be positive")
        if dedupe_capacity < 1:
            raise ValueError("dedupe capacity must be positive")
        self.epoch = epoch
        self._state = spec.initial
        self._revision = 0
        self.commands: BoundedMailbox[C] = BoundedMailbox(mailbox_capacity)
        self.controller = controller or NullTransitionController()
        self._transition_sink = transition_sink
        self._authority_sink: Callable[[TransitionCommit, Any], None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._dedupe_capacity = dedupe_capacity
        self._seen: dict[tuple[int, int, int], TransitionCommit | _CachedFailure] = {}
        self._seen_order: deque[tuple[int, int, int]] = deque()
        self._running = False
        self._changed = asyncio.Event()
        self._stopped_error: BaseException | None = None

    def _signal_change(self) -> None:
        changed, self._changed = self._changed, asyncio.Event()
        changed.set()

    def _assert_loop(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif loop is not self._loop:
            raise WrongEventLoop(f"{self.entity_id} is owned by a different event loop")

    @property
    def state(self) -> str:
        self._assert_loop()
        return self._state

    @property
    def revision(self) -> int:
        self._assert_loop()
        return self._revision

    def snapshot(self, *, expected_epoch: int | None = None) -> MachineSnapshot:
        self._assert_loop()
        if expected_epoch is not None and expected_epoch != self.epoch:
            raise StaleMachineAccess(
                f"{self.entity_id} epoch {expected_epoch} is stale; current epoch is {self.epoch}"
            )
        return MachineSnapshot(
            self.entity_id, self.spec.machine_type, self.epoch, self._revision,
            self._state, self._state in self.spec.terminal,
        )

    async def wait_for_revision(self, after_revision: int) -> MachineSnapshot:
        """Block until a newer authoritative snapshot is available.

        A runner that stops before advancing the revision wakes all waiters and
        propagates its failure/cancellation instead of leaving them stranded.
        """
        self._assert_loop()
        while self._revision <= after_revision:
            if not self._running and self._stopped_error is not None:
                raise self._stopped_error
            changed = self._changed
            await changed.wait()
        return self.snapshot()

    async def wait_terminal(self) -> MachineSnapshot:
        """Block on state-change notification until the machine is terminal."""
        snapshot = self.snapshot()
        while not snapshot.terminal:
            snapshot = await self.wait_for_revision(snapshot.revision)
        return snapshot

    async def submit(self, command: C) -> None:
        self._assert_loop()
        await self.commands.submit(command)

    def try_submit(self, command: C) -> None:
        self._assert_loop()
        self.commands.try_submit(command)

    async def next_cause(self) -> C:
        return await self.commands.receive()

    @abstractmethod
    async def step(self, cause: C) -> str | PreparedTransition[Any]:
        """Prepare one transition. Public state cannot be mutated from here."""

    async def prepare(self, cause: C) -> PreparedTransition[Any]:
        before = (self._state, self._revision, self.epoch)
        proposed = await self.step(cause)
        if before != (self._state, self._revision, self.epoch):
            raise AssertionError("step() mutated authoritative machine state")
        if isinstance(proposed, PreparedTransition):
            return proposed
        command = cause if isinstance(cause, MachineCommand) else None
        return PreparedTransition(
            before[0], proposed, None,
            command.cause_id if command is not None else cause,
            command.expected_epoch if command is not None else self.epoch,
            command.expected_revision if command is not None else before[1],
        )

    def commit(
        self, proposed: str | PreparedTransition[Any], cause: C | None = None
    ) -> TransitionCommit:
        """Validate and mutate synchronously in one event-loop turn."""
        _reject_observation_reentrancy()
        self._assert_loop()
        prepared = proposed if isinstance(proposed, PreparedTransition) else PreparedTransition(
            self._state, proposed, None,
            cause.cause_id if isinstance(cause, MachineCommand) else cause,
            self.epoch, self._revision,
        )
        if prepared.expected_epoch not in (None, self.epoch):
            raise StaleMachineAccess("prepared transition belongs to a stale epoch")
        if prepared.expected_revision not in (None, self._revision):
            raise StaleMachineAccess("prepared transition has a stale or future revision")
        if prepared.expected_state != self._state:
            raise StaleMachineAccess("prepared transition source state is stale")
        previous = self._state
        self.spec.validate(previous, prepared.proposed_state)
        self._state = prepared.proposed_state
        self._revision += 1
        self._signal_change()
        return TransitionCommit(
            self.entity_id, self.spec.machine_type, previous, prepared.proposed_state,
            self._revision, prepared.cause_id, time.monotonic_ns(), self.epoch,
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

    async def reconcile_terminal(self, prepared: PreparedTransition[Any]) -> None:
        """Join owned children/barriers before committing a terminal state."""
        return None

    async def after_commit(self, commit: TransitionCommit, effects: Any) -> None:
        return None

    def _reply(self, cause: C, result: TransitionCommit | BaseException) -> None:
        if not isinstance(cause, MachineCommand) or cause.reply is None:
            return
        if isinstance(result, BaseException):
            cause.reply.reject(result)
        else:
            cause.reply.resolve(result)

    def _remember(
        self, command: MachineCommand[Any, Any], result: TransitionCommit | BaseException
    ) -> None:
        key = command.deduplication_key
        if key is None:
            return
        cached: TransitionCommit | _CachedFailure = (
            _CachedFailure.from_error(result) if isinstance(result, BaseException) else result
        )
        if key not in self._seen:
            self._seen_order.append(key)
        self._seen[key] = cached
        while len(self._seen_order) > self._dedupe_capacity:
            self._seen.pop(self._seen_order.popleft(), None)

    def _reply_cached(
        self, cause: C, cached: TransitionCommit | _CachedFailure
    ) -> None:
        self._reply(cause, cached.materialize() if isinstance(cached, _CachedFailure) else cached)

    def close_mailbox(self, error: BaseException | None = None) -> None:
        rejected = self.commands.close()
        failure = error or MailboxClosed("machine mailbox is closed")
        for command in rejected:
            self._reply(command, failure)

    def abort(self, error: BaseException) -> None:
        """Wake queued commands and state waiters if owner startup is cancelled.

        A task cancelled before its coroutine's first timeslice never enters
        ``run()`` and therefore cannot execute that method's cancellation
        handler. Runtime task completion uses this idempotent hook to close the
        gap.
        """
        self._assert_loop()
        if self._stopped_error is None:
            self._stopped_error = error
        self.close_mailbox(error)
        self._signal_change()

    async def run(self) -> None:
        self._assert_loop()
        if self._running:
            raise RuntimeError("machine runner already has an owner task")
        self._running = True
        cause: C | None = None
        try:
            # A restartable lifecycle may use the same public ``stopped``
            # state for its pristine and reconciled terminal snapshots.  The
            # initial revision is not terminal evidence: accept the first
            # command and only stop the pump after a committed terminal edge.
            while self._state not in self.spec.terminal or self._revision == 0:
                cause = await self.next_cause()
                command = cause if isinstance(cause, MachineCommand) else None
                if command is not None:
                    if command.expected_epoch != self.epoch:
                        error = StaleMachineAccess("command belongs to a stale epoch")
                        self._reply(cause, error)
                        continue
                    retry_key = command.deduplication_key
                    cached = self._seen.get(retry_key) if retry_key is not None else None
                    if cached is not None:
                        self._reply_cached(cause, cached)
                        continue
                try:
                    prepared = await self.prepare(cause)
                except asyncio.CancelledError:
                    raise
                except BaseException as error:
                    if command is not None:
                        self._remember(command, error)
                        self._reply(cause, error)
                        continue
                    raise
                preview = TransitionCommit(
                    self.entity_id, self.spec.machine_type, self._state,
                    prepared.proposed_state, self._revision + 1, prepared.cause_id, 0,
                    self.epoch,
                )
                try:
                    self.spec.validate(self._state, prepared.proposed_state)
                    await self.controller.before_commit(
                        self._checkpoint(preview, "before_commit")
                    )
                    if prepared.proposed_state in self.spec.terminal:
                        await self.reconcile_terminal(prepared)
                    committed = self.commit(prepared, cause)
                except asyncio.CancelledError:
                    raise
                except BaseException as error:
                    if command is not None:
                        self._remember(command, error)
                        self._reply(cause, error)
                        continue
                    raise

                # From this point the edge is authoritative. Downstream
                # failures terminate the runner, but the active command still
                # observes the commit and queued/subsequent commands reject.
                if committed.to_state in self.spec.terminal:
                    self.close_mailbox()
                try:
                    if self._transition_sink is not None:
                        # Observation is downstream of the authoritative
                        # commit. A broken projection must never stop the
                        # protocol owner that already committed the edge.
                        try:
                            _dispatch_transition_sink(
                                self._transition_sink, committed, prepared.effects,
                            )
                        except Exception:
                            pass
                    await self.controller.after_commit(
                        self._checkpoint(committed, "after_commit")
                    )
                    await self.after_commit(committed, prepared.effects)
                    flush = getattr(self._transition_sink, "flush", None)
                    if flush is not None:
                        await flush()
                    if committed.to_state in self.spec.terminal:
                        await self.controller.terminal(
                            self._checkpoint(committed, "terminal")
                        )
                except BaseException as error:
                    if command is not None:
                        self._remember(command, committed)
                    self._reply(cause, committed)
                    self.close_mailbox(error)
                    raise
                if command is not None:
                    self._remember(command, committed)
                self._reply(cause, committed)
        except asyncio.CancelledError as error:
            self._stopped_error = error
            if cause is not None:
                self._reply(cause, error)
            self.close_mailbox(error)
            raise
        except BaseException as error:
            self._stopped_error = error
            raise
        finally:
            if self._state in self.spec.terminal:
                self.close_mailbox()
            self._running = False
            self._signal_change()


class SynchronousStateReducer:
    """Small event-loop-local state authority without a mailbox owner task.

    Protocol objects are already serialized by their Runtime event loop.  This
    reducer retains edge validation, immutable snapshots and change
    notification without allocating commands, reply futures, retry caches or
    a permanent task for every resource.
    """

    def __init__(
        self, spec: MachineSpec, *, entity_id: str, epoch: int = 1,
        transition_sink: Callable[[TransitionCommit], None] | None = None,
    ) -> None:
        self.spec = spec
        self.entity_id = entity_id
        self.epoch = epoch
        self._state = spec.initial
        self._revision = 0
        self._transition_sink = transition_sink
        self._authority_sink: Callable[[TransitionCommit, Any], None] | None = None
        self._changed = asyncio.Event()

    @property
    def state(self) -> str:
        return self._state

    @property
    def revision(self) -> int:
        return self._revision

    def snapshot(self) -> MachineSnapshot:
        return MachineSnapshot(
            self.entity_id, self.spec.machine_type, self.epoch, self._revision,
            self._state, self._state in self.spec.terminal,
        )

    def transition(
        self, proposed_state: str, *, cause: str = "", effect: Any = None,
    ) -> TransitionCommit:
        _reject_observation_reentrancy()
        previous = self._state
        self.spec.validate(previous, proposed_state)
        self._state = proposed_state
        self._revision += 1
        commit = TransitionCommit(
            self.entity_id, self.spec.machine_type, previous, proposed_state,
            self._revision, cause, time.monotonic_ns(), self.epoch,
        )
        changed, self._changed = self._changed, asyncio.Event()
        changed.set()
        if self._authority_sink is not None:
            self._authority_sink(commit, effect)
        if self._transition_sink is not None:
            # Synchronous reducers have the same commit boundary as async
            # owners: observability is best effort after the state mutation.
            try:
                _dispatch_transition_sink(self._transition_sink, commit, effect)
            except Exception:
                pass
        return commit

    async def wait_for_revision(self, after_revision: int) -> MachineSnapshot:
        while self._revision <= after_revision:
            await self._changed.wait()
        return self.snapshot()

    async def wait_terminal(self) -> MachineSnapshot:
        snapshot = self.snapshot()
        while not snapshot.terminal:
            snapshot = await self.wait_for_revision(snapshot.revision)
        return snapshot


class InlineStateMachineRunner:
    """Serialized event-loop reducer with no permanent mailbox task.

    This is a migration adapter for domain owners that still expose typed
    ``MachineCommand`` APIs. A Runtime-owned drain exists only while commands
    are pending; state reduction itself happens in the drain's event-loop turn.
    """

    def __init__(
        self, spec: MachineSpec, *, entity_id: str, mailbox_capacity: int = 16,
        dedupe_capacity: int = 128, controller=None, transition_sink=None,
    ) -> None:
        del dedupe_capacity
        self.spec = spec
        self.entity_id = entity_id
        self.epoch = 1
        self._state = spec.initial
        self._revision = 0
        self.commands = BoundedMailbox(mailbox_capacity)
        self.controller = controller or NullTransitionController()
        self._transition_sink = transition_sink
        self._changed = asyncio.Event()
        self._runtime = None
        self._owner_entity_id = entity_id
        self._owner_epoch = 1
        self._drain_handle = None

    @property
    def state(self): return self._state
    @property
    def revision(self): return self._revision

    def snapshot(self) -> MachineSnapshot:
        return MachineSnapshot(
            self.entity_id, self.spec.machine_type, self.epoch, self._revision,
            self._state, self._state in self.spec.terminal,
        )

    def activate(self, runtime, *, owner_entity_id=None, owner_epoch=None):
        self._runtime = runtime
        self._owner_entity_id = owner_entity_id or self.entity_id
        self._owner_epoch = owner_epoch or self.epoch
        return self

    async def submit(self, command) -> None:
        await self.commands.submit(command)
        self._ensure_drain()

    async def apply_command(self, command) -> None:
        """Apply directly from an owner workflow already providing serialization."""
        await self._apply(command)

    def try_submit(self, command) -> None:
        self.commands.try_submit(command)
        self._ensure_drain()

    def _ensure_drain(self) -> None:
        if self._drain_handle is not None and not self._drain_handle.done():
            return
        if self._runtime is None:
            raise RuntimeError("inline reducer is not Runtime-bound")
        from .runtime_services import FailurePolicy
        self._drain_handle = self._runtime.start_pump(
            self._drain, owner_entity_id=self._owner_entity_id,
            owner_epoch=self._owner_epoch,
            name=f"state-reducer:{self.entity_id}", kind="state-reducer",
            failure=FailurePolicy.REPORT,
        )
        self._drain_handle._task.add_done_callback(self._drain_finished)

    def _drain_finished(self, _task) -> None:
        if self.commands.depth and self._state not in self.spec.terminal:
            self._ensure_drain()

    async def _drain(self) -> None:
        while self.commands.depth:
            command = await self.commands.receive()
            await self._apply(command)

    async def prepare(self, command):
        return await self.step(command)

    async def step(self, command):
        raise NotImplementedError

    def commit(self, prepared, cause=None):
        _reject_observation_reentrancy()
        del cause
        if isinstance(prepared, str):
            prepared = PreparedTransition(
                self._state, prepared, None, "direct", self.epoch, self._revision,
            )
        self.spec.validate(self._state, prepared.proposed_state)
        previous = self._state
        self._state = prepared.proposed_state
        self._revision += 1
        changed, self._changed = self._changed, asyncio.Event()
        changed.set()
        return TransitionCommit(
            self.entity_id, self.spec.machine_type, previous, self._state,
            self._revision, prepared.cause_id, time.monotonic_ns(), self.epoch,
        )

    def _checkpoint(self, commit, phase):
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

    async def _apply(self, command) -> None:
        try:
            if command.expected_epoch != self.epoch:
                raise StaleMachineAccess("command belongs to a stale epoch")
            if (
                command.expected_revision is not None
                and command.expected_revision != self._revision
            ):
                raise StaleMachineAccess("machine revision changed")
            prepared = await self.prepare(command)
            preview = TransitionCommit(
                self.entity_id, self.spec.machine_type, self._state,
                prepared.proposed_state, self._revision + 1,
                prepared.cause_id, 0, self.epoch,
            )
            self.spec.validate(self._state, prepared.proposed_state)
            await self.controller.before_commit(self._checkpoint(preview, "before_commit"))
            if prepared.proposed_state in self.spec.terminal:
                await self.reconcile_terminal(prepared)
            committed = self.commit(prepared, command)
            if self._transition_sink is not None:
                _dispatch_transition_sink(
                    self._transition_sink, committed, prepared.effects,
                )
            await self.controller.after_commit(self._checkpoint(committed, "after_commit"))
            await self.after_commit(committed, prepared.effects)
            flush = getattr(self._transition_sink, "flush", None)
            if flush is not None:
                await flush()
            if committed.to_state in self.spec.terminal:
                self.commands.close()
                await self.controller.terminal(self._checkpoint(committed, "terminal"))
        except BaseException as error:
            if command.reply is not None:
                command.reply.reject(error)
            return
        if command.reply is not None:
            command.reply.resolve(committed)

    async def reconcile_terminal(self, prepared): return None
    async def after_commit(self, commit, effects): return None

    async def wait_for_revision(self, after_revision: int) -> MachineSnapshot:
        while self._revision <= after_revision:
            await self._changed.wait()
        return self.snapshot()

    async def wait_terminal(self) -> MachineSnapshot:
        snapshot = self.snapshot()
        while not snapshot.terminal:
            snapshot = await self.wait_for_revision(snapshot.revision)
        return snapshot

    def done(self) -> bool:
        return self.snapshot().terminal and (
            self._drain_handle is None or self._drain_handle.done()
        )

    def cancel(self) -> bool:
        cancelled = False
        if self._drain_handle is not None:
            cancelled = self._drain_handle.cancel()
        self.commands.close()
        if self._state not in self.spec.terminal and self.spec.terminal:
            self._state = sorted(self.spec.terminal)[0]
            self._revision += 1
            changed, self._changed = self._changed, asyncio.Event()
            changed.set()
        return cancelled

    async def wait(self) -> None:
        await self.wait_terminal()
        if self._drain_handle is not None and not self._drain_handle.done():
            await self._drain_handle.wait()
