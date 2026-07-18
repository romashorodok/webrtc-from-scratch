from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from .config import DebugConfig
from .logger import get_logger
from .machine_specs import MACHINE_SPECS
from .performance import observe_worker
from .runtime_services import FailurePolicy, OwnedTaskHandle, ScopeState
from .state_machine import (
    InlineStateMachineRunner, MachineCommand, PreparedTransition, ReplyPort,
    StaleMachineAccess, SynchronousStateReducer, TransitionCommit,
)

_LOG_STOP = object()


class _LifecycleCommand(Enum):
    MOVE = auto()


@dataclass(frozen=True, slots=True)
class _Move:
    state: str
    effect: object | None = None


class _LifecycleRunner(InlineStateMachineRunner):
    """Typed bounded runner used by Stage-6 auxiliary entities."""

    def __init__(self, runtime: Any, machine_type: str, entity_id: str, *, capacity: int = 16):
        self.runtime = runtime
        super().__init__(
            MACHINE_SPECS[machine_type], entity_id=entity_id,
            mailbox_capacity=capacity, dedupe_capacity=max(16, capacity * 2),
            controller=runtime.transition_controller,
            transition_sink=runtime.observe_transition,
        )

    async def step(self, command: MachineCommand[_Move, TransitionCommit]):
        if command.expected_epoch != self.epoch:
            raise StaleMachineAccess("auxiliary command belongs to a stale epoch")
        return PreparedTransition(
            self.state, command.payload.state, command.payload.effect,
            command.cause_id, command.expected_epoch, command.expected_revision,
        )


def _bind_runner(runtime: Any, machine_type: str, entity_id: str, *, capacity: int = 16):
    if runtime.state is not ScopeState.ACTIVE:
        raise RuntimeError("auxiliary entities require an active Runtime")
    runtime._assert_loop()
    runtime.register_owner(entity_id, epoch=1)
    runner = _LifecycleRunner(runtime, machine_type, entity_id, capacity=capacity)
    runner._transition_sink = runtime.observe_machine(
        entity_id, MACHINE_SPECS[machine_type], epoch=1,
    )
    handle = runner.activate(runtime, owner_entity_id=entity_id, owner_epoch=1)
    return runner, handle


def _command(runner: _LifecycleRunner, command_id: int, state: str, cause: str,
             *, reply: ReplyPort[TransitionCommit] | None = None,
             effect: object | None = None) -> MachineCommand[_Move, TransitionCommit]:
    return MachineCommand(
        _LifecycleCommand.MOVE, command_id, runner.epoch, _Move(state, effect), reply,
        expected_revision=None,
        cause_id=cause,
    )


async def _move(runner: _LifecycleRunner, command_id: int, state: str, cause: str,
                *, effect: object | None = None) -> TransitionCommit:
    reply = ReplyPort[TransitionCommit]()
    await runner.submit(_command(runner, command_id, state, cause, reply=reply, effect=effect))
    return await reply.wait()


class NeedMoreData: pass
class PeerEventInboxClosed: pass


class PeerEventInbox:
    """Bounded ordinary classes plus one non-droppable terminal slot."""

    def __init__(self, maxsize: int = 1024) -> None:
        if maxsize < 1:
            raise ValueError("peer inbox capacity must be positive")
        self.maxsize = maxsize
        self._items: deque[Any] = deque()
        self._terminal: Any | None = None
        self._ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._runtime = self._runner = self._handle = None
        self._command_id = 0

    def bind(self, runtime: Any, entity_id: str) -> None:
        if self._runner is not None:
            if runtime is not self._runtime or entity_id != self._runner.entity_id:
                raise RuntimeError("peer inbox is already bound")
            return
        self._runtime = runtime
        self._runner, self._handle = _bind_runner(runtime, "queue", entity_id)
        self._observe(exact=True)

    def _assert_bound(self) -> _LifecycleRunner:
        if self._runner is None:
            raise RuntimeError("peer inbox must be bound before mutation")
        self._runtime._assert_loop()
        self._runtime.assert_owner_epoch(self._runner.entity_id, self._runner.epoch)
        return self._runner

    def _observe(self, *, admitted: int = 0, delivered: int = 0,
                 rejected: int = 0, dropped: int = 0,
                 exact: bool = False) -> None:
        runner = self._assert_bound()
        depth = len(self._items) + (self._terminal is not None)
        self._runtime.record_queue_activity(
            entity_id=runner.entity_id, queue_kind="peer-event-inbox",
            depth=depth, capacity=self.maxsize + 1,
            deltas={"admitted": admitted, "delivered": delivered,
                    "rejected": rejected, "dropped": dropped}, exact=exact,
        )

    def _counter(self, name: str) -> int:
        if self._runner is None:
            return 0
        return self._runtime.queue_telemetry_snapshot(
            self._runner.entity_id
        ).get(name, 0)

    admitted = property(lambda self: self._counter("admitted"))
    delivered = property(lambda self: self._counter("delivered"))
    rejected = property(lambda self: self._counter("rejected"))
    dropped = property(lambda self: self._counter("dropped"))
    high_water = property(lambda self: self._counter("high_water"))

    @property
    def closed(self) -> bool:
        return self._runner is not None and (
            self._runner.snapshot().state != "open" or self._runner.commands.depth > 0
        )

    @staticmethod
    def _is_terminal(event: Any) -> bool:
        return isinstance(event, dict) and event.get("type") == "closed"

    def offer_nowait(self, event: Any) -> bool:
        self._assert_bound()
        if self.closed and not self._is_terminal(event):
            self._observe(rejected=1); return False
        if self._is_terminal(event):
            if self._terminal is None:
                self._terminal = event; self._observe(admitted=1)
            else:
                self._observe(rejected=1); return False
        elif len(self._items) >= self.maxsize:
            self._observe(dropped=1, rejected=1); return False
        else:
            self._items.append(event); self._observe(admitted=1)
        self._signal_ready(); return True

    def close(self) -> None:
        runner = self._assert_bound()
        if self.closed: return
        self._command_id += 1
        runner.try_submit(_command(runner, self._command_id, "closing", "peer-output-close"))
        self._signal_ready(); self._observe()

    def receive_nowait(self) -> Any | NeedMoreData | PeerEventInboxClosed:
        runner = self._assert_bound()
        if self._items:
            item = self._items.popleft()
        elif self._terminal is not None:
            item, self._terminal = self._terminal, None
        elif not self.closed:
            self._reset_ready(); return NeedMoreData()
        else:
            self._signal_ready(); return PeerEventInboxClosed()
        self._observe(delivered=1)
        if not self._items and self._terminal is None:
            if self.closed:
                self._command_id += 1
                runner.try_submit(_command(runner, self._command_id, "drained", "peer-output-drained"))
                self._command_id += 1
                runner.try_submit(_command(runner, self._command_id, "closed", "peer-output-closed"))
            else: self._reset_ready()
        return item

    def _signal_ready(self) -> None:
        if not self._ready.done():
            self._ready.set_result(None)

    def _reset_ready(self) -> None:
        if self._ready.done():
            self._ready = asyncio.get_running_loop().create_future()

    async def wait_ready(self) -> None:
        await asyncio.shield(self._ready)

    def __aiter__(self) -> AsyncIterator[Any]:
        async def iterator():
            while True:
                item = self.receive_nowait()
                if isinstance(item, NeedMoreData): await self.wait_ready(); continue
                if isinstance(item, PeerEventInboxClosed): return
                yield item
        return iterator()

    async def aclose(self) -> None:
        self.close()
        while self._items or self._terminal is not None:
            item = self.receive_nowait()
            if isinstance(item, (NeedMoreData, PeerEventInboxClosed)): break
        if self._handle is not None:
            await self._handle.wait()
            self._runtime.remove_owner(self._runner.entity_id, self._runner.epoch)


class PeerConnectionLogInbox:
    def __init__(self, maxsize: int = 4096) -> None:
        if maxsize < 1: raise ValueError("log inbox capacity must be positive")
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.accepting = True
        self._runtime = self._runner = self._handle = None
        self._command_id = 0
        self._drain_requested = False

    def bind(self, runtime: Any, entity_id: str) -> None:
        if self._runner is not None: return
        self._runtime = runtime
        self._runner, self._handle = _bind_runner(runtime, "queue", entity_id)
        self._observe(exact=True)

    def _assert_bound(self):
        if self._runner is None: raise RuntimeError("log inbox must be bound before mutation")
        self._runtime.assert_owner_epoch(self._runner.entity_id, self._runner.epoch)
        return self._runner

    def _observe(self, *, admitted=0, delivered=0, rejected=0, dropped=0,
                 dropped_debug=0, exact=False):
        runner = self._assert_bound(); depth = self._queue.qsize()
        self._runtime.record_queue_activity(
            entity_id=runner.entity_id, queue_kind="peer-log-inbox",
            depth=depth, capacity=self._queue.maxsize,
            deltas={"admitted": admitted, "delivered": delivered,
                    "rejected": rejected, "dropped": dropped,
                    "dropped_debug": dropped_debug}, exact=exact,
        )

    def _counter(self, name):
        if self._runner is None: return 0
        return self._runtime.queue_telemetry_snapshot(self._runner.entity_id).get(name, 0)
    admitted = property(lambda self: self._counter("admitted"))
    delivered = property(lambda self: self._counter("delivered"))
    rejected = property(lambda self: self._counter("rejected"))
    dropped = property(lambda self: self._counter("dropped"))
    dropped_debug = property(lambda self: self._counter("dropped_debug"))
    high_water = property(lambda self: self._counter("high_water"))

    def stop_intake(self):
        runner = self._assert_bound()
        if not self.accepting: return
        self.accepting = False; self._command_id += 1
        runner.try_submit(_command(runner, self._command_id, "closing", "log-intake-stop"))
        if self._queue.empty(): self._queue.put_nowait(_LOG_STOP)

    def put_nowait(self, event):
        self._assert_bound()
        if not self.accepting: self._observe(rejected=1); return False
        if not self._queue.full():
            self._queue.put_nowait(event); self._observe(admitted=1); return True
        level = getattr(getattr(event, "level", None), "value", 0)
        if level >= 4: self._observe(rejected=1, dropped_debug=1); return False
        removed = self._queue.get_nowait()
        extra_rejected = 1 if removed is not _LOG_STOP else 0
        self._queue.put_nowait(event)
        self._observe(admitted=1, rejected=1 + extra_rejected, dropped=1)
        return True

    async def get(self):
        item = await self._queue.get()
        self._observe(delivered=1 if item is not _LOG_STOP else 0); return item

    def drain_batch(self, maximum):
        self._assert_bound(); batch=[]
        for _ in range(maximum):
            try: item = self._queue.get_nowait()
            except asyncio.QueueEmpty: break
            if item is not _LOG_STOP: batch.append(item)
        self._observe(delivered=len(batch))
        if not self.accepting and self._queue.empty() and self._runner.state == "closing":
            self._command_id += 1
            self._runner.try_submit(_command(self._runner, self._command_id, "drained", "log-queue-drained"))
            self._drain_requested = True
        return batch

    async def aclose(self):
        self.stop_intake(); self.drain_batch(self._queue.maxsize + 1)
        while not self._handle.done():
            snapshot = self._runner.snapshot()
            if snapshot.state != "open": break
            await self._runner.wait_for_revision(snapshot.revision)
        while self._drain_requested and not self._handle.done():
            snapshot = self._runner.snapshot()
            if snapshot.state != "closing": break
            await self._runner.wait_for_revision(snapshot.revision)
        if self._runner.state == "closing":
            await _move(self._runner, self._next(), "drained", "log-queue-drained")
        if self._runner.state == "drained": await _move(self._runner, self._next(), "closed", "log-queue-close")
        await self._handle.wait(); self._runtime.remove_owner(self._runner.entity_id, 1)

    def _next(self): self._command_id += 1; return self._command_id
    def close(self):
        # Compatibility spelling; terminal reconciliation remains awaitable.
        self._assert_bound()


class AsyncLogDrain:
    def __init__(self, inbox=None):
        self.inbox = inbox or PeerConnectionLogInbox(DebugConfig.get().log_max)
        self._runtime = self._runner = self._handle = self._drain_handle = None
        self._command_id = 0
        self._failure: BaseException | None = None

    def bind(self, runtime, entity_id):
        self._runtime = runtime
        self._runner, self._handle = _bind_runner(runtime, "log-drain", entity_id)
        runtime.bind_observation(
            self, entity_id=entity_id, owner_epoch=self._runner.epoch,
            role="log-drain",
        )
        self._execution = runtime.execution_port(entity_id, self._runner.epoch)
        self.inbox.bind(runtime, f"{entity_id}:queue")

    def start(self):
        if self._runner is None: raise RuntimeError("log drain must be bound before start")
        if self._drain_handle is not None and not self._drain_handle.done(): return
        self._drain_handle = self._runtime.start_pump(
            self._run, owner_entity_id=self._runner.entity_id, owner_epoch=1,
            name="logger.drain", kind="log", failure=FailurePolicy.REPORT,
        )

    async def _run(self):
        try:
            await _move(self._runner, self._next(), "starting", "log-drain-start")
            await _move(self._runner, self._next(), "idle", "log-drain-ready")
            config=DebugConfig.get(); last=time.monotonic()
            while self.inbox.accepting:
                timeout=max(0.0, config.log_flush_interval-(time.monotonic()-last))
                try: first=await asyncio.wait_for(self.inbox.get(), timeout)
                except TimeoutError: first=None
                if first is _LOG_STOP: break
                batch=[] if first is None else [first]
                batch.extend(self.inbox.drain_batch(max(0, config.log_flush_max_batch-len(batch))))
                if batch:
                    await _move(self._runner,self._next(),"draining","log-batch")
                    await observe_worker(
                        self._execution,
                        self.write_batch, batch, name="worker:logger.write"
                    )
                    await _move(self._runner,self._next(),"idle","log-batch-complete")
                last=time.monotonic()
        except BaseException as error:
            self._failure=error
            if not isinstance(error, asyncio.CancelledError) and self._runner.state in {"starting","idle","draining"}:
                await _move(self._runner,self._next(),"failed","log-write-failed")
            raise

    def _next(self): self._command_id += 1; return self._command_id

    def stop_intake(self): self.inbox.stop_intake()

    def write_batch(self, batch): get_logger().write_events_sync(batch)

    async def aclose(self):
        self.stop_intake()
        if self._drain_handle is not None:
            try: await self._drain_handle.wait()
            except BaseException as error:
                if self._failure is None: self._failure=error
        while batch := self.inbox.drain_batch(max(1,DebugConfig.get().log_flush_max_batch)):
            try:
                await observe_worker(
                    self._execution,
                    self.write_batch, batch, name="worker:logger.write"
                )
            except BaseException as error:
                if self._failure is None: self._failure=error
                break
        if self._runner.state in {"starting","idle","draining","failed"}:
            await _move(self._runner,self._next(),"stopping","log-drain-stop")
        if self._runner.state == "stopping": await _move(self._runner,self._next(),"stopped","log-final-flush-complete")
        await self._handle.wait(); self._runtime.remove_owner(self._runner.entity_id,1)
        await self.inbox.aclose()
        if self._failure is not None: raise self._failure


async def _call_optional(target, name):
    method=getattr(target,name,None)
    if method is None: return False
    result = method()
    if inspect.isawaitable(result):
        await result
    return True


@dataclass(slots=True)
class _AttachmentEntry:
    identity: str
    target: Any
    state: SynchronousStateReducer
    failure: BaseException | None = None
    work: OwnedTaskHandle | None = None


class AttachmentController:
    def __init__(self, kind: str, *, capacity: int = 64):
        self.kind=kind; self.capacity=max(1,capacity)
        self._runtime=None; self._state=None; self._entity_id=""
        self._entries: dict[int,_AttachmentEntry]={}
        self._command_id=0; self._work:set[OwnedTaskHandle]=set()
        self._start_requested = False

    def bind(self,runtime,entity_id):
        if self._state is not None: return
        self._runtime=runtime; self._entity_id=entity_id
        runtime.register_owner(
            entity_id, epoch=1,
            role=("signaling-attachments" if self.kind == "signaling" else "media-attachments"),
        )
        self._state = SynchronousStateReducer(
            MACHINE_SPECS["attachment-registry"], entity_id=entity_id,
            transition_sink=runtime.observe_transition,
        )
        self._state._transition_sink = runtime.observe_machine(
            entity_id, MACHINE_SPECS["attachment-registry"], epoch=1,
        )

    def _assert_bound(self):
        if self._state is None: raise RuntimeError("attachments must be Runtime-bound before mutation")
        self._runtime.assert_owner_epoch(self._entity_id,1)

    def attach(self,attachment):
        self._assert_bound()
        if self._state.state in {"closing", "closed"}:
            raise RuntimeError(f"{self.kind} attachments are closing")
        key=id(attachment)
        if key in self._entries: raise ValueError("the same attachment object is already registered")
        if len(self._entries)>=self.capacity: raise OverflowError("attachment registry capacity exceeded")
        identity=uuid.uuid4().hex
        entity=f"{self._entity_id}:attachment:{identity}"
        state = SynchronousStateReducer(
            MACHINE_SPECS["attachment"], entity_id=entity,
            transition_sink=self._runtime.observe_transition,
        )
        state._transition_sink = self._runtime.observe_machine(
            entity, MACHINE_SPECS["attachment"], epoch=1,
        )
        entry=_AttachmentEntry(identity,attachment,state)
        self._entries[key]=entry
        state.transition("attached", cause=f"{self.kind}-attach")
        if self._start_requested: self._launch(entry)
        return attachment

    def start(self):
        self._assert_bound()
        if self._state.state in {"closing", "closed"}:
            raise RuntimeError(f"{self.kind} attachments are closing")
        if not self._start_requested:
            self._start_requested = True
            self._launch_registry_start()
        for entry in self._entries.values(): self._launch(entry)

    def _launch_registry_start(self):
        async def work():
            if self._state.state=="open": self._state.transition("starting",cause=f"{self.kind}-start")
            if self._state.state=="starting": self._state.transition("active",cause=f"{self.kind}-started")
        self._own(work,"attachment.registry.start")

    def _launch(self,entry):
        if entry.work is not None: return
        async def work():
            if entry.state.state != "attached":
                return
            entry.state.transition("starting",cause=f"{self.kind}-start")
            try: await _call_optional(entry.target,"start")
            except BaseException as error:
                entry.failure=error
                entry.state.transition("failed",cause=f"{self.kind}-start-failed")
                return
            entry.state.transition("active",cause=f"{self.kind}-active")
        entry.work = self._own(work,f"attachment.start:{entry.identity}")

    def _own(self,factory,name):
        handle=self._runtime.start_pump(factory,owner_entity_id=self._entity_id,owner_epoch=1,name=name,failure=FailurePolicy.REPORT)
        self._work.add(handle)
        return handle

    def _next(self): self._command_id+=1; return self._command_id
    async def aclose(self):
        self._assert_bound()
        if self._state.state in {"closing", "closed"}:
            for work in tuple(self._work):
                try: await work.wait()
                except BaseException: pass
            return
        for work in tuple(self._work):
            try: await work.wait()
            except BaseException: pass
        if self._state.state in {"open","starting","active","failed"}:
            self._state.transition("closing",cause=f"{self.kind}-close")
        first_failure=None
        for entry in reversed(tuple(self._entries.values())):
            if entry.state.state in {"attached","starting","active","failed"}:
                entry.state.transition("stopping",cause=f"{self.kind}-stop")
            try:
                await _call_optional(entry.target,"stop")
                if not await _call_optional(entry.target,"aclose"): await _call_optional(entry.target,"close")
            except BaseException as error:
                if first_failure is None: first_failure=error
            if entry.state.state=="stopping": entry.state.transition("stopped",cause=f"{self.kind}-stopped")
            self._runtime.projection.terminate_entity_epoch(entry.state.entity_id, 1)
            if first_failure is None and entry.failure is not None: first_failure=entry.failure
        if self._state.state=="closing": self._state.transition("closed",cause=f"{self.kind}-closed")
        self._runtime.remove_owner(self._entity_id,1)
        if first_failure is not None: raise first_failure


class SignalingController(AttachmentController):
    def __init__(self): super().__init__("signaling")
class MediaSourceController(AttachmentController):
    def __init__(self): super().__init__("media")
