import asyncio
import contextvars
import inspect
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, TypeVar

from webrtc.config import DebugConfig
from webrtc.runtime import (
    TaskContext,
    WebRTCRuntimeResources,
    get_current_task_context,
    get_default_runtime,
    reset_current_task_context,
    set_current_task_context,
)

if TYPE_CHECKING:
    from webrtc.peer_connection import PeerConnection


T = TypeVar("T")

_active_peer_context: contextvars.ContextVar["PeerContext | None"] = contextvars.ContextVar(
    "webrtc_active_peer_context",
    default=None,
)


def get_active_peer_context() -> "PeerContext | None":
    return _active_peer_context.get()


def spawn_peer_task(
    awaitable: Awaitable[Any] | Coroutine[Any, Any, Any],
    *,
    name: str,
    component: str,
    kind: str = "protocol",
    bounded: bool = False,
    runtime: WebRTCRuntimeResources | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
) -> asyncio.Task[Any]:
    peer_context = get_active_peer_context()
    if peer_context is not None and not peer_context.closed:
        return peer_context.spawn_component(
            awaitable,
            component=component,
            name=name,
            kind=kind,
            bounded=bounded,
        )

    return (runtime or get_default_runtime()).spawn_task(
        awaitable,
        name=name,
        kind=kind,
        loop=loop,
        metadata={"component": component, "bounded": bounded},
    )


class PeerClosed(RuntimeError):
    pass


class RoutineFailurePolicy(Enum):
    LOG = "log"
    FAIL_PEER = "fail-peer"
    IGNORE = "ignore"


@dataclass
class PeerTaskFailed:
    component: str
    task_name: str
    failure_policy: RoutineFailurePolicy
    error: BaseException
    generation: int


@dataclass
class PeerRoutine:
    task_id: str
    component: str
    name: str
    kind: str
    bounded: bool
    task: asyncio.Task[Any]
    trace_id: str | None
    started_at: float


class PeerConnectionLogInbox:
    def __init__(self, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.dropped_debug = 0
        self.dropped = 0

    def put_nowait(self, event: Any) -> bool:
        if not self._queue.full():
            self._queue.put_nowait(event)
            return True

        level = getattr(getattr(event, "level", None), "value", 0)
        if level >= 4:
            self.dropped_debug += 1
            return False

        self.dropped += 1
        try:
            self._queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False

    async def get(self) -> Any:
        return await self._queue.get()

    def drain_batch(self, max_batch: int) -> list[Any]:
        batch: list[Any] = []
        for _ in range(max_batch):
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    def empty(self) -> bool:
        return self._queue.empty()


class NeedMoreData:
    pass


class PeerEventInboxClosed:
    pass


class PeerEventInbox:
    def __init__(self, maxsize: int = 1024) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self._ready = asyncio.Event()
        self._closed = False

    def offer_nowait(self, event: Any) -> bool:
        if self._closed:
            return False
        self._queue.put_nowait(event)
        self._ready.set()
        return True

    async def get(self) -> Any:
        item = await self._queue.get()
        if self._queue.empty() and not self._closed:
            self._ready.clear()
        return item

    def close(self) -> None:
        self._closed = True
        self._ready.set()

    def receive_nowait(self) -> Any | NeedMoreData | PeerEventInboxClosed:
        try:
            event = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            if self._closed:
                return PeerEventInboxClosed()
            self._ready.clear()
            return NeedMoreData()

        if not self._queue.empty() or self._closed:
            self._ready.set()
        else:
            self._ready.clear()
        return event

    async def wait_ready(self) -> None:
        await self._ready.wait()

    def empty(self) -> bool:
        return self._queue.empty()


class PeerContext:
    def __init__(
        self,
        pc: "PeerConnection",
        *,
        runtime: WebRTCRuntimeResources | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        peer_id: str | None = None,
    ) -> None:
        self.pc = pc
        self.runtime = runtime or get_default_runtime()
        self.loop = loop or asyncio.get_running_loop()
        self.peer_id = peer_id or uuid.uuid4().hex
        self.tasks: set[asyncio.Task[Any]] = set()
        self.command_inbox: asyncio.Queue[Any] = asyncio.Queue(maxsize=1024)
        self.event_inbox = PeerEventInbox(maxsize=1024)
        self.log_inbox = PeerConnectionLogInbox(DebugConfig.get().log_max)
        self.pair_inboxes: dict[str, Any] = {}
        self.ice_connections: dict[str, Any] = {}
        self.transports: dict[str, Any] = {}
        self.state = "new"
        self.generation = 0
        self.closed = False
        self._started = False
        self._role: str | None = None
        self._role_task_started = False
        self._tg: asyncio.TaskGroup | None = None
        self._token: contextvars.Token[PeerContext | None] | None = None
        self._task_context_token: contextvars.Token[TaskContext | None] | None = None
        self._root_task_context: TaskContext | None = None
        self._transport_ready = asyncio.Event()
        self._selected_transport: Any = None
        self._log_drain_started = False
        self._routines: dict[asyncio.Task[Any], PeerRoutine] = {}

    async def __aenter__(self) -> "PeerContext":
        self._tg = asyncio.TaskGroup()
        await self._tg.__aenter__()
        self._token = _active_peer_context.set(self)
        self._root_task_context = self.runtime.create_task_context(
            name=f"PeerContext-{self.peer_id}",
            kind="peer",
            metadata={"peer_id": self.peer_id},
        )
        self.runtime.start_task_context(self._root_task_context)
        self._task_context_token = set_current_task_context(self._root_task_context)
        self._start_log_drain()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose("error" if exc else "closed", error=exc)

    def _start_log_drain(self) -> None:
        if self._log_drain_started:
            return
        self._log_drain_started = True
        self.spawn(
            self._log_drain_loop(),
            name=f"PeerContext-log-drain-{self.peer_id}",
            kind="log",
        )

    def spawn(
        self,
        awaitable: Awaitable[Any] | Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        kind: str = "task",
        metadata: dict[str, Any] | None = None,
    ) -> asyncio.Task[Any]:
        return self._spawn(
            awaitable,
            name=name,
            app_task=False,
            kind=kind,
            component="task",
            bounded=False,
            failure_policy=RoutineFailurePolicy.FAIL_PEER,
            metadata=metadata,
        )

    def spawn_app(
        self,
        awaitable: Awaitable[Any] | Coroutine[Any, Any, Any],
        *,
        name: str | None = None,
        kind: str = "app",
        metadata: dict[str, Any] | None = None,
    ) -> asyncio.Task[Any]:
        return self._spawn(
            awaitable,
            name=name,
            app_task=True,
            kind=kind,
            component="app-task",
            bounded=False,
            failure_policy=RoutineFailurePolicy.LOG,
            metadata=metadata,
        )

    def spawn_component(
        self,
        awaitable: Awaitable[Any] | Coroutine[Any, Any, Any],
        *,
        component: str,
        name: str | None = None,
        kind: str = "protocol",
        bounded: bool = False,
        failure_policy: RoutineFailurePolicy = RoutineFailurePolicy.FAIL_PEER,
        metadata: dict[str, Any] | None = None,
    ) -> asyncio.Task[Any]:
        return self._spawn(
            awaitable,
            name=name,
            app_task=False,
            kind=kind,
            component=component,
            bounded=bounded,
            failure_policy=failure_policy,
            metadata=metadata,
        )

    def _spawn(
        self,
        awaitable: Awaitable[Any] | Coroutine[Any, Any, Any],
        *,
        name: str | None,
        app_task: bool,
        kind: str,
        component: str,
        bounded: bool,
        failure_policy: RoutineFailurePolicy,
        metadata: dict[str, Any] | None,
    ) -> asyncio.Task[Any]:
        if self.closed:
            raise PeerClosed("peer context is closed")

        task_name = name or self.runtime._awaitable_name(awaitable)
        parent_context = get_current_task_context() or self._root_task_context
        trace_context = self.runtime.create_task_context(
            name=task_name,
            kind=kind,
            parent=parent_context,
            metadata={
                "component": component,
                "app_task": app_task,
                "bounded": bounded,
                "peer_id": self.peer_id,
                **(metadata or {}),
            },
        )
        started = False

        async def runner() -> None:
            nonlocal started
            started = True
            peer_token = _active_peer_context.set(self)
            try:
                await self.runtime.trace_awaitable(awaitable, context=trace_context)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._handle_task_failure(
                    component=component,
                    task_name=task_name,
                    failure_policy=failure_policy,
                    error=exc,
                    app_task=app_task,
                )
            finally:
                _active_peer_context.reset(peer_token)

        if self._tg is not None:
            task = self._tg.create_task(runner(), name=task_name)
        else:
            task = self.runtime.create_task(runner(), name=task_name, loop=self.loop)

        self.tasks.add(task)
        routine = PeerRoutine(
            task_id=uuid.uuid4().hex,
            component=component,
            name=task_name,
            kind=kind,
            bounded=bounded,
            task=task,
            trace_id=trace_context.trace_id,
            started_at=time.time(),
        )
        self._routines[task] = routine

        def on_done(done_task: asyncio.Task[Any]) -> None:
            self.tasks.discard(done_task)
            self._routines.pop(done_task, None)
            if not started and inspect.iscoroutine(awaitable):
                awaitable.close()
            try:
                done_task.exception()
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                pass

        task.add_done_callback(on_done)
        return task

    def _handle_task_failure(
        self,
        *,
        component: str,
        task_name: str,
        failure_policy: RoutineFailurePolicy,
        error: Exception,
        app_task: bool,
    ) -> None:
        if failure_policy is RoutineFailurePolicy.IGNORE:
            return

        if failure_policy is RoutineFailurePolicy.FAIL_PEER and not app_task:
            self.state = "error"

        self._offer_event(
            PeerTaskFailed(
                component=component,
                task_name=task_name,
                failure_policy=failure_policy,
                error=error,
                generation=self.generation,
            )
        )

    def active_routines(self) -> list[PeerRoutine]:
        return [routine for task, routine in self._routines.items() if not task.done()]

    def active_routine_count(self) -> int:
        return len(self.active_routines())

    async def offload_sync(
        self,
        fn: Callable[..., T],
        *args: Any,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
        aggregate: bool = False,
        group_name: str | None = None,
        group_key: str | None = None,
        **kwargs: Any,
    ) -> T:
        if self.closed or self.runtime.shutdown_started:
            raise PeerClosed("peer context is closed")
        return await self.runtime.offload_sync(
            self.loop,
            fn,
            *args,
            name=name,
            metadata=metadata,
            aggregate=aggregate,
            group_name=group_name,
            group_key=group_key,
            **kwargs,
        )

    async def to_thread(
        self,
        fn: Callable[..., T],
        *args: Any,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
        aggregate: bool = False,
        group_name: str | None = None,
        group_key: str | None = None,
        **kwargs: Any,
    ) -> T:
        return await self.offload_sync(
            fn,
            *args,
            name=name,
            metadata=metadata,
            aggregate=aggregate,
            group_name=group_name,
            group_key=group_key,
            **kwargs,
        )

    def _offer_event(self, event: Any) -> None:
        try:
            self.event_inbox.offer_nowait(event)
        except asyncio.QueueFull:
            pass

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.state = "starting"

        async def start_peer_connection() -> None:
            result = self.pc.start()
            if inspect.isawaitable(result):
                await result

        self.spawn(
            start_peer_connection(),
            name=f"PeerConnection-start-{self.peer_id}",
            kind="lifecycle",
        )
        self._start_role_task()

    def dial(self) -> None:
        self._role = "dial"
        self._start_role_task()

    def accept(self) -> None:
        self._role = "accept"
        self._start_role_task()

    def _start_role_task(self) -> None:
        if self._role_task_started or self._role is None:
            return
        self._role_task_started = True

        async def run_role() -> None:
            gatherer = getattr(self.pc, "gatherer", None)
            target = getattr(gatherer, self._role or "", None)
            if target is None:
                return
            result = target()
            if inspect.isawaitable(result):
                await result

        self.spawn(
            run_role(),
            name=f"PeerConnection-{self._role}-{self.peer_id}",
            kind="lifecycle",
        )

    async def request_close(self, reason: str = "closed") -> None:
        await self.aclose(reason)

    async def aclose(self, reason: str = "closed", error: BaseException | None = None) -> None:
        if self.closed:
            return
        self.closed = True
        self.state = "closed"
        self._offer_event({"type": "closed", "reason": reason, "generation": self.generation})
        self.event_inbox.close()

        for task in list(self.tasks):
            task.cancel()

        current = asyncio.current_task()
        wait_tasks = [task for task in self.tasks if task is not current]
        pending: set[asyncio.Task[Any]] = set()
        if wait_tasks:
            _, pending = await asyncio.wait(
                wait_tasks,
                timeout=DebugConfig.get().peer_shutdown_timeout,
            )
            for task in pending:
                self.tasks.discard(task)
                self._routines.pop(task, None)

        if self._tg is not None:
            tg = self._tg
            self._tg = None
            if not pending:
                try:
                    await asyncio.wait_for(
                        tg.__aexit__(None, None, None),
                        timeout=DebugConfig.get().peer_shutdown_timeout,
                    )
                except asyncio.TimeoutError:
                    pass

        if self._root_task_context is not None:
            self.runtime.close_trace_groups()
            self.runtime.complete_task_context(
                self._root_task_context,
                status="failed" if error else "completed",
                error=error,
            )
            self._root_task_context = None

        if self._task_context_token is not None:
            try:
                reset_current_task_context(self._task_context_token)
            except ValueError:
                pass
            self._task_context_token = None

        if self._token is not None:
            try:
                _active_peer_context.reset(self._token)
            except ValueError:
                pass
            self._token = None

    async def _log_drain_loop(self) -> None:
        config = DebugConfig.get()
        last_flush = time.monotonic()
        while not self.closed:
            timeout = max(0.0, config.log_flush_interval - (time.monotonic() - last_flush))
            try:
                first = await asyncio.wait_for(self.log_inbox.get(), timeout=timeout)
                batch = [first]
            except asyncio.TimeoutError:
                batch = []

            batch.extend(self.log_inbox.drain_batch(max(0, config.log_flush_max_batch - len(batch))))
            if not batch:
                continue

            from webrtc.logger import get_logger

            logger = get_logger()
            await self.offload_sync(
                logger.write_events_sync,
                batch,
                name="logger.write_events_sync",
                metadata={"count": len(batch)},
            )
            last_flush = time.monotonic()

    async def wait_nominated_transport(self, timeout: float | None = None) -> Any:
        if self._selected_transport is None:
            await asyncio.wait_for(self._transport_ready.wait(), timeout)
        return self._selected_transport

    async def wait_transport_ready(self, timeout: float | None = None) -> Any:
        return await self.wait_nominated_transport(timeout)

    async def send_rtp_packet(self, packet: bytes | bytearray) -> int:
        return await self.pc.send_rtp_packet(packet)

    async def send_rtp_packets(self, packets: Iterable[bytes | bytearray]) -> int:
        return await self.pc.send_rtp_packets(packets)

    async def send_rtcp_packet(self, packet: bytes | bytearray) -> int:
        return await self.pc.send_rtcp_packet(packet)

    @property
    def root_trace_id(self) -> str | None:
        return self._root_task_context.trace_id if self._root_task_context is not None else None

    def _set_selected_transport(self, transport: Any) -> None:
        self._selected_transport = transport
        self._transport_ready.set()

    async def handle_remote_description(self, *args, **kwargs):
        return await self.pc.set_remote_description(*args, **kwargs)

    async def set_remote_description(self, *args, **kwargs):
        return await self.pc.set_remote_description(*args, **kwargs)

    async def add_remote_candidate(self, *args, **kwargs):
        return await self.pc.gatherer.add_remote_candidate(*args, **kwargs)

    async def set_remote_credentials(self, *args, **kwargs):
        return await self.pc.gatherer.set_remote_credentials(*args, **kwargs)

    def attach_signaling(self, signaling: Any) -> Any:
        self.signaling = signaling
        task_factory = getattr(signaling, "start", None)
        if task_factory is not None:
            result = task_factory()
            if inspect.isawaitable(result):
                self.spawn_app(result, name=f"PeerContext-signaling-{self.peer_id}")
        return signaling

    def attach_media_source(self, source: Any, *, kind: str | None = None) -> Any:
        task_factory = getattr(source, "start", None)
        if task_factory is not None:
            result = task_factory()
            if inspect.isawaitable(result):
                self.spawn_app(result, name=f"PeerContext-media-source-{kind or 'media'}")
        return source

    def lifecycle_events(self) -> AsyncIterator[Any]:
        return self.__aiter__()

    def __aiter__(self) -> AsyncIterator[Any]:
        async def iterator() -> AsyncIterator[Any]:
            while True:
                item = self.event_inbox.receive_nowait()
                if isinstance(item, NeedMoreData):
                    await self.event_inbox.wait_ready()
                    continue
                if isinstance(item, PeerEventInboxClosed):
                    return
                yield item

        return iterator()
