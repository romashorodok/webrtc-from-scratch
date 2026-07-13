# Peer Context Refactoring Specification

## Objective

Remove `PeerContext` completely and centralize execution-policy compilation in
`ObservedMeta`, exposed through a stateless `ObservedComponent` base class.

The metaclass instruments every eligible synchronous and asynchronous component
method. It creates full live trace nodes for method calls, automatically sends
eligible synchronous calls to the active execution scope's worker lane, and
schedules only explicitly marked autonomous routines. It does not own mutable
execution resources.

The refactoring must eliminate duplicated scheduling, offloading, tracing, metric recording, task ownership, and shutdown logic currently spread across:

- `webrtc/runtime.py`
- `webrtc/performance.py`
- `webrtc/runtime_services.py`
- `webrtc/peer_context.py`

The resulting design must retain an explicit owner for executors and other
mutable execution resources. One `Runtime` exists per `PeerConnection`.
`ObservedMeta` decides how component methods execute, but it must not own global
executors, registries, locks, worker lanes, or shutdown state.

## Accepted design decisions

- Automatic metaclass handling is a non-negotiable invariant. Inheriting
  `ObservedComponent` automatically discovers and compiles every eligible method
  when the class is created. Component implementations must not manually look up
  Runtime, create trace nodes, dispatch to executors, record metrics, or manage
  worker cancelability.
- Use explicit nested lifetimes: `Runtime` outside, `PeerConnection` inside.
- Make `PeerConnection` an async context manager responsible for WebRTC-domain
  startup and ordered teardown.
- Instrument regular instance, static, and class methods inherited from
  `ObservedComponent`; exclude properties and most dunder methods.
- Permit explicit `@unobserved` exclusions for recursion-sensitive
  infrastructure and measured hot paths.
- Create a full trace node for every observed method call. Retain only live
  nodes, stream completion events, and retain bounded aggregate metrics.
- Outside an active `Runtime`, observed methods execute normally and do not
  record traces or metrics.
- Inside an active `Runtime`, eligible synchronous component methods return an
  awaitable and execute in the Runtime worker lane. Callers must use `await`.
- Use conservative class-creation-time affinity analysis. Known loop-affine
  methods stay on the event loop. Ambiguous methods must be classified with
  `@event_loop` or `@worker`; reflection is never treated as proof of thread
  safety.
- Use a configurable physical executor, which may be shared, with one logical
  serialized worker lane per PeerConnection Runtime. Different peers may run in
  parallel; synchronous operations belonging to one peer do not.
- Use explicit `Owned(resource)` and `Borrowed(resource)` declarations for
  injected mutable resources.
- Use `@task` only for autonomous background entry points. Ordinary async
  methods preserve coroutine semantics and structured awaiting.
- Enforce hierarchical task ownership. A managed child cannot outlive its
  managed parent; parent completion joins or cancels and awaits all descendants.
- Running synchronous worker calls are non-cancelable. Queued calls are
  cancelable. Shutdown waits for running calls up to a configurable timeout and
  raises `ScopeShutdownTimeout` if developer-provided blocking code does not
  finish.

## Current problems

The current implementation has three overlapping scheduling layers:

- `Runtime` composes scheduling, tracing, offloading, metrics, diagnostics, and shutdown.
- `PeerContext` independently composes almost the same services and wraps task creation again.
- `ObservedMeta` implements another scheduling and instrumentation layer but imports `peer_context` to find its services.

The main duplication is:

| Responsibility | `Runtime` | `PeerContext` | `ObservedMeta` |
|---|---:|---:|---:|
| Create tasks | `spawn_task` | `_schedule`, `spawn*` | `@task` wrapper |
| Run traced awaitables | `trace_awaitable` | `_schedule` to scheduler | async wrapper |
| Offload synchronous work | `_dispatch_offload`, `offload_sync` | `offload_sync` | `_run_metaclass_offload` |
| Record performance | offload helpers | owns metric sink | `_record` |
| Resolve execution scope | default runtime | active peer context | imports peer context |
| Track and cancel tasks | registry and scheduler | task set, routines, `TaskGroup` | indirectly |
| Own executor | yes | yes | indirectly |
| Handle shutdown | yes | yes | indirectly |

`ObservedMeta` cannot currently operate independently because it dynamically imports `peer_context`, reads peer-owned services, and calls `peer._schedule`.

## Target architecture

Keep four distinct concepts:

1. `performance.py` contains declarative markers, `ObservedMeta`, and the
   stateless `ObservedComponent` base class.
2. `runtime_services.py` contains neutral execution models, small execution
   mechanisms, hierarchical task ownership, and generic active-scope lookup.
3. `runtime.py` is the single resource-owning execution scope for one peer.
4. `peer_connection.py` owns WebRTC lifecycle and domain state.

Delete `peer_context.py`.

```text
ObservedComponent method / @task / @unobserved
              |
              v
        ObservedMeta wrapper
              |
              v
     current_execution_scope()
              |
              v
       Runtime / ExecutionScope
       |-- TaskScheduler
       |-- TaskRegistry
       |-- SyncOffloader
       |-- SerializedWorkerLane
       |-- TraceService
       |-- MetricSink
       `-- Diagnostics
```

`ObservedMeta` compiles method execution policy. It initiates scheduling for
`@task` entry points, creates method trace nodes, and routes synchronous calls.
Resource ownership remains in an explicitly activated execution scope.

This behavior is automatic for every class inheriting `ObservedComponent`.
There is no per-call `execution.offload(...)`, `runtime.trace(...)`, or manual
wrapper invocation in component code. `@task` declares an autonomous task
boundary; `@event_loop`, `@worker`, and `@unobserved` are exceptional
class-creation hints only when automatic classification cannot be safe or when
instrumentation must be deliberately excluded.

`ObservedMeta` must not instrument `Runtime`, scheduler, registry, tracing,
metric-sink, or offloader implementation classes. This prevents recursive
instrumentation.

## Generic execution scope

Define an `ExecutionScope` protocol in `runtime_services.py`. Use protocols for external services where necessary to avoid import cycles.

```python
class ExecutionScope(Protocol):
    task_scheduler: TaskScheduler
    task_registry: TaskRegistry
    sync_offloader: SyncOffloader
    worker_lane: SerializedWorkerLane
    trace_service: TraceServiceProtocol
    metric_sink: MetricSinkProtocol
    diagnostics: Counter[str]
    state: ScopeState

    def observe_task_failure(self, event: TaskFailureEvent) -> None: ...
```

Keep neutral scheduling types such as `TaskSpec`, `TaskFailureEvent`, trace-node
descriptors, and structural sink protocols in `runtime_services.py` (or a small
neutral execution-model module). `runtime_services.py` must not import
`performance.py`; otherwise `ObservedMeta` and the scope protocol form an import
cycle.

Add one generic execution-scope context variable:

```python
_current_execution_scope: ContextVar[ExecutionScope | None]

def current_execution_scope() -> ExecutionScope | None: ...
def require_execution_scope() -> ExecutionScope: ...
def use_execution_scope(scope: ExecutionScope): ...
```

`require_execution_scope()` rejects scopes in `closing` or `closed` state.
`current_execution_scope()` may still return the closing scope to cleanup code
that is already running.

This replaces:

- `_active_peer_context`
- `get_active_peer_context`
- `require_active_peer_context`
- peer-context tokens inside scheduled runners
- execution-service lookup through a peer

Keep the existing `ExecutionContext` context variable. The two contexts represent different concepts:

- `ExecutionScope` identifies the owner of resources and configuration.
- `ExecutionContext` identifies the active trace node and managed task lineage.

Rename the WebRTC-specific `ExecutionContext.peer_id` field to generic
`scope_id`. Add `peer_id` only as trace/domain metadata. A Runtime is one-to-one
with a PeerConnection, but runtime services remain domain-neutral.

## Runtime responsibilities

Retain `Runtime` as the single resource owner and execution scope. If the name is no longer desirable, rename it to `ExecutionScope` or `ObservedExecution`, but do not make resource ownership implicit or metaclass-global.

Its responsibilities are:

- Construct the scheduler, registry, tracing service, offloader, serialized
  worker lane, metric sink, diagnostics, and executor.
- Activate and deactivate the generic execution scope.
- Create and complete a root trace.
- Cancel and await managed tasks during shutdown.
- Track queued and dispatched synchronous work.
- Close only resources declared `Owned`; detach but never close resources
  declared `Borrowed`.
- Expose scoped observability queries.

Runtime configuration includes executor ownership, maximum physical workers,
worker queue capacity, shutdown timeout, trace limits, metric sink, task and
failure observers, and diagnostics limits. Internally created resources are
implicitly owned. Injected mutable resources must be wrapped explicitly:

```python
Runtime(
    executor=Borrowed(server_executor),
    metric_sink=Owned(connection_metrics),
)
```

The physical executor may be shared by multiple runtimes. Each Runtime owns an
async semaphore with capacity one as its logical worker lane. Thus different
peers may execute synchronous work concurrently, while a single peer never has
two active synchronous component calls. A nested synchronous component call
already running in that peer's worker context executes inline and must not
reacquire the lane.

Recommended lifecycle:

```python
async with Runtime(scope_id=connection.id) as execution:
    async with connection:
        await connection.wait_closed()
```

The inner context exits first, so WebRTC cleanup remains observable and may use
the Runtime's worker lane. `PeerConnection.start()` must not define connection
lifetime merely by scheduling startup and returning. `PeerConnection.__aenter__`
starts the connection, `wait_closed()` represents its live lifetime, and
`__aexit__` performs domain cleanup.

Remove these duplicated methods from `Runtime`:

- `spawn_task`
- `trace_awaitable`
- public `offload`, `offload_sync`, and `to_thread` forwarding helpers
- `_dispatch_offload`
- transitional execution-context aliases
- `_looks_like_loop`
- the default-runtime singleton and `atexit` cleanup

Stable operations must be scheduled by compiled `ObservedMeta` wrappers.

For genuinely dynamic application awaitables, retain one narrow escape hatch
that accepts a factory rather than an already-created coroutine:

```python
runtime.start(lambda: application_coroutine(), *, name, kind="application")
```

This method delegates directly to `TaskScheduler.spawn_factory`. It must not
duplicate tracing, failure, or context logic. A compatibility overload accepting
an existing coroutine must close that coroutine on every rejection path and is
removed after callers migrate.

`start()` attaches the new task to the current managed parent. It does not
create detached tasks. A dynamic task that must live for the complete scope must
be started while the root owner is current, or through an explicitly named root
owner API.

## ObservedMeta responsibilities

`ObservedMeta` must never import `peer_context`.

Expose it through a stateless base class:

```python
class ObservedComponent(metaclass=ObservedMeta):
    pass
```

The base class does not contain a Runtime reference. It exists only to apply the
metaclass consistently. At class creation, the metaclass wraps regular instance,
static, and class methods, including private methods. It excludes properties and
most dunder methods. `@unobserved` explicitly excludes a method.

Automatic compilation must perform all of the following without cooperation
from the method body:

1. Preserve the original descriptor and callable metadata.
2. Determine sync versus async behavior.
3. Detect `@task` and the exceptional affinity/exclusion markers.
4. Classify synchronous thread affinity or reject unresolved ambiguity.
5. Compile scope lookup, trace-node creation, outcome recording, and cleanup.
6. Compile worker queueing and serialized-lane handling for worker methods.
7. Register no global state and capture no Runtime instance.

Application code still writes `await` when a call returns an awaitable. A
metaclass can automatically produce and route that awaitable, but Python syntax
does not allow it to suspend the caller automatically.

Wrappers resolve services using:

```python
scope = require_execution_scope()
```

For ordinary observed methods, use `current_execution_scope()` rather than
`require_execution_scope()`: without a scope, invoke the original function
normally and skip trace and metric recording.

### Ordinary asynchronous calls

An ordinary async method remains an async method. Its wrapper creates a full
non-task trace node beneath the current execution context, awaits the original
method directly, records success/cancellation/failure, publishes completion,
and removes the node from live storage. It must not create an `asyncio.Task`.

### Trace nodes versus managed tasks

A full trace node does not imply independent task ownership:

- `@task` nodes own native tasks and may be cancelled hierarchically.
- ordinary async method nodes run in their caller's task; they are cancelled only
  through that owning task, not independently;
- inline synchronous nodes are non-cancelable;
- queued worker nodes are cancelable until dispatch;
- dispatched worker nodes are non-cancelable until their function returns.

Observability must expose `node_type`, `owner_task_id`, and `cancelable` rather
than presenting every method node as a task. Replace ambiguous
`delete_task(task_id)` behavior with `cancel(node_id)` that rejects
non-cancelable nodes without deleting their live trace. Cancelling an ordinary
async method node is rejected; callers cancel its owning managed task when that
is the intended operation.

### Ordinary synchronous calls

Without an active Runtime, invoke the method synchronously and return its normal
value. Inside an active Runtime:

- a worker-classified method returns an awaitable and runs through the Runtime's
  serialized worker lane;
- an event-loop-classified method executes inline and returns its normal value;
- a nested worker-classified call already in the same Runtime worker context
  executes inline without redispatch;
- every call receives a full trace node;
- queued calls are cancelable, while dispatched calls are marked
  non-cancelable until completion.

This is deliberately context-sensitive API behavior. Migration and type
documentation must state that worker-classified synchronous calls inside
Runtime are invoked with `await`, while the same calls outside Runtime remain
synchronous.

Classify affinity conservatively at class creation. Reflection may identify
direct references to known asyncio, event-loop, task, event, transport, and
protocol APIs, but indirect access cannot be proven safe. Ambiguous methods
fail class creation until explicitly marked `@event_loop` or `@worker`.
Reflection is a convenience, not a correctness boundary.

### Sync-to-async transformation and offloading examples

The metaclass does not rewrite synchronous function bodies into native
`async def` functions and cannot insert a hidden `await` into their callers. It
compiles a context-sensitive wrapper:

```python
def compiled_sync_wrapper(*args, **kwargs):
    scope = current_execution_scope()

    # Normal synchronous library use.
    if scope is None:
        return original(*args, **kwargs)

    # A nested sync call already executing for this Runtime must not dispatch
    # again or reacquire the serialized lane.
    if scope.worker_lane.is_current_worker_context():
        return trace_inline(scope, original, args, kwargs)

    if method_policy is MethodPolicy.EVENT_LOOP:
        return trace_inline(scope, original, args, kwargs)

    # This branch returns an awaitable. It does not return the final value yet.
    return scope.worker_lane.run_observed(original, *args, **kwargs)
```

Consequently, the same worker-classified method has these call forms:

| Calling context | Expression | Result |
|---|---|---|
| No active Runtime | `codec.decode(packet)` | Value returned synchronously |
| Async code inside Runtime | `await codec.decode(packet)` | Value returned after worker execution |
| Nested call inside the same Runtime worker | `self.parse_header(packet)` | Value returned inline in that worker |
| Event-loop-classified sync method inside Runtime | `component.mark_ready()` | Value returned inline on the event loop |

Example component:

```python
class PacketCodec(ObservedComponent):
    def decode(self, packet: bytes) -> Frame:
        # The nested method call stays in the current worker. It still receives
        # a child trace node, but it does not enqueue another worker job.
        header = self.parse_header(packet)
        return decode_payload(header, packet)

    def parse_header(self, packet: bytes) -> Header:
        return Header.parse(packet)

    @event_loop
    def mark_ready(self) -> None:
        # asyncio.Event is owned by the event-loop thread.
        self._ready.set()

    async def send(self, frame: Frame) -> None:
        # Ordinary async methods remain ordinary directly awaited coroutines.
        await self._transport.send(frame)

    @task(name="codec.receive", failure=FailurePolicy.FAIL_CONNECTION)
    async def receive_loop(self) -> None:
        while True:
            packet = await self._transport.receive()
            frame = await self.decode(packet)
            await self.send(frame)

    @unobserved
    def _trace_internal_key(self) -> str:
        return self._name
```

Use from the async WebRTC server:

```python
async with Runtime(
    scope_id=pc.id,
    executor=Borrowed(server_executor),
) as execution:
    async with pc:
        codec.mark_ready()              # loop-affine sync call: do not await
        frame = await codec.decode(data)  # worker sync call: await is required
        await codec.send(frame)           # native async call: await as usual
        receive_task = codec.receive_loop()  # @task returns asyncio.Task
        await pc.wait_closed()
```

Use the same worker-classified implementation from synchronous code without an
active Runtime:

```python
codec = PacketCodec(...)
frame = codec.decode(data)
```

This context-sensitive API is intentional but cannot make asynchronous waiting
look synchronous inside an async function. The following is incorrect inside
Runtime:

```python
frame = codec.decode(data)  # frame is an awaitable, not a Frame
```

The metaclass cannot suspend the surrounding coroutine through reflection,
stack inspection, or bytecode metadata. Blocking the event-loop thread until the
worker returns is forbidden because it defeats offloading and may deadlock.

For a synchronous program calling a genuinely asynchronous method, create one
async boundary at application entry rather than one event loop per method:

```python
def main() -> None:
    asyncio.run(async_main())

async def async_main() -> None:
    async with Runtime(scope_id="peer"):
        await component.send(frame)
```

#### Offload lifecycle

For each worker-classified call inside Runtime:

1. Create its live trace node on the event-loop thread and record its owning
   managed task.
2. Enter the per-Runtime serialized lane. While waiting for the lane, the call
   is queued and cancelable.
3. Copy the execution `ContextVar` state and submit to the configured physical
   executor.
4. Immediately after dispatch, mark the call non-cancelable. Cancellation of
   its awaiting asyncio task changes the node to `cancellation_requested`, but
   must not be represented as cancellation of the already-running thread
   function.
5. Run nested synchronous observed calls inline in the same worker context.
6. If the caller remains active, transfer the return value or original exception
   back to it. If the caller was cancelled, retain the worker result only for
   diagnostics and preserve `CancelledError` as the caller's outcome.
7. When the physical worker actually finishes, record queue, worker, and total
   duration plus success, failure, or `completed_after_cancellation`; publish the
   terminal trace event and remove the node from live storage.
8. Release the serialized lane from the tracked worker-future completion path,
   not merely from the awaiting wrapper's `finally`. A cancelled waiter must not
   permit a second call for that peer to run while the first thread is active.

If the asyncio caller is cancelled after worker dispatch, Runtime retains the
worker-call record as a non-cancelable descendant until the thread function
actually finishes. The managed parent's terminal task event is delayed until
that descendant is reconciled, while awaiting the native parent task still
preserves cancellation semantics. Shutdown waits for the worker up to its
configured timeout. Python thread-pool cancellation cannot forcibly stop a
function that has already begun executing.

The type contract must make the context-sensitive result visible. At minimum,
documentation and type-checking tests must prevent treating the Runtime branch
as its final value without `await`. If ordinary static typing cannot express the
scope-dependent overload accurately, expose a generated protocol/stub for async
application code rather than weakening the annotation to `Any`.

### `@task`

The compiled synchronous wrapper must:

1. Resolve the execution scope before creating a coroutine.
2. Build immutable call information.
3. Extract task metadata.
4. Construct a coroutine factory without invoking it.
5. Delegate once to `scope.task_scheduler.spawn_factory`.
6. Return the native `asyncio.Task`.

Conceptually:

```python
def scheduled(*args, **kwargs):
    scope = require_execution_scope()
    call = CallInfo(args, immutable_kwargs(kwargs))
    metadata = extract_metadata(task_spec, call, scope.diagnostics)

    return scope.task_scheduler.spawn_factory(
        lambda: invoke_observed(scope, fn, call),
        name=task_spec.name or fn.__qualname__,
        kind=task_spec.kind,
        metadata=metadata,
    )
```

Scope and scheduler-state validation must happen before coroutine creation so a
missing or closing scope does not leak an unawaited coroutine. The scheduler
must invoke the factory only after it has a running loop and has accepted task
ownership. If task construction itself fails, it closes any coroutine already
created.

### Synchronous worker execution

Automatic worker wrappers replace `@offload` as the normal public mechanism.
The compiled wrapper must:

- Resolve the same generic scope.
- Use `scope.sync_offloader.run_observed`.
- Rely on `SyncOffloader` for context copying.
- Mark the task registry entry non-cancelable only after worker dispatch.
- Emit queue, worker, and total metrics through one shared recording helper.
- Restore cancelability in `finally`.
- Preserve cancellation and worker exceptions.

Remove `@offload` after migration. Retain `@worker` only to resolve affinity
analysis that cannot classify a synchronous method safely; it is not required
for ordinary automatically classified worker methods.

### Performance and no-scope behavior

Recommended behavior:

- `@task` requires an active execution scope.
- ordinary observed sync and async methods execute without a scope and skip
  trace and metric recording.
- performance metadata decorators remain optional overrides for operation name,
  grouping, and attribute extraction; instrumentation itself is automatic.

This allows explicitly synchronous low-level operations to remain usable outside managed execution.

### Simplify wrapper compilation

Split the current large `_wrap` method into focused helpers:

```python
_compile_async_call(...)
_compile_sync_call(...)
_compile_task_entry(...)
_invoke_observed(...)
_classify_sync_affinity(...)
_run_worker_call(...)
_run_inline_call(...)
_record_metric(...)
_extract_attributes(...)
```

Use one outcome-recording path for success, cancellation, and failure rather than repeating the same `try`/`except`/metric logic in runtime and metaclass wrappers.

Validate invalid marker combinations and ambiguous affinity when the class is
created. Preserve descriptor behavior and expose accurate context-sensitive
typing stubs/documentation for static and class methods. Properties,
constructors, and most dunder methods are excluded from automatic wrapping.

## Failure handling

Remove peer-specific fields and policies from generic task specifications:

- `component`
- `bounded`
- `app_task`
- `fail-peer`
- `PeerTaskFailed`
- `RoutineFailurePolicy`

Use neutral scheduler reporting plus a domain observer. Autonomous task markers
may declare:

```python
class FailurePolicy(Enum):
    REPORT = "report"
    FAIL_CONNECTION = "fail-connection"
    IGNORE = "ignore"
```

`FAIL_CONNECTION` is interpreted by a PeerConnection-owned failure observer,
not by `TaskScheduler` or `ObservedMeta`. Runtime may separately treat its own
infrastructure failure as a scope failure. Default critical protocol loops to
`FAIL_CONNECTION`; optional application, log-export, or monitoring routines use
`REPORT` unless explicitly changed.

Every task must retain native task semantics regardless of policy:

- Results remain available from `await task` and `task.result()`.
- Cancellation remains cancellation.
- Exceptions remain available from `await task` and `task.exception()`.
- Failure reporting must never consume or replace the original exception.

`TaskScheduler` should notify tracing and registered generic failure observers,
then re-raise:

```python
except BaseException as error:
    notify_task_failed(error)
    notify_failure_observers(TaskFailureEvent(spec, context, error))
    raise
```

Peer-connection state transitions belong in `PeerConnection` or a registered domain observer, not in the scheduler or metaclass.

Every managed task records its parent task identifier at acceptance time. A
parent cannot complete while managed children remain active. On parent failure,
cancellation, or shutdown, the scheduler recursively cancels cancelable
descendants and awaits all descendants before publishing the parent's terminal
event. On normal parent completion, it joins children or cancels them according
to the parent's structured block; it never silently detaches them. Running
synchronous descendants are non-cancelable and participate in the configured
shutdown timeout.

## Removing PeerContext responsibilities

`PeerContext` currently combines execution ownership, task scheduling, WebRTC lifecycle, forwarding methods, logging, events, signaling, and media attachment. These responsibilities need explicit destinations.

### Move to PeerConnection

Move or expose directly on `PeerConnection`:

- `start`, `dial`, and `accept`
- lifecycle state and generation
- selected transport state
- transport, DTLS, and SRTP waits
- SDP, candidate, and credential operations
- RTP and RTCP send/receive helpers
- signaling attachment
- media-source attachment
- peer domain-event handling
- protocol failure response
- peer event inbox, async iteration, and `wait_closed()` signaling
- construction and ownership of focused signaling, media-source, and log-drain
  components
- ordered shutdown of media/transceivers, SRTP, DTLS, ICE, and UDP resources

Do not replace `PeerContext` with another forwarding facade containing the same methods.

### Move to Runtime or execution scope

Move:

- task registry
- scheduler
- offloader
- serialized worker lane
- tracing service
- metrics
- diagnostics
- executor lifecycle
- managed task collection and cancellation
- root trace lifecycle
- observability facade
- queued and dispatched worker-call tracking

Expose observability through the active resource owner:

```python
execution.observability.live_tree()
execution.observability.metric_snapshots()
execution.observability.subscribe()
execution.observability.cancel(node_id)
```

### Logging

Move peer log-inbox and drain behavior into a focused component:

```python
class AsyncLogDrain(ObservedComponent):
    @task(name="logger.drain", kind="log")
    async def run(self): ...

    @performance(name="logger.write")
    def write_batch(self, batch): ...
```

Inside Runtime, `write_batch()` is automatically worker-dispatched and is
therefore awaited by `run()`. PeerConnection constructs the drain, starts it as
a managed child, stops intake during domain shutdown, and requests a final
flush before Runtime begins generic task shutdown.

### Event emitter

`AsyncEventEmitter` should:

- use the active execution scope's dynamic `start()` method when a scope exists;
- otherwise use plain `asyncio.create_task`;
- never depend on a default singleton runtime or peer context.

It also owns its fallback `_waiting` tasks when no scope exists and must expose
an `aclose()` operation that cancels and awaits them. Under an active Runtime,
those tasks are children of the current managed owner.

### Complete ownership map

| Resource or state | Owner | Shutdown obligation |
|---|---|---|
| Physical executor | Declared `Owned` provider or external `Borrowed` provider | Runtime closes only `Owned` |
| Per-peer worker lane and queue | Runtime | Reject queued calls, cancel undispatched calls, await dispatched calls |
| Scheduler, task registry, task hierarchy | Runtime | Recursively cancel/join managed roots and descendants |
| Trace service, event bus, subscriber timers | Runtime | Complete child/root nodes, close subscriptions, cancel flush handles |
| Metric aggregator/sink | Declared owner | Flush/close only when `Owned` |
| Runtime diagnostics | Runtime | Remain queryable after failed close |
| Peer lifecycle, role, generation, selected transport | PeerConnection | Transition once and signal `wait_closed()` |
| Peer event inbox and async iterator | PeerConnection | Publish terminal event, then close/wake consumers |
| Signaling attachment | PeerConnection-owned focused component | Stop callbacks and await its managed tasks |
| Media sources and transceivers | PeerConnection/components | Stop production and local tasks before transport teardown |
| SRTP, DTLS, ICE, UDP/socket resources | Their domain components, orchestrated by PeerConnection | Close in reverse dependency order |
| Log inbox and drain | PeerConnection-owned `AsyncLogDrain` | Stop intake, final flush, then close |
| Component-local long-running task handle | Component | Stop/restart locally; Runtime remains global hierarchy owner |
| Dynamic fallback event tasks without Runtime | AsyncEventEmitter | Cancel and await in emitter `aclose()` |

Delete `PeerRoutine`, but preserve its useful data in neutral task/trace entries:
task id, parent id, name, kind, start time, native task, cancelability, and
metadata. Replace active-routine tests with Runtime task-hierarchy and live-trace
queries.

### Required cleanup order

1. Atomically move PeerConnection into `closing` and reject new application and
   protocol-start work. Runtime remains active for observed domain cleanup.
2. Stop signaling, media sources, event producers, and transceiver production.
3. Close media/RTP, SRTP, DTLS, ICE, and UDP resources in reverse dependency
   order while Runtime remains active.
4. Stop log intake and flush the final batch.
5. Finish `PeerConnection.__aexit__`, then move Runtime into `closing` and reject
   new tasks and worker calls.
6. Recursively cancel cancelable managed task trees and await descendants.
7. Cancel worker calls that have not dispatched; await dispatched calls within
   the configured timeout.
8. If work remains, raise `ScopeShutdownTimeout`, retain diagnostics, and leave
   Runtime in `closing`. A later `aclose()` may finish cleanup.
9. After all child terminal events, complete the root trace.
10. Close owned trace subscriptions/timers and owned metric sinks.
11. Reset execution and scope ContextVar tokens in the activation context.
12. Close only the owned executor and mark Runtime `closed`.

## Migration phases

### Phase 1: stabilize generic scope primitives

In `runtime_services.py`:

- Add the `ExecutionScope` protocol.
- Add the execution-scope `ContextVar` and access helpers.
- Add neutral task, trace-node, failure-event, scope-state, and resource-ownership
  models without importing `performance.py`.
- Replace awaitable-taking scheduling with rejection-safe coroutine factories.
- Enhance `TaskScheduler` with hierarchical parent/child ownership and generic
  failure observers.
- Ensure task results, cancellation, and exceptions are never swallowed.
- Standardize shutdown errors around an execution scope rather than a peer or WebRTC runtime.
- Keep context propagation solely in `TaskScheduler` and `SyncOffloader`.
- Add dispatched-worker tracking and a serialized per-Runtime worker lane.

Tests:

- Nested activation and token reset.
- Missing-scope errors.
- Parent task-context propagation.
- Concurrent-scope isolation.
- Executor queue and cancellation behavior.
- Coroutine-factory rejection without unawaited coroutine warnings.
- Parent completion/failure/cancellation recursively joins descendants.
- Dispatched worker timeout leaves the Runtime truthfully in `closing`.

### Phase 2: make ObservedMeta self-sufficient

In `performance.py`:

- Remove every import of `peer_context`.
- Resolve services through `runtime_services`.
- Add stateless `ObservedComponent` and automatic eligible-method wrapping.
- Add `@unobserved`, `@event_loop`, and `@worker` markers.
- Conservatively classify synchronous method affinity and reject ambiguity.
- Split wrapper compilation into focused helpers.
- Consolidate outcome and metric recording.
- Validate decorator combinations at class creation.
- Ensure scope lookup precedes coroutine creation.
- Preserve descriptors and signatures.

Tests:

- `@task` returns an `asyncio.Task` immediately.
- Results, exceptions, and cancellation propagate.
- Worker-dispatched synchronous calls propagate execution context.
- Decorator combinations behave consistently.
- Static and class methods retain descriptor behavior.
- Missing scope does not leak a coroutine.
- Performance-only calls work outside a scope without recording.
- Sync methods return normal values outside Runtime and awaitables inside Runtime
  when worker-classified.
- Event-loop methods remain inline inside Runtime.
- Nested calls in the same worker do not redispatch or deadlock.
- Cancelling a dispatched call does not release the serialized lane before its
  physical worker finishes.
- A cancelled caller retains `CancelledError` while the worker node reports its
  eventual `completed_after_cancellation` outcome.
- Every observed call creates a full live node and removes it after publishing
  its terminal event.
- Properties and dunder behavior remain unchanged.
- Direct reflection hits classify known loop-affine methods; indirect ambiguity
  fails until explicitly resolved.
- Full-node overhead and event volume remain within an agreed packet-path
  performance budget.

### Phase 3: reduce Runtime to resource ownership

In `runtime.py`:

- Implement the generic `ExecutionScope` protocol.
- Add async context-manager activation.
- Add root execution-context lifecycle.
- Add explicit `Owned`/`Borrowed` resource handling.
- Support a shared physical executor with one serialized lane per Runtime.
- Remove duplicate task and offload entry points.
- Remove transitional aliases, default runtime, and `atexit` state.
- Retain configuration, shutdown, observability, and one dynamic `start` escape hatch.
- Ensure shutdown cancels managed tasks, waits within a configured timeout, completes the root trace, and closes the executor.
- Close trace subscriptions/timers and only owned sinks/executors.

Tests:

- Independent runtime isolation.
- Root and child trace relationships.
- Shutdown and executor ownership.
- Observer and sink isolation.
- Dynamic application task behavior.
- Shared borrowed executor with isolated per-peer worker lanes.
- Owned versus borrowed resource shutdown.
- Runtime rejection during the transition from active to closing is race-safe.
- Retrying `aclose()` after `ScopeShutdownTimeout` completes once worker work
  finishes.

### Phase 4: remove peer scheduling dependencies

Convert `_schedule_peer_task` call sites to decorated methods in:

- `PeerConnection`
- transceiver
- ICE agent
- DTLS FSM
- DTLS transport
- UDP mux
- audio analyzer
- SRTP session
- logging and media components

Make migrated component classes inherit `ObservedComponent`. Apply `@task` only
to autonomous background entry points such as receive loops, FSM runners,
controller loops, and log drains. Keep ordinary async methods directly awaited.
Remove `@offload`; synchronous worker dispatch is automatic after affinity
classification. Use `@performance` only for explicit naming, grouping, or
attribute extraction, and use `@unobserved` only for justified exclusions.

Remove nested runner coroutines where the enclosing operation can itself be marked.

### Phase 5: fold PeerContext behavior into its owners

- Move protocol and lifecycle APIs into `PeerConnection`.
- Introduce focused logging, signaling, and media components.
- Implement `PeerConnection.__aenter__`, `wait_closed`, idempotent `aclose`, and
  ordered domain teardown.
- Update callers from:

```python
async with PeerContext(pc) as peer:
    peer.start()
```

to:

```python
async with Runtime(scope_id=pc.id) as execution:
    async with pc:
        await pc.wait_closed()
```

- Replace `peer.observability` with `execution.observability`.
- Replace `peer.task_scope.start` with `execution.start` only for genuinely dynamic awaitables.
- Remove forwarding methods after their real owners expose the required APIs.

Tests:

- Inner PeerConnection cleanup can still create observed cleanup calls because
  Runtime remains active.
- Signaling and media stop before SRTP/DTLS/ICE/UDP teardown.
- The final log batch is flushed before Runtime closes its worker lane.
- Peer event iteration receives exactly one terminal event and wakes on close.
- Domain task failure triggers connection cleanup without replacing the task's
  original exception.

### Phase 6: delete obsolete APIs

Delete:

- `webrtc/peer_context.py`
- active-peer context variables and accessors
- `_schedule_peer_task`
- `PeerTaskScope`
- `PeerObservability`
- `PeerRoutine`
- peer scheduling aliases
- transitional runtime context aliases
- default runtime singleton
- runtime injection in component constructors
- `@offload` after all synchronous methods have been classified

Update examples, documentation, performance harnesses, and tests.

### Phase 7: verification

Run the intended suites and compilation checks:

```bash
uv run pytest -q tests
uv run pytest -q tests/performance
uv run python -m compileall -q webrtc examples
```

Run static cleanup gates:

```bash
rg "peer_context|PeerContext|get_active_peer_context|require_active_peer_context|_schedule_peer_task" webrtc tests examples
rg "get_default_runtime|RuntimeBound|spawn_peer_task|spawn_component|spawn_app" webrtc tests examples
rg "\.runtime\b|runtime=" webrtc tests examples
rg "@offload|from .*performance import .*offload" webrtc tests examples
```

These searches should return no compatibility or scheduling references, apart from documentation explicitly describing removed APIs.

## Architectural constraint

Scheduling can be initiated entirely by `ObservedMeta`, but resource ownership must not live on the metaclass itself.

A metaclass-global executor, scheduler, or registry would:

- mix independent peer connections and tests;
- make shutdown nondeterministic;
- turn execution configuration into global state;
- weaken trace and observer isolation;
- make executor ownership unclear.

The required division is:

- `ObservedMeta` compiles tracing and execution behavior for eligible component
  methods and schedules only `@task` entry points.
- `runtime_services.py` implements execution mechanisms and generic scope lookup.
- One explicitly activated Runtime per PeerConnection owns mutable resources and
  its serialized worker lane; a physical executor may be explicitly borrowed.
- `PeerConnection` owns WebRTC lifecycle and domain state.
- `PeerContext` is removed completely.
