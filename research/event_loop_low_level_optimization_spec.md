# Python-Metalanguage Event-Loop Optimization Specification

## Status

This document specifies a Python-first implementation of the optimized
`WebRTCSelectorEventLoop`.

The event loop, queue algorithms, timer processing, bounded datagram draining,
cross-thread publication, and worker orchestration must be written as ordinary
executable Python. PyMeta metadata describes facts and optimization requests.
The compiler lowers the same source into a CPython extension.

There is no handwritten event-loop C implementation and no event-loop-specific
filename route. Generated C is a backend artifact, not a second source of
behavior.

The source has two valid uses:

1. **Reference Python:** import and run the module under CPython for semantics,
   differential tests, debugging, and unsupported-runtime fallback.
2. **Compiled module:** compile the decorated regions and classes into a pinned
   free-threaded CPython extension with the requested native storage and
   concurrency lowerings.

Production auto-selection may choose only the compatible compiled artifact or
stock `asyncio`. It must not silently select the interpreted custom loop.

The current generated loop is semantically promising but does not meet the
performance gate:

| Scenario | Native relative to stock |
|---|---:|
| Idle | 5.4% faster |
| Cross-thread CPU | 9.1% faster |
| 1 ms timers | 24.8% slower |
| Ready storms | 61.5% slower |
| UDP floods | 8.4% slower |

The Python-metalanguage design must remove the backend-specific dynamic work
responsible for those regressions without changing the Python source meaning.

## Normative relationship to the metalanguage

`research/python_metalanguage_spec.md` is the normative source-language
contract. This document is an application profile of that language.

The following rules therefore apply:

- the module is a normal `.py` module accepted by the pinned CPython;
- the interpreted module is the executable specification;
- decorators attach immutable metadata and do not compile at import time;
- annotations describe representation and ownership facts without changing
  Python values;
- native compilation of a required region is all-or-reject;
- no compiler intrinsic may lack real Python behavior;
- ordinary Python evaluation, exception, mutation, cancellation, and cleanup
  order remains authoritative;
- target, ABI, artifact, and deployment choices live in a policy sidecar;
- generated artifacts include a source-correlated capability report.

The event-loop source must not contain:

- C declarations or C snippets;
- CPython member offsets;
- `PyObject *`, reference-count operations, or vectorcall calls;
- C11 atomic expressions or memory-order intrinsics;
- platform symbol names;
- module-init, GC traversal, or deallocation functions;
- copied `_heapq`, deque, selector, or socket C implementation;
- decorators that are merely compiler no-ops.

Those are compiler and backend concerns.

## Feasibility

This architecture is possible because the Python source can express all
required behavior:

- `asyncio.SelectorEventLoop` provides the public loop contract;
- `collections.deque` expresses the reference ready FIFO;
- `heapq` expresses the reference timer ordering;
- `selectors` and socket methods express reactor I/O;
- `queue`, `threading`, and a lock-backed atomic object express correct
  reference cross-thread behavior;
- dataclasses and enums express typed commands and packet records;
- bounded `for` loops express packet and callback budgets;
- PyMeta descriptors express ownership, fixed capacity, representation,
  effects, and execution policy.

The compiled result can still use direct native fields, a native FIFO, a native
heap, atomics, SPSC/MPSC queues, syscall batching, and native workers. Those
lowerings are legal only when the frontend and IR prove that they preserve the
reference Python contract.

## Source organization

The implementation should be divided into small ordinary Python modules:

```text
webrtc/event_loop/
├── __init__.py             public factory and mode reporting
├── loop.py                 WebRTCSelectorEventLoop and _run_once
├── scheduler.py            ready snapshot and timer algorithms
├── commands.py             command model and thread-safe publication
├── datagrams.py            bounded receive and packet ownership
├── workers.py              fixed peer-sharded worker pipeline
├── atomic.py               lock-backed Python atomic reference
└── compile_policy.py       pinned CPython/backend/artifact policy
```

Only `compile_policy.py` may contain target and deployment choices. The other
modules define behavior and remain importable without a compiler.

Helper operations should be separate component methods or module functions
marked as required regions when their contracts are independently useful and
verifiable. `_run_once` should delegate to the scheduler rather than contain
every algorithm in one compiler-shaped method.

## Object model

The source should use composition-oriented OOP. The event loop is the public
facade and owns five focused components:

```text
WebRTCSelectorEventLoop
├── ReactorScheduler
├── CommandInbox
├── DatagramReactor
├── PacketWorkerPool
└── LoopLifecycle
```

Each component:

- is an ordinary Python class with a useful interpreted implementation;
- owns one coherent group of mutable state;
- exposes a small method surface;
- uses `@region` on computationally important methods;
- declares its owner and storage through annotations;
- is constructed once before the loop starts;
- is not replaced while the loop is running.

The hot path uses exact component classes rather than an inheritance hierarchy:

```python
@native_class(compact_object, gc=tracked, weakrefs=False)
class ReactorScheduler:
    def __init__(self, config: LoopConfig) -> None:
        self._config = config

    @region(
        required,
        effects=effects(
            reads={"loop._ready", "loop._scheduled", "loop._selector"},
            writes={"loop._ready", "loop._scheduled"},
            owner="reactor",
            suspend=never,
        ),
    )
    def run_once(self, loop: "WebRTCSelectorEventLoop") -> None:
        ...
```

The compiler may devirtualize and inline calls such as
`self._scheduler.run_once(self)` because the field has an exact annotated type
and is immutable after initialization. OOP structure must therefore not imply
per-callback dynamic method lookup in compiled code.

Use protocols only at cold public boundaries, such as packet delivery or
configuration. Do not use mixins, runtime-pluggable scheduler strategies,
multiple inheritance, or one subclass per platform in the scheduling hot path.
Platform selection belongs to compilation policy.

Methods should remain small enough to differential-test independently.
Private component state is preferable to a large collection of loop fields,
but state already required by `asyncio` remains visible through compatible loop
attributes or generated descriptors.

This style provides clear ownership, isolated tests, and replaceable reference
implementations during development. Its risks are extra objects, bound-method
creation, attribute loads, and virtual dispatch. The native artifact avoids
those costs through exact component types, construction-time field freezing,
escape analysis, scalar replacement, devirtualization, inlining, and region
fusion. If the capability report cannot prove those transformations for a
required hot method, compilation is rejected rather than accepting an
allocation-heavy OOP path.

## Public contract

The custom source exposes one event-loop implementation and one factory:

```python
def new_event_loop(
    *,
    packet_workers: int,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
) -> asyncio.AbstractEventLoop:
    ...


def event_loop_mode() -> Literal["native", "asyncio"]:
    ...
```

The production loader follows this rule:

```python
def automatic_loop_factory(config: LoopConfig) -> asyncio.AbstractEventLoop:
    native = load_compatible_native_artifact(config)
    if native is not None:
        return native.new_event_loop(**config.factory_arguments())
    return asyncio.new_event_loop()
```

It never imports the reference custom loop as a production fallback.

The reference module may be selected explicitly by tests and development
tools:

```python
from webrtc.event_loop.loop import new_event_loop as reference_loop_factory
```

That explicit path is not an additional runtime mode in the native module. It
is the executable specification used to validate compilation.

## Semantic invariants

Interpreted and compiled execution must preserve:

- the ready-queue snapshot: callbacks scheduled by callbacks run next turn;
- FIFO ordering of immediate callbacks;
- pinned `heapq` behavior, including equal-deadline timers;
- cancellation before callback claim and no cancellation after claim;
- `contextvars.Context.run`;
- `SystemExit` and `KeyboardInterrupt` propagation;
- `call_exception_handler` context and error behavior;
- debug `_current_handle`, timing, and slow-callback reporting;
- selector, signal, subprocess, SSL, executor, transport, and wakeup behavior;
- per-socket and per-peer packet order;
- configured packet/time budgets and documented bounded interleaving;
- reference ownership, cyclic GC, weak-reference, and shutdown behavior;
- source-level exceptions and cleanup order.

Python callbacks, Tasks, Futures, transports, selector dispatch, and timer-heap
mutation remain serialized on the reactor thread. Free-threaded does not mean
parallel callback execution.

## PyMeta vocabulary required by this profile

The existing minimal `pymeta/__init__.py` implementation is not yet sufficient
for this plan. It currently stores a string region name and unstructured values
and supports only a small effect enum.

Before the event loop is implemented, PyMeta must provide executable immutable
descriptors matching `research/python_metalanguage_spec.md`.

The minimum additions are:

```python
from pymeta import (
    allocate,
    bounded,
    effects,
    exact_type,
    float_,
    lifetime,
    never,
    owned_by,
    preferred,
    region,
    required,
    sint,
    specialize,
    storage,
    suspend,
    uint,
)
from pymeta.concurrent import (
    atomic,
    bounded_queue,
    coalesced_notification,
    mpsc,
    owned_shard,
    spsc,
)
from pymeta.cpython import (
    compact_object,
    cpython_exact,
    native_class,
    pinned_semantics,
    tracked,
)
```

These names are semantic descriptor objects or constructors, not strings.
Every descriptor must have stable `repr`, equality, hashing, normalization,
serialization, and public inspection.

Required storage descriptors:

- `storage.native_field`: permit an annotated instance field to be represented
  directly in a generated heap type;
- `storage.fifo`: preserve append/popleft/FIFO semantics with a bounded or
  growable native ring;
- `storage.min_heap`: preserve `heapq` ordering using a declared key and tie
  contract;
- `storage.slab`: preserve object lifetime through pooled fixed-capacity
  storage;
- `storage.inline_record`: unbox a fixed record when escape analysis permits.

Required concurrency descriptors:

- `owned_by("reactor")` and `owned_by("worker")`;
- `atomic[uint[32]]` with explicit compare-exchange semantics;
- `bounded_queue(capacity=...)`;
- `mpsc` and `spsc`;
- `coalesced_notification`;
- `owned_shard(key="peer_id", workers="packet_workers")`.

The pure-Python behavior is provided by normal Python classes. For example,
the reference atomic is lock-backed:

```python
from threading import Lock
from typing import Generic, TypeVar


T = TypeVar("T")


class LockedAtomic(Generic[T]):
    def __init__(self, value: T) -> None:
        self._value = value
        self._lock = Lock()

    def load(self) -> T:
        with self._lock:
            return self._value

    def compare_exchange(self, expected: T, desired: T) -> tuple[T, bool]:
        with self._lock:
            previous = self._value
            if previous == expected:
                self._value = desired
                return previous, True
            return previous, False
```

The compiler may lower this protocol to a lock-free atomic only after proving
the representation and linearization points. The lock-backed reference is not
removed from the Python source.

## Annotated loop state

The class remains a normal Python subclass. Field annotations communicate
storage and ownership facts while the interpreted instance retains ordinary
Python values:

```python
from asyncio import Handle, TimerHandle
from collections import deque
from typing import Annotated


ReadyQueue = Annotated[
    deque[Handle],
    storage.fifo
    | owned_by("reactor")
    | bounded(min=0),
]

TimerQueue = Annotated[
    list[TimerHandle],
    storage.min_heap(
        key="_when",
        ordering=pinned_semantics("heapq"),
    )
    | owned_by("reactor"),
]

TimerCount = Annotated[
    int,
    sint[64] | storage.native_field | owned_by("reactor"),
]

ClockValue = Annotated[
    float,
    float_[64] | storage.native_field | owned_by("reactor"),
]
```

The event-loop declaration is behavior-neutral:

```python
@native_class(compact_object, gc=tracked, weakrefs=False)
class WebRTCSelectorEventLoop(asyncio.SelectorEventLoop):
    _ready: ReadyQueue
    _scheduled: TimerQueue
    _timer_cancelled_count: TimerCount
    _clock_resolution: ClockValue
    _scheduler: Annotated[
        ReactorScheduler,
        exact_type(ReactorScheduler) | owned_by("reactor"),
    ]
    _command_inbox: Annotated[
        CommandInbox,
        exact_type(CommandInbox) | owned_by("reactor"),
    ]
    _datagrams: Annotated[
        DatagramReactor,
        exact_type(DatagramReactor) | owned_by("reactor"),
    ]
    _packet_workers: Annotated[
        PacketWorkerPool,
        exact_type(PacketWorkerPool) | owned_by("reactor"),
    ]
    _lifecycle: Annotated[
        LoopLifecycle,
        exact_type(LoopLifecycle),
    ]

    def __init__(self, config: LoopConfig) -> None:
        super().__init__()
        self._config = config
        self._scheduler = ReactorScheduler(config)
        self._command_inbox = CommandInbox(config.command_capacity)
        self._datagrams = DatagramReactor(config)
        self._packet_workers = PacketWorkerPool(config)
        self._lifecycle = LoopLifecycle()

    def _run_once(self) -> None:
        self._scheduler.run_once(self)
```

The backend may generate native descriptors so assignments performed by the
base initializer populate native fields. It must generate heap-type layout,
GC, weak-reference, reference ownership, and module-state code from general
class IR. None of that appears in `loop.py`.

## Python scheduling regions

The following regions are methods of the exact `ReactorScheduler` component.
They are shown separately so each algorithm and effect contract remains
readable and independently testable.

### Ready snapshot

The ready batch is ordinary Python:

```python
@region(
    required,
    effects=effects(
        reads={"loop._ready", "loop._debug"},
        writes={"loop._ready", "loop._current_handle"},
        owner="reactor",
        allocate=never,
        suspend=never,
    ),
    specialize=specialize(
        queue=storage.fifo,
        handles=exact_type(asyncio.Handle, asyncio.TimerHandle),
        semantics=cpython_exact,
    ),
)
def run_ready_snapshot(
    self,
    loop: "WebRTCSelectorEventLoop",
) -> None:
    count = len(loop._ready)
    debug = loop._debug

    for _ in range(count):
        handle = loop._ready.popleft()
        if handle._cancelled:
            continue

        if debug:
            loop._current_handle = handle
            started = loop.time()
            try:
                handle._run()
            finally:
                elapsed = loop.time() - started
                loop._current_handle = None
            if elapsed >= loop.slow_callback_duration:
                loop._report_slow_callback(handle, elapsed)
        else:
            handle._run()
```

The compiler may:

- capture the FIFO size once;
- use direct exact-handle fields;
- snapshot callback, arguments, and context once;
- inline exact `Handle._run`;
- use direct context entry and vectorcall;
- avoid loading exceptional-path fields on success;
- retain generic behavior only outside a required compiled artifact.

The source does not request those mechanisms separately. They follow from
exact-type, ownership, effects, and pinned-semantics proofs.

### Cancelled timer cleanup

Use readable Python and `heapq`:

```python
@region(
    required,
    effects=effects(
        reads={"loop._scheduled", "loop._timer_cancelled_count"},
        writes={"loop._scheduled", "loop._timer_cancelled_count"},
        owner="reactor",
        suspend=never,
    ),
    specialize=specialize(
        queue=storage.min_heap,
        item=exact_type(asyncio.TimerHandle),
        semantics=pinned_semantics("heapq"),
    ),
)
def remove_cancelled_timers(
    self,
    loop: "WebRTCSelectorEventLoop",
) -> None:
    scheduled = loop._scheduled

    if (
        len(scheduled) > _MIN_SCHEDULED_TIMER_HANDLES
        and loop._timer_cancelled_count / len(scheduled)
        > _MIN_CANCELLED_TIMER_HANDLES_FRACTION
    ):
        retained = []
        for handle in scheduled:
            if handle._cancelled:
                handle._scheduled = False
            else:
                retained.append(handle)
        scheduled[:] = retained
        heapq.heapify(scheduled)
        loop._timer_cancelled_count = 0
        return

    while scheduled and scheduled[0]._cancelled:
        handle = heapq.heappop(scheduled)
        handle._scheduled = False
        loop._timer_cancelled_count -= 1
```

The compiler lowers `heapq.heapify`, `heapq.heappop`, list length/root access,
the list comprehension, and exact `_when` comparison from semantic IR. It may
use the pinned heap algorithm internally, but the algorithm remains expressed
once in Python through `heapq`.

Equal-deadline behavior must match the reference. A compiler-generated direct
comparison is legal only when the capability report proves exact
`TimerHandle`, exact-float `_when`, and unchanged pinned ordering.

### Timeout and timer promotion

```python
@region(
    required,
    effects=effects(
        reads={"loop._ready", "loop._scheduled", "loop._stopping"},
        writes={"loop._ready", "loop._scheduled"},
        owner="reactor",
        allocate=never,
        suspend=never,
    ),
)
def compute_timeout(
    self,
    loop: "WebRTCSelectorEventLoop",
) -> float | None:
    if loop._ready or loop._stopping:
        return 0.0
    if not loop._scheduled:
        return None
    return max(0.0, loop._scheduled[0]._when - loop.time())


@region(
    required,
    effects=effects(
        reads={"loop._scheduled", "loop._clock_resolution"},
        writes={"loop._scheduled", "loop._ready"},
        owner="reactor",
        suspend=never,
    ),
)
def promote_due_timers(
    self,
    loop: "WebRTCSelectorEventLoop",
) -> None:
    deadline = loop.time() + loop._clock_resolution
    while loop._scheduled:
        handle = loop._scheduled[0]
        if handle._when >= deadline:
            break
        handle = heapq.heappop(loop._scheduled)
        handle._scheduled = False
        loop._ready.append(handle)
```

Unboxed monotonic time and inline ULP calculation are backend optimizations
derived from exact `loop.time`, pinned semantics, and `float_[64]`. The source
continues to call `loop.time()`.

### Selector processing

The selector result is validated and processed as Python data:

```python
@region(
    required,
    effects=effects(
        reads={"events"},
        writes={"loop._ready", "loop._selector"},
        owner="reactor",
        suspend=never,
    ),
    specialize=specialize(
        selector=pinned_semantics("selectors"),
        key=exact_type(selectors.SelectorKey),
    ),
)
def process_selector_events(
    self,
    loop: "WebRTCSelectorEventLoop",
    events: list[tuple[selectors.SelectorKey, int]],
) -> None:
    for key, mask in events:
        reader, writer = key.data

        if mask & selectors.EVENT_READ and reader is not None:
            if reader._cancelled:
                loop._remove_reader(key.fileobj)
            else:
                loop._ready.append(reader)

        if mask & selectors.EVENT_WRITE and writer is not None:
            if writer._cancelled:
                loop._remove_writer(key.fileobj)
            else:
                loop._ready.append(writer)
```

The frontend must compare this body with the pinned base behavior and reject
unsupported selector shapes. The generated region may fuse validation and
dispatch after proving that no partial mutation precedes a possible
deoptimization.

### `_run_once` orchestration

The complete turn remains small and Pythonic:

```python
@region(
    required,
    effects=effects(
        reads={
            "self._ready",
            "self._scheduled",
            "self._selector",
            "self._stopping",
        },
        writes={
            "self._ready",
            "self._scheduled",
            "self._timer_cancelled_count",
            "self._current_handle",
        },
        owner="reactor",
        suspend=never,
    ),
    specialize=specialize(
        class_contract=cpython_exact,
        fuse=(
            ReactorScheduler.remove_cancelled_timers,
            ReactorScheduler.compute_timeout,
            ReactorScheduler.process_selector_events,
            ReactorScheduler.promote_due_timers,
            ReactorScheduler.run_ready_snapshot,
        ),
    ),
)
def run_once(self, loop: "WebRTCSelectorEventLoop") -> None:
    self.remove_cancelled_timers(loop)
    loop._command_inbox.merge_into(loop)
    timeout = self.compute_timeout(loop)
    events = loop._selector.select(timeout)
    self.process_selector_events(loop, events)
    self.promote_due_timers(loop)
    self.run_ready_snapshot(loop)
```

`fuse` is a compiler optimization request over separately testable functions.
It does not alter method-call behavior in reference Python. The loop's
`_run_once` method is only the facade delegation:

```python
def _run_once(self) -> None:
    self._scheduler.run_once(self)
```

## Cross-thread command boundary

### Typed commands

Commands are normal enums and dataclasses:

```python
class CommandKind(Enum):
    CALLBACK = auto()
    WORKER_RESULT = auto()
    REGISTER_FD = auto()
    REMOVE_FD = auto()
    STOP = auto()


@record(abi="webrtc.event_loop.command.v1")
@dataclass(frozen=True, slots=True)
class Command:
    kind: CommandKind
    payload: object
```

The reference inbox may use `queue.SimpleQueue` or a bounded `queue.Queue`.
The field carries an MPSC descriptor:

```python
CommandQueue = Annotated[
    "CommandInbox",
    mpsc
    | bounded_queue(capacity="config.command_capacity")
    | owned_by("reactor"),
]
```

Only external commands use this inbox:

- `call_soon_threadsafe`;
- executor or worker completion;
- signaling commands;
- descriptor registration/removal;
- stop requests.

Loop-local callbacks, selector events, timers, and received RTP packets go
directly to the reactor-owned FIFO.

### Atomic published handle

The cancellation state machine is expressed in Python:

```python
class PublishedState(IntEnum):
    PENDING = 0
    CANCELLED = 1
    CLAIMED = 2
    DONE = 3


PublishedAtomic = Annotated[
    AtomicValue[PublishedState],
    atomic[uint[32]],
]


@native_class(compact_object, gc=tracked, weakrefs=False)
class PublishedHandle:
    _state: PublishedAtomic

    def __init__(self, callback, args, context) -> None:
        self._state = LockedAtomic(PublishedState.PENDING)
        self._callback = callback
        self._args = args
        self._context = context

    @region(required, effects=effects(writes={"self._state"}))
    def cancel(self) -> None:
        self._state.compare_exchange(
            PublishedState.PENDING,
            PublishedState.CANCELLED,
        )

    @region(required, effects=effects(writes={"self._state"}))
    def claim(self) -> bool:
        _, claimed = self._state.compare_exchange(
            PublishedState.PENDING,
            PublishedState.CLAIMED,
        )
        return claimed
```

The compiled representation may use a lock-free compare-exchange. The Python
reference uses the lock-backed atomic. Both have the same linearization point:
cancellation wins before claim or execution wins after claim.

Only the reactor releases callback, argument, and context ownership after it
observes cancellation or completes execution.

### Merge and wakeup

```python
@region(
    required,
    effects=effects(
        reads={"self._queue"},
        writes={"self._queue", "loop._ready"},
        owner="reactor",
        suspend=never,
    ),
)
def merge_into(self, loop: "WebRTCSelectorEventLoop") -> None:
    for command in self.drain_snapshot():
        dispatch_command(loop, command)
```

`CommandInbox.merge_into` and `drain_snapshot` have real Python queue behavior.
Its MPSC descriptor permits a compiler-generated publication queue with
reactor-only reclamation.

The notification object is annotated with `coalesced_notification`. Reference
Python protects the pending bit using `LockedAtomic`; the compiled artifact may
use an atomic exchange and one self-pipe/eventfd write per burst.

The capability report must state:

- queue algorithm;
- linearization points;
- memory ordering;
- node ownership and reclamation;
- full-queue behavior;
- wakeup coalescing;
- shutdown interaction.

Lock-free is accepted only after proof and ThreadSanitizer tests. It is not
inferred from the name `mpsc`.

## Bounded datagram path

Packet draining is expressed as a bounded Python loop:

```python
@region(
    required,
    effects=effects(
        reads={"transport.socket", "config.receive_packet_budget"},
        writes={"transport.protocol", "packet_pool"},
        owner="reactor",
        allocate=never,
        suspend=never,
    ),
    specialize=specialize(
        socket=exact_type(socket.socket),
        storage=storage.slab,
        batch_syscalls=preferred,
    ),
)
def drain_socket(
    self,
    loop: "WebRTCSelectorEventLoop",
    transport: "WebRTCDatagramTransport",
) -> None:
    started = loop.time()
    budget = loop._config.receive_packet_budget
    time_budget = loop._config.receive_time_budget_us / 1_000_000

    for _ in range(budget):
        if loop.time() - started >= time_budget:
            transport.request_reschedule()
            return

        packet = transport.receive_one()
        if packet is None:
            return
        transport.deliver(packet)
```

`WebRTCDatagramTransport` registers the exact
`loop._datagrams.drain_socket` method as its reader callback. Selector dispatch
therefore schedules exactly one bounded drain callback for a read-ready socket;
`_run_once` does not perform a second independent datagram drain. The compiler
may represent this callback as an exact component/method pair without creating
a temporary bound-method object per packet.

`receive_one()` has a Python implementation using a nonblocking socket and an
explicit packet pool. The pool is a normal Python resource with checked
acquire/release behavior. Its buffer fields use `Annotated` storage, access,
lifetime, and no-escape descriptors.

The compiler may:

- receive directly into final packet storage;
- remove intermediate tuple and address allocations after ICE nomination;
- use a bounded nonblocking `recvmmsg` lowering on Linux;
- retain a bounded nonblocking receive loop on macOS;
- inline packet parsing into the receive region;
- materialize `bytes` only at the ordinary `DatagramProtocol` boundary;
- transfer a pooled `PacketView` only through an explicit WebRTC protocol.

Syscall batching is legal only if error order, packet order, budget accounting,
and documented callback interleaving match the Python region contract.

Each activation has a packet and time budget. The whole turn also has a global
budget, and active sockets are visited round-robin. One peer must not starve
timers, DTLS, RTCP, signaling, or ready callbacks.

Incoming UDP packets never traverse the global MPSC command inbox.

## Packet worker pipeline

The reference implementation uses normal Python threads and bounded queues.
The source partitions ownership by peer:

```python
@region(
    required,
    execute=owned_shard(
        key="packet.peer_id",
        workers="config.packet_workers",
        input=spsc,
        output=spsc,
        ordered=True,
    ),
    effects=effects(
        reads={"packet"},
        writes={"self.peer_state"},
        owner="worker",
        noescape={"packet.payload"},
        allocate=never,
        suspend=never,
    ),
)
def process_packet(
    self,
    packet: "OwnedPacket",
) -> "PacketResult":
    header = parse_rtp(packet.payload)
    authenticated = self.srtp.authenticate(packet.payload)
    return PacketResult(packet.peer_id, header, authenticated)
```

This is an exact `PacketWorker` method owned by `PacketWorkerPool`. In reference
Python, the pool computes:

```python
worker_index = hash(packet.peer_id) % len(workers)
workers[worker_index].input.put_nowait(packet)
```

The compiled worker region is eligible for a true native thread only when all
reachable operations compile without Python objects or Python C API calls.
Dataclasses and enums used in source become fixed native records through
`@record` and representation annotations.

The compiler must reject native worker creation if:

- a value remains boxed;
- a Python callback is reachable;
- an exception would cross the worker boundary without a typed status record;
- packet or peer state has ambiguous ownership;
- a buffer can escape its declared lifetime;
- queue capacity or overload behavior is unspecified.

The fixed worker count is build/factory configuration. It does not change while
the loop runs. Peer state is not migrated. SPSC queues are preallocated, and
queue-full behavior is explicit and counted.

Suitable worker work includes SRTP, RTP parsing, FEC, and sufficiently large
native media operations. Tasks, Futures, Handles, protocols, transports, and
loop fields never enter a packet worker.

## Free-threaded and GIL-free contract

The Python source remains executable on ordinary CPython because that is part
of the metalanguage contract. The production compiled artifact is accepted
only for the pinned free-threaded CPython build.

The target policy requires:

```python
event_loop_target = cpython_extension(
    revision="070700ed4d95c16855603cecab3f41f3b587f973",
    abi=exact,
    free_threaded=required,
    gil=not_used,
    subinterpreters=unsupported,
)
```

This belongs in `compile_policy.py`, not `loop.py`.

The backend emits the extension's free-threading declaration after proving:

- all module-global mutable state is in per-module state;
- reactor-owned state has one mutator;
- published Python objects use supported strong-reference operations;
- shared scalar state is atomic or synchronized;
- native workers touch no Python object or API;
- shutdown joins workers before releasing their memory;
- generated type lifecycle is safe under free-threaded CPython.

“GIL-free” does not mean “no synchronization anywhere.” The desired steady
state is:

- no global interpreter lock;
- no application mutex on reactor-local state;
- no application mutex in native packet workers;
- lock-free SPSC queues;
- a lock-free MPSC command queue when proof and platform support permit it;
- atomics only at actual publication and cancellation boundaries;
- CPython-supported object synchronization where shared Python objects require
  it.

Python callbacks remain serial on the reactor because asyncio semantics require
one owner, not because a GIL exists.

## Shutdown and reclamation

The lifecycle is ordinary Python state:

```python
class LoopState(IntEnum):
    OPEN = 0
    CLOSING = 1
    DRAINING = 2
    CLOSED = 3


@native_class(compact_object, gc=tracked, weakrefs=False)
class LoopLifecycle:
    def __init__(self) -> None:
        self._state = LockedAtomic(LoopState.OPEN)

    @region(required, effects=effects(writes={"self._state"}))
    def begin_close(self) -> bool:
        _, changed = self._state.compare_exchange(
            LoopState.OPEN,
            LoopState.CLOSING,
        )
        return changed

    def is_open(self) -> bool:
        return self._state.load() is LoopState.OPEN
```

The loop delegates producer admission and close transitions to
`LoopLifecycle`. Its transition methods are required regions over a lock-backed
atomic in reference Python. The compiler may lower them to atomics while
preserving the same state transitions:

```text
OPEN → CLOSING → DRAINING → CLOSED
```

Shutdown order:

1. change `OPEN` to `CLOSING`;
2. reject new external publications;
3. wake the reactor;
4. stop admitting worker inputs;
5. drain accepted commands and required completions;
6. join all packet workers;
7. return packet slabs and queue nodes;
8. close network and notification descriptors;
9. transition to `CLOSED`.

The compiler-generated MPSC implementation uses reactor-only reclamation and
must prove that no producer can still link through a retired node. The proof,
memory order, and sentinel lifetime appear in the capability report.

## Compiler responsibilities

The compiler, rather than the application source, implements these mechanics:

- CPython heap-type generation and base initialization;
- native field layout and descriptors;
- GC traversal, clearing, deallocation, and weak-reference behavior;
- exact-type and pinned-revision validation;
- direct Handle and TimerHandle field access;
- callback context entry and vectorcall;
- native FIFO and timer-heap storage;
- deque/list/heapq idiom recognition;
- selector-event fusion;
- monotonic-clock and floating-point lowering;
- atomic compare-exchange and coalesced notification;
- SPSC and MPSC queue layout and memory ordering;
- slab allocation and ownership transfer;
- native worker creation and joining;
- bounded syscall batching;
- exception translation and cleanup;
- module state and `Py_MOD_GIL_NOT_USED`;
- artifact metadata and compatibility validation.

These are general compiler capabilities selected from class, type, effects,
ownership, and region IR. No pass may ask whether the input filename is
`event_loop.py`.

The backend must not contain an event-loop source template that duplicates
`_run_once`. It may contain reusable lowerings for semantic operations such as
FIFO, min-heap, exact CPython slot access, selector dispatch, atomic queues, and
bounded socket receive.

## Capability report

Every build produces a source-correlated report containing:

- each requested class and region;
- inferred and declared effects;
- accepted ownership and lifetime proofs;
- boxed and unboxed values;
- native field representations;
- allocation sites retained or removed;
- recognized deque, heapq, selector, socket, atomic, and queue operations;
- fusion and inlining decisions;
- Python calls remaining inside required regions;
- exception and cleanup paths;
- worker object/API reachability;
- generated synchronization and memory order;
- guards and startup assumptions;
- rejection reasons with source spans;
- source, PyMeta, compiler, CPython, ABI, and policy hashes.

The event-loop artifact is acceptable only when:

- all required regions are `compiled`;
- no required hot path contains an interpreted fallback;
- native packet workers contain no Python API operations;
- the generated module declares GIL independence;
- all requested ownership and queue lowerings are proven.

## Implementation plan

### Stage M0: complete executable PyMeta

Implement the immutable descriptor vocabulary used by this document:

- structured effects with reads, writes, owner, noescape, allocation,
  suspension, blocking, I/O, and synchronization;
- representation composition through `Annotated`;
- native class, storage, exact-type, pinned-semantics, queue, atomic, and
  execution descriptors;
- stable normalization, inspection, serialization, and diagnostics;
- lock-backed atomics, Python bounded queues, ownership resources, and
  coalesced notification reference behavior.

Gate:

- all metadata imports and runs under plain CPython;
- decorators leave callable behavior unchanged;
- contradictory descriptors fail deterministically;
- normalized metadata is hash-stable;
- current compiler tests remain green.

### Stage M1: write the complete reference Python loop

Implement:

- annotated `WebRTCSelectorEventLoop`;
- exact `ReactorScheduler` and facade `_run_once`;
- `CommandInbox`, typed commands, and published handles;
- `DatagramReactor` and bounded datagram draining;
- packet pool and explicit `PacketView`;
- `PacketWorkerPool` with fixed peer-sharded reference workers;
- `LoopLifecycle` shutdown state machine;
- public factory.

Gate:

- differential behavior against pinned stock asyncio;
- no compiler or generated artifact is required to run tests;
- ready, timer, cancellation, context, exception, and debug behavior matches;
- bounded UDP interleaving is documented and tested.

### Stage M2: lower native class and scheduler storage

Extend frontend and IR to consume:

- native-class metadata;
- annotated field storage;
- exact CPython types;
- owner and thread affinity;
- FIFO and min-heap semantic operations;
- required-region calls and fusion requests.

Generate the loop heap type, native fields, FIFO, heap, timer arithmetic, and
ready snapshot from the Python source.

Gate:

- no event-loop filename or source-template routing;
- no duplicated native `_run_once`;
- ready storms, timers, and idle polling are no worse than stock;
- lifecycle and deallocation stress pass.

### Stage M3: lower selector and datagram regions

Recognize selector iteration, socket receive, packet-pool lifetime, and bounded
drain loops. Fuse the corresponding required regions when legal.

Gate:

- improved packets per syscall and packets per CPU-second;
- packet order and error behavior match the reference contract;
- no peer can exceed global fairness budgets;
- ordinary `DatagramProtocol` retains immutable `bytes` semantics.

### Stage M4: lower concurrency descriptors

Lower:

- lock-backed atomic protocol to native atomics;
- known-producer SPSC queues;
- external-producer MPSC inbox;
- coalesced notification;
- owner-sharded worker execution;
- typed native worker records.

Gate:

- worker regions contain no Python object/API operation;
- SPSC and MPSC linearizability and wraparound tests pass;
- cancellation/claim races match reference behavior;
- ThreadSanitizer reports no races;
- packet throughput scales without p99 regression.

### Stage M5: free-threaded artifact and production loader

Generate and validate the pinned CPython extension:

- exact revision and ABI;
- free-threaded release build;
- per-module state;
- GIL-independent declaration;
- source and policy hashes;
- required class/factory surface.

The loader selects the artifact only when every check passes; otherwise it
uses stock asyncio.

Gate:

- interpreted custom source is never production-auto-selected;
- stale, mismatched, absent, and failed-import artifacts use stock asyncio;
- repeated create/run/close/deallocate and server restart tests pass.

## Verification matrix

Every stage must include:

- source import and execution without a compiler;
- metadata introspection and normalization tests;
- capability-report assertions for each required region;
- stock/reference/compiled differential schedules;
- immediate and equal-deadline ordering;
- callbacks scheduling and cancelling callbacks;
- context variables and exception-handler failure;
- debug and slow-callback behavior;
- thread-safe cancellation and wakeup races;
- signals, TCP, UDP, SSL, subprocesses, and executor completion;
- cyclic GC, weak references, and deallocation stress;
- UDP saturation and multi-peer fairness;
- packet-budget and time-budget boundaries;
- packet-pool exhaustion and retained-view lifetime;
- SPSC wraparound, full queue, and ownership transfer;
- MPSC publication gaps and reclamation;
- atomic published-handle cancel/claim races;
- shutdown during receive, worker work, and publication;
- late-producer rejection and fd reuse;
- strict C17 generated-output checks;
- ASan, UBSan, and ThreadSanitizer;
- `git diff --check`.

Test builds expose counters without changing source semantics:

```text
reactor_turns
ready_snapshot_callbacks
timer_heap_operations
selector_events
udp_packets
udp_receive_syscalls
udp_budget_packet_yields
udp_budget_time_yields
packet_pool_acquires
packet_pool_fallback_allocations
spsc_publications
mpsc_publications
mpsc_publication_retries
wakeup_writes
wakeup_coalesced
worker_batches
worker_queue_full
```

Benchmarks alternate stock and compiled process order and use release builds
from the same pinned free-threaded CPython revision. Report CPU, callbacks,
selector polls, syscalls, wakeups, allocations, packets per second,
packets per CPU-second, and p50/p95/p99 latency.

## Adoption rule

Production native selection remains disabled until:

- median loop-core CPU improves by at least 20%;
- end-to-end WebRTC CPU improves by at least 5%;
- the paired confidence bound favors native;
- p99 latency regresses by no more than 1 ms;
- packet and workload parity hold;
- every required region is proven compiled;
- the generated artifact passes free-threaded sanitizer and lifecycle gates.

The implementation order is M0 through M5. Optimization work begins in normal
Python and PyMeta IR. Backend changes are accepted only when they generalize
the declared semantic operations and remain traceable to the Python source.
