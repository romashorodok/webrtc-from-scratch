# Aggregated Live Tracing Performance Plan

## Status

Implementation plan only. This document supersedes the performance-related
parts of `docs/tracing.md`; it does not replace the runtime ownership and
lifecycle rules in `peer_context_refactoring.md`.

The plan keeps automatic observation and a complete live view of meaningful
application state, but it deliberately changes two expensive invariants:

> An observed method call must be accounted for, but it does not always need a
> unique live trace node.

> A runtime task does not automatically need a frontend trace node. The task
> registry may retain it for execution ownership while observability projects
> only selected state-machine transitions and controllable operations.

Creating a UUID-backed node and three transport events for every short repeated
call is incompatible with low-overhead tracing on packet and media paths. Exact
nodes remain mandatory where identity is needed for ownership, cancellation,
failure diagnosis, or an explicitly requested detailed trace. Repeated calls
are represented by stable aggregate activity spans.

## Goals

- Preserve a live, causally structured view of the entire application through
  state-machine entities, selected control handles, repeated activity,
  failures, domain state, tracing health, and backpressure.
- Aggregate calls at the instrumentation boundary so duplicate data is never
  inserted into the live tree or sent over the network.
- Make tracing memory proportional to observable state machines, explicitly
  exposed control handles, and bounded aggregate cardinality—not runtime task
  count or total call count.
- Avoid per-call event publication, JSON construction, UUID generation, full
  tree scans, and full group snapshots on normal aggregate paths.
- Send idempotent incremental patches in bounded batches and recover explicitly
  from dropped batches.
- Keep frontend work proportional to changed and visible records. Do not regroup
  thousands of raw backend records on every render.
- Retain an opt-in exact mode for debugging one operation without making exact
  tracing the production default.

## Non-goals

- Tracing every packet payload, argument, return value, queue item, or mutable
  Python object. Whole-application observability means all meaningful bounded
  state, not a heap dump.
- Using trace aggregation to change task ownership, cancellation, protocol
  ordering, executor ordering, or backpressure behavior.
- Keeping a server-side archive of completed calls.
- Replacing protocol performance benchmarks with live tracing statistics.
- Introducing a binary protocol before JSON encoding is measured as a remaining
  bottleneck.

## Problems in the current implementation

### Backend hot path

`ObservedMeta` currently routes every eligible non-task method through
`_start_node` and `_finish_node`. A short call therefore performs work that can
cost more than the observed operation:

- create a random UUID and descriptor;
- create a `TaskTrace`, metadata dictionary, and transitions list;
- acquire the trace-store lock and mutate the arena;
- publish `trace:init`, `trace:complete`, and `trace:delete` objects;
- construct repeated full task dictionaries;
- schedule subscriber batching and retain pending event objects;
- emit a separate `MetricEvent` and update a second aggregation structure.

This duplicates lifecycle and metric accounting for the same call. Frontend
virtual grouping occurs only after all individual nodes have already paid their
backend, JSON, network, reducer, and allocation cost.

### Store and delivery amplification

- `TraceService._payload` scans all live tasks to rediscover `peer_id`.
- `Runtime.trace_groups` snapshots all groups, scans the live tree, builds a set
  of task IDs, filters the snapshots, and converts each retained group to a
  dictionary.
- The WebSocket pump repeats that work on each outgoing batch and heartbeat.
- Every group snapshot is sent even if only one group changed.
- Heartbeats can snapshot every running node just to update durations that the
  browser can derive from a server clock anchor.
- Each subscriber holds its own list of full pending event objects. Overflow
  silently drops the oldest entries, so the client cannot know it needs a fresh
  snapshot.
- Event coalescing serializes whole event bodies to JSON to find duplicates.

### Frontend amplification

- `enqueueTraceEvents` dispatches each inner batch event separately, causing
  multiple complete reducer passes for one WebSocket message.
- Reducer paths repeatedly rebuild maps, arrays, tombstone sets, archives, group
  lists, and summaries.
- `groupTraceRecords` receives raw per-call nodes and repeatedly scans and sorts
  them even though repeated calls share a stable backend identity.
- Trace archive synthesis may copy whole subtrees and group arrays during live
  completion traffic.
- React, D3 hierarchy construction, layout, and SVG reconciliation still see up
  to hundreds of records per update. A render bound limits DOM size but does not
  prevent upstream processing of all records.

## Required observability model

The live view has four bounded planes. They share `trace_id` and scope identity
but have different lifecycles. Runtime task ownership remains an internal
execution concern and is not a fifth frontend plane.

1. **Observable state machines** — peer, ICE, DTLS, transport, transceiver,
   media, worker-lane, and selected long-running controller state. A machine is
   one stable entity with revisioned transitions; it is not one node per task.
2. **Activity groups** — stable aggregate spans for repeated observed calls.
   They show current in-flight count and cumulative statistics without one node
   per invocation.
3. **Control handles and facets** — optional exact handles only for work the
   viewer or a test must cancel, pause, or inspect, plus revisioned scalar state
   such as queue depth and selected pair. Facets update only when values change.
4. **Diagnostics** — bounded counters describing observation loss, rejected
   cardinality, subscriber lag, resyncs, extractor failures, and tracing CPU or
   queue pressure.

This model observes the whole application without claiming that every call is
a separately addressable task.

```text
Runtime / PeerConnection scope
|
|-- observable state-machine graph
|     `-- peer / ICE / DTLS / transport / media states
|
|-- aggregate activity graph
|     `-- repeated method/path groups attached to a machine or group
|
|-- selected control handles and facets
|     `-- cancel/pause target plus latest bounded semantic values
|
`-- tracing diagnostics
      `-- admission, loss, lag, and overhead counters
```

The internal `TaskRegistry` remains authoritative for shutdown and hierarchical
cancellation. Observability stores an owner ID only when needed for correlation;
it does not mirror every registry entry, task start, or task completion to the
browser.

## State-machine projection

Each observable subsystem declares a bounded machine definition:

```python
@dataclass(frozen=True, slots=True)
class MachineSpec:
    machine_type: str
    initial: str
    transitions: Mapping[str, frozenset[str]]
    terminal: frozenset[str]

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
```

Examples are one peer lifecycle entity, one ICE agent entity, one DTLS
transport entity, one worker-lane entity, and one entity per bounded
transceiver/track. Long-running tasks update the state of their owning entity
instead of appearing as permanent running trace nodes. Short helper tasks are
hidden entirely unless they expose a control handle or exact capture is active.

The reducer validates transitions. Invalid transitions do not mutate visible
state; they increment diagnostics and retain one bounded exemplar. A transition
contains a `cause_id` that can refer to another transition, an activity group,
or a control handle, preserving causality without a task tree.

## Deterministic transition checkpoints for tests

Tests need a separate control plane, not a production subscriber callback that
blocks arbitrary work. Add an optional `TransitionController` owned by Runtime
and installed only by tests:

```python
controller = TransitionController()
controller.pause_at("dtls", to_state="connected", phase="before_commit")

async with Runtime(transition_controller=Borrowed(controller)):
    ...
    reached = await controller.wait_until("dtls", "connected")
    # Assert the pre-transition application state here.
    controller.release(reached.checkpoint_id)
```

Supported phases are explicit:

- `before_commit`: transition is validated and announced to the controller but
  has not changed the authoritative machine state;
- `after_commit`: state and CRDT projection are committed, but the component
  has not passed the checkpoint;
- `terminal`: selected controller outcome is committed and owned child/barrier
  reconciliation is complete.

Rules for checkpoints:

- The production default is a zero-cost null controller selected once on
  Runtime construction.
- Only async safe points may pause. Never block an executor thread, UDP/socket
  callback, lock holder, destructor, or synchronous state mutation halfway
  through an invariant.
- A checkpoint has a timeout and is released automatically during Runtime
  shutdown so a failed test cannot deadlock teardown.
- Matching is by stable machine/transition IDs and optional bounded predicate,
  never arbitrary callback execution in the protocol hot path.
- The controller supports `release`, `cancel_owner`, and `inject_failure` only
  at transitions whose machine definition explicitly permits that test action.
- Tests assert both sides of the transition and verify no following transition
  occurred before release.

If existing code changes protocol state synchronously, split it into
prepare/commit/continue boundaries before adding a pausable checkpoint. Do not
turn ordinary tracing observers into awaitable hooks.

## DTLS FSM review and reusable runner

`webrtc/dtls/fsm.py` is the best current example of an application state
machine, but it is a migration source rather than a generic implementation to
copy unchanged.

### Ideas to retain

- `FSMState` provides small stable phase identities (`Preparing`, `Sending`,
  `Waiting`, `Errored`, `Finished`).
- `prepare`, `send`, and `wait` isolate phase behavior and return a next state.
- `run` is the single coroutine that serializes phase execution.
- `handshake_state_transition` acts as an async mailbox instead of letting
  callers execute FSM work concurrently.
- `handshake_complete` exposes semantic completion without asking callers to
  inspect the runner task.
- Flight handlers are separated from the phase runner, so protocol work and
  orchestration can be observed independently.

### Problems not to generalize

- `handshake_state_transition_lock` is held while phase handlers await network,
  retransmit, and sleep work. A dispatch that needs the same lock can wait for
  the entire phase. A single runner already serializes state mutation, so this
  lock should not guard the runner loop.
- The queue carries both wake-up requests and internally generated next-state
  values. Commands and committed state are different concepts and need separate
  types/channels.
- `self.handshake_state` is initialized and read by `dispatch`, but the runner
  does not assign each returned state to it. It can therefore describe stale
  state even while queue-driven execution advances.
- Legal edges are implicit in handler return values. There is no transition
  table, revision, cause, or invalid-edge diagnostic.
- `Errored` is numerically false, which makes truthiness-based queue logic
  fragile. State enums must never be used as “has next state” sentinels.
- Completion is split between `_complete_handshake`, `handshake_complete`, the
  `Finished` return, and runner exit. One committed terminal transition should
  define observation and testing order.
- The current observer sees method/task activity around the FSM, not an
  authoritative committed transition stream.

### Generic runner shape

Extract a small `AsyncStateMachineRunner[S, C]` into `runtime_services.py` (or a
neutral `state_machine.py`). It is an execution primitive and must not import
tracing, DTLS, or component policy.

```python
class AsyncStateMachineRunner(Generic[S, C]):
    state: S
    revision: int
    commands: asyncio.Queue[C]

    async def step(self, cause: C | None) -> S: ...
    async def next_cause(self) -> C | None: ...

    async def run(self) -> None:
        while self.state not in self.spec.terminal:
            cause = await self.next_cause()
            proposed = await self.step(cause)
            self.spec.validate(self.state, proposed)
            await self.controller.before_commit(...)
            committed = self.commit(proposed)  # no await, one loop writer
            self.projector.transition(committed)
            await self.controller.after_commit(committed)
```

The concrete DTLS runner may keep specialized retransmission and flight logic,
but it should use the same transition commit primitive:

- external `dispatch` enqueues a typed `Start`/`Wake` command without taking a
  state lock;
- the runner owns `state`, `flight`, and transition revision;
- a phase handler proposes a state but cannot publish it directly;
- synchronous `commit` validates and updates `self.state` atomically within one
  event-loop turn;
- the observational CRDT projector consumes the committed `TransitionOp`;
- test checkpoints surround commit only at the runner's async safe point;
- the terminal commit sets `handshake_complete` and runner completion in a
  documented order.

Do not force every protocol into the DTLS five-state enum. Reuse the runner and
transition contract while giving peer, ICE, transport, and media their own
explicit state types and legal-edge tables.

## Observation policy

### Policy values

Compile one immutable policy for every method in `ObservedMeta`:

```python
class TraceDetail(str, Enum):
    STATE = "state"
    AGGREGATE = "aggregate"
    EXACT = "exact"
    OFF = "off"

@dataclass(frozen=True, slots=True)
class CompiledObservation:
    operation_id: int
    operation: str
    group: str
    detail: TraceDetail
    slow_ms: float | None
    capture_failures: bool
```

`operation_id` is allocated once at class creation and is used internally
instead of repeating qualified strings on the hot path. The string table is
included in snapshots and only patched when a new compiled operation appears.

### Default classification

| Work | Default | Reason |
| --- | --- | --- |
| Ordinary `@task` entry point | off | The registry owns it; tracing need not mirror it. |
| `@task(state=...)` controller | state | Updates the owning observable machine. |
| Runtime root / peer lifetime | state | One peer lifecycle machine represents the scope. |
| Explicitly exposed cancel/pause target | exact | UI/test control needs a unique handle. |
| Long-running autonomous routine | state | Updates controller/lane state instead of a permanent task node. |
| Ordinary async or inline sync method | aggregate | Repeated execution is activity, not ownership. |
| Explicit `@unobserved` method | off | Required infrastructure/hot-path exclusion. |
| Explicit diagnostic capture | exact | Temporary bounded investigation. |

Add `@observe(detail=..., group=..., slow_ms=..., capture_failures=...)` only
for exceptions to these defaults. Keep `@performance` as a metric naming and
attribute contract during migration, then fold its static fields into the
compiled observation policy. Component implementations must not call tracing
services directly.

### Exact escalation

Aggregate mode must preserve useful anomalies without enabling raw mode:

- Always increment aggregate error/cancellation counters.
- Retain only the latest bounded failure class and timestamp by default.
- Emit a bounded terminal exemplar for a failure or a call exceeding `slow_ms`.
  An exemplar is diagnostic data attached to the group; it is not inserted as a
  fake live task and is never cancelable.
- Permit a viewer to request exact capture for one `operation_id`, machine,
  explicit control handle, or state facet for a duration or call budget. The
  server enforces both limits and automatically returns to aggregate mode.
- Never offer an unlimited global raw-mode toggle in the production viewer.

### Causal aggregation

An aggregate key is:

```text
(trace_id, owner_entity_id, parent_ref, operation_id, bounded_dimensions)
```

`parent_ref` identifies an observable machine, an explicit control handle, or
another stable aggregate group. Nested repeated operations therefore retain
their logical call path without retaining individual invocations.
`bounded_dimensions` may contain only
predeclared low-cardinality values such as direction or packet kind. Peer IDs,
SSRCs, candidate addresses, arbitrary names, exception messages, and argument
values must not become group-key dimensions unless they have an explicit hard
cardinality budget.

The stable `group_id` is derived from the interned key with a fast scoped
integer allocator. Do not hash strings or allocate UUIDs per call. Concurrent
invocations increment `in_flight`; a group span is visibly active while
`in_flight > 0`.

## Aggregate record

Keep a compact mutable internal record and create a transport dictionary only
when the dirty group is drained:

```text
group_id
trace_id
owner_entity_id
parent_ref_type: machine | control | group
parent_ref_id
operation_id
calls
in_flight
successes
cancellations
errors
total_duration_ns
min_duration_ns
max_duration_ns
last_started_ns
last_finished_ns
latest_failure_class
revision
```

Use integer nanoseconds internally. Compute averages and convert to milliseconds
only at the transport or display boundary. Add a small fixed latency histogram
only if percentile rendering is required and a benchmark shows its overhead is
acceptable; do not retain raw samples.

Groups live for the epoch of their owner machine, plus the existing short client
grace period needed to show a final state. When an entity reaches a terminal
state or begins a new epoch, the server flushes final dirty groups before the
transition, then removes the old-epoch groups from live memory. A client summary
may freeze the final aggregate values within its own bounded archive.

## Low-overhead instrumentation path

### Aggregate begin/end

The normal wrapper should do only the following:

1. Resolve the active scope and precompiled `CompiledObservation`.
2. Resolve or cache the group handle for the current owner/parent context.
3. Increment `calls` and `in_flight`, record `monotonic_ns`, and mark the group
   dirty without publishing an event.
4. Execute the method.
5. Decrement `in_flight`, update integer counters/duration, and mark dirty.

Do not create `CallInfo`, `MappingProxyType`, attribute dictionaries, event
dataclasses, trace snapshots, or UUIDs when there is no extractor or exact
capture. Run success extractors only when explicitly required. Run failure
extractors lazily only on failures. Bound every extracted string and field.

### Concurrency design

- The event-loop path updates event-loop-owned records directly.
- A normal worker call returns its timing/outcome to the event loop, which
  performs the aggregate update there.
- Nested inline calls already inside a worker use a thread-local delta buffer
  associated with the worker submission. Merge that buffer once when the worker
  result returns to the loop.
- Do not take one global `RLock` for every observed call. If a borrowed metric
  sink must accept arbitrary-thread updates, isolate it behind a separate
  adapter so the default live aggregator remains loop-owned.
- Reuse the queue/worker/total timings already produced by
  `WorkerCallCompleted`; do not emit three standalone `MetricEvent` objects.

## Lock-free, CRDT-style projection

CRDT convergence and lock freedom solve different problems. A CRDT can make
duplicate and reordered updates converge, but putting a CRDT map behind an
`RLock` is still lock-based. Conversely, blindly mutating shared Python
dictionaries is not safely lock-free. Use both of these constraints:

1. no shared mutable observability record is written by multiple producers;
2. replicated patches use monotonic, idempotent merge rules.

### Single-writer ownership

The Runtime event loop is the only writer of machine, group, facet, journal, and
subscriber projection stores. Event-loop component calls update it directly.
Workers never mutate those stores: each worker submission owns a small local
`ObservationDelta` and returns it with `WorkerCallCompleted`; the event loop
merges it once. This removes `RLock` from the normal tracing path.

Domain state transitions should already return to the owning event loop before
commit. An exceptional external-thread producer writes immutable operations to
a bounded ingress queue and wakes the loop; it never receives a reference to a
store record. The plan promises no application-level tracing lock or shared-map
contention. It does not claim that CPython, the event loop wakeup primitive, or
an optional external MPSC queue is implemented without internal locks on every
platform.

Use per-producer dots `(runtime_epoch, producer_id, producer_seq)` so the
single-writer reducer can discard duplicates. Producer sequence allocation is
local to each producer and requires no shared atomic counter.

### Convergent data types

Use CRDT-inspired fields appropriate to each value:

| Value | Merge rule |
| --- | --- |
| calls/successes/errors/cancellations | Per-producer G-counters; merge component-wise maximum, display the sum. |
| in-flight | PN-counter (`starts - finishes`) per producer; assert it never displays below zero. |
| total duration | Per-producer G-counter in integer nanoseconds. |
| minimum/maximum duration | Min/max semilattice with unset sentinel. |
| latest failure/exemplar | Bounded last-writer register ordered by producer dot after authoritative loop sequencing. |
| machine state | Validated transition register ordered by machine epoch and transition revision; never arbitrary wall-clock LWW. |
| entity/group map | Epoch-scoped observed-remove map; remove wins only for the same or older epoch. |
| diagnostics | G-counters and max gauges. |

The authoritative protocol state machine still executes transitions in strict
event-loop order. CRDT rules apply to its observability projection and frontend
replica; they must never merge two incompatible protocol states and then feed
the result back into ICE, DTLS, SRTP, or peer behavior.

The server sends absolute joined values plus record revision, not raw increment
operations, for normal frontend delivery. This keeps the browser reducer cheap
while remaining idempotent. Raw producer components are useful internally and
in convergence tests.

### Removal and bounded tombstones

Observed-remove maps normally retain tombstones indefinitely, which conflicts
with bounded memory. Scope every record to a Runtime epoch and retain removal
tombstones only until all current subscriber cursors acknowledge the removal or
until those subscribers are forced to resynchronize from a newer snapshot.
Disconnecting subscribers do not pin tombstones. A snapshot starts a new
replication checkpoint from which older tombstones can be discarded.

### Cardinality and admission

Set separate limits for exact nodes, aggregate groups, state facets, dirty
records, exemplars, and operation strings. On a group-cardinality limit:

1. Merge into a preallocated overflow group scoped to the owner entity and
   component, rather than dropping all accounting.
2. Increment `group_cardinality_overflow`.
3. Never evict an active group with `in_flight > 0`.

Expose all limit hits in the diagnostics plane and initial snapshot.

## Backend storage changes

Stop using `TraceStore` as a mirror of Runtime tasks. Retain a small
`ControlHandleStore` only for explicitly exposed exact operations, and add
`MachineStore` plus `ActivityGroupStore` under a new `ObservabilityService`.
It needs these indexes:

- aggregate key to group handle;
- `group_id` to record;
- `owner_entity_id` and epoch to group IDs for O(groups owned by entity) cleanup;
- dirty group IDs;
- removed group IDs awaiting one transport drain.

Store `scope_id`/`peer_id` once on the service and peer machine. Remove the
`TraceService._payload` scan. Use direct entity/epoch indexes for owner cleanup;
do not call `live_tree()` to filter metrics.

Unify live activity aggregation and `MetricGroupAggregator`. Keeping two
aggregators for the same invocation doubles hot-path work and risks mismatched
lifecycle. External metric sinks may receive a lower-rate drained snapshot or
delta adapter, but must not force per-call object allocation in the default
path.

## Change journal and transport

### Source-side coalescing

Replace per-subscriber lists of full events with one bounded runtime change
journal plus subscriber cursors:

- Machine transitions and explicit control-handle lifecycle entries retain
  ordering.
- Repeated facet/control updates coalesce by stable ID within transition
  boundaries.
- Aggregate and state changes coalesce by stable ID and retain only the latest
  absolute revision.
- A flush drains dirty IDs once and serializes the resulting patch once. The
  same immutable encoded batch can be offered to all matching subscribers.
- Slow subscribers do not make producers allocate unbounded data.

If a cursor falls behind the journal head or its queue overflows, send
`trace:resync_required` and then a fresh snapshot. Never silently discard state
and continue as if the client is synchronized.

### Versioned idempotent schema

Use absolute counters and per-record revisions rather than arithmetic deltas.
This makes duplicate and retried batches harmless.

```json
{
  "event": "trace:batch",
  "data": {
    "schema": 2,
    "trace_id": "...",
    "sequence": 42,
    "server_monotonic_ms": 123456.0,
    "events": [
      {"type": "machine:transition", "records": []},
      {"type": "control:upsert", "records": []},
      {"type": "control:remove", "ids": []},
      {"type": "group:upsert", "records": []},
      {"type": "group:remove", "ids": []},
      {"type": "state:upsert", "records": []},
      {"type": "diagnostics:patch", "values": {}}
    ]
  }
}
```

The first message is `trace:snapshot` with a complete bounded set of current
machines, control handles, groups, facets, operation strings, diagnostics, and
`snapshot_sequence`.
Snapshot capture must use a consistent service revision so changes that happen
during serialization are sent in the next batch.

### Flush policy

- Flush machine transitions and control-handle terminal changes promptly,
  subject to one event-loop turn of coalescing.
- Flush aggregate/state dirty records at a configurable display cadence,
  initially 100–250 ms while the viewer is open.
- When no viewer is attached, keep aggregating but do not build transport
  dictionaries or run heartbeat snapshot scans.
- When the overlay is closed, the client may request a low-rate mode. Reopening
  requests a fresh snapshot before returning to the live cadence.
- Send a transport ping or clock anchor only as needed for connection health.
  The browser computes active duration from `started_monotonic_ms` plus the
  latest server clock anchor; do not send every entity/group to advance a label.
- Apply byte and record budgets per batch. Continue overflow in the next
  sequence without breaking lifecycle ordering.

Keep JSON for the first implementation. After the object-count and full-snapshot
problems are removed, profile encoding. Only then consider compact array tuples,
MessagePack, or another binary representation.

## Domain state facets

Add an observation-neutral state interface in `runtime_services.py` so protocol
components do not import the frontend or transport:

```python
class StateFacetSink(Protocol):
    def transition(self, operation: TransitionOp) -> None: ...
    def merge_values(self, entity_id: str, dot: ProducerDot,
                     values: Mapping[str, Scalar]) -> None: ...
    def remove(self, entity_id: str, epoch: int, dot: ProducerDot) -> None: ...
```

Prefer adapters from existing semantic domain events. Do not poll arbitrary
component objects. Initial facets should cover:

- peer lifecycle and signaling/connection state;
- ICE gathering/connection state and selected candidate pair identity;
- DTLS state;
- transceiver/track direction and active/inactive state;
- bounded queue depth/high-water marks;
- worker lane queued/running state;
- trace admission and subscriber health.

Facet records contain only stable IDs, enum/string states, booleans, bounded
numbers, and revisions. Payload bytes, SDP, keys, certificates, full addresses,
and unbounded exception text are excluded.

## Frontend state pipeline

### One batch, one state commit

Change the WebSocket handlers to pass a complete canonical batch to one reducer
dispatch. The reducer applies all entries in sequence order and commits once.
Do not call `enqueueTraceEvent` in a loop.

Maintain normalized canonical state:

```text
machinesById: Map
controlsById: Map
groupsById: Map
facetsById: Map
operationNamesById: Map
machineOrder / root IDs
childrenByParent
groupsByParent
diagnostics
lastSequence
topologyVersion
valueVersion
```

Apply copy-on-write only to maps touched by the batch. Reject stale revisions.
Materialize arrays only for selectors that need them. Do not rebuild normalized
maps from transport arrays after every action.

Separate topology changes from value changes. Starts, removals, and parent
changes increment `topologyVersion`; durations, counters, state, and status
updates increment `valueVersion`. D3 layout depends only on topology and the
active filter, so a counter refresh must not reconstruct the hierarchy.

### Archive behavior

- Freeze one final machine/group record on terminal transitions.
- Do not copy every visible ancestor and every group for each completion.
- Store archived records normalized and reference shared immutable ancestors by
  ID where possible.
- Keep existing count/byte limits and add an explicit archive memory estimate.
- Exact tombstones apply only to explicit control handles. Aggregate and machine
  removals use epoch/revision rules and do not enter a global task tombstone set.

### Backend groups are first-class presentation nodes

Remove normal use of `groupTraceRecords` for backend activity. The renderer
attaches group records to their `parent_ref`; it never receives thousands of
individual successful leaves to regroup. A small UI-only grouping function may
remain for exact diagnostic captures, but it must operate only on the bounded
visible capture.

## Rendering design

Use a two-tier renderer:

1. A virtualized list/table for searchable complete machine, control, group,
   facet, transition, failure, and diagnostic data.
2. A bounded topology visualization for the selected root/subtree.

For the topology visualization, first retain SVG with the normalized pipeline
and measure it. Ensure stable keyed node components, memoized geometry, and
imperative text updates for fast duration/counter refreshes. If SVG commit or
layout remains above budget, replace the graph body with Canvas:

- compute layout only on `topologyVersion` changes;
- draw links and nodes in one `requestAnimationFrame`;
- keep pan/zoom as a transform without React state updates per pointer event;
- maintain a small spatial index for hit testing and keyboard selection;
- render the selected-node details and accessible mirror as normal HTML;
- draw only the viewport plus a small overscan margin;
- cap graph nodes independently from total normalized records.

Canvas is a measured second step, not a substitute for backend aggregation.
Moving the current raw-node stream from SVG to Canvas would reduce DOM cost but
leave most CPU, memory, and network amplification intact.

When the overlay is closed, do not run grouping, layout, export formatting, or
animation work. Export is generated lazily on user request, preferably from the
normalized selected subtree rather than every live record.

## Implementation stages

### Stage 0 — Establish profiles and budgets

Add a repeatable tracing benchmark before changing semantics:

- one runtime with stable peer/ICE/DTLS/media machines and many hidden tasks;
- 10k, 100k, and 1M short observed calls across 10, 100, and over-limit group
  cardinalities;
- nested aggregate calls;
- concurrent event-loop and worker calls;
- one and multiple subscribers, including a deliberately slow subscriber;
- overlay open, closed, and exact-capture modes.

Measure wall time, process CPU time, allocations, peak RSS, trace-store/group
count, journal depth, encoded bytes, messages, frontend reducer time, React
commit time, layout time, frame time, and dropped/resync counts. Record an
unobserved baseline, current exact tracing, and the new aggregate path.

Initial acceptance budgets, to be confirmed against real workloads:

- aggregate tracing adds at most 5% CPU over the unobserved workload at normal
  cardinality;
- tracing memory remains flat with task/call count after machine and group shape
  stabilize;
- no more than one live aggregate record per aggregate key;
- overlay-closed transport work is effectively zero apart from connection
  health traffic;
- p95 frontend batch application is below 4 ms for a normal batch and below
  16 ms for a maximum-budget batch;
- pan/zoom stays within a 16.7 ms frame budget for the configured visible-node
  cap;
- slow subscribers cause an explicit resync and never unbounded memory growth.

Do not lock these numbers into production defaults until the secured peer E2E
workload validates them.

### Stage 1 — Amend contracts and compile policies

- Update `peer_context_refactoring.md` to replace “full trace node for every
  observed method call” with the exact-versus-aggregate policy in this plan.
- Update `docs/tracing.md` with the four-plane model and schema versioning.
- Add `TraceDetail`, `CompiledObservation`, and `@observe`.
- Define peer, ICE, DTLS, transport, worker, transceiver, and media machine
  specs; map selected `@task(state=...)` owners without exposing helper tasks.
- Extract the neutral single-runner transition/commit primitive from the useful
  shape of `webrtc/dtls/fsm.py`; keep commands separate from state values.
- Add the null and test `TransitionController` implementations and safe-point
  contracts before converting existing transitions.
- Intern operation IDs at class creation.
- Add tests proving automatic instrumentation still covers every eligible
  method and selects the intended policy.

Exit condition: no component manually chooses a runtime service, and policy is
fully determined by compiled metadata plus bounded temporary capture rules.

### Stage 2 — Implement the aggregate hot path

- Add `ActivityGroupStore` and compact records.
- Add begin/end APIs using cached group handles and integer timings.
- Make event-loop ownership the default; add worker delta merging.
- Integrate worker queue/worker/total measurements without three metric events.
- Add failure/slow exemplars and overflow groups.
- Keep the old exact path behind a compatibility policy.

Exit condition: repeated aggregate calls produce no UUID, `TaskTrace`, event
bus publication, transition list, or transport dictionary per invocation.

### Stage 3 — Add single-writer CRDT projection and remove duplicate metrics

- Add the event-loop-owned machine/group/facet reducer, producer dots, epoch
  rules, and worker-owned delta buffers. Remove tracing `RLock` use from normal
  observation and domain-event paths.
- Stop projecting all `TaskRegistry` entries. Replace `TraceStore` with the
  machine stores and the small explicit `ControlHandleStore`.
- Tie groups to owner-machine epoch with direct indexes.
- Replace `MetricGroupAggregator` on the default path with the unified activity
  store.
- Remove full-tree liveness filtering and peer-ID scans.
- Preserve external metric sinks through a drained adapter.
- Add merge-order, duplication, producer-concurrency, tombstone-GC, and state
  transition validation tests.

Exit condition: state converges under duplicate/reordered projection operations,
normal calls take no observability lock, and terminating one entity epoch
flushes/removes only its indexed groups.

### Stage 4 — Add journaled patch transport

- Implement one bounded change journal and subscriber cursors.
- Add schema-2 snapshot, absolute upsert/remove patches, revisions, operation
  string table, and explicit resync.
- Drain dirty records at the configured cadence.
- Remove full group attachment from `trace_pump.py`.
- Remove duration snapshot heartbeats and use a server clock anchor.
- Keep a temporary schema-1 adapter only while frontend migration requires it.

Exit condition: changing one group sends one group patch; it does not snapshot
all groups or all running tasks.

### Stage 5 — Connect state machines, facets, and test checkpoints

- Define the neutral facet sink and bounded value rules.
- Adapt existing domain events for peer, ICE, DTLS, transceiver/media, queue,
  worker, and tracing-health facets.
- Replace selected task lifecycle projection with machine transitions.
- Migrate DTLS first: remove the long-held transition lock, update the
  authoritative state on every commit, validate legal edges, and make one
  terminal transition own completion ordering.
- Insert `before_commit`, `after_commit`, and terminal test checkpoints only at
  safe async boundaries; add shutdown auto-release and timeout behavior.
- Include facets in consistent snapshots and dirty patches.
- Add transition-stop/release, revision, cardinality, redaction, and teardown
  tests.
- Update `tests/test_dtls_tracing.py` to assert committed state/revision rather
  than only checking that `dispatch` placed the initial enum in a queue.

Exit condition: the viewer can describe current application/protocol state even
when no short method call has an exact node.

### Stage 6 — Normalize the frontend pipeline

- Dispatch and reduce one WebSocket batch once.
- Store machines, control handles, groups, facets, and operation names in
  normalized maps.
- Apply sequence/revision checks and request resync on gaps.
- Split topology and value versions.
- Make backend groups first-class graph/list records.
- Replace per-completion subtree copying with bounded normalized archives.

Exit condition: a group counter patch changes one map record and causes no tree
layout or global regroup.

### Stage 7 — Optimize the renderer

- Add virtualized complete-data lists and a selected-subtree graph.
- Memoize SVG nodes/links and update values without rebuilding topology.
- Measure batch, layout, commit, and frame budgets in browser tests.
- Implement the Canvas graph only if measured SVG cost misses the budget.
- Suspend all expensive derived views while the overlay is closed.

Exit condition: the maximum configured live view remains responsive under the
sustained E2E trace workload and frontend memory is bounded.

### Stage 8 — Add bounded diagnostic capture and remove compatibility code

- Add server-authorized exact capture by operation/entity with time and call
  budgets.
- Mark captures and exemplars clearly in export and UI.
- Prove capture expiry and teardown under failure/cancellation.
- Remove schema-1, raw global mode, frontend normal-path virtual grouping, and
  duplicate metric compatibility paths.

Exit condition: aggregate mode is the only production default, while exact
diagnosis remains available and bounded.

## File-level change map

| Area | Planned changes |
| --- | --- |
| `webrtc/performance.py` | Compile observation policies; replace per-call node/metric allocation with aggregate begin/end; add bounded exact escalation. |
| `webrtc/runtime_services.py` | Add machine/facet protocols, producer dots, worker delta results, and transition checkpoint contracts without importing component policy. |
| `webrtc/runtime.py` | Own limits, single-writer projection, activity/machine/facet stores, test controller, journal, and capture rules. |
| `webrtc/tracing/service.py` | Reduce machine transitions and CRDT-style activity/facet operations; manage revisions, snapshots, explicit controls, and entity-epoch cleanup. |
| `webrtc/tracing/store.py` | Replace task-tree projection with machine/group/facet indexes and a small explicit control-handle store. |
| `webrtc/domain_events.py` | Remove global lock-based live projection; route immutable bounded operations to the owning Runtime loop. |
| `webrtc/dtls/fsm.py` | First state-machine migration: typed command mailbox, single lock-free runner/commit path, current-state revision, legal-edge validation, terminal ordering, and test checkpoints. |
| `webrtc/tracing/events.py` | Replace duplicated pending event lists and JSON signature coalescing with a bounded journal/cursors and explicit resync. |
| `webrtc/tracing/models.py` | Add compact transport snapshots separately from mutable internal records. |
| `examples/examples/trace_pump.py` | Send snapshot/patch batches; remove full-group attachment and duration heartbeat scans. |
| `web/src/lib/useTraceState.ts` | One dispatch per batch, sequence-gap handling, and selector-friendly normalized storage. |
| `web/src/lib/trace.ts` | Schema-2 types/reducer, group/facet revisions, bounded normalized archives, and lazy export. |
| `web/src/lib/TraceOverlay.tsx` | Render backend groups directly, separate topology/value updates, virtualize complete lists, and gate Canvas on measurements. |
| `tests/performance/` | Backend throughput/RSS/wire benchmarks and end-to-end tracing overhead baselines. |
| `web/src/lib/*.test.ts` | Batch atomicity, stale revision, resync, no-layout-on-value-change, retention, and render-bound tests. |

## Correctness tests

### Backend

- Every eligible method is compiled to state, aggregate, exact, or off.
- Ordinary helper tasks remain absent from the observable projection while
  Runtime ownership, cancellation, and shutdown tests still pass.
- Machine definitions reject invalid transitions and accept each legal edge.
- `before_commit` and `after_commit` checkpoints stop only at declared safe
  points, resume deterministically, time out, and auto-release on shutdown.
- Repeated calls with the same key share one group and preserve accurate
  success/cancellation/error/in-flight counters.
- Nested aggregate groups retain stable causal parents.
- Concurrent calls cannot make `in_flight` negative or lose terminal counts.
- Worker delta merging preserves queue/worker/total timing and owner context.
- Entity terminal transition flushes final groups before epoch removal.
- Active groups are not evicted; overflow accounting is visible.
- Failure and slow exemplars are bounded and redact unbounded values.
- Journal overflow produces resync; a subsequent snapshot converges exactly.
- Duplicate/out-of-order absolute patches are harmless.
- CRDT component merges are associative, commutative, and idempotent; bounded
  tombstone GC after subscriber acknowledgment preserves convergence.
- Tracing failure cannot change application result, scheduling, ordering, or
  shutdown behavior.

### Frontend

- One canonical batch produces one reducer commit.
- Snapshot replacement clears stale machines, controls, groups, facets, and
  tombstones and archives according to the schema contract.
- Sequence gaps request resync and do not apply ambiguous later patches.
- Stale group/facet revisions are ignored.
- Value-only updates do not reconstruct D3 topology.
- Group/control removal and terminal machine transitions preserve the
  five-second final-state grace behavior without copying unrelated live
  records.
- Closed overlay performs no grouping, layout, export, or animation work.
- Visible limits retain selected, running, failed, and ancestor records.
- Exact captures and aggregate groups cannot collide in identity or
  cancellation controls.

## Performance validation matrix

| Scenario | Backend assertions | Frontend assertions |
| --- | --- | --- |
| Stable hot group, 1M calls | One group, flat RSS, bounded CPU, bounded dirty set | Counter patches only; no topology/layout change |
| 10k hidden runtime tasks | Registry behavior remains correct; observable size follows machines/controls only | No task-count-dependent state or rendering growth |
| Paused test transition | Safe point holds without lock/thread/socket blockage; shutdown releases it | Committed phase/revision is unambiguous |
| Reordered/duplicate producer ops | CRDT projection converges to the same snapshot | Duplicate/stale patches do not rerender |
| High legal cardinality | Memory follows configured groups, not calls | Records remain searchable; graph remains capped |
| Cardinality overflow | Overflow group and diagnostic increment | Overflow is visible, UI remains responsive |
| Worker burst | Correct timing and no global lock contention | Coalesced value updates |
| Slow subscriber | Bounded journal/queue and explicit resync | Gap detected; fresh snapshot converges |
| Overlay closed | No serialization without subscribers | No derived render work |
| Bounded exact capture | Budget expires and normal cost returns | Capture is identifiable and bounded |
| Peer shutdown | Final groups precede owner removal; stores empty | Final grace/archive is correct; no timer leaks |

## Rollout and observability of tracing itself

Ship behind runtime configuration with aggregate mode as the new opt-in during
comparison, then make it the default after the E2E gates pass. During rollout,
expose:

- machines, explicit controls, and groups currently live;
- calls aggregated and exact nodes created;
- dirty/journal depth and batch count/bytes;
- snapshot/resync count;
- cardinality overflows and admission rejections;
- extractor, observer, serialization, and subscriber failures;
- approximate tracing CPU time and flush duration;
- frontend batch/reducer/layout/commit duration and visible record count.

Do not compare current exact and aggregate implementations by running both full
pipelines for every production call; that would preserve the duplicate cost.
Use controlled benchmark runs or sample a small bounded percentage.

## Final acceptance criteria

- Automatic observation still covers every eligible component method.
- Runtime tasks remain internally owned and cancelable without all becoming
  trace records; only explicitly exposed control operations are frontend
  addressable.
- Repeated short calls are represented by stable, causally attached activity
  groups rather than individual live nodes.
- Failures, slow calls, state transitions, and tracing loss remain visible.
- No default hot path allocates a UUID, event object, snapshot dictionary, or
  transition list per aggregate call.
- Server memory is bounded by machine/control/group/facet cardinality, not task
  count or historical call volume.
- Normal updates transmit only changed records; no recurring full group/tree
  snapshots are attached to batches.
- The frontend applies one batch once, skips layout for value-only changes, and
  bounds list, graph, archive, and export work.
- Slow or disconnected viewers cannot create unbounded server work.
- Backend and frontend meet budgets established from the secured full peer
  connection E2E workload with tracing on and off.
- Machine projection and activity updates use a single event-loop writer; the
  normal observation path takes no shared tracing lock.
- Tests can pause, inspect, release, cancel, or inject an allowed failure at
  declared state transitions without enabling a blocking production observer.
- CRDT-style projection and transport patches converge under duplication and
  reordering, with epoch-scoped bounded tombstones.
- The live viewer exposes state machines, selected control ownership, activity,
  domain state, failures,
  diagnostics, and data-loss/resync status for the complete peer scope.
