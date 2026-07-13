# Bounded Live Tracing

Tracing is a bounded, causally structured projection of meaningful runtime
state. Runtime task ownership remains internal and is not mirrored one-for-one
to the browser.

## Observable planes

The live view combines four independently bounded planes:

1. Observable state machines: peer, ICE, DTLS, transport, worker lane,
   transceiver, and media entities with validated revisioned transitions.
2. Activity groups: stable aggregate spans for repeated observed operations,
   including in-flight and cumulative outcome counters.
3. Control handles and facets: exact cancel/pause/inspection targets plus
   revisioned bounded scalar domain values.
4. Diagnostics: admission, cardinality, extractor, subscriber lag, resync, and
   observation-loss counters.

`ObservedMeta` compiles a `CompiledObservation` once per eligible method.
Ordinary methods default to aggregate, ordinary `@task` entry points to off,
and `@task(state=...)` owners to state. `@observe` declares bounded exceptions;
`@unobserved` remains the explicit infrastructure exclusion. Operation names
are interned at class creation and calls use their integer operation ID.

## Identity

A peer session owns one `trace_id`. Each runtime task owns a unique `task_id`, and causal nesting is represented by `parent_task_id`. A trace ID correlates work; it never identifies a tree node.

The immutable runtime context is:

```text
ExecutionContext(trace_id, task_id, parent_task_id, scope_id)
```

The same context is propagated to executor workers. Metrics and domain events copy its correlation fields but have independent storage and lifecycle.

## Ownership boundaries

- `TaskScheduler` executes tasks and emits neutral lifecycle events.
- `TaskRegistry` owns active cancellation state and is keyed by `task_id`.
- `SyncOffloader` owns executor capacity, queueing, context propagation, and shutdown.
- `TraceService` observes lifecycle events and owns only the live task tree and subscriptions.
- `ActivityGroupStore` is the sole live activity aggregation path. Optional external metric sinks receive lower-rate drained absolute snapshots and never add per-call metric allocation.
- Domain event dispatch describes semantic protocol milestones without importing tracing or performance code.

## Live lifecycle

Starting a task inserts it into the live tree. Before a managed task finishes, the scheduler reconciles its owned children and worker-completion barriers. `TraceService` then observes the terminal lifecycle event, emits `trace:complete`, removes only that task from the server-side tree, and emits `trace:delete`. Any children still visible in the trace store are promoted to the completed task's parent.

There is no server-side completed or deleted archive. A terminal task is removed from the backend live tree after its `trace:complete` snapshot. Terminal statuses include task outcomes (`completed`, `failed`, `cancelled`) and observed-node outcomes (`success`, `error`, `cancelled`). The viewer freezes the terminal snapshot immediately, keeps the final node visible for a five-second grace period, suppresses the backend's immediate matching delete during that period, and then applies a client-local delete with an exact-task tombstone. Promoted children remain live.

## Transport schema

The aggregate projection uses versioned, idempotent schema 2. The initial
`trace:snapshot` contains the complete bounded machine/control/group/facet
projection, operation string table, diagnostics, and snapshot sequence.
Subsequent `trace:batch` messages carry monotonically sequenced absolute record
values and revisions, so duplicate delivery is harmless. A cursor gap produces
`trace:resync_required`; it is never treated as a valid partial stream.

There is no schema-1 lifecycle adapter or global raw mode. The WebSocket pump
forwards only schema-2 snapshots, patches, and resynchronization messages.

Diagnostic exact capture is server-authorized and scoped to one operation,
entity, control handle, or facet. Every authorization has both a monotonic time
deadline and a call budget, is capped by Runtime limits, and is cancelled on
teardown. Captured invocations remain accounted in their activity group and are
published as bounded `capture:upsert` records marked `diagnostic_capture`.
Exception messages, arguments, and return values are never retained.

## Deletion

Deletion requests identify one live trace node by `task_id`. `TraceService` reads that node's current trace subtree for result reporting, but cancellation eligibility is checked on the requested target. A runtime task delegates to `TaskRegistry.cancel(task_id)`; an observed non-task node delegates to its registered node canceller. Descendant shutdown follows the owning scheduler or node implementation rather than direct trace-store mutation.

Queued offloads and managed asyncio tasks may be cancelable. Once executor work has started, its owning task is temporarily non-cancelable. A request is sent as `{"task_id":"…"}`. Rejections use `task_not_found`, `non_cancelable_path`, or `cancellation_rejected`; `failed_task_ids` currently identifies the requested target that rejected cancellation.

A successful `trace:delete_result` acknowledges that cancellation was accepted and reports the subtree visible when the request was evaluated. It does not prove that every reported node has already terminated, and it does not remove frontend state early. Terminal lifecycle observers emit `trace:complete` followed by `trace:delete`. The frontend archives on completion, delays the matching live-view deletion for five seconds, and then tombstones the task. This preserves the final status, duration, transitions, and most recent relevant group snapshot while making completion visible briefly.

## Heartbeats and export

The browser derives running duration from the server monotonic anchor. It renders
backend aggregate groups directly, virtualizes complete-data lists, and marks
captures and failure exemplars explicitly in diagnostic exports.
