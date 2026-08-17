# Frame-Free Scheduler Superregion Implementation Specification

## Status and authority

Status: proposed and benchmark-gated.

This document specifies the next event-loop compiler stage. It supplements
`event_loop_low_level_optimization_spec.md` and
`python_metalanguage_spec.md`; where it is more specific about scheduler
superregions, it is normative.

Python remains the behavioral source of truth and generated C remains a build
artifact. Lowering MUST be derived from generic IR, effects, representations,
and storage contracts. It MUST NOT recognize application names, method names,
paths, or line numbers as optimization authority.

## 1. Objective and required order

The objective is to remove the generic direct-emitter architecture from the
timer path. Do not spend another optimization cycle on isolated scalar,
ownership, or attribute peepholes before measuring this design.

Implementation MUST proceed in this order:

1. Add native phase-cycle counters around timeout calculation, inbox handling,
   selector polling and dispatch, timer promotion, and ready execution.
2. Implement a frame-free scheduler superregion.
3. Store timer keys in native heap entries only when key stability is proven.
4. Integrate inbox notification and worker-count fast paths into the shared
   scheduler context.
5. Re-run the immediate-timer microbenchmark.
6. Run the stable paired timer preflight only if immediate timers approach or
   beat 7.5 microseconds per iteration.
7. Run the 15-triple suite only when a 1.20x one-sided bound against both
   baselines is plausible.

`performance_adopted` MUST remain false until every existing acceptance gate
passes.

## 2. Baseline and target

The measurements motivating this stage are:

| Operation | asyncio | compiled | Interpretation |
| --- | ---: | ---: | --- |
| `call_soon` | 710.8 ns | 632.0 ns | ingress is effective |
| `call_at` | 1083.9 ns | 946.5 ns | ingress is effective |
| immediate ready iteration | 7862.2 ns | 7837.9 ns | approximately tied |
| immediate timer iteration | 8497.9 ns | 10677.1 ns | decisive gap |
| `selector.select(0)` | 5379.8 ns | 4799.0 ns | selector alone is not the gap |
| empty inbox merge | n/a | 224.2 ns | not the primary gap |

The latest stable timer preflight was approximately 0.87x asyncio and 1.16x
the Python reference. Allocation and plateau gates passed; throughput did not.

This stage is structurally successful only when the required scheduler graph:

- has no generic expression dispatch or object local frame;
- uses one guarded context per iteration;
- has zero warmed compiler-runtime allocations; and
- preserves Python fallback, invalidation, lifecycle, and escape semantics.

## 3. Scope

In scope are a fused scheduler CFG, scalar C locals, direct native storage,
post-boundary continuations, proven-key heap entries, and inbox/worker fast
paths. Selector calls, callbacks, logging, and arbitrary Python calls remain
external boundaries.

Out of scope are object pools, signature changes, a replacement selector,
handwritten event-loop C, and further standalone emitter peepholes. If this
backend reaches an architectural ceiling, a native reactor is a separate later
design.

### 3.1 Migration removals

Removal is staged. Nothing in this section is deleted until the superregion
backend has an equivalent tested path and the ordinary Python implementation
continues to pass differential tests.

Remove these workarounds from the Python scheduler source once fusion works:

- The manually duplicated cancellation, timeout, selector-dispatch, and timer-
  promotion bodies inside `ReactorScheduler.run_once`. Replace them with calls
  to `remove_cancelled_timers`, `compute_timeout`,
  `process_selector_events`, and `promote_due_timers`. The compiler, not the
  source author, then fuses those required regions into one CFG.
- The comment and design assumption that source-level duplication is needed to
  avoid separate AOT frames.
- The source-level `if self._config.packet_workers` performance branch. Call
  `PacketWorkerPool.drain_results` compositionally and let the guarded
  scheduler context eliminate it when native `worker_count == 0`.
- `ReactorScheduler._config` and its constructor argument if the worker branch
  is its last use. Configuration remains owned by the loop and its actual
  components.
- The `loop.time` and `math.ulp` return contracts duplicated on `run_once` after
  those calls move back into their phase regions. The contracts remain on the
  external call edges that actually invoke them.

Remove these items only from the generated scheduler hot graph, not from the
general compiler runtime:

- `WrtcRegionFrame`, object slots for scalar locals, ownership bits for
  scalars, and per-expression helper functions;
- Python argument binding, descriptor lookup, result boxing, and repeated
  guards for fused internal region calls;
- runtime IR/source-span dispatch and generic statement/expression evaluators;
- repeated native-storage resolution after the scheduler context is guarded;
- repeated timer-key attribute reads when, and only when, the key-stability
  proof permits keyed heap entries; and
- unconditional inbox drains and worker iteration when the context's proven
  notification and worker-count fast paths apply.

Do not remove the following:

- the phase methods themselves; they remain executable Python semantics and
  generic compiler inputs;
- `_compact_cancelled_timers`, `CommandInbox.merge_into`, and command dispatch
  logic required by the Python fallback;
- public `CommandInbox.drain_snapshot` tuple semantics and the module-level
  `dispatch_command` compatibility entry point;
- `_run_once`, scheduling ingress methods, public signatures, exact Handle and
  TimerHandle allocation, debug behavior, selector calls, or callback calls;
- container materialization/escape behavior and permanent boxed fallback;
- generic direct-emitter/frame support used by non-superregion code; or
- lifecycle, close/drain, invalidation, cache ownership, and exception cleanup.

After the new artifact passes structural checks, dead-code elimination SHOULD
avoid emitting scheduler-only helper bodies that no reachable fallback or
non-superregion entry uses. This is a generated-artifact size optimization, not
permission to remove the general compatibility tier.

## 4. Phase-cycle profiling

### 4.1 Required phases

The compiler MUST attribute:

- entry guard/context resolution;
- cancelled-timer maintenance;
- inbox notification and drain;
- timeout calculation;
- selector polling;
- selector-result dispatch;
- worker-result drain;
- timer promotion; and
- fixed-snapshot ready execution.

Selector time and Python callback time MUST remain separately visible and MUST
be outside compiler allocation accounting.

### 4.2 Runtime contract

Each record MUST contain at least calls, total ticks, minimum ticks, and maximum
ticks as `uint64_t`. The scheduler thread owns hot updates, so no atomic update
is permitted there. The clock MUST be native, monotonic, non-allocating, and
must not call Python.

Profiling has two compile modes:

- `off`: all probes compile out, including the branch;
- `profile`: inline timestamps update module-owned records.

The artifact records the mode and tick conversion. Snapshot/reset may allocate
only after compiler accounting is paused. Acceptance uses `off`; attribution
uses `profile` and reports calibrated probe overhead.

## 5. Superregion discovery and IR

A required root is eligible only when:

- every reachable required internal edge uses the direct ABI;
- the graph contains no suspend, dynamic-code, or boxed-executor edge;
- native FIFO, heap, inbox, atomic, selector, and worker contracts resolve;
- scalar types and object ownership are known at every merge;
- mutation and external-boundary effects are explicit; and
- every post-mutation invalidation point has a valid continuation.

Eligibility is structural and fail-closed. An unsupported operation rejects the
superregion; it MUST NOT silently insert an expression helper.

Add a scheduler-superregion IR containing:

- CFG blocks, edges, branches, loops, and phi/merge values;
- typed scalar and object locals;
- borrowed/owned object state;
- native-storage operations and mutation points;
- external-boundary descriptors;
- invalidation checks and continuation targets; and
- one complete cleanup plan.

Required scalar representations are `Py_ssize_t`, `int64_t`, `double`, boolean,
and nullable state. Objects are borrowed or owned `PyObject *`. Scalars MUST NOT
occupy object-frame slots or ownership masks.

The builder fuses reachable required internal regions into one CFG. Internal
edges lose Python binding, descriptor lookup, per-region guards, runtime IR
arguments, and `PyObject *` result wrappers. External edges retain typed inputs,
checked result conversion, exception edges, accounting pause/resume, an epoch
check, and a continuation ID.

## 6. Frame-free generated ABI

Resolve one context before mutation, equivalent to:

```c
typedef struct {
    void *module_state;
    PyObject *receiver;                 /* borrowed */
    PyObject *scheduler;                /* borrowed */
    WrtcNativeFifo *ready;
    WrtcNativeMinHeap *scheduled;
    WrtcNativeMpsc *inbox;
    WrtcNativeAtomicUint32 *notified;
    PyObject *selector;                 /* borrowed */
    PyObject *workers;                  /* borrowed or NULL */
    Py_ssize_t worker_count;
    uint64_t invalidation_epoch;
    uint32_t flags;
} WrtcSchedulerContext;
```

Exact fields may follow existing runtime types, but all hot components MUST be
resolved once. Never cache a bound method.

The generated entry uses a direct status ABI, for example:

```c
int wrtc_scheduler_superregion_<ir_id>(
    WrtcSchedulerContext *context,
    PyObject **result_out);
```

Its body uses ordinary C control flow and scalar C locals. Python-object locals
are declared individually. One cleanup epilogue covers success, exception,
return, loop control, and continuation exits. An ownership mask is allowed only
for genuinely owned object locals; direct conditional decrefs are also valid.

The reachable hot graph MUST NOT reference `WrtcRegionFrame`, generic
expression/statement evaluators, `wrtc_boxed_execute`, source-span dispatch,
bound-method construction, or an `aot_pyobject` internal edge.

## 7. Guards and continuation safety

Before mutation, entry guards validate exact receiver/component types, native
and non-escaped storage modes, pinned versions and original descriptors,
Handle/TimerHandle construction and comparison contracts, selector shape,
heap-key proof, inbox protocol, cached unbound targets, and module epoch.

Failure before mutation calls the cached original Python root. Once mutation
starts, the root is never restarted. After every selector, callback, logging,
or other Python boundary, compare the epoch and transfer on invalidation to a
generic continuation for the current safe point.

Continuations receive all live values and mutation state explicitly. Selector
events already returned are never polled again. Callback-time invalidation
preserves the original ready snapshot count so newly scheduled handles wait for
the next iteration.

Tests MUST invalidate before mutation and after inbox drain, selector return,
timer promotion, and every ready-callback position.

## 8. Proven-key native heap

The native heap MAY use entries equivalent to:

```c
typedef struct {
    PyObject *value;  /* owned while enqueued */
    double key;
} WrtcNativeHeapEntry;
```

It MUST support direct root-key access, push-with-key, pop, truth, size,
iteration, stable cancelled compaction, materialization, traverse, clear, and
capacity retention without retaining removed Python objects.

Comparator behavior MUST match the proven source contract for equal keys,
infinities, and unordered floating values. Do not invent a stable sequence
number unless it is part of that contract.

### 8.1 Mandatory key-stability proof

An exact float read is insufficient to cache a key. IR metadata MUST prove that
the comparison key is stable for the complete enqueue interval. Valid proofs
include immutable storage, a compiler-visible write barrier that updates or
invalidates the entry, or an equivalent sealed-storage guarantee.

If the scheduled object escapes and its key can change without that barrier,
keyed mode is ineligible. A descriptor-version guard alone does not prove
per-instance immutability. Do not sacrifice private-attribute mutation
correctness for benchmark speed; leave keyed mode disabled until the proof is
available.

A Python-visible scheduled-container read materializes once and permanently
selects boxed compatibility. Preserve current heap-array order and identities,
and never re-adopt. Teardown visits or releases each owned entry exactly once.

## 9. Inbox and worker fast paths

The context resolves the inbox, its coupled notification atomic, and worker
count once.

Skipping an empty drain requires a proven producer protocol: queue publication
happens before notification/wakeup publication. Reset after drain MUST include
the protocol-required queue recheck/re-arm, preventing a lost concurrent
wakeup. This contract comes from generic native-operation metadata, never from
field or method names.

When guarded `worker_count == 0`, omit worker-result draining for that
iteration. A nonzero or invalidated value follows the generic direct worker
path. Neither fast path may allocate, bind a method, or repeat component guards.
TSan coverage is required for publication, reset, close, and drain races.

## 10. Artifact policy

The manifest MUST distinguish this backend from the generic direct emitter and
record at least:

```json
{
  "backend": "aot_scheduler_superregion",
  "frame_free": true,
  "runtime_ir_dispatch": false,
  "phase_profile": "off",
  "keyed_heap": "disabled|proven",
  "shared_scheduler_context": true,
  "post_boundary_continuations": true
}
```

Policy checks inspect the complete reachable hot call graph, not just its root.
Every module cache participates in traverse, clear, and free.

## 11. Verification

Compiler fixtures MUST vary names, formatting, and paths while preserving the
same IR, proving name-independent discovery. Negative fixtures break one proof
at a time and must reject the backend. Inspect emitted code for scalar C locals,
complete cleanup, boundary continuations, and forbidden symbols.

Differentially test ready ordering, fixed snapshots, timer ordering and
cancellation, equal/NaN/infinite keys, selector events and failures,
cross-thread publication, callback failures, debug logging, container escape,
subclasses, descriptor replacement, monkeypatching, invalidation, teardown,
and repeated subprocess construction/shutdown.

Run each empty and active superregion at least 10,000 warmed iterations and
require zero compiler-runtime allocations, zero owned locals at exit, balanced
native allocation/free counts, and a retained-memory plateau. Counter snapshots
and benchmark bookkeeping are excluded from workload retention.

Run ASan/UBSan for ownership and bounds and TSan for inbox, SPSC/MPSC,
notification, and worker lifecycle paths.

## 12. Benchmark escalation

First run the immediate-timer benchmark in fresh warmed subprocesses with
identical selector and callback work. Report median, dispersion, sample count,
phase totals, and both allocation systems. Continue only if the compiled median
approaches or beats 7.5 microseconds. Otherwise use phase attribution to select
architectural work, not unrelated peepholes.

Then run the established stable paired timer preflight with randomized or
alternating order and all latency, idle, allocation, semantic, and plateau
checks enabled. The 15-triple suite is plausible only when both comparison
medians are at least 1.20x and short-run lower bounds are close enough that
ordinary variance could cross 1.20x.

Only then run at least 15 paired triples. Promotion still requires the existing
one-sided 95% throughput, p99 latency, idle CPU, allocation, plateau, semantic,
lifecycle, and sanitizer gates.

## 13. Delivery milestones and stop condition

1. Phase profiler, snapshot/reset API, tests, and attribution report.
2. Superregion IR, eligibility diagnostics, and manifest schema.
3. Shared context, entry guards, and post-boundary continuations.
4. Frame-free emitter and structural/ownership tests.
5. Proven-key heap contract, representation, and fallback tests.
6. Inbox/worker fast paths and TSan coverage.
7. Immediate-timer go/no-go report.
8. Stable preflight and, only if justified, full acceptance.

Every milestone builds the compiler and production extension and keeps the
Python fallback usable.

If a verified frame-free superregion remains materially slower and counters
show that residual cost is dominated by unavoidable reactor transitions, stop
extending the generic compiler for this path. Produce a measurement report and
evaluate a native-reactor backend separately; do not relax semantic or
performance gates.
