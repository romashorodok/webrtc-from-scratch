# Event-loop compiler checkpoint — 2026-07-30

## Status

Work was stopped at the user's request. The active sequential subagent
`/root/m4_python_free_workers` was interrupted. No benchmark was run.

The compiler remains fail-closed for the complete event loop:

- direct full-loop compilation exits with status 1;
- the output directory contains zero native artifacts;
- no compiled event-loop result is valid for Kernel E adoption evidence;
- the old development benchmark remains diagnostic and nonconforming.

The governing specifications remain:

- `research/event_loop_low_level_optimization_spec.md`
- `research/python_metalanguage_spec.md`
- previous checkpoint: `research/event_loop_compiler_checkpoint_2026-07-26.md`

Subagents were run sequentially and were explicitly prohibited from spawning
their own subagents.

## Completed and validated sections

### Generic native-class generator and capability reporting

Implemented:

- proof-indexed generated hooks;
- per-class and per-region hook generation;
- generic multi-source discovery and source-correlated diagnostics;
- distinction between semantic proof and actually emitted execution;
- normative compiled/interpreted/rejected capability statuses;
- fail-closed artifact metadata.

Validation included strict Release C17 builds, CTest, compiler tests,
ASan/UBSan tests, and direct zero-artifact rejection.

### Generic storage operations and cross-class region fusion

Implemented:

- alias binding;
- FIFO and heap length/truth operations;
- heap root reads, iteration, slice assignment, and heapify;
- deoptimization/materialization semantics;
- strict operation arity proofs;
- generic required-region resolution across source files and native classes;
- guarded direct calls preserving normal Python attribute lookup,
  subclassing, and monkeypatch behavior.

Validated direct regions include scheduler self-calls,
`_run_once -> ReactorScheduler.run_once`, and
`CommandInbox.merge_into`.

### Atomic lifecycle lowering

Implemented:

- `atomic[uint[32]]` storage;
- C11 `_Atomic uint_least32_t`;
- load, store, and compare/exchange lowering;
- sequentially consistent/process-scope metadata;
- field-linked atomic IR and exact linearization reporting;
- fail-closed rejection of unsupported atomic use.

Lifecycle transitions are represented by three required CAS regions.

### Go-style bounded MPSC command channel

Implemented:

- fixed-capacity sequence-cell MPSC ring;
- capacity-one and general-capacity operation;
- nonblocking `OK`, `FULL`, `EMPTY`, and `CLOSED` results;
- FIFO publication;
- release/acquire atomics;
- close/admission quiescence using one atomic state word;
- close-then-drain semantics for all accepted commands;
- coalesced notification with reset/empty/CAS rearm proof;
- reactor-only drain and reclamation;
- proof-indexed generated hooks;
- contained GC-tracked native owner;
- typed boxed-record support for frozen, slotted ABI dataclasses;
- exact `Command` type checking;
- producer-to-queue-to-reactor ownership transfer;
- correct INCREF/DECREF handling on success, full, closed, clear, and drain;
- `CommandInbox.close_and_drain()` and lifecycle shutdown ordering.

The reference `CommandInbox` now uses
`pymeta.concurrent.BoundedQueue`, with fixed capacity and nonblocking hot-path
operations.

Validation after repair:

- strict Release C17 serial build: passed;
- CTest: 16/16;
- generated MPSC lifecycle/shutdown: 4/4;
- relevant Python suite: 69 passed, 1 skipped;
- ASan/UBSan CTest: 16/16;
- TSan MPSC stress: passed;
- `git diff --check`: passed;
- direct full-loop compile: exit 1, zero artifacts.

### Bounded SPSC worker channels

Implemented:

- generic fixed-capacity SPSC ring;
- capacity-one and wraparound-safe monotonic indices;
- FIFO order;
- nonblocking `OK`, `FULL`, `EMPTY`, and `CLOSED`;
- release publication and acquire consumption;
- atomic close/admission quiescence;
- close-then-drain behavior;
- traversal and exactly-once payload reclamation;
- proof-indexed SPSC field and operation IR;
- generated `put_nowait`, `get_nowait`, `qsize`, `empty`, and `close` hooks;
- capability reporting for typed payloads, endpoints, ordering, shutdown,
  and reclamation;
- bounded input and completion channels in the packet-worker reference path;
- ABI metadata for `OwnedPacket`.

Reactor-facing operations are nonblocking. Worker waiting remains outside the
event-loop thread.

Validation:

- strict Release C17 serial build with warnings as errors: passed;
- CTest: 17/17;
- focused final Python rerun: 17/17;
- generated SPSC lifecycle, GC, and ownership subprocess: passed;
- ASan/UBSan CTest: 17/17;
- TSan 100,000-item producer/consumer FIFO stress: passed;
- `git diff --check`: passed;
- direct full-loop compile: exit 1, zero artifacts.

Both worker queues report `bounded_spsc`, typed payloads,
release/acquire ordering, close/drain, and single-consumer reclamation.
No `spsc_contract_unproven` rejection remains.

## Native worker record and reachability foundation

This was the active section when work was stopped.

Implemented before interruption:

- generic worker ABI record IR;
- `native_worker_record.c/.h`;
- exact frozen/slotted dataclass guards;
- integer width and range checks;
- immutable byte-buffer retention;
- move-only record ownership;
- worker-thread raw scalar/buffer access without Python C-API calls;
- reactor-side materialization and release;
- transitive reachable-call proof for required native regions;
- precise rejection of constructor-injected Python callables;
- capability fields separating reachability, emission completeness, and
  Python-free execution.

Observed behavior:

- a positive native-region fixture proves record layouts and transitive exact
  required-region reachability;
- it still correctly reports `worker_emission_complete=False` and
  `worker_python_free=False`;
- `self._processor(packet)` reports `worker_reachability=False` because
  `_processor` is a constructor-injected arbitrary Python callable.

Validation completed before the final edit:

- strict Release C17 serial build: passed;
- CTest: 18/18;
- focused worker proof tests: 5/5;
- relevant Python suite: 106 passed, 1 skipped;
- ASan/UBSan CTest: 18/18;
- focused TSan worker-record pthread test: passed;
- direct full-loop compile: exit 1, zero artifacts;
- `git diff --check`: passed.

The agent then replaced a fixed 1024-region reachability limit with checked
dynamic sizing. The final strict rebuild and focused rerun after that last edit
were interrupted by the user's stop request. Therefore the latest dynamic
sizing edit is **not yet independently validated**.

## Crash findings and safety repairs

### Old recursive GC crash

The earlier handwritten specialized event-loop emitter caused:

`subtype_traverse -> loop_traverse -> subtype_traverse`

This recursively exhausted the stack and produced SIGSEGV. That emitter and
its unsafe artifact were removed. The generic implementation must never
delegate a native heap type's traversal back through `subtype_traverse` in a
cycle.

### Generated MPSC setter SIGBUS

A generated queue setter imported `pymeta.concurrent`, decremented the module,
but retained a dangling pointer. A validation failure jumped to cleanup and
decremented it again, corrupting import state. A later setter crashed in
`PyImport_ImportModule`.

Repair:

- set the released module pointer to `NULL` immediately after DECREF;
- add a subprocess regression performing two failing setters followed by a
  successful create/send/receive operation;
- treat child signal exits as test failures.

The repaired generated lifecycle subsequently passed.

### ASan loader abort on macOS

Loading an ASan-instrumented generated `.so` into the uninstrumented Homebrew
Python aborted inside `__sanitizer::InitializePlatformEarly`.
macOS stripped the required `DYLD_INSERT_LIBRARIES`, so ASan interceptors were
not available. This happened before module initialization.

This is recorded as unavailable generated-extension ASan coverage on this
host, not as proof of a generated-code defect and not as successful coverage.
The standalone ASan/UBSan C suites passed.

## Exact remaining blockers

1. Revalidate the last checked-dynamic-sizing reachability edit.
2. Implement a generic Python-independent statement/kernel emitter.
3. Implement a persistent native owned-shard worker executor.
4. Replace or explicitly compile the constructor-injected `_processor`
   boundary. Arbitrary Python callables must continue to reject.
5. Fully emit native worker records/results where the specification permits;
   boxed `object` fields cannot be used from a Python-free worker thread.
6. Complete remaining generic multi-class/direct-callee emission.
7. Complete selector/datagram native regions and their ownership/lifecycle
   proofs.
8. Emit and load a conforming complete native event-loop artifact.
9. Run independent semantic, lifecycle, GC, sanitizer, concurrency, metadata,
   and subprocess validation on that artifact.
10. Only then run the Kernel E v0.3 benchmark using the compiled event loop.

## Resume procedure

1. Start one root-level subagent only; prohibit nested subagents.
2. First rerun the strict build and focused worker reachability/record tests
   after the dynamic-sizing edit.
3. Preserve the dirty shared working tree; do not reset or discard changes.
4. Inspect the direct capability report and choose one exact remaining section.
5. Keep unsupported compilation fail-closed with zero artifacts.
6. Do not use the old development benchmark as adoption evidence.

## History restoration capsule

Use this section to restore the working history after context loss or in a new
session.

The project goal is to implement the custom compiled event loop described by
`research/event_loop_low_level_optimization_spec.md`, using the compiler and
language rules in `research/python_metalanguage_spec.md`. The finished artifact
must be a generic compiler result, not a handwritten event-loop-specific C
extension. Every implementation section and its validation must run in a
root-level subagent. Subagents must be sequential, must not run in parallel,
and must not spawn their own subagents.

The work resumed originally from
`research/event_loop_compiler_checkpoint_2026-07-26.md` because
`webrtc/compiler/native_compiler/native_class_generator.c` and its tests were
broken. The generator, capability reporting, native storage operations,
cross-class region resolution, lifecycle atomics, bounded command MPSC,
boxed-command ownership, and bounded worker SPSC sections were subsequently
implemented and validated. The relevant subagent stages were:

1. generator repair and proof-indexed hook emission;
2. capability-report execution/emission distinction;
3. generic storage hooks and region fusion;
4. atomic lifecycle lowering;
5. bounded MPSC runtime, generated hooks, ownership, and shutdown;
6. independent boxed `Command` and shutdown validation;
7. bounded SPSC worker channels;
8. native worker-record and transitive reachability foundations.

The latest named subagent stages visible at stop time were:

- `validate_boxed_command_shutdown` (`Carson`): completed;
- `m4_spsc_worker_channels` (`Kant`): completed;
- `m4_python_free_workers` (`Huygens`): interrupted after replacing a fixed
  1024-region reachability limit with checked dynamic sizing.

The last Huygens edit did not receive its final strict rebuild and focused
rerun. All validation evidence predating that edit remains useful, but it does
not validate the final working tree.

Two generated-extension crash reports must remain part of the restored safety
history:

- the old specialized emitter recursively traversed GC through
  `subtype_traverse -> loop_traverse -> subtype_traverse`; that emitter and
  artifact were removed;
- the generic MPSC setter retained a dangling imported-module pointer and
  double-decremented it on failure; it was fixed by nulling the pointer after
  DECREF and covered by a fail/fail/success subprocess regression.

The later ASan SIGABRT was an interceptor-initialization failure caused by
loading an ASan `.so` into uninstrumented Homebrew Python without the required
macOS environment injection. It was not an event-loop crash, and it must not
be counted as generated-extension ASan coverage.

The current full event loop is deliberately not compiled. Direct compilation
must continue to return a nonzero status and leave zero output artifacts until
all required regions have safe generic lowering. The existing file
`benchmark-results/kernel-e-v0.3-compiled-development-loop-20260725.json` is
diagnostic only: it used a nonconforming emitter and measured roughly 0.955%
slower native Kernel E. It is not adoption evidence and must not be compared as
if it represented the current compiler.

### Copyable restore instruction

The following instruction can be given to a future primary agent:

> Continue from `research/event_loop_compiler_checkpoint_2026-07-30.md` and
> the dirty shared working tree. Read both governing specifications before
> changing code. Run exactly one root-level subagent at a time and explicitly
> prohibit nested subagents. First validate or repair the interrupted checked
> dynamic-sizing worker-reachability edit. Keep the complete event-loop build
> fail-closed with zero artifacts. Then implement each remaining section in
> the order below, with its validation performed inside its implementing
> subagent. Do not run Kernel E until a conforming generic compiled event loop
> emits, loads, passes semantic/lifecycle/metadata tests, and is independently
> validated. Preserve all existing work and never restore the handwritten
> emitter.

## Next implementation roadmap

Each numbered stage below is one sequential root-level subagent. Do not begin
the next stage until the current stage has finished and reported validation.

### 1. Revalidate and repair worker reachability

Start with the interrupted checked-dynamic-sizing edit.

Required work:

- inspect the final diff in native worker-record and reachability files;
- prove allocation-overflow checks and cleanup on every failure path;
- test zero, one, more than 1024, cyclic, and malformed region graphs;
- verify source-correlated diagnostics and deterministic capability metadata;
- ensure arbitrary constructor-injected callables still reject exactly;
- run direct full-loop compilation and confirm zero artifacts.

Validation gate:

- strict Release C17 serial build with warnings as errors;
- CTest, including worker-record and reachability tests;
- relevant Python compiler/capability tests;
- ASan/UBSan CTest;
- focused TSan worker-record test where meaningful;
- `git diff --check`;
- fail-closed direct compilation evidence.

### 2. Generic Python-independent statement/kernel emitter

Implement the missing backend that turns proven PyMeta statement/expression IR
into native worker code without Python C-API access.

Required work:

- emit scalar arithmetic, comparisons, branches, loops, record field access,
  and proven native calls generically from IR;
- define explicit supported types, overflow behavior, error representation,
  and deoptimization/rejection boundaries;
- compute transitive reachability over emitted regions and backend operations;
- reject imports, attribute lookup, allocation, exceptions, boxed objects, and
  arbitrary calls unless a separately proven native lowering exists;
- record per-statement and per-call emission facts in capability metadata;
- add positive multi-region fixtures and negative Python-operation fixtures.

This emitter must not contain event-loop class names, source paths, region
indices, or fixture-specific behavior.

Validation gate:

- strict compiler build and focused emitter unit tests;
- generated native kernel subprocess tests against Python reference results;
- boundary, overflow, error, and unsupported-operation tests;
- ASan/UBSan tests and TSan tests for any shared native state;
- proof that rejected input creates no native artifact.

### 3. Persistent native owned-shard worker executor

Use the generic kernel emitter and the validated SPSC channels to implement
the persistent worker execution model required by the event-loop spec.

Required work:

- create and stop the native worker thread without blocking the reactor;
- move native `OwnedPacket` records into the input SPSC channel;
- execute only proven Python-independent kernels outside the GIL;
- move native result/error records into the completion SPSC channel;
- wake or notify the reactor with the already-proven coalescing mechanism;
- close admission, quiesce, drain, join outside the hot path, and reclaim every
  accepted or rejected payload exactly once;
- handle capacity one, full output, cancellation, processor failure, startup
  failure, partial initialization, close races, and repeated close;
- retain the ordinary Python fallback for unsupported processors.

The constructor-injected `_processor` boundary must either resolve to an exact
declared native region/kernel or remain rejected. Do not treat an arbitrary
Python callable as native.

Validation gate:

- reference/native parity tests;
- high-volume ordering and close-race stress;
- GC, deletion, reinitialization, subclass, and monkeypatch tests;
- worker-thread assertion that no Python C-API operation occurs;
- ASan/UBSan, TSan, and clean child-process shutdown;
- capability proof that `worker_emission_complete` and
  `worker_python_free` become true only for the positive native fixture.

### 4. Remaining generic multi-class and direct-callee emission

Complete generic artifact assembly for all proven native classes and required
cross-component calls.

Required work:

- emit all required heap types from multiple sources into one module;
- correctly resolve constructors, exact component fields, and required-region
  callees;
- preserve ordinary Python lookup, subclass, class monkeypatch, and instance
  monkeypatch semantics at every guarded direct-call boundary;
- implement safe module/type creation, traversal, clear, deallocation, partial
  initialization cleanup, and module unload;
- avoid traversal recursion through base-type `subtype_traverse`;
- ensure capability metadata matches the functions actually emitted.

Validation gate:

- generated multi-class subprocess lifecycle tests;
- cycle collection and repeated import/unload tests;
- lookup/monkeypatch/deoptimization parity tests;
- fault-injection tests for every initialization stage;
- strict build, sanitizers, and zero-artifact rejection for incomplete graphs.

### 5. Selector and datagram native regions

Implement the remaining event-loop I/O regions only after the generic
multi-class emitter is safe.

Required work:

- inspect the direct capability report for the exact selector/datagram
  rejection sites;
- lower registration, modification, removal, readiness dispatch, timer
  interaction, and datagram batching according to the low-level spec;
- define file-descriptor ownership and generation/version checks to prevent
  stale readiness delivery;
- preserve Python exceptions, cancellation, close ordering, and callback
  ordering at the boundary;
- keep all reactor-facing channel operations nonblocking;
- add platform-specific fallback where a native primitive is unavailable.

Validation gate:

- socketpair/UDP integration tests;
- descriptor reuse, close/readiness race, cancellation, and backpressure tests;
- reference-loop ordering parity;
- leak, sanitizer, and subprocess teardown tests;
- exact capability and emitted-hook evidence.

### 6. Complete artifact integration

Only after all required capability facts are true:

- emit the complete event-loop native module through the generic compiler;
- load it in a fresh subprocess;
- verify the compiled implementation is actually selected;
- reject stale, missing, mismatched, or development metadata;
- run semantic parity, lifecycle, GC, subclass/monkeypatch, error, shutdown,
  and stress suites;
- verify no handwritten/specialized emitter or cached unsafe `.so` is used.

The artifact metadata must identify the source set, compiler version/options,
operation proofs, emitted regions/hooks, native storage layout, concurrency
proofs, and implementation identity consumed by the benchmark harness.

### 7. Independent final validation

Use a fresh sequential validation-only subagent that did not implement the
last integration section.

Required evidence:

- clean strict Release build;
- complete CTest and Python suites;
- generated artifact subprocess lifecycle and repeated import/unload;
- ASan/UBSan native tests;
- TSan concurrency stress;
- macOS generated-extension ASan only if an instrumented host process can be
  launched correctly; otherwise record the limitation without claiming it;
- direct metadata inspection proving the compiled event loop is active;
- `git diff --check` and zero unexpected artifacts in the source tree.

### 8. Kernel E v0.3 compiled-loop benchmark

Run `research/kernel_e_v0.3_benchmark_evidence.md` only after stage 7 passes.

Benchmark requirements:

- require compiled mode; no interpreted fallback;
- validate artifact identity and capability metadata before timing;
- execute the same workload and configuration for reference and compiled
  loops;
- include warmup, multiple samples, CPU time, wall time, throughput, latency,
  variance/confidence data, environment details, and correctness checks;
- store raw and summarized evidence under `benchmark-results/`;
- label regressions honestly and do not claim CPU improvement without
  statistically credible evidence.

If compiled artifact selection or metadata validation fails, the benchmark
must fail closed instead of silently measuring the Python reference loop.
