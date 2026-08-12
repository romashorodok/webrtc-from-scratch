# Event-loop compiler checkpoint — 2026-08-08

## Stop status

Work was stopped at the user's request on 2026-08-08. The active sequential
subagent `/root/generic_multiclass_artifact` was interrupted while implementing
the final generated native worker adapter. No compiler, CTest, pytest, or stress
process remained after the stop.

The shared working tree is intentionally dirty and contains both staged and
unstaged changes. Preserve it exactly; do not reset, checkout, or discard edits.
The interrupted adapter edit has **not** passed its final build or validation.
At stop time `git diff --check` reported one trailing-whitespace error in
`webrtc/compiler/native_compiler/native_worker_codegen.c` on the generated
`send(..., MSG_DONTWAIT)` source fragment.

The governing specifications remain:

- `research/event_loop_low_level_optimization_spec.md`
- `research/python_metalanguage_spec.md`
- previous checkpoint: `research/event_loop_compiler_checkpoint_2026-07-30.md`

Subagents were run one at a time at root level and were prohibited from
spawning subagents. Because the environment reached its child-thread limit,
later stages reused completed root-level agents through follow-up tasks.

## Current production status

Production native selection remains deliberately disabled/fail-closed.

- A complete-looking generated artifact was temporarily emitted and loaded,
  but a non-default probe found that it only worked with `packet_workers=0`.
- `new_event_loop(packet_workers=1)` failed because generated `PacketWorker`
  objects still constructed a Python `threading.Thread(target=self._run)` while
  `_run` and the native executor lifecycle were not attached to the emitted
  heap type.
- The compiler's owned-shard acceptance gate was restored after this finding.
- The latest direct full graph therefore returns nonzero and creates zero
  artifacts.
- The production loader must remain disabled until the worker adapter is fully
  assembled and independently validated.
- No Kernel E benchmark was run in this continuation.

The GIL-enabled host is also not production-policy compatible with the planned
free-threaded artifact. A GIL-built development artifact must never be labeled
as production compatible.

## Completed stages since the 2026-07-30 checkpoint

### 1. Worker reachability revalidation

Completed and validated:

- checked dynamic graph sizing;
- malformed edge bounds validation before dereference;
- deterministic fail-closed workspace overflow/allocation reasons;
- cleanup on all allocation success paths;
- zero, one, cyclic, malformed, deterministic, source-correlated, and
  1,025-region graph tests;
- precise rejection of constructor-injected arbitrary Python callables.

Validation: strict Release build; CTest 18/18; focused 7/7; relevant Python
51/51; ASan/UBSan 18/18; focused TSan 1/1; direct loop nonzero/zero artifacts;
diff check passed at that stage.

### 2. Generic Python-independent kernel emitter

Added `native_kernel.c/.h` and a standalone generated-kernel test. The backend
generically emits proven `bool` and unsigned 8/16/32/64 scalar regions with
checked or wrapping arithmetic, comparisons, boolean/unary expressions,
assignments, branches, `range` loops, control flow, fixed-record unsigned field
reads, exact required-region calls, record results, and typed overflow/division
status. Unsupported Python behavior rejects with source spans.

Validation at completion: strict Release build; CTest 19/19; relevant Python
48 plus focused 2; ASan/UBSan 19/19; direct loop nonzero/zero artifacts.

### 3. Persistent native worker executor foundation

Added:

- `native_worker_abi.h`;
- `native_worker_executor.c/.h`;
- generic record pack/materialize bridge;
- preallocated executor slots and results;
- bounded input/completion SPSC queues;
- typed errors, queued cancellation, output-full retry;
- coalesced notification/rearm;
- close, drain, join, idempotent shutdown, and reactor-only reclamation;
- generated Python-free kernel adapter and record-result construction.

Positive fixtures set worker emission/Python-free facts only for exact emitted
kernels and typed bounded queues. Arbitrary `_processor` remains rejected.

Validation before later integration edits: Release CTest 20/20; ASan/UBSan
20/20; Python capability/parity 58/58; direct loop nonzero/zero artifacts.

### 4. Lost-wakeup diagnosis and fast stress rewrite

The apparent 35-minute TSan soak was proven to be a lost-wakeup livelock, not
healthy progress. Two read-only samples showed the main thread spinning before
the first kernel entry while the worker slept in `pthread_cond_wait`.

Repair:

- `wake_worker` now holds `wait_mutex` across epoch increment and condition
  signal;
- waits use a five-second no-progress watchdog;
- default stress uses 2,048 items with many wraps;
- `WRTC_WORKER_EXECUTOR_STRESS_COUNT` selects explicit larger soaks;
- the 100,000-item Release and TSan soaks are separate evidence.

Post-fix evidence: default TSan 1.14 s clean; valid 100,000-item TSan 1.33 s
clean; Release CTest 20/20. The old 35-minute run is invalid evidence.

### 5. Generic multi-class artifact assembly

Implemented transactional overflow-safe multi-source merging, duplicate
class/record/factory rejection, exact emitted metadata tuples, safe partial
module initialization cleanup, generated multiple heap types, guarded direct
calls, cycle collection, and fresh-process repeated lifecycle.

Translation-unit boxed signature/default/global state still permits only one
live module instance. A second simultaneous exec rejects before mutation and
cannot clear the first instance. Metadata declares
`single_live_module;subinterpreters_unsupported`. This limitation must not be
weakened without a genuine per-module-state refactor.

### 6. Native reactor and datagram foundations

Added:

- `native_reactor.c/.h` and generated-source embedding;
- bounded reactor-owned selector registry;
- generation-tagged descriptor tokens and stale-FD protection;
- register/modify/remove/poll;
- fixed packet slab and generation-tagged leases;
- bounded nonblocking UDP draining;
- packet/time budgets, backpressure, retained/consumed ownership;
- fast bounded reactor tests for socketpair, UDP, fd reuse, budgets, ownership,
  teardown, ASan/UBSan, and focused TSan where applicable.

The Python `DatagramReactor` now uses executable reference generation semantics
and declares compatible selector/slab storage and required regions.

### 7. Guarded reactor-thread Python boundaries

Implemented normalized generic call-edge facts and generated GIL-asserted
guarded calls for selector reader/writer removal, datagram generation checks,
delivery, exception cleanup, lease ownership, and bounded rescheduling.
Lowering is driven by normalized receiver/callee/arity/effects/owner facts;
source spans are diagnostic identity only.

Ordinary lookup, argument order, return/exception propagation, instance/class
monkeypatch, and subclass behavior are preserved. Validation included generated
socketpair/UDP subprocesses, real selector mutation, callback exceptions,
stale generations, and exactly-once retained lease release.

### 8. Generated reactor heap state

Added PyMeta descriptors:

- `storage.selector_registry(capacity=...)`;
- `storage.packet_slab(capacity=..., buffer_size=...)`.

Generated heap types lazily initialize reactor-owned selector/slab state, clean
partial initialization, traverse boxed owners only, and avoid all
`subtype_traverse` recursion. Generated wrappers cover selector operations,
ordinary immutable-bytes packet delivery, retained GC-tracked leases,
idempotent release, released-access rejection, callback exceptions, delete and
reinitialize, and close/GC.

Validation at Stage 5c completion: strict Release build; CTest 21/21; relevant
Python 65; generated lifecycle passed; standalone reactor ASan/UBSan passed;
direct loop still fail-closed at that time.

### 9. Generic constructor and graph integration

Implemented generic native-class constructor IR and generated `Py_tp_init`:

- Python signature/default/keyword binding;
- custom `__new__` rejection;
- structural zero-argument `super().__init__` lowering;
- direct GC traversal/clear/dealloc for object-base generated types without
  delegating into `subtype_traverse`;
- immutable one-time exact component fields;
- boxed dict, f-string, and formatted-value constructor expressions;
- closure-free positional lambda with captured-lambda rejection;
- ordinary list/loop/append/tuple construction used by `PacketWorkerPool`;
- live source-global identity guards so emitted class substitution is used only
  while the source global still equals the captured original; replacement uses
  ordinary Python behavior, and pre-load replacement rejects import.

All eight event-loop constructors became emission-complete. Focused constructor,
GC, exact-field, live-global replacement, and lambda tests passed.

### 10. First full artifact probe and rollback

Scheduler hook aggregation, selector operations, constructor containment, and
worker proof facts were closed enough for the compiler to emit a temporary full
module. It loaded in a fresh subprocess, exposed eight native classes and 27
regions, and worked for `packet_workers=0`.

A required non-default probe caught the missing worker assembly:

```text
new_event_loop(packet_workers=1)
AttributeError: event_loop_native.PacketWorker object has no attribute _run
```

This artifact is not conforming evidence. The owned-shard gate was restored and
the compiler again rejects the full graph with zero output.

### 11. Production entry and loader policy groundwork

Added `webrtc/event_loop/event_loop.py` as a stable generic compiler entry that
imports the proven implementation and yields `event_loop_native` without
emitter class-name hardcoding. Compiler metadata now includes compiler version,
CPython/source revisions, cache tag, ABI flags, and optimization mode.

The production loader continues to require exact compatible free-threaded
runtime, source, manifest, policy, and artifact metadata; otherwise it falls
back to stock asyncio. It must stay disabled until worker assembly and final
validation are complete.

## User-reported regressions at stop

The user reported these failures:

- `test_multi_source_native_types_direct_calls_and_module_lifecycle`;
- `test_native_class_with_zero_region_graph_stays_fail_closed`;
- two handle fast-path tests;
- native base-initializer/member descriptor failure;
- native deallocation subprocess timeout;
- five native-field tests hitting the single-live-module guard.

Resolved before stop:

- the multi-source lifecycle test now respects construction-time immutable
  exact fields and exercises subclass deoptimization on a fresh facade;
- zero-region rejection now occurs before C emission and restores the
  source-correlated `zero_region_graph.py` diagnostic;
- exact rerun of those two tests passed 2/2;
- native-field fixture scope was changed to avoid repeated live-module loads;
- descriptor checking was generalized to a data descriptor;
- teardown stress was bounded to 250 iterations.

Not yet honestly runnable/resolved:

- handle fast-path and full native-field behavior depend on the complete full
  event-loop artifact;
- they currently fail or error at artifact setup because the owned-shard gate
  correctly rejects the incomplete worker assembly;
- do not re-enable incomplete emission merely to make those fixtures start.

## Interrupted worker-adapter work

The final active task was attaching the already-proven worker executor to
generated `PacketWorker` heap objects.

New/interrupted files include:

- `webrtc/compiler/native_compiler/native_worker_codegen.c`;
- `webrtc/compiler/native_compiler/native_worker_codegen.h`;
- in-progress integration in
  `webrtc/compiler/native_compiler/native_class_generator.c`;
- temporary application integration edits in
  `webrtc/event_loop/workers.py` and `scheduler.py`.

The chosen generic design is a Thread-compatible generated native adapter
stored in the constructor-discovered thread field. It is intended to:

- own `WrtcNativeWorkerExecutor` and input/result ABI descriptions;
- bypass Python `threading.Thread(target=self._run)` only when the exact native
  worker proof is complete;
- preserve Python Thread fallback for custom/replaced processors;
- pack native `OwnedPacket`, submit nonblocking, materialize `PacketResult`,
  and surface typed errors on the reactor;
- use a native pipe/socket notification registered with the reactor;
- expose start, close, join, is_alive, submit, completion count, and consume;
- integrate pool sharding, completion drain, close/join/dealloc, partial init,
  repeated shutdown, and retained-owner reclamation.

At stop, `native_worker_codegen.c` contains an emitted CPython adapter skeleton,
but attachment into generated constructors/fields and operation dispatch is not
complete. It has not passed a final compile after the last edits. Inspect every
failure path and reference-count transition before continuing.

The interrupted unstaged diff also adds `PacketWorkerPool.drain_results()` to
the scheduler turn and calls an optional thread `close()` from `PacketWorker`.
These changes are provisional and must be validated or revised with the final
adapter lifecycle.

## Dirty-tree snapshot

At stop, `git status --short` reported 41 modified/added tracked files. The
large staged foundation is approximately 6,723 insertions and 221 deletions,
plus an unstaged interrupted adapter patch of roughly 242 lines. Key additions:

- `native_kernel.c/.h` and test;
- `native_reactor.c/.h`, codegen, and test;
- `native_worker_abi.h`;
- `native_worker_executor.c/.h` and test;
- `native_worker_codegen.c/.h` (incomplete);
- `webrtc/event_loop/event_loop.py`;
- extensive compiler, PyMeta, event-loop, and test modifications.

Always run both `git diff --cached` and `git diff` when restoring context.

## Exact resume procedure

1. Read this checkpoint, the 2026-07-30 checkpoint, and both governing specs.
2. Preserve the dirty tree. Do not reset or unstage user/agent work.
3. Run exactly one root-level subagent at a time and prohibit nested subagents.
   Reuse an existing completed agent with a follow-up task if the thread limit
   prevents spawning a new one.
4. First inspect staged versus unstaged adapter changes and fix the known
   trailing whitespace. Do not treat that mechanical fix as validation.
5. Complete generic native worker adapter attachment:
   - create/own the adapter only for proof-complete exact workers;
   - bypass Python Thread construction in that guarded case;
   - retain ordinary Python fallback for custom/replaced processors;
   - wire submit/cancel/completion/drain/notification/pool sharding;
   - wire start/stop/join/close/dealloc/partial-init/reinit;
   - ensure the worker thread never calls Python C API;
   - release every accepted/rejected/cancelled/queued/completed owner exactly
     once.
6. Add focused `packet_workers=1` and `packet_workers>1` generated-artifact
   probes before lifting the owned-shard gate. Cover capacity one, full input
   and output, cancellation, typed processor error, notification coalescing,
   callback failure, close races, repeated shutdown, GC, and subprocess exit.
7. Rerun the exact user-reported tests. Fix real regressions generically; do not
   weaken the one-live-module safety guard or emit an incomplete artifact.
8. Only after all non-default probes pass, regenerate the full graph and verify:
   eight classes, 27 required regions, exact metadata, native worker selection,
   scheduler/datagram/command/lifecycle state, and zero unexplained fallback.
9. Run strict Release warnings-as-errors build, full CTest, relevant Python and
   compiled-loop suites, generated full-artifact subprocess lifecycle,
   ASan/UBSan standalone suites, focused TSan queue/worker/reactor tests, and
   `git diff --check`.
10. Use a separate independent validation subagent after implementation.
11. Only after independent validation may the production loader be enabled for
    compatible metadata and the Kernel E v0.3 benchmark be run with the actual
    compiled event loop.

## Copyable restore instruction

> Continue from
> `research/event_loop_compiler_checkpoint_2026-08-08.md` and the existing
> staged/unstaged dirty tree. Read both specs and the 2026-07-30 checkpoint.
> Run one root-level subagent at a time; no nested agents. The full compiler is
> intentionally fail-closed because generated worker executor proof exists but
> the Thread-compatible adapter is only partially emitted and not attached to
> `PacketWorker`. Inspect `native_worker_codegen.c`,
> `native_class_generator.c`, `workers.py`, and `scheduler.py`; fix the known
> trailing whitespace; complete the generic adapter lifecycle and operation
> wiring; preserve Python Thread fallback for custom processors; validate
> `packet_workers=1` and `>1`; then rerun the user-reported handle/native-field
> failures. Do not re-enable the loader or benchmark until a conforming full
> artifact passes independent validation. Never restore the historical
> handwritten emitter or recursive `subtype_traverse` behavior.
