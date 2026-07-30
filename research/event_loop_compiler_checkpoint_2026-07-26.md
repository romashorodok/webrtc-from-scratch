# Event-loop compiler checkpoint — 2026-07-26

## Stop state

Work was stopped at the user's request. Both active implementation agents were
interrupted. The working tree was preserved; no reset, cleanup, commit, or
artifact deployment was performed.

The event-loop compiler must still be treated as fail-closed. No conforming
compiled event-loop artifact or compiled Kernel E benchmark exists at this
checkpoint.

## Last independently validated milestone

The generic boxed-Python/native-heap preparation was independently validated:

- strict Release C17 build passed;
- Release CTest passed 9/9;
- generic compiler/artifact tests passed 22/22;
- reference event-loop semantics/component tests passed 14/14;
- metadata, policy, selection, PyMeta, and benchmark-controller tests passed
  74 with 1 skip;
- ASan/UBSan CTest passed 9/9 with no findings
  (`detect_leaks=0`, because Apple ASan does not support LeakSanitizer here);
- the compiled-development benchmark rejected a missing event-loop artifact
  instead of falling back;
- `git diff --check` passed.

That validation covered:

- structured boxed statement/expression IR;
- artifact-owned serialized IR runtime;
- CPython-style signature/default binding;
- package-derived source globals;
- CPython 3.12+ negative-basicsize heap types using relative object members;
- generic factories and complete call-edge arrays;
- derived-class GC/cycle/deallocation stress without custom recursive base
  traversal.

## Completed after that independent validation

These later slices were validated by their implementation agents and by
focused root checks, but have not yet received a new end-to-end independent
validation pass:

1. `native_storage.c/.h`
   - tagged scalar storage with arbitrary boxed fallback;
   - owned FIFO ring;
   - owned min-heap using Python `<` semantics;
   - public readback/deoptimization, deletion, traversal, clear, and reference
     ownership;
   - randomized 3,000-operation FIFO/deque and heap/heapq differential tests.

2. `native_storage_codegen.c/.h`
   - embeds the authoritative native-storage runtime into generated artifacts
     without a source-tree dependency.

3. `native_operation.c/.h`
   - per-site, source-spanned native-field operation proofs;
   - alias tracking and monotonic evaluation order;
   - scalar reads/writes/augassign;
   - FIFO length/truth/append/popleft;
   - heap root/iteration/slice replacement/heapify/push/pop;
   - conservative unsupported-escape rejection.

The merged real `loop.py` and `scheduler.py` operation proof was complete for:

- `_ready`;
- `_scheduled`;
- `_timer_cancelled_count`;
- `_clock_resolution`.

The last clean root build before the interrupted integration passed CTest
12/12.

## Interrupted, unvalidated work

Two agents were interrupted while editing:

1. Native storage adoption in `native_class_generator.c` and boxed executor
   hooks.
   - A contained GC-tracked `NativeStorageOwner` design was being generated.
   - Proof-indexed evaluate/assign hooks were being connected so compiled
     storage operations bypass public descriptors.
   - Generator eligibility had begun consulting complete operation proofs.
   - This work was not built or tested after the final edits.
   - It must not be assumed safe or complete.

2. Expanded capability reporting in `native_class.c`.
   - `generator_accepted`, operation-proof completeness, field
     representation, operation sites, remaining Python calls, execution
     strategy, and rejection reasons were being added.
   - `tests/capability_report_c_test.c` was added.
   - This work was not built or tested after the final edits.

Before resuming, run `git diff --check`, a fresh strict C17 build, and the full
CTest suite. Do not load any generated native-class artifact until the
interrupted storage-owner/hook code passes subprocess lifecycle tests and
ASan/UBSan.

## Remaining blockers

- Finish and validate proof-indexed native storage hooks.
- Confirm contained storage-owner GC, deallocation, deletion, deoptimization,
  and Python-subclass behavior.
- Finish and validate capability-report changes.
- Re-run direct event-loop compilation. It must either emit a fully proven
  artifact or reject with zero artifact files.
- Native atomics, MPSC/SPSC queues, coalesced wakeups, worker ownership, and
  Python-free worker regions remain unimplemented.
- The current host has `Py_GIL_DISABLED=0`; free-threaded M4/M5 and TSan
  evidence require a separate pinned free-threaded CPython environment.
- Run the conforming compiled-loop semantic/lifecycle suites before any
  benchmark.
- Only then run the 7-pair compiled Kernel E benchmark. The earlier
  compiled-development JSON remains nonconforming diagnostic evidence.

## Working-tree note

Several new compiler and test files are untracked. They are part of this
checkpoint and must be included in any eventual commit; do not clean them as
temporary output.
