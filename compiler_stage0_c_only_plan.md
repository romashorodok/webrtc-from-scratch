# Compiler Stage 0: C-Only Preparation Plan

## Status

Planning document only. Stage 0 authorizes no implementation.

This plan replaces the rejected WebSocket state-machine CPU optimization plan.
It prepares an evidence base for a possible compiler without implementing a
compiler, changing the WebRTC server, or claiming a performance result.

`ffi-working` at revision `8b85614672a1e51d8a464288db202cfc791a0d3d` is
the fixed reference architecture. The canonical source-language contract
remains the
[`Python Meta-Language Specification`](./research/python_metalanguage_spec.md).
This plan defines neither a new language nor a second runtime.

## Stage 0 Decision

Stage 0 evaluates only the Python-independent, plain C ABI direction described
by research track B. Native reference work is limited to portable C. It may be
loaded by a future `ctypes.CDLL` boundary. The completed compiler workflow must
load its native compiled module into the selected Python runtime; producing an
unused shared library is not a complete compiler result. Stage 0 specifies that
loading contract but does not create the loader or integrate native code into
the server.

The kernel source is ordinary Python conforming to the
[`Python Meta-Language Specification`](./research/python_metalanguage_spec.md).
That Python module is the maintained source and executable specification. A
future compiler consumes it and generates the native artifact; developers do
not write the production kernel in C or embed C in the meta-language. The
handwritten C oracle is a temporary Stage 1 research control used to establish
headroom and compare generated-code quality. It is neither compiler input nor
the authoritative kernel implementation.

The host interpreter and authoritative CPython source tree for this compiler
project is [`romashorodok/cpython`](https://github.com/romashorodok/cpython).
The future native build system is CMake. Stage 0 records these choices and
their versioning rules but creates no CMake project and builds no CPython or C
artifact.

The following are deferred until Stage 0 passes:

- a Python-to-C compiler;
- AST validation, type checking, IR, lowering, or optimization passes;
- a CPython extension backend;
- a meta-compiler, transformation search, MLIR, LLVM, or assembly backend;
- generated bindings, import hooks, artifact injection, or runtime compilation;
- PyMeta runtime or annotation implementation;
- changes to packet processing, UDP sending, tracing, scheduling, or ownership;
- production build, cache, packaging, or rollout machinery.

“C-only” means that any later native oracle is handwritten ISO C with a plain,
versioned C ABI. It does not mean that the compiler itself is implemented in C
during Stage 0, and it does not mean that the maintained kernel is authored in
C. There is no compiler implementation in this stage.

## Fixed Toolchain Direction

- **CPython source and runtime:** use the
  [`romashorodok/cpython`](https://github.com/romashorodok/cpython) fork, not an
  unspecified system Python or a different CPython checkout.
- **Revision policy:** Stage 0 must record an exact commit SHA from that fork;
  a branch name such as `main` is not reproducible enough for Stage 1.
- **Native language:** generated and handwritten native code is C only. C++
  must not be required by the public ABI or build.
- **Build system:** CMake is the sole project-level native build generator.
  Direct ad hoc compiler commands may be documented for diagnosis but are not
  the reproducible build contract.
- **C compiler:** CMake must discover and record the selected C compiler,
  version, target triple, generator, build type, flags, and sanitizer options.
- **Separation:** the plain C kernel library must not link to CPython. The
  selected CPython fork hosts the reference Python implementation and future
  compiler frontend; it does not become part of the kernel ABI.
- **Native loading:** the selected `romashorodok/cpython` executable must load
  the CMake-built shared library through generated `ctypes.CDLL` bindings,
  validate ABI and artifact compatibility before the first native call, and
  expose the compiled function through the normal Python module API.

The Stage 0 build plan must reserve CMake targets for a future C oracle,
sanitizer variants, and tests without prescribing implementation files. It
must also define out-of-source builds and keep generated artifacts outside the
source tree.

## Purpose

Before building compiler infrastructure, determine whether the intended native
boundary is coherent, measurable, portable, and valuable enough to justify a
compiler project.

Stage 0 answers four questions:

1. Which one WebRTC kernel is the smallest useful compiler target?
2. What exact Python behavior and C ABI must that kernel preserve?
3. Can a handwritten C oracle plausibly beat the best simple Python baseline
   after all boundary and copy costs are counted?
4. Is code generation likely to provide enough value over maintaining one
   small handwritten C library?

Stage 0 produces plans, contracts, fixtures, and measurement definitions. Any
execution of those plans belongs to Stage 1 or a separately approved research
task.

## Inputs Reviewed

This plan reconciles the repository compiler specifications as follows:

- [`ffi_working_native_compiler_research.md`](./ffi_working_native_compiler_research.md)
  supplies the fixed baseline, candidate kernels, measurement method, and
  compiler go/no-go standard.
- [`python_metalanguage_spec.md`](./research/python_metalanguage_spec.md) remains
  the only normative source and semantic contract.
- [`python_cdll_compiler_hypotheses.md`](./research/python_cdll_compiler_hypotheses.md)
  is the selected direction because it isolates generated code behind a plain
  C ABI and does not depend on CPython internals.
- [`cpython_native_module_compiler_hypotheses.md`](./research/cpython_native_module_compiler_hypotheses.md)
  is deferred because its extension-module and CPython-internal surface is
  larger than the Stage 0 question.
- [`python_metacompiler_frontier_hypotheses.md`](./research/python_metacompiler_frontier_hypotheses.md)
  is deferred in full because it is explicitly speculative and depends on a
  proven conventional compiler foundation.

Where those documents describe implementation deliverables, Stage 0 treats
them as future work, not current tasks.

## Scope

### In scope

- Freeze the reference revision and benchmark variants.
- Freeze the `romashorodok/cpython` revision and CMake toolchain identity.
- Select exactly one initial kernel.
- Specify its observable Python behavior with no native assumptions.
- Specify a portable, versioned C ABI for the kernel on paper.
- Define buffer ownership, lifetimes, aliasing, error codes, integer widths,
  byte order, capacities, and concurrency rules.
- Define handwritten C oracle requirements and review rules.
- Define differential, malformed-input, sanitizer, and benchmark plans.
- Define Stage 1 entry criteria and compiler rejection criteria.
- Define how the future compiled native module is discovered, validated,
  loaded, and made callable from the original Python module.
- Record unresolved decisions and owners.

### Out of scope

- Editing application Python to introduce compilation regions.
- Writing `.c`, `.h`, Python binding, compiler, build, or test code.
- Producing or loading a shared library.
- Running performance experiments and presenting uncollected numbers.
- Optimizing the rejected state-machine Runtime.
- Altering wire behavior, packet order, timing, cancellation, or fallback.
- Selecting advanced optimizations before the C oracle establishes headroom.

## Required Baselines

The future experiment must compare against all of these variants, in order:

1. unmodified `ffi-working`;
2. `ffi-working` with direct event-loop UDP sending;
3. the direct-UDP variant with production media tracing disabled;
4. the best simple Python implementation of the chosen kernel;
5. that same implementation with the handwritten C oracle substituted.

The compiler opportunity is the difference between variants 4 and 5. Wins
against only the rejected Runtime branch or only the unmodified baseline do not
justify a compiler.

## Initial Kernel Selection

Stage 0 must choose one kernel before any native work is approved. The default
candidate is frame-level RTP packet construction, corresponding to Kernel E in
the native compiler research plan.

It is preferred because it:

- amortizes a future foreign-function boundary across a frame;
- includes enough computation to test whether native execution matters;
- can be checked byte-for-byte against Python;
- avoids cryptography and network I/O;
- keeps ownership explicit through caller-provided input and output buffers.

RTP header serialization alone is allowed only as a correctness smoke fixture;
it cannot be the performance justification. Native socket sending, SRTP,
asyncio scheduling, callbacks into Python, and shared mutable session state are
excluded from the initial kernel.

If frame-level packet construction cannot be specified without importing
Python object semantics into C, Stage 0 must reject it and document the next
candidate rather than expanding the ABI.

## C ABI Contract to Specify

The Stage 0 ABI document must use only:

- exact-width integers from `<stdint.h>`;
- `size_t` for buffer lengths and capacities;
- pointers with an explicit nullable/non-null contract;
- caller-owned input and output storage;
- a versioned ABI identifier;
- explicit integer status codes;
- fixed-layout structures only where field offsets, sizes, and versioning are
  stated.

The ABI must not contain:

- `PyObject *` or CPython headers;
- C++ or Rust types;
- compiler-dependent enums or bitfields;
- borrowed pointers retained after the call;
- pointers to temporary error strings;
- hidden allocation, global mutable state, Python callbacks, or network I/O;
- behavior that relies on the GIL.

The contract must define behavior for null pointers, zero lengths, insufficient
capacity, overlapping buffers, integer overflow, malformed values, maximum
frame size, MTU limits, partial output, and unsupported ABI versions. Failure
must leave output length and caller-visible state in a defined condition.

## Semantic Contract to Freeze

The chosen Python function remains the executable specification. The planning
artifact must enumerate:

- accepted input types and ranges;
- exact output bytes and packet order;
- sequence, timestamp, marker, and extension behavior;
- integer overflow and rollover rules;
- mutation and aliasing behavior;
- exception type and ordering for every rejected input;
- output ownership and lifetime;
- determinism requirements;
- concurrency and reentrancy assumptions.

Nothing may be weakened merely because C integer, pointer, or overflow behavior
is different. An undefined C behavior is always a defect, never an optimization.

## Stage 0 Work Plan

### 0.1 Freeze evidence inputs

- Record the reference commit, Python versions, target operating systems,
  architectures, C compilers, and WebRTC workload.
- Record the exact `romashorodok/cpython` commit, its configure/build settings,
  and whether it is a regular or free-threaded build.
- Record the minimum CMake version, selected generator, C language standard,
  build types, and the release and sanitizer flag policy.
- Record the exact source function proposed as Kernel E and all transitive pure
  Python dependencies.
- Identify existing golden vectors and missing edge cases.

Deliverable: baseline and source inventory document.

### 0.2 Write the semantic kernel contract

- Convert current behavior into an input/output/error table.
- List all observable state and prove the kernel can remain pure or explicitly
  caller-state-driven.
- Define byte-for-byte and exception-equivalence requirements.

Deliverable: reviewed semantic contract with no C terminology in its normative
behavior section.

### 0.3 Design the paper C ABI

- Map every semantic input and output to fixed-width scalars or bounded
  buffers.
- Define ownership, capacities, status codes, and ABI version negotiation.
- Trace every possible copy and allocation across the planned boundary.
- Review portability for macOS arm64 and Linux x86-64 first; document Windows
  implications without expanding Stage 0 implementation scope.

Deliverable: proposed `.h` interface shown as a non-compiling design excerpt,
plus an ABI rationale and lifetime table.

### 0.3a Design the paper CMake build graph

- Define future targets for the C oracle library, differential test executable,
  ASan/UBSan variants, installation/export metadata, and ABI-version checks.
- Require out-of-source, reproducible builds with no network fetch during
  configure or build.
- Keep the C library independent of CPython headers and libraries.
- Pass the selected `romashorodok/cpython` executable to future tests as an
  explicit path; do not discover an arbitrary Python from the environment.

Deliverable: target/dependency diagram and configuration-variable table. No
`CMakeLists.txt` is written in Stage 0.

### 0.3b Specify native module loading

- Define the platform artifact names for `.so`, `.dylib`, and `.dll` outputs.
- Require generated `ctypes.CDLL` bindings with signatures declared once at
  module initialization.
- Define artifact discovery without compiling or downloading during import.
- Validate ABI version, target architecture, pointer width, and required
  exported symbols before enabling the native path.
- Convert native status codes into the exceptions required by the frozen
  semantic contract.
- Keep all buffer owners alive for the full native-call lifetime and prevent
  native pointers from escaping into public Python APIs.
- Specify deterministic behavior for missing, incompatible, or unloadable
  artifacts. Development fallback may use the Python implementation, while a
  configuration requiring native execution must fail clearly.
- Require tests to prove that the callable actually executes the loaded native
  symbol rather than silently using Python fallback.

Deliverable: native loading, validation, and failure-behavior contract. No
binding or loader code is written in Stage 0.

### 0.4 Define the handwritten C oracle

- Specify how a future handwritten implementation will serve as the upper
  bound for generated C.
- Require ISO C, explicit bounds checks, no undefined behavior, no hidden
  allocation, and deterministic results.
- Fix equivalent release flags for oracle and generated code.

Deliverable: oracle implementation checklist. No oracle code is written in
Stage 0.

### 0.5 Define verification before performance

- Plan golden, minimum, typical, maximum, empty, truncated, rollover,
  misalignment, overlap, and capacity tests.
- Plan randomized differential tests against Python.
- Plan AddressSanitizer and UndefinedBehaviorSanitizer runs; include
  ThreadSanitizer only if the final contract permits shared state.
- Require identical results across approved optimization levels.

Deliverable: verification matrix mapping each contract rule to a future test.

### 0.6 Define the measurement protocol

- Include call preparation, ABI validation, native execution, and output
  conversion in native timing.
- Alternate warmed AB/BA samples and use identical pre-generated inputs.
- Measure wall time, process CPU, calls per second, allocations, copied bytes,
  RSS, and frame latency percentiles.
- Run end-to-end media measurements only after differential and sanitizer gates
  pass.
- Reject kernel-only wins that do not improve the complete media workload.

Deliverable: benchmark protocol and blank result template. Stage 0 contains no
benchmark results.

### 0.7 Make the Stage 1 decision

- Estimate the smallest compiler slice capable of reproducing the accepted C
  oracle without handwritten escape hatches.
- Compare that maintenance cost with keeping the handwritten C library.
- Choose `proceed`, `revise kernel`, or `reject compiler` with recorded reasons.

Deliverable: signed Stage 0 decision record.

## Stage 0 Completion Criteria

Stage 0 is complete only when:

- one kernel and its exact Python source boundary are selected;
- the semantic contract covers success, failure, rollover, ownership, and
  ordering;
- the proposed C ABI is Python-independent, versioned, bounded, and reviewable;
- every ABI field maps to a semantic fact and every copy is accounted for;
- the verification and benchmark plans include the full boundary cost;
- the baseline variants and target environments are frozen;
- an exact `romashorodok/cpython` revision and CMake toolchain contract are
  frozen;
- the native compiled-module discovery, ABI validation, loading, and fallback
  contract is frozen;
- no compiler or production implementation has been added;
- the Stage 1 decision record identifies explicit go/no-go evidence.

Document completion alone does not authorize Stage 1.

## Stage 1 Entry Gates

Implementation may be proposed only after Stage 0 and must proceed in this
order:

1. Python fixtures and differential vectors.
2. Handwritten C oracle and minimal research-only loader.
3. Native-module loading and ABI-validation tests under the pinned
   `romashorodok/cpython` runtime.
4. Sanitizer and malformed-input verification.
5. Isolated full-boundary benchmark, including module loading and call costs
   where applicable.
6. End-to-end media benchmark against the best simple Python baseline.
7. Maintenance-cost comparison: compiler versus handwritten C.
8. Only then, a minimal AST-to-C compiler slice for the accepted kernel that
   emits and loads the compiled artifact.

The compiler proposal is rejected if the future oracle fails to improve
end-to-end CPU by at least 5% relative to the best simple baseline, if output
copying removes the gain, if correctness requires Python callbacks or hidden
object semantics, or if a small handwritten C library is materially simpler
for equivalent value.

## Relationship to Later Research

Passing Stage 0 opens only the plain C ABI oracle experiment. It does not
validate track A, track C, speculative optimizations, free-threaded scaling,
runtime compilation, or a general Python compiler.

If the C oracle later passes, the first compiler must target only the proven
kernel, emit deterministic C conforming to the frozen ABI, build it with CMake,
and load the resulting native module through the generated binding. Broader
language coverage, optimization passes, CPython-dependent modules, and
meta-compilation remain separate decisions with separate evidence gates.

## Expected Outcome

Stage 0 should make it inexpensive to reject the compiler idea. Its successful
outcome is not “a compiler exists”; it is a precise, reviewable decision about
whether one C-only native boundary has enough verified headroom to justify the
first compiler implementation stage.
