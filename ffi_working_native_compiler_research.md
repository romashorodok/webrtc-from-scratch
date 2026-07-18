# Native Python-Subset Compiler Research for `ffi-working`

## Status

Research proposal. No performance benefit described in this document is
accepted as proven until its corresponding benchmark passes.

`ffi-working` is the reference architecture and the main branch for future
performance work. The state-machine Runtime redesign, mutable peer reducer,
TaskGroup ownership redesign, and attempts to optimize those architectures are
treated as rejected experiments and are outside this research.

## Research Question

Can a small compiler that translates a statically typed subset of Python
syntax into native C produce measurable media-path improvements over
`ffi-working`, while remaining independent of PyO3 and compatible with regular
and free-threaded CPython through a plain `ctypes` C ABI?

The compiler is not assumed to be a good optimization. The purpose of the
research is to determine whether it is useful enough to justify its complexity.

## Fixed Baseline

All comparisons use the unmodified `ffi-working` revision as the primary
baseline:

```text
8b85614672a1e51d8a464288db202cfc791a0d3d
```

Before native-compiler experiments, establish two additional baselines derived
from `ffi-working`:

1. `ffi-working` with direct event-loop UDP sending.
2. `ffi-working` with direct UDP sending and production media tracing disabled.

The compiler must outperform the best simpler baseline, not merely outperform
the slower state-machine branch.

## Rejected Approaches

The research must not depend on:

- The current universal state-machine Runtime.
- A mutable peer reducer rewrite.
- A TaskGroup/structured-concurrency rewrite.
- Per-packet task ownership or reconciliation.
- PyO3.
- Python C-extension module initialization.
- The CPython Limited API or Stable ABI.
- Embedded handwritten C source strings inside Python modules.
- Python callbacks invoked from native packet-processing code.

These exclusions keep the experiment focused on isolated computation kernels
and prevent architectural changes from contaminating the result.

## Proposed Compiler Model

The application language, operations, annotations, and Python-native PyMeta API
are defined only by the canonical
[`Python Meta-Language Specification`](./research/python_metalanguage_spec.md).
Application source remains ordinary CPython; the CDLL backend supports a
restricted eligibility core rather than defining a restricted Python dialect.
The compiler validates and lowers eligible functions into a typed intermediate
representation, writes generated artifacts into a build directory, invokes the
platform C compiler, and loads the shared library through `ctypes.CDLL`.

```text
typed Python source file
    -> Python ast
    -> validation and type checking
    -> typed intermediate representation
    -> generated .c/.h files
    -> clang/gcc/MSVC
    -> shared library
    -> ctypes C ABI
```

Generated native functions do not execute Python bytecode and do not access
Python objects. Python is used only to compile, load, call, and test the native
library.

## Initial Backend Eligibility

The first CDLL version targets the portable kernel core defined in the canonical
specification. Unsupported Python remains executable under CPython; a requested
kernel that is not eligible must be rejected with a source location and clear
explanation. It must never silently fall back inside a function reported as
native.

## Compiler Structure

Suggested modules:

```text
native_compiler/
    annotations.py
    parser.py
    validation.py
    typecheck.py
    ir.py
    lowering.py
    c_backend.py
    build.py
    cache.py
    bindings.py
```

Responsibilities:

- `annotations.py`: native scalar, buffer, and structure types.
- `parser.py`: locate and parse declared native functions.
- `validation.py`: reject unsupported AST constructs.
- `typecheck.py`: resolve widths, signedness, buffer element types, and returns.
- `ir.py`: typed, Python-independent intermediate operations.
- `lowering.py`: convert validated AST into IR.
- `c_backend.py`: write deterministic `.c` and `.h` output files.
- `build.py`: invoke the system compiler with explicit flags.
- `cache.py`: cache by source, IR, ABI, compiler, flags, target, and architecture.
- `bindings.py`: declare `ctypes` signatures and manage buffer lifetimes.

Generated artifacts belong in an ignored build/cache directory and must not be
written into the source tree during normal imports.

## Native ABI Requirements

The generated library must expose a versioned C ABI using only fixed-width
integers, opaque handles, pointers, sizes, and explicit result codes.

The ABI must not expose:

- `PyObject *`.
- Borrowed Python memory without a documented call-scoped lifetime.
- C++ or Rust layouts.
- Compiler-dependent enums or unversioned structures.
- Pointers to temporary error strings.

Every entry point must validate pointers, lengths, capacities, and overlapping
buffers before processing.

`ctypes.CDLL` is the required loader. Shared mutable native state must use its
own single-thread ownership contract, mutex, or atomics; it must never rely on
the GIL for correctness.

## Candidate Kernels

Research kernels are introduced one at a time. A later kernel is not started
until the earlier result has been measured and recorded.

### Kernel A: RTP Header Serialization

Inputs:

- Payload type.
- Marker bit.
- Sequence number.
- Timestamp.
- SSRC.
- Preallocated output buffer.

Output:

- Serialized 12-byte RTP header.

Purpose:

- Validate compiler correctness and ABI overhead using a small deterministic
  function.
- Establish whether a `ctypes` call is more expensive than the Python work it
  replaces.

Expected result:

- This kernel may fail the performance gate because the operation is very
  small. Failure is useful evidence that per-packet native calls are too fine
  grained.

### Kernel B: RTP Packet and Extension Serialization

Inputs include RTP header fields, TWCC, extension map, payload view, and one
preallocated output buffer.

Purpose:

- Test whether combining header, extensions, and payload copy amortizes the
  `ctypes` boundary.

### Kernel C: TWCC Feedback Calculation

Parse a bounded RTCP TWCC feedback buffer and return aggregate results through
a caller-provided structure.

Purpose:

- Compare native calculation with direct Python processing and the existing
  executor path.

### Kernel D: AV1 Frame Fragmentation

Split one encoded AV1 frame into bounded RTP payload descriptions without
creating one Python object for every intermediate fragment.

Purpose:

- Test a frame-level boundary where native execution has more work per call.

### Kernel E: Frame-Level Packet Construction

In one call:

```text
AV1 fragmentation
    -> RTP headers
    -> RTP extensions and TWCC
    -> serialized packet buffers
```

Purpose:

- Test the first candidate likely to amortize compilation and `ctypes`
  overhead.

SRTP is excluded from the first compiler version. Adding cryptography requires
calling a reviewed existing C implementation or separately validating a native
implementation; cryptographic code must not be generated casually from the
experimental language subset.

### Kernel F: Frame Processing and Native Send

Only if Kernel E passes, test a native operation that constructs all packets
and writes them to a nonblocking socket before the output arena is reused.

Linux may use `sendmmsg()`. Other platforms retain bounded `sendmsg()` or
`sendto()` loops. Partial sends and `EAGAIN` must be explicit results, never
silent packet loss.

## Claims and Required Verification

### Hypothesis 1: Direct UDP is faster than worker-offloaded UDP

Existing evidence:

- `asyncio.DatagramTransport.sendto()` is nonblocking.
- `ffi-working` dispatches it through a worker.

Required test:

- Compare direct event-loop send and worker-offloaded send using the real media
  workload and equivalent packet counts.

Acceptance:

- Direct send reduces process CPU without increasing packet loss or event-loop
  lag.

### Hypothesis 2: A native kernel can beat Python

Required test:

- Benchmark each kernel against its Python implementation with identical input
  and output semantics.
- Include the full `ctypes` call, argument preparation, validation, and output
  conversion in the native measurement.

Acceptance:

- Median native CPU time is at least 20% lower than Python for the isolated
  kernel.
- End-to-end media CPU improves by at least 3% relative, not 3 percentage
  points, after integration.

If the isolated kernel wins but end-to-end CPU does not improve, reject the
integration.

### Hypothesis 3: Combining work amortizes the `ctypes` boundary

Required test:

- Compare per-field, per-packet, and per-frame native boundaries.

Acceptance:

- The frame-level boundary outperforms both finer native boundaries and the
  Python baseline.
- No frame-level p99 latency regression greater than 1 ms.

### Hypothesis 4: Native buffers reduce copying

Required test:

- Count input copies, output copies, bytes allocated, and Python objects
  created per frame.
- Verify buffer reuse under actual asynchronous UDP behavior.

Acceptance:

- At least one full-size packet copy per packet is removed without exposing a
  buffer that Python or the transport may retain after reuse.

If safe ownership requires converting every result back to `bytes`, report that
copy and re-evaluate the benefit.

### Hypothesis 5: Generated C matches handwritten C

Required test:

- Implement one small handwritten reference kernel in a separate research
  fixture.
- Compare generated C assembly or runtime with equivalent compiler flags.

Acceptance:

- Generated code is within 10% of handwritten C for the same algorithm.
- Any difference has an identified cause such as bounds checks or ABI
  conversion.

### Hypothesis 6: The compiler is compatible with free-threaded Python

Required test:

- Run the same bindings and native library under regular and free-threaded
  CPython.
- Invoke independent contexts concurrently from multiple Python threads.
- Attempt prohibited concurrent access to one single-owner context and verify
  deterministic rejection or documented synchronization.

Acceptance:

- Loading the library does not enable the GIL.
- Independent contexts execute correctly in parallel.
- ThreadSanitizer reports no native data races in the supported concurrency
  contract.

### Hypothesis 7: Runtime compilation is operationally acceptable

Required test:

- Measure clean compilation time, cached import time, cache contention, failed
  compiler discovery, read-only filesystem behavior, and concurrent process
  startup.

Acceptance:

- Cached load adds less than 20 ms to application startup on the reference
  host.
- Compilation is never required on a production request path.
- A missing compiler produces a clear fallback or installation error.
- Cache publication is atomic and safe across processes.

## Benchmark Methodology

### Environments

At minimum test:

- macOS on the current development architecture.
- Linux x86-64.
- Regular CPython 3.13 or later.
- A matching free-threaded CPython build.

Record:

- Python version and free-threading status.
- Compiler name and version.
- Optimization flags.
- CPU architecture and available instruction sets.
- Operating system and kernel version.
- Whether CPU frequency scaling or thermal throttling occurred.

### Isolated benchmarks

For each kernel:

- Use identical pre-generated inputs.
- Warm both implementations.
- Alternate AB/BA execution order.
- Run at least seven paired samples.
- Disable cyclic GC only inside the timed region and restore it afterwards.
- Report wall time, process CPU, calls per second, allocation count, allocated
  bytes, and output-copy bytes.
- Measure normal and worst-case accepted packet/frame sizes.
- Verify every result against the Python reference outside the timed region.

Do not use `tracemalloc` during CPU timing. Run allocation profiling separately.

### End-to-end media benchmark

Use the same browser or real loopback peer, AV1 input, FPS, MTU, executor size,
logging configuration, and duration for all variants.

Variants:

1. Clean `ffi-working`.
2. `ffi-working` with direct UDP.
3. `ffi-working` with direct UDP and unobserved media execution.
4. Best simple Python variant plus one native kernel.
5. Best simple Python variant plus the frame-level native kernel.

Warm for at least 30 seconds and measure at least 120 seconds. Run at least five
alternating paired samples.

Collect:

- Process CPU and wall time.
- Event-loop lag p50/p95/p99.
- Frames and RTP/RTCP packets.
- Packet loss and TWCC feedback rate.
- Worker and native calls.
- Python allocations and RSS in a separate run.
- Native arena high-water usage.
- Per-frame processing p50/p95/p99/max.
- Shutdown time and outstanding native work.

## Correctness Tests

Every compiled kernel must have:

- Golden-vector parity with Python.
- Minimum, typical, and maximum-size inputs.
- Empty and truncated input tests.
- Output-capacity failure tests.
- Integer rollover tests.
- Misaligned input/output tests where supported.
- Overlapping-buffer rejection tests.
- Randomized differential tests against Python.
- AddressSanitizer and UndefinedBehaviorSanitizer runs.
- ThreadSanitizer runs for any shared native state.
- Deterministic behavior across optimization levels used for release.

For RTP-related kernels, verify byte-for-byte packet equality, sequence and
timestamp rollover, marker behavior, extension layout, MTU enforcement, and
packet order.

## Go/No-go Criteria

Proceed beyond research only if all of the following are true:

- At least one frame-level kernel improves end-to-end CPU by 5% or more
  relative to the best simple `ffi-working` variant.
- Event-loop lag and media correctness do not regress.
- Generated code is within 10% of handwritten C for the same kernel.
- The compiler and bindings pass sanitizer and free-threaded tests.
- Cached startup and deployment behavior meet the operational budget.
- The useful native workload includes enough logic to justify maintaining the
  compiler instead of one small handwritten C library.

Reject the compiler approach if any of the following holds:

- Only tiny per-packet kernels improve in isolation.
- End-to-end CPU improvement is below 5%.
- Output copying erases the native gain.
- The generated code requires frequent handwritten C escape hatches.
- The compiler becomes responsible for cryptographic correctness.
- Cross-platform ABI or build maintenance exceeds the value of the optimized
  kernels.
- A handwritten C library is materially simpler with equivalent performance.

## Research Deliverables

1. Typed subset definition.
2. AST validator and typed IR.
3. Deterministic C backend.
4. Cached compiler and `ctypes` loader.
5. Kernel A as a compiler smoke test.
6. Kernel B or C as a boundary-amortization test.
7. Kernel E as the main performance experiment.
8. Differential correctness suite.
9. Sanitizer and free-threaded test reports.
10. Paired isolated and end-to-end benchmark reports.
11. Final decision: adopt, restrict to research, or reject.

## Expected Research Outcome

The likely result is that very small native functions lose to direct Python
because `ctypes` argument preparation and calls dominate. Frame-level kernels
have a better chance of winning because they amortize that boundary.

This expectation is a hypothesis, not a result. The compiler is adopted only
if it beats the simplest optimized `ffi-working` implementation in the real
media workload and provides enough reusable value to justify maintaining a
custom language toolchain.
