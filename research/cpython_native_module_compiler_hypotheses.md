# CPython-Dependent Native Module Compiler Research Hypotheses

## Status

Research specification. Every numbered statement is a hypothesis that must be
tested. Nothing in this document is an accepted performance claim.

This is research track A of three. It covers hypotheses H01-H12. Track B,
[`python_cdll_compiler_hypotheses.md`](./python_cdll_compiler_hypotheses.md),
covers H13-H24. The deliberately speculative meta-compiler track,
[`python_metacompiler_frontier_hypotheses.md`](./python_metacompiler_frontier_hypotheses.md),
covers H25-H48.

All source syntax, annotations, operations, metadata, and backend-eligibility
terms in this track are defined by the canonical
[`Python Meta-Language Specification`](./python_metalanguage_spec.md). This file
contains research hypotheses only and does not define another language.

## Objective

Research an ahead-of-time optimizing compiler for high-load media servers
written in ordinary typed Python. It produces importable CPython native modules
while preserving an interpreted CPython implementation from the same source.

The compiler may use CPython itself as a build and runtime dependency. It may
reuse appropriate CPython source, generated interpreter definitions, compiler
infrastructure, bytecode semantics, micro-op definitions, calling conventions,
and runtime helpers instead of recreating Python.

Any reused CPython source must retain its required copyright and license
notices. Internal CPython APIs are version-specific and provide no stability
guarantee; generated modules must therefore be pinned to and tested against an
explicit CPython source revision.

## Source Contract

This track implements the canonical source contract. Its distinguishing backend
choice is permission to use version-pinned CPython APIs and Python objects in a
compiled region. It must retain the interpreted implementation and may not use
PyO3.

## Intended Output

The compiler produces a version-specific extension alongside the ordinary
Python module, with separate regular and free-threaded builds where supported.

```text
webrtc/fast/rtp.cpython-314-darwin.so
webrtc/fast/rtp.cpython-314t-darwin.so
```

The source distribution retains the `.py` fallback. Binary distributions may
include both regular and free-threaded extension builds.

## Proposed Compiler Pipeline

```text
Python source
    -> CPython parser/AST and symbol-table semantics
    -> mypy semantic analysis and inferred types
    -> high-level typed Python IR
    -> control-flow, ownership, and effect analysis
    -> optimization passes
    -> low-level CPython/native IR
    -> generated C and CPython runtime helpers
    -> platform C compiler
    -> importable CPython extension
```

The frontend must not invent a new grammar or type system. CPython supplies
language syntax and baseline semantics. Mypy supplies standard annotation
resolution and gradual type inference. The research contribution is the IR,
optimization passes, WebRTC-specific lowering, and generated module runtime.

## Metadata

This track uses canonical in-place PyMeta annotations and decorators, with
optional companion stubs and Python policy sidecars. CPython-specific guard,
target, and interpreter-release choices remain sidecar or inferred IR policy.

### Track A syntax profile

Track A keeps Python objects available, so its syntax may describe guarded
unboxing, native class storage, and synchronous segments between suspension
points. Every decorated object remains callable under ordinary CPython.

```python
from dataclasses import dataclass
from typing import Annotated, Literal, TypeAlias

from pymeta import (
    checked,
    effects,
    generic,
    preferred,
    region,
    sint,
    specialize,
    variants,
)
from pymeta.cpython import (
    between_awaits,
    compact_object,
    cpython_exact,
    native_class,
    tracked,
)


PayloadType: TypeAlias = Annotated[int, sint[8] | checked]


@native_class(compact_object, gc=tracked, weakrefs=False)
@dataclass(slots=True)
class PacketRoute:
    payload_type: PayloadType
    destination: str


@region(
    preferred,
    variants=variants(limit=4, fallback=generic),
    specialize=specialize(codec=("opus", "av1")),
    effects=effects(
        reads={"route", "packet", "codec"},
        noescape={"packet"},
    ),
)
def classify_packet(
    route: PacketRoute,
    packet: bytes,
    codec: Literal["opus", "av1"],
) -> int:
    return route.payload_type if packet else -1
```

`@native_class` attaches a frozen layout request and leaves a normal Python
class behind. `@region` attaches a `RegionSpec`; it does not eagerly compile or
replace the function. Guards, boxing paths, and specialization decisions must
be visible through PyMeta inspection and the capability report.

Async control uses a decorator on the ordinary coroutine rather than a second
coroutine syntax:

```python
@region(preferred, segments=between_awaits, cancellation=cpython_exact)
async def encode_and_send(frame: Frame, transport: Transport) -> None:
    packet = encode(frame)
    await transport.send(packet)
```

Syntax coverage across this track is intentional: H01 uses ordinary Python
bodies; H02 uses `Annotated`; H03 and H08 use `specialize(...)`; H04 and H07 use
`@region`; H05 uses `@native_class`; H06 uses ownership and `noescape`; H09 uses
async segmentation; H10 consumes the same descriptors in CPython IR; H11 adds
owner and thread-affinity effects; and H12 uses executable semantic-operation
stubs. No hypothesis requires another surface language.

## H01: Reusing CPython Semantics Prevents a New-Language Fork

### Claim to test

Reusing CPython parsing, symbol tables, bytecode/compiler semantics, exception
rules, and runtime helpers can keep compiled modules compatible with their
interpreted source more effectively than an independent Python-subset parser.

### Experiment

- Compile a semantic corpus covering calls, descriptors, exceptions,
  comprehensions, generators, context managers, pattern matching, and async
  cancellation.
- Run identical tests interpreted and compiled.
- Differentially compare results, exceptions, tracebacks, and side effects.
- Repeat against every supported pinned CPython revision.

### Reject if

- Compatibility requires reimplementing large portions of CPython semantics.
- Version upgrades require pervasive manual fixes rather than regeneration.
- The compiler cannot clearly report unsupported constructs.

## H02: Mypy Types Enable Profitable Unboxing Without Custom Types

### Claim to test

Standard annotations and inferred types are sufficient to unbox hot local
integers, booleans, fixed tuples, and direct function results while retaining
ordinary Python source.

### Candidate optimizations

- Native-width loop indices and lengths.
- Unboxed RTP sequence, timestamp, SSRC, payload type, and TWCC fields.
- Unboxed boolean marker and state flags.
- Fixed-layout temporary tuples.
- Boxing only at interpreted/compiled boundaries or overflow paths.

### Experiment

- Compare boxed, inferred-unboxed, and explicitly annotated variants.
- Count Python allocations and overflow slow paths.
- Test arbitrary-precision integer behavior at boundaries.

### Reject if

- Required runtime type checks erase the improvement.
- Normal Python integer behavior cannot be preserved safely.
- Developers must introduce nonstandard scalar syntax.

## H03: CPython Specialization Profiles Can Drive AOT Decisions

### Claim to test

Type and branch behavior gathered during representative interpreted runs can
select safe compilation and specialization targets for later AOT builds.

CPython's specializing interpreter already observes types and hot paths. The
research should reuse available CPython mechanisms or exported profile data
rather than introduce permanent per-packet instrumentation.

### Experiment

- Train on representative AV1, Opus, ICE, DTLS, RTP, and RTCP sessions.
- Generate a profile-guided compiled module.
- Test it against different peers, codecs, MTUs, and renegotiations.
- Measure deoptimization or generic fallback frequency.

### Reject if

- Profiles overfit one session.
- Collecting or consuming the profile is version-fragile.
- Static mypy types provide the same result without training.

## H04: Whole Compilation Units Make Early Binding Material

### Claim to test

Compiling related hot modules as one unit reduces Python namespace lookup,
boxing, and generic call overhead more than compiling isolated functions.

Candidate unit:

```text
rtp + rtcp + twcc + av1 + packet_batch + media_sender
```

### Experiment

- Compare interpreted modules, individually compiled modules, and one combined
  compilation unit.
- Count Python-call-boundary crossings and boxed arguments.
- Measure build time and incremental rebuild cost.

### Reject if

- Unit size makes rebuilds or imports operationally unacceptable.
- Circular imports require architecture-specific compiler exceptions.
- End-to-end improvement over isolated compilation is below 2%.

## H05: Native Python Class Layouts Reduce Media Object Cost

### Claim to test

Ordinary annotated Python classes can receive fixed native layouts, direct
attribute offsets, early-bound methods, and optional GC elision when compiled.

Candidates:

- Packet batches.
- RTP header and extension state.
- Send-time cache.
- TWCC accumulator.
- Pacing state.
- Compact media statistics.

### Experiment

- Compare normal classes, slotted interpreted classes, and compiled native
  layouts.
- Measure allocation CPU, attribute CPU, memory per instance, and GC cost.
- Verify inheritance, weak-reference, pickling, and introspection requirements.

### Reject if

- Required Python dynamism forces dictionary-backed layouts.
- Native layouts change public behavior relied on by the server.
- Packet objects should instead be eliminated entirely by fusion.

## H06: Escape Analysis Can Eliminate Temporary Python Objects

### Claim to test

The compiler can prove that temporary headers, fragments, tuples, result
objects, and short-lived lists do not escape a compiled unit, then replace them
with stack/native locals or scalar fields.

### Candidate transformations

```text
RtpHeader instance -> scalar replacement
fragment list -> one fused output loop
temporary result tuple -> multiple native return fields
small callback object -> direct call target
```

### Experiment

- Emit an escape report for every eliminated or retained allocation.
- Differentially test reference identity and exception paths.
- Compare allocation count and end-to-end CPU.

### Reject if

- Python observability or identity makes most objects escape.
- Conservative analysis eliminates too little.
- Incorrect escape results cannot be detected reliably.

## H07: Vectorcall and Private Native Calls Reduce Boundary Cost

### Claim to test

Public compiled functions can use CPython's efficient call protocol, while
calls within one compiled unit use a private unboxed convention.

### Experiment

- Compare ordinary Python calls, generated vectorcall entry points, and private
  direct C calls.
- Measure positional, keyword, default, and error cases.
- Test calls from interpreted and compiled callers.

### Reject if

- Internal CPython call coupling dominates maintenance.
- Most hot calls still cross interpreted boundaries.
- The improvement is negligible after function inlining.

## H08: Inlining, Devirtualization, and Constant Folding Fit WebRTC

### Claim to test

Precise types plus negotiated constants allow the compiler to inline small
functions, devirtualize packetizer/codec methods, and remove branches for fixed
session configuration.

Candidate constants:

- Codec and payload type.
- RTP extension map.
- MTU and clock rate.
- Direction.
- Address family.
- SRTP profile.

### Experiment

- Generate generic and session-specialized variants.
- Include compilation/cache lookup in lifecycle measurements.
- Test renegotiation and variant invalidation.

### Reject if

- Variant explosion increases memory materially.
- Sessions are too short to amortize specialization.
- Dynamic dispatch is not visible in profiles.

## H09: Compiled Async Segments Can Retain Asyncio Semantics

### Claim to test

Normal `async def` functions can remain CPython-compatible coroutine objects
while synchronous regions between `await` points are compiled and optimized.

Potential optimizations:

- Native locals that survive suspension.
- Inlining async helpers with a statically known suspension graph.
- Eliminating temporary awaitables proven not to suspend.
- Fusing packetization work between readiness and pacing awaits.

### Experiment

- Compile the media sender and RTCP loops incrementally.
- Test cancellation at every suspension boundary.
- Compare traceback, context-variable, task-local, and exception behavior.
- Measure resumes, Futures, Tasks, and CPU per frame.

### Reject if

- Async compatibility requires duplicating the asyncio scheduler.
- Debugging or cancellation semantics diverge.
- Synchronous kernel compilation captures nearly all available benefit.

## H10: CPython Micro-op/JIT Infrastructure Can Be Reused for AOT Modules

### Claim to test

Because CPython is an explicit dependency, selected CPython-generated
interpreter definitions, micro-op semantics, or copy-and-patch machinery can
help generate optimized native module code without maintaining a separate
semantic backend.

This is intentionally version-pinned research. CPython's JIT documentation
warns that its implementation is tightly coupled to the interpreter.

### Experiment

- Compare a conventional generated-C backend with a CPython-derived micro-op
  backend for the same typed functions.
- Measure generated-code quality, build complexity, upgrade effort, and runtime
  dependencies.

### Reject if

- Reuse effectively becomes a permanent CPython fork.
- A CPython upgrade cannot be handled through regeneration and focused fixes.
- Generated C is simpler and equally fast.

## H11: Generated Free-Threaded Modules Can Scale Peer Shards

### Claim to test

Compiled modules that declare free-threaded support and avoid shared mutable
module globals can run independent peer shards in parallel while preserving
single-owner mutation inside each peer.

### Experiment

- Build regular and free-threaded variants.
- Run one peer, one peer per thread, and oversubscribed peer counts.
- Audit container access, borrowed references, caches, and module state.
- Run ThreadSanitizer for generated native state.

### Reject if

- Importing a compiled module re-enables the GIL.
- Internal locking removes parallel gains.
- Single-loop sharding or multiple processes remain simpler and faster.

## H12: WebRTC-Specific Fusion Beats Generic Mypyc

### Claim to test

A custom CPython-dependent backend can outperform unmodified mypyc by fusing
WebRTC operations that a generic compiler cannot safely recognize.

Candidate pass:

```text
AV1 fragmentation
    -> RTP header and extensions
    -> TWCC assignment
    -> serialization into reusable buffers
```

Other candidates:

- Incremental RTCP/TWCC parsing.
- SSRC routing specialization.
- Send-time ring conversion.
- Disabled metrics/logging dead-code elimination.
- Absolute-deadline pacing calculations.

### Experiment

- Compare interpreted CPython, JIT-enabled CPython, mypyc, custom generic
  backend, and custom WebRTC passes.
- Attribute improvement to individual passes.

### Reject if

- The custom backend cannot beat mypyc by at least 5% on the compiled unit.
- End-to-end server CPU improves less than 5% over the best simple baseline.
- Passes become coupled to one example instead of reusable media patterns.

## Verification Matrix

Every hypothesis must be evaluated with:

- Clean `ffi-working` reference.
- Best simple Python optimization baseline.
- Interpreted typed source.
- JIT-enabled CPython where available.
- Mypyc compilation.
- Custom compiled module with one pass enabled at a time.
- Custom compiled module with the selected pass set.

Measure:

- Process CPU and wall time.
- Event-loop lag p50/p95/p99/max.
- Frames and RTP/RTCP packets.
- Packet loss, pacing error, and TWCC behavior.
- Python and native allocations in separate runs.
- Calls across interpreted/compiled boundaries.
- Startup, import, compilation, cache, and shutdown costs.
- Memory per peer and code/variant cache size.

Use at least five alternating AB/BA end-to-end samples after warmup. Isolated
compiler benchmarks require at least seven paired samples.

## Compatibility Suite

Required:

- Differential interpreted/compiled tests.
- CPython language semantic corpus relevant to supported constructs.
- Byte-for-byte RTP/RTCP/STUN/DTLS output parity.
- Cancellation at every compiled async suspension boundary.
- Exception type, message, cause, context, and cleanup parity.
- Imports, reload policy, pickling, weak references, and introspection policy.
- Regular and free-threaded CPython builds.
- AddressSanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer.
- Debug mode with all compiler optimizations disabled.

## Track A Go/No-go Criteria

Proceed only if:

- Source remains valid and useful interpreted Python.
- Mypy-compatible annotations are sufficient; no custom language types are
  required in application code.
- End-to-end CPU improves by at least 5% over optimized `ffi-working`.
- The custom backend improves the selected unit by at least 5% over mypyc.
- Event-loop p99 regresses by no more than 1 ms.
- Protocol and cancellation parity pass.
- CPython upgrades remain bounded regeneration/compatibility work.

Reject or narrow the compiler if:

- It becomes an independent Python implementation.
- It requires a permanent CPython fork.
- Most useful functions remain boxed or interpreted.
- Debugging and profiling become operationally unacceptable.
- A small handwritten extension or Track B CDLL is simpler with equivalent
  performance.

## Primary References

- [Mypyc introduction](https://mypyc.readthedocs.io/en/latest/introduction.html)
- [Mypyc compilation units](https://mypyc.readthedocs.io/en/latest/compilation_units.html)
- [Mypyc native classes](https://mypyc.readthedocs.io/en/latest/native_classes.html)
- [Mypyc differences from Python](https://mypyc.readthedocs.io/en/latest/differences_from_python.html)
- [CPython specializing interpreter, PEP 659](https://peps.python.org/pep-0659/)
- [CPython JIT compilation, PEP 744](https://peps.python.org/pep-0744/)
- [CPython free-threaded extension guidance](https://docs.python.org/3/howto/free-threading-extensions.html)
