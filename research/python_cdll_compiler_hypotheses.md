# Python-to-CDLL Compiler and Server Injection Research Hypotheses

## Status

Research specification. Every numbered statement is a hypothesis that must be
verified. No isolated microbenchmark is sufficient to accept a hypothesis.

This is research track B of three. It covers hypotheses H13-H24. Track A,
[`cpython_native_module_compiler_hypotheses.md`](./cpython_native_module_compiler_hypotheses.md),
covers H01-H12. The deliberately speculative meta-compiler track,
[`python_metacompiler_frontier_hypotheses.md`](./python_metacompiler_frontier_hypotheses.md),
covers H25-H48.

All source syntax, annotations, operations, metadata, and backend-eligibility
terms in this track are defined by the canonical
[`Python Meta-Language Specification`](./python_metalanguage_spec.md). This file
contains research hypotheses only and does not define another language.

## Objective

Research an optimizing translator that accepts ordinary typed Python modules,
generates a Python-independent native shared library with a versioned C ABI,
and injects generated bindings into the existing Python WebRTC server.

Unlike track A, the generated CDLL does not import CPython headers, construct
Python objects, or implement a CPython extension module. Python loads it through
generated `ctypes.CDLL` bindings. The original `.py` source remains executable
and is the correctness fallback.

## Source Contract

This track implements the canonical source contract with the following
backend-specific requirements:

- The `.py` implementation runs normally without the CDLL.
- The same module tests both implementations.
- The native library has no CPython runtime dependency.
- PyO3 is not used.
- No native thread invokes a Python callback.
- Public Python APIs do not expose native pointers.
- Native errors cross the ABI as explicit status codes and are converted into
  the same Python exceptions as the reference implementation.
- The server can disable injection with one configuration switch.

## Intended Output

```text
build/native/linux-x86_64/libwebrtc_kernels.so
build/native/macos-arm64/libwebrtc_kernels.dylib
build/native/windows-x86_64/webrtc_kernels.dll
webrtc/fast/_generated_bindings.py
webrtc/fast/_generated_manifest.json
```

The generated Python binding module selects the compatible library, validates
its ABI, declares `ctypes` signatures once, and exposes normal Python callables.

## Proposed Compiler Pipeline

```text
ordinary typed Python source
    -> CPython ast
    -> mypy resolved type information
    -> typed kernel IR
    -> alias, ownership, range, and effect analysis
    -> generic and WebRTC-specific optimization passes
    -> C ABI lowering
    -> generated .c/.h files
    -> platform C compiler
    -> shared library
    -> generated ctypes bindings
    -> server injection or Python fallback
```

Track B does not implement Python object semantics inside native functions.
Only functions that can be lowered to buffers, scalars, fixed-layout records,
opaque handles, and explicit status codes are eligible.

## Metadata

This track uses canonical in-place PyMeta annotations and decorators, with
optional companion stubs and Python policy sidecars. Buffer effects and
ownership must be present in IR, bounds remain checks unless proved, and
platform selection remains build policy.

### Track B syntax profile

Track B makes the Python-independent boundary visually explicit while keeping
the same function executable as Python. Representations live in annotations;
the decorator describes ABI, effects, ownership, and error translation.

```python
from typing import Annotated, Protocol, TypeAlias

from pymeta import (
    buffer,
    contiguous,
    effects,
    lifetime,
    noescape,
    read,
    region,
    required,
    u8,
    uint,
    write,
)
from pymeta.abi import c_abi, status_errors


PacketId: TypeAlias = Annotated[int, uint[32]]
Input: TypeAlias = Annotated[
    bytes | bytearray | memoryview,
    buffer[u8] | read | lifetime.call | contiguous,
]
Output: TypeAlias = Annotated[
    bytearray | memoryview,
    buffer[u8] | write | lifetime.call | contiguous | noescape,
]


@region(
    required,
    abi=c_abi(version=1, errors=status_errors),
    effects=effects(reads={"packet"}, writes={"output"}),
)
def protect_packet(packet_id: PacketId, packet: Input, output: Output) -> int:
    return (
        packet
        | decode[RtpPacket]
        | protect_with(packet_id)
        | write_into(output)
    )
```

The annotation reads as a phrase, but each `|` operand is an immutable Python
descriptor. The body is the fallback and differential-test oracle. Generated
bindings derive fixed C types, capacity checks, status translation, and lifetime
rules from the normalized `RegionSpec` rather than duplicating a signature.

Caller-owned allocation uses an executable protocol:

```python
class OutputArena(Protocol):
    def reserve(self, capacity: int) -> memoryview: ...
    def commit(self, written: int) -> bytes: ...
```

A pure-Python arena implementation is mandatory; a CDLL lowering may replace
its operations only after proving the same ownership and failure behavior.

Syntax coverage across this track is intentional: H13 and H20 use `c_abi`;
H14 uses the original decorated callable; H15 uses coarse `@region` boundaries;
H16 uses buffer ownership descriptors; H17 uses `OutputArena`; H18 uses the
executable `|` packet pipeline; H19 uses a completion protocol; H21 and H22 use
effects and `noescape` for fusion; H23 uses native-operation stubs; and H24 derives injection metadata from
the normalized `RegionSpec`. Every H13-H24 experiment therefore shares one
Python-native surface.

## C ABI Model

The ABI may expose only:

- Fixed-width integers and floats.
- `size_t` lengths and capacities.
- Input pointers with call-scoped lifetimes.
- Caller-owned output buffers.
- Fixed-layout versioned structures.
- Opaque context handles.
- Explicit status codes.

Every public structure begins with size and ABI-version fields where evolution
is expected. The library exports an ABI query:

```c
uint32_t wf_abi_version(void);
```

The ABI must not expose Python objects, compiler-dependent C++ layouts, Rust
layouts, temporary string pointers, or ownership not expressible in the
generated binding manifest.

## H13: A Pure C ABI Is Portable Across CPython Execution Modes

### Claim to test

A Python-independent CDLL can be reused by regular and free-threaded CPython
builds because its ABI does not depend on Python object layout or extension
module initialization.

### Experiment

- Load the same native library from matching regular and free-threaded Python
  builds on each platform.
- Run independent native contexts concurrently.
- Verify `ctypes.CDLL` call behavior and native synchronization.
- Compare results and throughput.

### Reject if

- Generated bindings depend on CPython-private memory.
- Free-threaded calls reveal data races or require global serialization.
- Separate libraries are still needed for interpreter rather than platform
  reasons.

## H14: Generated Bindings Can Preserve Normal Module APIs

### Claim to test

A generated Python wrapper can expose the same function names, annotations,
exceptions, and return types as the interpreted module while selecting native
or Python execution at import or call time.

### Experiment

- Run the same API and protocol test suites with injection on and off.
- Compare introspection explicitly promised by the public API.
- Test missing, corrupt, mismatched, and unsupported native libraries.

### Reject if

- Users must call a second native-only API.
- Error or cancellation behavior diverges.
- Selection adds material cost to every hot call; selection should be resolved
  once during import or object construction.

## H15: Per-frame Boundaries Amortize `ctypes` Overhead

### Claim to test

Native calls made once per frame or feedback batch improve end-to-end CPU, while
very small per-field or per-packet calls lose to Python because argument
preparation and foreign-call overhead dominate.

### Experiment

Compare identical work through:

```text
one native call per header field
one native call per RTP packet
one native call per encoded frame
one native call per bounded multi-frame batch
```

Include binding dispatch, pointer construction, bounds validation, output
conversion, and errors in measurements.

### Reject if

- Frame calls do not beat optimized Python by at least 20% in the isolated
  kernel.
- End-to-end improvement is below 3%.
- Batching causes unacceptable latency or pacing bursts.

## H16: Ownership Analysis Can Produce Copy-Safe Buffer Views

### Claim to test

The compiler can infer call-scoped readonly inputs, exclusive mutable outputs,
and nonescaping views well enough to avoid unnecessary input copies without
exposing unsafe lifetimes.

### Experiment

- Pass `bytes`, `bytearray`, and contiguous `memoryview` inputs.
- Count every copy and pin duration.
- Mutate source objects concurrently in negative tests.
- Verify behavior for noncontiguous and readonly views.

### Reject if

- Safe binding requires copying most inputs.
- Buffer acquisition/release costs dominate the kernel.
- Free-threaded mutation cannot be constrained by the public API.

## H17: Caller-Owned Native Arenas Can Remove Output Allocation

### Claim to test

Preallocated per-peer arenas represented by stable generated binding objects can
let native kernels write packet batches without allocating one Python `bytes`
object for every intermediate result.

### Required design

- Fixed capacity and byte budget.
- Slot generation numbers.
- Explicit acquire/release state.
- No reuse while Python, asyncio, or the OS may retain a view.
- High-water and exhaustion counters.

### Experiment

- Compare Python allocation count, copy bytes, RSS, and CPU.
- Exercise large keyframes, cancellation, partial send, and close races.

### Reject if

- Async transport ownership requires copying every final packet anyway.
- Arena bookkeeping exceeds allocator cost.
- Incorrect reuse cannot be made structurally impossible.

## H18: Process-and-Send Fusion Removes the Final Output Copy

### Claim to test

A frame-level kernel that packetizes and writes encrypted datagrams to a
nonblocking socket before returning can outperform a kernel that materializes
packet results back in Python.

Potential fused path:

```text
frame
    -> fragmentation
    -> RTP headers/extensions
    -> encryption through a reviewed native crypto dependency
    -> bounded nonblocking datagram send
```

### Experiment

- Compare Python direct send, native packets returned to Python, and native
  process-and-send.
- Record partial sends, `EAGAIN`, pacing error, and packet order.
- Keep cryptography outside generated experimental code unless it calls an
  independently reviewed library.

### Reject if

- Fusion violates pacing or asyncio socket ownership.
- Platform handling fragments the compiler excessively.
- Output copying is not material in profiles.

## H19: Native Completion Rings Can Reuse the Python Event Loop

### Claim to test

A native worker and bounded SPSC rings can integrate with the existing asyncio
event loop through one notification file descriptor, eliminating
`run_in_executor`, native-to-Python callbacks, and one Future per packet.

```text
Python submits descriptor -> native input ring
native processes work     -> completion ring
native signals eventfd/pipe
asyncio add_reader         -> drains bounded completions
```

### Experiment

- Compare executor, synchronous CDLL, and native-ring paths.
- Measure wakeups, ring contention, completion latency, and loop fairness.
- Test Linux eventfd and portable pipe/socketpair notification.

### Reject if

- Frame copies into the ring erase the gain.
- Cross-thread wakeup latency exceeds executor latency.
- Shutdown and cancellation become ambiguous.

## H20: A Generated Fixed-Signature Binding Can Beat Generic `ctypes`

### Claim to test

After a kernel proves useful, a generated CPython-side call adapter or
ABI-specific stub may reduce generic `ctypes` marshalling while leaving the
native CDLL Python-independent.

This hypothesis deliberately permits a tiny optional generated adapter module;
the CDLL remains a pure C ABI. The ordinary `ctypes` binding remains the
fallback and correctness reference.

### Experiment

- Compare cached `ctypes` functions, generated adapter, and Track A extension
  entry points for fixed signatures.
- Include build and compatibility costs.

### Reject if

- Improvement is below 10% at the call boundary or below 1% end to end.
- The adapter recreates most of Track A without its benefits.
- Free-threaded compatibility becomes version-fragile.

## H21: Direct Native Calls Across Generated Kernels Enable Fusion

### Claim to test

Kernels generated into one CDLL can call each other through private native
signatures, allowing inlining and unboxed values while exposing only coarse
public ABI functions to Python.

### Experiment

- Compare separate shared libraries, one CDLL with public calls between
  kernels, and one CDLL with private direct calls/inlining.
- Measure link-time optimization where supported.

### Reject if

- Build size and invalidation become unacceptable.
- Whole-library compilation does not reduce Python crossings.
- Platform LTO differences undermine reproducibility.

## H22: Effect Analysis Can Automatically Fuse Media Pipelines

### Claim to test

Compiler analysis of pure functions, readonly inputs, exclusive outputs, and
ordered state effects can fuse ordinary Python function pipelines without a
handwritten fused implementation.

The candidate is an ordinary sequence of fragmentation, RTP construction,
extension application, and serialization calls. The potential result is one
native loop writing final output buffers.

### Experiment

- Emit a human-readable fusion and rejection report.
- Test exceptions and partial mutations at every original operation boundary.
- Enable passes individually for attribution.

### Reject if

- Python exception semantics prevent safe fusion.
- Metadata assertions are required everywhere.
- Manually designed coarse kernels remain clearer and equally fast.

## H23: Platform Network Backends Help Only at Server Scale

### Claim to test

Optional generated/native backends such as Linux `sendmmsg`, `recvmmsg`, or
`io_uring` improve high-peer-count server throughput while portable Python
socket behavior remains the default.

### Experiment

- Test one peer and increasing peer/packet rates.
- Compare portable `sendto`, Linux batching, multishot receive, and registered
  buffers where available.
- Measure CPU, latency, burst behavior, drops, and operational requirements.

### Reject if

- Improvement exists only in synthetic rates outside expected deployment.
- Pacing behavior worsens.
- Kernel/NIC requirements make deployment impractical.

## H24: Injection and Fallback Are Operationally Sustainable

### Claim to test

The server can safely select compiled kernels when compatible artifacts exist
and fall back to the Python-native implementation without configuration drift,
protocol divergence, or unacceptable startup cost.

### Required mechanism

- Manifest containing source hash, ABI, compiler version, flags, target, and
  enabled passes.
- Atomic artifact cache publication.
- Import-time compatibility validation.
- One process-level decision per module/kernel set.
- Explicit diagnostic describing native or fallback selection.
- Production policy that never compiles on a request path.

### Experiment

- Missing compiler and missing library.
- Corrupt, stale, wrong-architecture, and wrong-ABI artifacts.
- Concurrent server startup.
- Read-only filesystem.
- Native crash containment strategy and fallback on next restart.
- Rolling deployment with mixed artifact versions.

### Reject if

- Native and fallback configurations can silently diverge.
- Cached load adds more than 20 ms on the reference host.
- Build/distribution complexity exceeds the measured server improvement.

## Candidate Kernel Sequence

Implement only one research kernel at a time:

1. RTP header serialization as a boundary-cost negative control.
2. Complete RTP header and extension serialization.
3. RTCP/TWCC parsing into a fixed result structure.
4. AV1 frame fragmentation into caller-owned descriptors.
5. Frame-level RTP construction into an arena.
6. Native completion-ring integration.
7. Process-and-send only after output copies are proven material.

Tiny Kernel 1 is expected possibly to lose. That result establishes the minimum
profitable native work size.

## Verification Matrix

Compare:

1. Clean `ffi-working`.
2. Best simple Python-native `ffi-working` variant.
3. Typed interpreted kernels.
4. Track A CPython native module.
5. Track B CDLL through `ctypes`.
6. Track B CDLL through an optional generated adapter.
7. Track B coarse frame kernel.
8. Track B ring or platform backend where applicable.

Measure:

- Full binding-inclusive kernel CPU.
- End-to-end server process CPU.
- Event-loop p50/p95/p99/max lag.
- Frame and packet throughput.
- Packet loss, order, pacing, and TWCC behavior.
- Input/output copy counts and bytes.
- Python/native allocations and memory high water.
- Foreign calls, syscalls, and wakeups per frame.
- Startup, artifact validation, shutdown, and close races.

Use at least seven paired isolated samples and five alternating AB/BA
end-to-end samples after warmup.

## Correctness and Safety Suite

Required:

- Differential tests against interpreted source.
- Byte-for-byte protocol vectors.
- Randomized and malformed inputs.
- Minimum, typical, and maximum bounded sizes.
- Buffer capacity, alignment, overlap, and lifetime tests.
- Integer overflow and sequence rollover.
- Cancellation, close, partial-send, and stale-completion races.
- AddressSanitizer and UndefinedBehaviorSanitizer.
- ThreadSanitizer for native contexts and rings.
- ABI compatibility and manifest mismatch tests.
- Regular and free-threaded CPython callers.
- Fuzzing for parsers and buffer-writing kernels.

## Track B Go/No-go Criteria

Proceed only if:

- Source remains ordinary typed Python with an interpreted fallback.
- Native selection is transparent to the server's public API.
- A coarse kernel improves isolated CPU by at least 20%.
- Integration improves end-to-end CPU by at least 5% over optimized
  `ffi-working`.
- Event-loop p99 regresses by no more than 1 ms.
- Protocol, buffer-lifetime, and sanitizer suites pass.
- The CDLL works from regular and free-threaded Python under its documented
  ownership contract.

Reject or narrow Track B if:

- Only tiny synthetic kernels win.
- Python/CDLL crossings or output copies erase gains.
- Unsafe metadata assertions are needed for ordinary code.
- Native networking changes pacing semantics.
- Track A or unmodified mypyc is simpler with equivalent performance.
- Maintaining generated bindings and artifacts costs more than the measured
  improvement warrants.

## Relationship Between Tracks

Track A provides deeper CPython integration, native Python classes, optimized
async segments, and lower-cost Python object boundaries. Its cost is CPython
version coupling.

Track B provides a Python-independent native ABI, simpler free-threaded reuse,
and potential native worker/network integration. Its cost is marshalling,
restricted eligible functions, and explicit buffer ownership.

The tracks are experiments, not predetermined layers. The final decision may
select Track A, Track B, a narrow combination, unmodified mypyc, or no custom
compiler.

## Primary References

- [Python `ctypes` documentation](https://docs.python.org/3/library/ctypes.html)
- [Python asyncio event-loop file-descriptor integration](https://docs.python.org/3/library/asyncio-eventloop.html)
- [Linux `sendmmsg(2)`](https://man7.org/linux/man-pages/man2/sendmmsg.2.html)
- [Linux io_uring zero-copy receive](https://www.kernel.org/doc/html/next/networking/iou-zcrx.html)
- [Mypyc introduction](https://mypyc.readthedocs.io/en/latest/introduction.html)
- [Mypyc compilation units](https://mypyc.readthedocs.io/en/latest/compilation_units.html)
