# Python Meta-Compiler Frontier Hypotheses

## Status

Research specification, not an implementation plan. This is the deliberately
speculative track C of three and contains hypotheses H25-H48. None of the
performance statements in this file are accepted claims.

The conventional CPython-extension hypotheses are in
[`cpython_native_module_compiler_hypotheses.md`](./cpython_native_module_compiler_hypotheses.md).
The Python-independent C ABI hypotheses are in
[`python_cdll_compiler_hypotheses.md`](./python_cdll_compiler_hypotheses.md).

All source syntax, annotations, operations, metadata, and backend-eligibility
terms in this track are defined by the canonical
[`Python Meta-Language Specification`](./python_metalanguage_spec.md). This file
contains research hypotheses only and does not define another language.

The current experimental runtime, reducer, and generalized state-machine
approaches remain rejected for future server work. `ffi-working` remains the
reference implementation and performance baseline. This file does not reverse
that decision. It describes isolated experiments that may be applied to the
baseline only after they win independently.

## Research Objective

Investigate whether a compiler can optimize not only typed Python programs but
also its own choice and ordering of compiler transformations, native ABI,
memory layout, event-loop integration, and kernel transport strategy for a
specific WebRTC workload.

The strongest version is a meta-compiler:

```text
ordinary typed Python source
    + in-place Python PyMeta descriptors
    + representative workload profiles
    + target CPU, OS and CPython policy sidecar
        -> semantic Python IR
        -> compiler-search IR
        -> generated candidate pass schedules and native variants
        -> differential correctness and safety gates
        -> end-to-end benchmark tournament
        -> one signed, reproducible native artifact
        -> ordinary Python import/injection with Python fallback
```

It does not invent another Python language. Python syntax, annotations,
exceptions, imports, cancellation and observable behavior continue to be
defined by the normal CPython implementation. The meta-layer searches how an
eligible region is compiled; it does not change what that region means.

## Proposed Compiler-of-Compiler Structure

The meta-compiler is not a second runtime and is not a self-modifying production
server. It is an offline build system with five separately testable layers:

```text
semantic frontend
    CPython AST + mypy types + explicit effects
        -> stable typed Python IR

transformation generator
    declarative rewrite rules + legality predicates
        -> generated optimization passes and pass schedules

candidate compiler
    typed IR + one schedule + one target description
        -> CPython extension or plain C ABI artifact

verification compiler
    source semantics + transformed IR
        -> proof obligations, differential tests and sanitizer builds

selection compiler
    verified candidates + workload corpus + operational budgets
        -> reproducible deployment manifest selecting one candidate per region
```

The transformation generator is the actual “compiler of the compiler”: it
compiles declarative optimization rules into executable compiler passes. The
selection compiler then compiles benchmark evidence into a fixed deployment
decision. Neither layer runs on live packets. Generated pass code and selected
schedules are materialized in the build output so they can be audited and
reproduced without trusting an opaque search result.

## Non-Negotiable Constraints

- Source remains ordinary `.py` accepted by CPython and mypy.
- PyMeta decorators attach inspectable metadata and preserve Python fallback behavior.
- The original Python path remains executable, testable and deployable.
- Unsupported or unstable code stays in Python or fails compilation explicitly.
- PyO3 is not used.
- Generated CPython modules may depend on the exact pinned CPython source tree.
- Generated CDLL kernels expose a versioned plain C ABI.
- No native thread calls Python through a `ctypes` callback.
- Compiler search happens offline, never in a production media process.
- A build is reproducible from source, compiler version, target policy,
  profile corpus, random seed and selected transformation schedule.
- Every native result passes differential, sanitizer and malformed-input tests.
- A candidate is accepted only on end-to-end WebRTC load, not a kernel-only
  microbenchmark.
- CPU reduction cannot be bought by worse packet loss, pacing, latency,
  cancellation, memory growth, fairness or interoperability.

## Metadata

This track uses canonical in-place PyMeta annotations and decorators, with
optional companion stubs and Python policy sidecars. Latency budgets,
deoptimization, verification, and pass-search choices remain build or IR
policy. Assumptions must be proved or checked.

### Track C syntax profile

Application regions use the same in-place syntax as tracks A and B. Compiler
search is itself authored as typed Python: transformations are immutable values,
rewrite rules are decorated Python functions, and schedules compose with `>>`.

```python
from pymeta.search import (
    Search,
    c_abi,
    cancellation_equivalence,
    capture,
    cost,
    differential_tests,
    fuse,
    inline,
    lower,
    noescape,
    ordered_errors,
    pipeline,
    protect,
    rule,
    sanitizers,
    serialize,
    serialize_protect_write,
    single_owner,
    vectorize,
    write,
)


@rule(
    matches=(
        serialize(capture.packet)
        >> protect(capture.bytes)
        >> write(capture.output)
    ),
    requires={single_owner, noescape, ordered_errors},
)
def fuse_packet_path(match: Match) -> Rewrite:
    return fuse(match, operation=serialize_protect_write)


baseline = pipeline(inline(max_depth=2) >> lower(c_abi))
simd = pipeline(inline(max_depth=4) >> fuse_packet_path >> vectorize(lanes=(4, 8)))

search = Search(
    regions={"webrtc.media.packetize_frame"},
    candidates={baseline, simd},
    objective=cost(cpu=1.0, p99_latency=2.0, rss=0.25),
    subject_to={
        differential_tests,
        sanitizers,
        cancellation_equivalence,
    },
    budget={"build_minutes": 20, "variants": 16},
)
```

The `@rule` decorator stores a frozen pattern and proof requirements while the
function constructs a normal `Rewrite` value. Calling it in tests exercises the
same rule builder used by search. `>>` means ordered composition and returns a
new immutable schedule; it never mutates either operand.

Deployment choice is also Python data, not a hidden search result:

```python
deployment.choose(
    "webrtc.media.packetize_frame",
    among={python, cpython_native, cdll},
    by=benchmark("representative_webrtc_load"),
    fallback=python,
)
```

The selected value, rejected candidates, evidence, random seed, toolchain, and
normalized descriptors must be serialized into the reproducible artifact.

Syntax coverage across H25-H48 is grouped by concern:

- H25-H28 use typed IR values, `@rule`, patterns, and bounded schedules.
- H29-H35 use specialization, profiles, guards, tier choices, and shadow policy.
- H36-H37 use verification and proof requirements on rewrite values.
- H38-H43 use async, completion, transport, `|` batching pipelines, and
  `lanes[width]` SIMD iterables.
- H44-H46 use layout choices and target-policy values.
- H47-H48 use `deployment.choose(...)` across transport and backend variants.

These declarations are executable or inspectable Python values. Search may
generate candidates, but it may not generate a private syntax unavailable to
the source, test, and reporting APIs.

## Common Measurement Contract

Every hypothesis must be tested against the unmodified `ffi-working` baseline
and the best previously accepted candidate using the same:

- Python and compiler build, CPU affinity and power policy;
- NIC, kernel, MTU, socket buffers and network impairment profile;
- codec inputs, resolutions, bitrates and peer-count ramp;
- signaling, ICE, DTLS, SRTP, RTP, RTCP, TWCC and retransmission behavior;
- warm-up period and minimum steady-state measurement window;
- packet loss, reordering, jitter and burst scenarios;
- CPU time, instructions, cycles, IPC, cache misses, allocations and syscalls;
- event-loop lag, frame lateness, packet pacing error and p50/p95/p99 latency;
- RSS, native arena high-water mark, build time and artifact size.

A performance result is invalid if outputs differ from the Python reference,
the process drops required work, or the test does not saturate the same useful
media throughput.

## Meta-Compiler Hypotheses

## H25: A WebRTC MLIR Dialect Can Preserve Optimization Intent

**Hypothesis.** A small internal dialect for packets, bounded buffers, peer
ownership, timestamps, batches and effects can retain information that is lost
when Python is lowered directly to C or LLVM IR. It enables useful fusion and
bufferization without creating new application syntax.

**Experiment.** Lower the same three kernels through direct C generation and a
minimal dialect followed by LLVM lowering. Compare generated code, compilation
cost and end-to-end CPU.

**Reject if.** It produces no repeatable server improvement, requires protocol
semantics duplicated outside Python, or adds more maintenance than the accepted
optimizations it enables.

## H26: A Meta-Compiler Can Search Transformation Schedules

**Hypothesis.** The best ordering of inlining, scalar replacement,
bufferization, bounds-check elimination, fusion and vectorization depends on
the media kernel. A compiler-search IR can generate and benchmark pass
schedules more effectively than one fixed hand-written pipeline.

**Experiment.** Enumerate a strictly bounded schedule space for packetization,
RTP extension writing and feedback parsing. Train on one corpus and validate on
unseen codecs, peer counts and CPUs.

**Reject if.** Search winners do not generalize, search cost is excessive, or a
small manually selected pipeline matches them within measurement noise.

## H27: Equality-Saturation Can Find Cross-Layer Packet Rewrites

**Hypothesis.** An e-graph or equivalent bounded rewrite system can discover
legal combinations of byte swaps, masks, shifts, header writes and checksum
operations that ordinary local optimization misses.

**Experiment.** Apply only to pure fixed-width packet expressions. Extract
candidates under measured latency and code-size costs, then prove equivalence
over the finite bit-vector domain with an independent checker.

**Reject if.** LLVM already produces equivalent machine code, extraction is
unstable, or proof/checking cost outweighs measurable benefit.

## H28: Superoptimization Is Practical for Tiny Protocol Kernels

**Hypothesis.** Exhaustive or stochastic instruction search can improve a few
very small, branch-heavy kernels such as RTP header classification, sequence
number extension or fixed extension parsing.

**Experiment.** Limit search to functions with fixed-width scalar inputs and no
allocation. Validate exhaustively where possible and compare against optimized
C at multiple CPU microarchitectures.

**Reject if.** The result is architecture-fragile, not faster end to end, cannot
be independently verified, or makes malformed-input behavior less safe.

## H29: Staged Partial Evaluation Can Remove Session Constants

**Hypothesis.** Codec, RTP extension IDs, SSRC mappings, negotiated algorithms,
MTU and direction become stable after negotiation. Specializing kernels once
for that finite configuration can remove dictionary lookups and branches.

**Experiment.** Generate at most a bounded number of variants from a canonical
configuration key. Measure dispatch, instruction-cache cost and renegotiation.

**Reject if.** Variant explosion, compile latency, memory use or invalidation
cost exceeds the saved CPU, or untrusted values can enter generated code.

## H30: Runtime Profiles Can Select AOT Variants Without Runtime Compilation

**Hypothesis.** Offline-built variants for common packet shapes and codec modes
can be selected from low-cost counters at safe boundaries, gaining adaptation
without executable-memory generation in production.

**Experiment.** Build generic plus specialized variants. Switch only between
frames or feedback batches using hysteresis and compare with one static build.

**Reject if.** Selection overhead or oscillation removes the benefit, profiles
are not stable, or the generic version is within noise.

## H31: CPython Specialization Data Can Guide Native Compilation

**Hypothesis.** CPython's adaptive instruction/cache observations can reveal
stable types, call targets and attribute shapes for an offline compiler without
adding packet-level tracing.

**Experiment.** Capture only aggregate warm-up information from a pinned
CPython build, compile guarded variants, and test them on a held-out workload.

**Reject if.** Required CPython internals are too unstable, observation distorts
the workload, guards fail frequently, or mypy information alone performs as
well.

## H32: Low-Impact Monitoring Can Find Compilation Regions

**Hypothesis.** Coarse `sys.monitoring` events and statistical native sampling
can locate hot Python regions with materially less distortion than tracing, and
can automate candidate-region discovery.

**Experiment.** Compare sampled profiles, selected monitoring events and the
previous tracing system against an external profiler and known injected loads.

**Reject if.** CPU overhead is material, specialization is disrupted, or the
method selects regions that do not improve end-to-end CPU after compilation.

## H33: A Frame-Evaluation Hook Can Provide Safe Tier Dispatch

**Hypothesis.** In a compiler-specific pinned CPython build, the frame
evaluation mechanism can dispatch whole eligible functions to precompiled code
while immediately retaining default evaluation for all other frames.

**Experiment.** Prototype a minimal whole-frame trampoline with no runtime
compiler. Test recursion, generators, exceptions, tracing, debugging and
free-threaded builds.

**Reject if.** Version coupling is greater than direct extension imports,
observability breaks, or dispatch costs more than an explicit generated wrapper.

## H34: Guarded Deoptimization Can Enlarge Compilable Regions

**Hypothesis.** Exact maps from native program points to Python locals and stack
state can allow optimized code to return to CPython on a failed type, shape or
global-version guard rather than rejecting the entire function.

**Experiment.** Start with synchronous, side-effect-free regions. Force every
guard to fail in tests and compare reconstructed execution with the reference.

**Reject if.** State reconstruction cannot be made exact, exception tracebacks
differ materially, or guard failures are common enough to erase the speedup.

## H35: Shadow Execution Can Validate Speculation Before Activation

**Hypothesis.** A tiny sampled fraction of real inputs can run through both
Python and native implementations outside the latency-critical result path,
detecting semantic drift before a new compiler artifact is promoted.

**Experiment.** Mirror bounded, non-secret test inputs in staging and canary
processes; compare outputs and state digests without affecting network sends.

**Reject if.** Duplication affects production latency/CPU, inputs cannot be
handled safely, or stateful behavior cannot be compared without side effects.

## H36: Compiler-Generated Differential Tests Can Beat Handwritten Coverage

**Hypothesis.** Typed IR, branch conditions and protocol bounds can generate
boundary, metamorphic and malformed-packet tests that find native/Python
differences earlier than the existing suite.

**Experiment.** Mutate lengths, extension orders, rollover boundaries, packet
loss and cancellation points. Seed known translation faults and measure the
fraction detected.

**Reject if.** Generated tests find no additional faults, are mostly invalid,
or cannot minimize a failure into a reproducible Python test.

## H37: A Proof-Carrying Optimization Pipeline Can Limit Meta-Compiler Risk

**Hypothesis.** Each aggressive pass can emit either a mechanically checked
proof for a narrow IR or a translation-validation obligation, allowing the
search system to explore transformations without trusting every generator.

**Experiment.** Cover fixed-width arithmetic, bounds elimination and buffer
write fusion first. Deliberately inject faulty transformations to test the gate.

**Reject if.** The checker is as complex as the compiler, relevant WebRTC
operations cannot be expressed, or proof generation dominates build time.

## H38: Compiler-Generated Coroutine Segments Can Reduce Scheduler Work

**Hypothesis.** A typed `async def` can be divided at actual suspension points;
straight-line segments can be native while ordinary `asyncio.Future` and `Task`
objects preserve scheduling, cancellation and debugging semantics.

**Experiment.** Compile only segments between awaits in the frame producer,
RTCP handling and bounded control paths. Count allocations, callbacks and task
steps under cancellation storms.

**Reject if.** The number of suspensions is unchanged and dominates cost,
cancellation/traceback behavior differs, or direct synchronous callbacks are
simpler and equally fast.

## H39: Event-Loop Operation Fusion Can Remove Ready-Queue Churn

**Hypothesis.** A compiler can recognize a sequence such as dequeue, process,
send and counter update that contains no actual suspension, then emit one
event-loop callback instead of multiple coroutine resumptions.

**Experiment.** Add an IR effect proving the fused region neither blocks nor
calls arbitrary Python. Compare ready-queue operations and fairness at high
peer counts.

**Reject if.** Fairness or cancellation latency worsens, effect proof is too
weak, or existing callback restructuring obtains the same result without a
compiler.

## H40: A Native Completion Ring Can Reuse the Existing Asyncio Loop

**Hypothesis.** Native workers can publish fixed-size completion records to a
single-producer/single-consumer ring and wake the normal event loop through one
file descriptor, amortizing Python scheduling while retaining asyncio control.

**Experiment.** Compare eventfd/pipe batch draining with one callback per native
completion. Measure empty wakeups, batch delay, overflow and shutdown races.

**Reject if.** A direct event-loop callback is faster, ring backpressure is hard
to make safe, or batching violates the media latency budget.

## H41: An io_uring Transport Island Can Reduce Linux Receive Cost

**Hypothesis.** On supported Linux kernels, one native transport island using
multishot receive and registered buffers can reduce receive syscalls and copies
while returning batches to the existing Python event loop.

**Experiment.** Implement behind a transport capability with portable asyncio
as fallback. Test UDP loss, buffer starvation, cancellation and kernel versions.

**Reject if.** CPU is not lower than the portable baseline, kernel/version
constraints are excessive, zero-copy ownership is unsafe, or p99 latency rises.

## H42: UDP Segmentation Can Reduce Outbound Syscalls for Compatible Batches

**Hypothesis.** Linux UDP GSO can reduce syscall/network-stack cost when a set
of same-sized encrypted datagrams to one destination satisfies its segmentation
contract.

**Experiment.** Detect NIC/kernel support and compare GSO, `sendmmsg`, and direct
`sendto` for real RTP sizes. Verify every received datagram byte-for-byte.

**Reject if.** SRTP/TWCC packet individuality makes legal grouping rare,
portability cost is high, or GSO increases pacing burstiness or loss.

## H43: Compiler-Generated Packet Batches Can Enable SIMD Across Packets

**Hypothesis.** Processing corresponding header fields from several packets in
structure-of-arrays form can vectorize classification, sequence extension,
timestamp conversion or feedback decoding better than packet-at-a-time code.

**Experiment.** Generate scalar and ISA-specific variants with runtime feature
selection. Include small batches and partially filled tails.

**Reject if.** gather/scatter and transposition cost dominates, latency needed
to form batches is unacceptable, or compiler auto-vectorization already matches it.

## H44: Layout Autotuning Can Select Data Structures Per Workload

**Hypothesis.** A meta-compiler can choose array-of-structures,
structure-of-arrays, bitsets, dense SSRC tables or compact hashes using measured
peer and packet distributions instead of one universal Python-oriented layout.

**Experiment.** Generate a bounded set of layouts with an identical API and
train on representative small and large deployments; validate on held-out load.

**Reject if.** one layout wins consistently, conversion dominates, or selected
layouts overfit and regress memory or tail latency.

## H45: Whole-Pipeline Ownership Inference Can Remove More Copies Than Pools

**Hypothesis.** Interprocedural lifetime and alias analysis from frame input to
socket submission can identify borrowed, uniquely owned and escaping buffers,
allowing exact copy placement rather than generalized object pooling.

**Experiment.** Emit an ownership report for every buffer and instrument actual
copies. Validate retained views, asynchronous sends and exception paths.

**Reject if.** dynamic Python aliases prevent useful proof, defensive copies
remain necessary at most boundaries, or manual ownership APIs are clearer.

## H46: CPU-Specific PGO, ThinLTO and Post-Link Layout Can Compound Gains

**Hypothesis.** Representative server profiles applied to generated native
modules through PGO, ThinLTO and post-link optimization can improve branch and
instruction-cache behavior beyond source-level compiler passes.

**Experiment.** Build identical artifacts with each technique separately and in
combination. Test on the trained CPU and at least one different deployment CPU.

**Reject if.** gains disappear end to end, profiles are too deployment-specific,
build reproducibility suffers, or artifact distribution becomes impractical.

## H47: A Deployment Compiler Can Choose Transport and Compiler Variants Together

**Hypothesis.** The optimal native layout and batching strategy depends on the
OS transport (`sendto`, `sendmmsg`, UDP GSO, completion ring), so jointly
selecting a small compiler/transport configuration can outperform independent
tuning.

**Experiment.** Search a bounded Cartesian set offline for Linux and macOS,
penalizing code size, portability and p99 latency in addition to CPU.

**Reject if.** interactions are negligible, the search overfits, or operational
complexity exceeds a predeclared maintenance budget.

## H48: A Tiered Meta-Compiler Can Select Python, CPython-Native or CDLL Per Region

**Hypothesis.** No single lowering is optimal for the whole server. A build-time
planner can keep dynamic control code in Python, compile Python-semantic hot
regions as CPython modules, and lower buffer kernels to a plain C ABI, while
generating one coherent import and fallback manifest.

**Experiment.** Give the planner measured crossing costs, mutation/exception
effects and workload profiles. Compare its partition with a manually selected
partition and with each uniform track.

**Reject if.** boundary crossings erase gains, failure/debug behavior becomes
unclear, or a much smaller manually chosen hybrid is equally fast.

## Deliberately Excluded Ideas

The following are not candidates unless the constraints change:

- A new Python-like grammar, language or incompatible type system.
- Requiring annotations to change interpreted Python semantics.
- Replacing CPython with a bespoke VM.
- Compiling arbitrary `eval`, monkey-patching or reflection by guessing behavior.
- Runtime machine-code generation in production media processes.
- Letting an ML model emit unchecked machine code or select unbounded variants.
- Python callbacks from native networking or crypto threads.
- Per-packet `ctypes` calls merely to claim that work is native.
- Moving the whole media server into C while retaining Python only as branding.
- Kernel bypass, AF_XDP, DPDK or GPU offload before ordinary socket and batching
  costs are proven to be the bottleneck. Their operational and batching costs
  make them separate server products, not compiler optimizations.

## Experiment Order

The hypotheses are intentionally not ordered by novelty. The recommended
research sequence is ordered by information gained per engineering cost:

1. Freeze the `ffi-working` benchmark, correctness oracle and profile corpus.
2. Test H32 and H36 to obtain trustworthy region discovery and differential tests.
3. Build the smallest IR experiment for H25, H29 and H45.
4. Test build-only optimizations H46 before creating new runtime machinery.
5. Test bounded scheduling H26 and tiny-kernel experiments H27-H28.
6. Test event-loop reductions H38-H40 only where profiles show scheduler cost.
7. Test Linux transport hypotheses H41-H42 behind portable capability switches.
8. Consider H30-H35 and H43-H48 only after simpler candidates independently win.

At every step, merge only the smallest winning mechanism into a branch based on
`ffi-working`. A failed hypothesis is recorded and removed; it is not rescued by
combining it with several other unproven mechanisms.

## Acceptance Gates

A hypothesis may advance only if all of these conditions hold:

1. **Semantic equivalence:** differential tests match normal Python, including
   exception type, cancellation, mutation and malformed-input behavior.
2. **End-to-end value:** useful media throughput and p99 latency are maintained
   while total CPU falls outside the confidence interval of the baseline.
3. **Attribution:** counters or controlled ablation show why the CPU changed.
4. **Generalization:** the win survives held-out media, network and peer profiles.
5. **Boundedness:** variants, memory, compile time and queues have explicit caps.
6. **Fallback:** disabling the artifact returns to the tested Python path.
7. **Operations:** shutdown, crash diagnosis, symbols and deployment stay usable.
8. **Reproducibility:** the exact artifact can be rebuilt from its manifest.

The default practical threshold should be declared before testing. A reasonable
starting gate is at least a 5% end-to-end CPU reduction at equal useful load,
with no statistically significant p99 regression, unless the experiment exists
primarily to validate compiler feasibility.

## Primary References

- [PEP 659: Specializing Adaptive Interpreter](https://peps.python.org/pep-0659/)
- [PEP 669: Low Impact Monitoring for CPython](https://peps.python.org/pep-0669/)
- [PEP 523: Adding a frame evaluation API to CPython](https://peps.python.org/pep-0523/)
- [PEP 703: Making the Global Interpreter Lock Optional](https://peps.python.org/pep-0703/)
- [MLIR pass infrastructure](https://mlir.llvm.org/docs/PassManagement/)
- [MLIR Transform dialect](https://mlir.llvm.org/docs/Dialects/Transform/)
- [MLIR conversion to LLVM IR](https://mlir.llvm.org/docs/TargetLLVMIR/)
- [LLVM profile-guided optimization](https://llvm.org/docs/HowToBuildWithPGO.html)
- [LLVM advanced builds and BOLT](https://llvm.org/docs/AdvancedBuilds.html#bolt)
- [Python 3.14 asyncio event-loop APIs](https://docs.python.org/3.14/library/asyncio-eventloop.html)
- [Linux io_uring zero-copy receive](https://docs.kernel.org/networking/iou-zcrx.html)
- [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html)
- [Linux networking-stack scaling](https://docs.kernel.org/networking/scaling.html)

These references establish that the underlying mechanisms exist. They do not
establish that any hypothesis will improve this WebRTC server.
