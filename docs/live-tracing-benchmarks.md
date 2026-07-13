# Live tracing performance benchmarks

Stage 0 establishes a repeatable measurement contract before tracing semantics
change. The numeric budgets are intentionally provisional: normal tests enforce
the result schema and bounded structural behavior, not machine-dependent timing.
The secured full-peer E2E workload must validate the numbers before they become
production defaults or required CI thresholds.

The canonical profile and budgets are encoded in
`tests/performance/baselines/live_tracing_budgets.json`. It covers 10k, 100k,
and 1M calls; 10, 100, and 4,097 groups (one above the current 4,096 limit);
closed/open/exact-capture overlay states; and single, multiple, and deliberately
slow subscribers.

## Backend runner

Run unobserved, aggregate, and compatibility exact-node profiles from the repository root:

```sh
uv run python tests/performance/live_tracing_benchmark.py \
  --mode unobserved --calls 10000 --groups 10 --overlay closed
uv run python tests/performance/live_tracing_benchmark.py \
  --mode aggregate --calls 100000 --groups 100 --overlay open --subscribers 1
uv run python tests/performance/live_tracing_benchmark.py \
  --mode capture --calls 10000 --groups 10 --overlay open --subscribers 1 \
  --track-allocations --output /tmp/live-tracing-exact.json
uv run python tests/performance/live_tracing_benchmark.py \
  --mode capture --calls 100000 --groups 100 --subscribers 4 --slow-subscriber
uv run python tests/performance/live_tracing_benchmark.py \
  --mode capture --workload mixed --calls 10000 --groups 100 --subscribers 1
```

Run each case in a fresh process, pin the same Python/build configuration, and
repeat it at least five times. Allocation tracking materially changes timing;
use its allocation/RSS values, but compare CPU overhead using runs without it.
The report includes wall/process CPU, allocation peak, sampled RSS peak, live
store/group cardinality, encoded bytes/messages, inferred queue replacement,
and currently available diagnostics.
The `mixed` workload combines synchronous event-loop calls, nested async calls,
and concurrently submitted worker calls; use the individual `inline`, `nested`,
and `worker` values when isolating one path.

Stage 2 adds aggregate measurements while leaving future fields null instead of
inventing data: journal/resync measurements arrive in Stage 4, and stable
machine/hidden-task profiles in Stage 5. The current slow-subscriber
result is expected to show dropped messages and no explicit resync; this is a
baseline defect that Stage 4 must reverse.

## Frontend runner

From `web/`, run normal and maximum-budget batch sizes:

```sh
bun run benchmark:tracing --records=256 --samples=30
bun run benchmark:tracing --records=2048 --samples=30
```

The runner compares the current sequential reducer amplification with one
atomic reducer action, then measures grouping and D3 layout. React commit and
pan/zoom frame p95 remain null because the repository has no browser performance
harness yet; Stage 7 owns those browser-only measurements.

Focused structural checks are:

```sh
uv run pytest -q tests/performance/test_live_tracing_benchmark.py
cd web && bun test src/lib/trace.performance.test.ts
```

Do not commit ad-hoc hardware results as universal thresholds. Store candidate
reports as CI artifacts and promote only broadly validated values into the
canonical budget file.

## Stage 7 renderer decision

The normalized renderer retains SVG. Its topology is independently capped at
300 nodes and `trace.renderer.test.ts` measures 20 warmed maximum-cap D3 layout
samples against the 16 ms maximum-batch budget. On the Stage 7 implementation
host, a 30-sample maximum-profile run measured 0.59 ms p95, leaving the layout
comfortably below 16 ms. The complete-data list is virtualized separately; a
100,000-record fixture mounts no more than 27 rows for the tested viewport and
overscan.

Canvas was therefore not implemented. The SVG uses stable keyed memoized node
components, recomputes geometry only for `topologyVersion` or selected-subtree
changes, and applies zoom transforms directly to the viewport element without
React state updates. A value-only revision changes displayed row/node values
while preserving identical geometry.

`TraceOverlay.renderer.test.tsx` also renders the initially closed overlay and
proves that the normalized list, SVG, export, and animation surface are not
mounted. The legacy exact-capture export is generated only while both the
overlay and export drawer are open.

The repository still has no real-browser automation dependency. React commit
and requestAnimationFrame/pan p95 therefore remain browser-E2E measurements for
the secured trace workload rather than being misreported from Bun's server DOM.
The pure batch, virtualization, topology, and layout budgets are enforced in
the normal frontend suite; browser commit/frame timings should be captured as
CI artifacts when that harness is introduced.
