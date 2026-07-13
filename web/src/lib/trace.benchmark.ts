import {
  TRACE_GRAPH_NODE_LIMIT,
  layoutTraceTopology,
  virtualTraceWindow,
  type TraceDataRow,
} from "./TraceNormalizedView";
import {
  createInitialTraceState,
  reduceTraceState,
} from "./trace";

export type FrontendTraceBenchmark = {
  schema_version: 1;
  benchmark: "live_tracing_frontend";
  records: number;
  samples: number;
  sequential_reducer_p95_ms: number;
  atomic_batch_reducer_p95_ms: number;
  grouping_p95_ms: number;
  layout_p95_ms: number;
  normalized_max_svg_layout_p95_ms: number;
  normalized_graph_nodes: number;
  virtualized_rows: number;
  react_commit_p95_ms: null;
  frame_p95_ms: null;
  limitations: string[];
};

function p95(values: number[]) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * 0.95) - 1)] ?? 0;
}

function sample(samples: number, operation: () => void) {
  const values: number[] = [];
  for (let index = 0; index < samples + 3; index += 1) {
    const started = performance.now();
    operation();
    const duration = performance.now() - started;
    if (index >= 3) values.push(duration);
  }
  return p95(values);
}

export function runFrontendTraceBenchmark(records = 256, samples = 30): FrontendTraceBenchmark {
  if (!Number.isInteger(records) || records < 1 || !Number.isInteger(samples) || samples < 1) {
    throw new Error("records and samples must be positive integers");
  }
  const groups = Array.from({ length: records }, (_, index) => ({
    group_id: index, trace_id: "benchmark", task_id: "peer", group: "benchmark",
    operation: `operation-${index}`, calls: 1, successes: 1, cancellations: 0,
    errors: 0, total_duration_ms: 1, average_duration_ms: 1,
    min_duration_ms: 1, max_duration_ms: 1, latest_failure_class: null, revision: 1,
  }));
  const snapshot = { event: "trace:snapshot", data: {
    schema: 2, trace_id: "benchmark", snapshot_sequence: 0, groups,
  }};

  const sequentialReducer = sample(samples, () => {
    let state = createInitialTraceState();
    state = reduceTraceState(state, { type: "events", events: [snapshot] });
  });
  const atomicBatchReducer = sample(samples, () => {
    reduceTraceState(createInitialTraceState(), { type: "events", events: [snapshot] });
  });
  const grouping = sample(samples, () => {
    void groups.length;
  });
  const layout = sample(samples, () => {
    layoutTraceTopology([]);
  });
  const normalizedTopology: TraceDataRow[] = Array.from(
    { length: TRACE_GRAPH_NODE_LIMIT },
    (_, index) => ({
      id: `group:${index}`,
      ownerId: "peer",
      parentId: index === 0 ? null : "group:0",
      kind: index === 0 ? "machine" : "group",
      name: `operation-${index}`,
      value: `${index} calls`,
      revision: 1,
    }),
  );
  const normalizedLayout = sample(samples, () => {
    layoutTraceTopology(normalizedTopology);
  });
  const virtual = virtualTraceWindow(100_000, 50_000, 240);

  return {
    schema_version: 1,
    benchmark: "live_tracing_frontend",
    records,
    samples,
    sequential_reducer_p95_ms: sequentialReducer,
    atomic_batch_reducer_p95_ms: atomicBatchReducer,
    grouping_p95_ms: grouping,
    layout_p95_ms: layout,
    normalized_max_svg_layout_p95_ms: normalizedLayout,
    normalized_graph_nodes: normalizedTopology.length,
    virtualized_rows: virtual.end - virtual.start,
    react_commit_p95_ms: null,
    frame_p95_ms: null,
    limitations: [
      "React commit and pan/zoom frame timing require the Stage 7 browser harness",
      "this Stage 0 runner measures JavaScript reduction, grouping, and D3 layout only",
    ],
  };
}

if (import.meta.main) {
  const recordsArgument = process.argv.find((value) => value.startsWith("--records="));
  const samplesArgument = process.argv.find((value) => value.startsWith("--samples="));
  const records = Number(recordsArgument?.split("=")[1] ?? 256);
  const samples = Number(samplesArgument?.split("=")[1] ?? 30);
  console.log(JSON.stringify(runFrontendTraceBenchmark(records, samples), null, 2));
}
