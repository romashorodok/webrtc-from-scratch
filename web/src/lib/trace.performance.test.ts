import { expect, test } from "bun:test";
import { runFrontendTraceBenchmark } from "./trace.benchmark";

test("frontend tracing benchmark reports repeatable reducer/group/layout fields", () => {
  const result = runFrontendTraceBenchmark(32, 2);

  expect(result.schema_version).toBe(1);
  expect(result.records).toBe(32);
  expect(result.sequential_reducer_p95_ms).toBeGreaterThanOrEqual(0);
  expect(result.atomic_batch_reducer_p95_ms).toBeGreaterThanOrEqual(0);
  expect(result.grouping_p95_ms).toBeGreaterThanOrEqual(0);
  expect(result.layout_p95_ms).toBeGreaterThanOrEqual(0);
  expect(result.normalized_max_svg_layout_p95_ms).toBeLessThan(16);
  expect(result.normalized_graph_nodes).toBe(300);
  expect(result.virtualized_rows).toBeLessThanOrEqual(27);
  expect(result.react_commit_p95_ms).toBeNull();
  expect(result.frame_p95_ms).toBeNull();
});
