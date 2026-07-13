import { expect, test } from "bun:test";
import {
  TRACE_GRAPH_NODE_LIMIT,
  buildTraceDataRows,
  copyTraceExport,
  filterTraceDataRows,
  formatNormalizedTraceExport,
  layoutTraceTopology,
  selectBoundedTopology,
  stabilizeTraceDataRows,
  virtualTraceWindow,
} from "./TraceNormalizedView";
import type { GroupSnapshot, TraceFacet, TraceMachine } from "./trace";

function fixtures(machineCount = 2, groupsPerMachine = 4) {
  const machinesById = new Map<string, TraceMachine>();
  const groupsById = new Map<number, GroupSnapshot>();
  const facetsById = new Map<string, TraceFacet>();
  for (let machine = 0; machine < machineCount; machine += 1) {
    const entity = `peer-${machine}`;
    machinesById.set(entity, {
      entity_id: entity,
      machine_type: "peer",
      state: "connected",
      machine_epoch: 1,
      revision: 1,
      cause_id: null,
      monotonic_ns: 1,
    });
    facetsById.set(`queue-${machine}`, {
      facet_id: `queue-${machine}`,
      owner_entity_id: entity,
      owner_epoch: 1,
      value: machine,
      revision: 1,
    });
    for (let group = 0; group < groupsPerMachine; group += 1) {
      const id = machine * groupsPerMachine + group;
      groupsById.set(id, {
        group_id: id,
        trace_id: "trace",
        task_id: "owner",
        owner_entity_id: entity,
        group: "activity",
        operation: `operation-${group}`,
        calls: 10,
        successes: 10,
        cancellations: 0,
        errors: 0,
        total_duration_ms: 10,
        average_duration_ms: 1,
        min_duration_ms: 1,
        max_duration_ms: 1,
        latest_failure_class: null,
        revision: 1,
      });
    }
  }
  return {
    machinesById,
    controlsById: new Map(),
    groupsById,
    facetsById,
    operationNamesById: new Map(),
    diagnostics: { subscriber_lag: 0 },
  };
}

test("complete normalized list is searchable by kind, state, and owner", () => {
  const rows = buildTraceDataRows(fixtures());
  expect(rows.filter((row) => row.kind === "machine")).toHaveLength(2);
  expect(rows.filter((row) => row.kind === "transition")).toHaveLength(2);
  expect(rows.filter((row) => row.kind === "group")).toHaveLength(8);
  expect(filterTraceDataRows(rows, "connected", "transition")).toHaveLength(2);
  expect(filterTraceDataRows(rows, "peer-1", "facet")).toHaveLength(1);
  expect(filterTraceDataRows(rows, "subscriber", "diagnostic")).toHaveLength(1);
});

test("diagnostic state can be copied through the export action", async () => {
  const exportText = formatNormalizedTraceExport(buildTraceDataRows(fixtures()));
  let copied = "";
  await copyTraceExport(exportText, async (value) => { copied = value; });
  expect(copied).toBe(exportText);
  expect(copied).toContain("WebRTC runtime trace (schema 2, compact LLM summary)");
  expect(copied).toContain("Operations:");
  expect(copied).not.toContain("revision");
  expect(copied).not.toContain("parentId");
});

test("virtual list renders only viewport plus bounded overscan", () => {
  const window = virtualTraceWindow(100_000, 50_000, 240);
  expect(window.end - window.start).toBeLessThanOrEqual(27);
  expect(window.totalHeight).toBe(3_400_000);
});

test("topology includes every disconnected root and respects the independent graph cap", () => {
  const rows = buildTraceDataRows(fixtures(80, 8));
  const selected = selectBoundedTopology(rows, "machine:peer-7");
  expect(selected).toHaveLength(TRACE_GRAPH_NODE_LIMIT);
  expect(selected[0]?.id).toBe("machine:peer-7");
  expect(new Set(selected.map((row) => row.ownerId)).size).toBeGreaterThan(1);

  const oneLargeRoot = buildTraceDataRows(fixtures(1, TRACE_GRAPH_NODE_LIMIT + 50));
  expect(selectBoundedTopology(oneLargeRoot, "machine:peer-0")).toHaveLength(TRACE_GRAPH_NODE_LIMIT);
});

test("graph projection does not hide normalized record kinds", () => {
  const rows = buildTraceDataRows(fixtures(4, 20));
  expect(rows).toHaveLength(4 + 4 + 80 + 4 + 1);
  expect(selectBoundedTopology(rows, null)).toEqual(rows);
  expect(selectBoundedTopology(rows, null).map((row) => row.kind)).toContain("diagnostic");
  expect(selectBoundedTopology(rows, null).map((row) => row.kind)).toContain("transition");
});

test("maximum SVG topology layout stays inside the 16 ms budget", () => {
  const rows = buildTraceDataRows(fixtures(1, TRACE_GRAPH_NODE_LIMIT + 20));
  const topology = selectBoundedTopology(rows, "machine:peer-0");
  const samples: number[] = [];
  for (let index = 0; index < 25; index += 1) {
    const started = performance.now();
    const layout = layoutTraceTopology(topology);
    if (index >= 5) samples.push(performance.now() - started);
    expect(layout.nodes.length).toBeLessThanOrEqual(TRACE_GRAPH_NODE_LIMIT);
  }
  samples.sort((left, right) => left - right);
  const p95 = samples[Math.ceil(samples.length * 0.95) - 1] ?? Infinity;
  expect(p95).toBeLessThan(16);
});

test("value-only records preserve identical topology geometry", () => {
  const before = buildTraceDataRows(fixtures(1, 20));
  const changedFixtures = fixtures(1, 20);
  changedFixtures.groupsById.get(0)!.calls = 999;
  changedFixtures.groupsById.get(0)!.revision = 2;
  const after = buildTraceDataRows(changedFixtures);
  const beforeLayout = layoutTraceTopology(selectBoundedTopology(before, "machine:peer-0"));
  const afterLayout = layoutTraceTopology(selectBoundedTopology(after, "machine:peer-0"));
  expect(afterLayout.nodes).toEqual(beforeLayout.nodes);
  expect(after.find((row) => row.id === "group:0")?.value).toContain("999 calls");
});

test("value patches retain row identity for every unchanged SVG node", () => {
  const cache = new Map();
  const before = stabilizeTraceDataRows(buildTraceDataRows(fixtures(1, 20)), cache);
  const changedFixtures = fixtures(1, 20);
  changedFixtures.groupsById.get(0)!.calls = 999;
  changedFixtures.groupsById.get(0)!.revision = 2;
  const after = stabilizeTraceDataRows(buildTraceDataRows(changedFixtures), cache);
  const beforeById = new Map(before.map((row) => [row.id, row]));
  expect(after.find((row) => row.id === "group:0")).not.toBe(beforeById.get("group:0"));
  expect(after.find((row) => row.id === "group:1")).toBe(beforeById.get("group:1"));
  expect(after.find((row) => row.id === "machine:peer-0")).toBe(beforeById.get("machine:peer-0"));
});
