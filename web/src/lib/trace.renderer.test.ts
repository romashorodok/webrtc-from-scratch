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
import type {
  GroupSnapshot, TraceFacet, TraceMachine, TraceMachineTransition,
} from "./trace";

function fixtures(machineCount = 2, groupsPerMachine = 4) {
  const machinesById = new Map<string, TraceMachine>();
  const groupsById = new Map<number, GroupSnapshot>();
  const facetsById = new Map<string, TraceFacet>();
  const transitions: TraceMachineTransition[] = [];
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
    transitions.push({
      order: machine + 1, entity_id: entity, machine_type: "peer",
      from_state: "new", to_state: "connected", state: "connected",
      machine_epoch: 1, revision: 1, cause_id: null, monotonic_ns: machine + 1,
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
    transitions,
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
  expect(copied).toContain("Machine transitions:");
  expect(copied).toContain("new → connected");
  expect(copied).toContain("subscriber_lag");
  expect(copied).not.toContain("transition #");
  expect(copied).not.toContain("Entities:");
  expect(copied).not.toContain("peer-0");
  expect(copied).not.toContain("revision");
  expect(copied).not.toContain("parentId");
});

test("operation rows expose outcomes, latency distribution, and worker queue totals", () => {
  const data = fixtures(1, 1);
  const group = data.groupsById.get(0)!;
  Object.assign(group, {
    in_flight: 2,
    calls: 12,
    successes: 7,
    errors: 2,
    cancellations: 1,
    average_duration_ms: 3.25,
    min_duration_ms: 0.5,
    max_duration_ms: 19.75,
    total_worker_ms: 31.2,
    total_queue_ms: 4.125,
  });

  const rows = buildTraceDataRows(data);
  const value = rows.find((row) => row.id === "group:0")?.value;
  expect(value).toBe(
    "2 active · 12 calls · 7 ok / 2 errors / 1 cancelled · " +
    "avg 3.25ms (0.50ms–19.8ms) · worker total 31.2ms · queue total 4.13ms",
  );
  const exported = formatNormalizedTraceExport(rows);
  expect(exported).toContain(
    "2 active · 12 calls · 2 errors / 1 cancelled",
  );
  expect(exported).not.toContain("avg 3.25ms");
  expect(exported).not.toContain("worker total");
  expect(exported).not.toContain("0.50ms–19.8ms");
});

test("operation rows remain readable when older aggregate fields are absent", () => {
  const data = fixtures(1, 1);
  const group = data.groupsById.get(0)!;
  delete group.in_flight;
  delete group.successes;
  delete group.errors;
  delete group.cancellations;
  delete group.average_duration_ms;
  delete group.min_duration_ms;
  delete group.max_duration_ms;

  const value = buildTraceDataRows(data).find((row) => row.id === "group:0")?.value;
  expect(value).toBe("10 calls");
  expect(value).not.toContain("undefined");
  expect(value).not.toContain("NaN");
});

test("compact export retains nested duplicate operations without exposing group identities", () => {
  const data = fixtures(1, 0);
  const makeGroup = (id: number, operation: string, parent: number | null): GroupSnapshot => ({
    group_id: id,
    trace_id: "trace",
    task_id: `activity:${id}`,
    owner_entity_id: "peer-0",
    parent_ref_type: parent == null ? "machine" : "group",
    parent_ref_id: parent ?? "peer-0",
    group: "activity",
    operation,
    calls: 1,
    in_flight: 0,
    successes: 1,
    cancellations: 0,
    errors: 0,
    average_duration_ms: 1,
    min_duration_ms: 1,
    max_duration_ms: 1,
    latest_failure_class: null,
    revision: 1,
  });
  data.groupsById.set(10, makeGroup(10, "branch.left", null));
  data.groupsById.set(11, makeGroup(11, "shared.work", 10));
  data.groupsById.set(20, makeGroup(20, "branch.right", null));
  data.groupsById.set(21, makeGroup(21, "shared.work", 20));

  const rows = buildTraceDataRows(data);
  expect(new Set(rows.filter((row) => row.kind === "group").map((row) => row.id)).size).toBe(4);
  const exported = formatNormalizedTraceExport(rows);
  expect(exported).toContain("- branch.left [@1]");
  expect(exported).toContain("  - shared.work: 1 calls");
  expect(exported).toContain("- branch.right [@1]");
  expect(exported).not.toContain("group #");
  expect(exported).not.toContain("1 ok / 0 errors / 0 cancelled");
  expect(exported).toContain("1 calls");
  expect(exported).not.toContain("avg 1.00ms");
});

test("LLM export retains all records while reducing per-record detail", () => {
  const rows = buildTraceDataRows(fixtures(1, 40));
  const exported = formatNormalizedTraceExport(rows);
  expect(exported).toContain("operation-23 [@1]");
  expect(exported).toContain("operation-39 [@1]");
  expect(exported).not.toContain("records omitted");
});

test("LLM export removes UUIDs and long hexadecimal identifiers from all record text", () => {
  const data = fixtures(1, 1);
  const uuid = "0ab91234-1234-4abc-8def-0123456789ab";
  const digest = "0123456789abcdef0123456789abcdef";
  data.facetsById.set(`queue:${uuid}`, {
    facet_id: `queue:${uuid}`,
    owner_entity_id: "peer-0",
    owner_epoch: 1,
    value: { session_id: uuid, stream_key: digest },
    revision: 1,
  });

  const exported = formatNormalizedTraceExport(buildTraceDataRows(data));
  expect(exported).not.toContain(uuid);
  expect(exported).not.toContain(digest);
  expect(exported).toContain("queue:<id>");
  expect(exported).toContain('"session_id":"<id>"');
});

test("LLM export groups repetitive records without dropping their values", () => {
  const exported = formatNormalizedTraceExport(buildTraceDataRows(fixtures(2, 1)));
  const transitionLines = exported.split("\n").filter((line) => line.includes("new → connected"));
  const facetLines = exported.split("\n").filter((line) => line.includes("queue-"));
  expect(transitionLines).toHaveLength(2);
  expect(facetLines).toHaveLength(2);
  expect(exported).toContain("subscriber_lag=0");
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
