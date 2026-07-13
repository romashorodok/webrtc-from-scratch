import { expect, test } from "bun:test";
import { buildTraceDataRows, formatNormalizedTraceExport } from "./TraceNormalizedView";
import { createInitialTraceState, reduceTraceState } from "./trace";

test("schema-1 lifecycle input is not admitted by the production reducer", () => {
  const state = createInitialTraceState();
  expect(reduceTraceState(state, {
    type: "events", events: [{ event: "trace:init", data: { tasks: [{ task_id: "raw" }] } }],
  })).toBe(state);
});

test("bounded captures are marked in normalized UI rows and exports", () => {
  const snapshot = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{ event: "trace:snapshot", data: {
      schema: 2, trace_id: "trace", snapshot_sequence: 0,
      captures: [{
        record_id: 1, capture_id: 7, selector_kind: "operation", selector_value: 3,
        operation_id: 3, operation: "media.encode", owner_entity_id: "peer",
        started_ns: 1, finished_ns: 2, duration_ms: 0.1, outcome: "error",
        failure_class: "ValueError", revision: 2, diagnostic_capture: true,
      }],
    }}],
  });
  const rows = buildTraceDataRows({
    machinesById: snapshot.machinesById, controlsById: snapshot.controlsById,
    groupsById: snapshot.groupsById, facetsById: snapshot.facetsById,
    capturesById: snapshot.capturesById,
    operationNamesById: snapshot.operationNamesById, diagnostics: snapshot.diagnostics,
  });
  expect(rows[0]?.kind).toBe("capture");
  expect(rows[0]?.name).toContain("CAPTURE #7");
  expect(formatNormalizedTraceExport(rows)).toContain("[diagnostic capture]");
});
