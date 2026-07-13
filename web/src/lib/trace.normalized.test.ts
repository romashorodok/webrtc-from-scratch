import { expect, test } from "bun:test";
import {
  NORMALIZED_ARCHIVE_LIMIT,
  createInitialTraceState,
  reduceTraceState,
  type GroupSnapshot,
  type TraceEventInput,
} from "./trace";

function group(id: number, revision: number, calls = revision): GroupSnapshot {
  return {
    group_id: id,
    trace_id: "trace",
    task_id: `activity:${id}`,
    owner_entity_id: "peer",
    owner_epoch: 1,
    parent_ref_type: "machine",
    parent_ref_id: "peer",
    operation_id: 7,
    operation: "peer.tick",
    group: "peer",
    calls,
    in_flight: 0,
    successes: calls,
    cancellations: 0,
    errors: 0,
    total_duration_ms: calls,
    average_duration_ms: 1,
    min_duration_ms: 1,
    max_duration_ms: 1,
    latest_failure_class: null,
    revision,
  };
}

function snapshot(groups: GroupSnapshot[] = []): TraceEventInput {
  return {
    event: "trace:snapshot",
    data: {
      schema: 2,
      trace_id: "trace",
      snapshot_sequence: 0,
      machines: [{
        entity_id: "peer", machine_type: "peer", state: "new",
        machine_epoch: 1, revision: 0, cause_id: null, monotonic_ns: 1,
      }],
      controls: [], groups, facets: [],
      operation_strings: { 7: "peer.tick" }, diagnostics: {},
    },
  };
}

function batch(sequence: number, events: unknown[]): TraceEventInput {
  return {
    event: "trace:batch",
    data: { schema: 2, trace_id: "trace", sequence, events },
  };
}

function transition(order: number, revision = order) {
  const states = ["new", "starting", "active", "closed"];
  return {
    order, entity_id: "peer", machine_type: "peer",
    from_state: states[revision - 1] ?? `state-${revision - 1}`,
    to_state: states[revision] ?? `state-${revision}`,
    state: states[revision] ?? `state-${revision}`,
    machine_epoch: 1, revision, cause_id: null, monotonic_ns: order * 10,
  };
}

function apply(state: ReturnType<typeof createInitialTraceState>, event: TraceEventInput) {
  return reduceTraceState(state, { type: "events", events: [event] });
}

test("one canonical batch applies all records in one atomic reducer commit", () => {
  const initial = apply(createInitialTraceState(), snapshot());
  const next = apply(initial, batch(1, [
    { type: "machine:transition", records: [{
      entity_id: "peer", machine_type: "peer", state: "active",
      machine_epoch: 1, revision: 1, cause_id: null, monotonic_ns: 2,
    }] },
    { type: "control:upsert", records: [{
      handle_id: "stop", trace_id: "trace", owner_entity_id: "peer",
      owner_epoch: 1, name: "Stop", cancelable: true, revision: 1,
    }] },
    { type: "group:upsert", records: [group(1, 1)] },
    { type: "state:upsert", records: [{
      facet_id: "peer.ready", owner_entity_id: "peer", owner_epoch: 1,
      value: true, revision: 1,
    }] },
  ]));

  expect(next.commitVersion).toBe(initial.commitVersion + 1);
  expect(next.machinesById.get("peer")?.state).toBe("active");
  expect(next.controlsById.has("stop")).toBe(true);
  expect(next.groupsById.get(1)?.calls).toBe(1);
  expect(next.facetsById.get("peer.ready")?.value).toBe(true);
  expect(next.groupIdsByOwner.get("peer")).toEqual([1]);
});

test("committed transitions survive one coalesced patch in truthful order", () => {
  const initial = apply(createInitialTraceState(), snapshot());
  const next = apply(initial, batch(1, [{
    type: "machine:transition",
    records: [transition(1), transition(2), transition(3)],
  }]));

  expect(next.transitions.map((item) => item.order)).toEqual([1, 2, 3]);
  expect(next.transitions.map((item) => `${item.from_state}->${item.to_state}`)).toEqual([
    "new->starting", "starting->active", "active->closed",
  ]);
  expect(next.machinesById.get("peer")?.revision).toBe(3);
});

test("transition reset and replacement snapshot enforce the advertised bound", () => {
  let state = apply(createInitialTraceState(), {
    event: "trace:snapshot",
    data: {
      ...(snapshot().data as Record<string, unknown>),
      transition_journal_limit: 2,
      transitions: [transition(1), transition(2)],
    },
  });
  state = apply(state, batch(1, [{
    type: "machine:transition", records: [transition(3)],
  }]));
  expect(state.transitions.map((item) => item.order)).toEqual([2, 3]);

  state = apply(state, batch(2, [{
    type: "machine:transition", reset: true,
    records: [transition(8, 2), transition(9, 3)],
  }]));
  expect(state.transitions.map((item) => item.order)).toEqual([8, 9]);

  state = apply(state, {
    event: "trace:snapshot",
    data: {
      ...(snapshot().data as Record<string, unknown>), snapshot_sequence: 20,
      transition_journal_limit: 2, transitions: [transition(20, 1)],
    },
  });
  expect(state.transitions.map((item) => item.order)).toEqual([20]);
  expect(state.resyncRequired).toBe(false);
});

test("schema-2 snapshot replaces every live normalized collection", () => {
  let state = apply(createInitialTraceState(), snapshot([group(1, 1)]));
  state = apply(state, batch(1, [{ type: "control:upsert", records: [{
    handle_id: "stop", trace_id: "trace", owner_entity_id: "peer",
    owner_epoch: 1, name: "Stop", cancelable: true, revision: 1,
  }] }]));
  state = apply(state, {
    event: "trace:snapshot",
    data: {
      schema: 2, trace_id: "trace", snapshot_sequence: 9,
      machines: [], controls: [], groups: [group(2, 1)], facets: [],
      operation_strings: {}, diagnostics: {},
    },
  });

  expect([...state.machinesById]).toEqual([]);
  expect([...state.controlsById]).toEqual([]);
  expect([...state.groupsById.keys()]).toEqual([2]);
  expect(state.sequence).toBe(9);
  expect(state.resyncRequired).toBe(false);
});

test("a sequence gap requests one explicit resync and blocks patches until snapshot", () => {
  const initial = apply(createInitialTraceState(), snapshot());
  const gap = apply(initial, batch(2, [{ type: "group:upsert", records: [group(1, 1)] }]));
  const ignored = apply(gap, batch(3, [{ type: "group:upsert", records: [group(1, 2)] }]));

  expect(gap.resyncRequired).toBe(true);
  expect(gap.resyncReason).toContain("sequence_gap");
  expect(gap.resyncRequestVersion).toBe(1);
  expect(gap.groupsById.size).toBe(0);
  expect(ignored).toBe(gap);
});

test("stale revisions and duplicate batches cannot overwrite current values", () => {
  let state = apply(createInitialTraceState(), snapshot([group(1, 4, 4)]));
  state = apply(state, batch(1, [{ type: "group:upsert", records: [group(1, 3, 99)] }]));
  const duplicate = apply(state, batch(1, [{ type: "group:upsert", records: [group(1, 5, 99)] }]));

  expect(state.groupsById.get(1)?.calls).toBe(4);
  expect(duplicate).toBe(state);
});

test("a group counter patch changes values without changing topology", () => {
  const initial = apply(createInitialTraceState(), snapshot([group(1, 1, 1)]));
  const next = apply(initial, batch(1, [{ type: "group:upsert", records: [group(1, 2, 2)] }]));

  expect(next.groupsById.get(1)?.calls).toBe(2);
  expect(next.topologyVersion).toBe(initial.topologyVersion);
  expect(next.valueVersion).toBe(initial.valueVersion + 1);
  expect(next.groupIdsByOwner).toBe(initial.groupIdsByOwner);
});

test("operation timing and outcome aggregates survive snapshot and patch reduction", () => {
  const timed = {
    ...group(1, 1, 4),
    in_flight: 1,
    successes: 2,
    errors: 1,
    cancellations: 0,
    average_duration_ms: 2.5,
    min_duration_ms: 1,
    max_duration_ms: 6,
    total_worker_ms: 8,
    total_queue_ms: 2,
  };
  let state = apply(createInitialTraceState(), snapshot([timed]));
  expect(state.groupsById.get(1)).toMatchObject({
    successes: 2, errors: 1, cancellations: 0,
    average_duration_ms: 2.5, min_duration_ms: 1, max_duration_ms: 6,
    total_worker_ms: 8, total_queue_ms: 2,
  });

  state = apply(state, batch(1, [{ type: "group:upsert", records: [{
    ...timed, revision: 2, calls: 5, successes: 3,
    total_worker_ms: 10, total_queue_ms: 3,
  }] }]));
  expect(state.groupsById.get(1)).toMatchObject({
    calls: 5, successes: 3, total_worker_ms: 10, total_queue_ms: 3,
  });
});

test("removals retain bounded normalized records and reject stale resurrection", () => {
  let state = apply(createInitialTraceState(), snapshot([group(0, 2)]));
  let sequence = 0;
  state = apply(state, batch(++sequence, [{ type: "group:remove", ids: [0] }]));
  state = apply(state, batch(++sequence, [{ type: "group:upsert", records: [group(0, 2, 200)] }]));
  expect(state.groupsById.has(0)).toBe(false);
  expect(state.groupArchive.recordsById.get("0")?.revision).toBe(2);

  for (let id = 1; id <= NORMALIZED_ARCHIVE_LIMIT + 8; id += 1) {
    state = apply(state, batch(++sequence, [{ type: "group:upsert", records: [group(id, 1)] }]));
    state = apply(state, batch(++sequence, [{ type: "group:remove", ids: [id] }]));
  }
  expect(state.groupArchive.order).toHaveLength(NORMALIZED_ARCHIVE_LIMIT);
  expect(state.groupArchive.recordsById.size).toBe(NORMALIZED_ARCHIVE_LIMIT);
  expect(state.groupArchive.recordsById.has("0")).toBe(false);
});

test("a newer owner epoch can replace an archived low-epoch facet", () => {
  let state = apply(createInitialTraceState(), snapshot());
  state = apply(state, batch(1, [{ type: "state:upsert", records: [{
    facet_id: "peer.ready", owner_entity_id: "peer", owner_epoch: 1,
    value: false, revision: 50,
  }] }]));
  state = apply(state, batch(2, [{ type: "state:remove", ids: ["peer.ready"] }]));
  state = apply(state, batch(3, [{ type: "state:upsert", records: [{
    facet_id: "peer.ready", owner_entity_id: "peer", owner_epoch: 2,
    value: true, revision: 1,
  }] }]));
  expect(state.facetsById.get("peer.ready")?.owner_epoch).toBe(2);
  expect(state.facetsById.get("peer.ready")?.value).toBe(true);
});

test("capture removals keep the normalized capture map bounded", () => {
  let state = apply(createInitialTraceState(), snapshot());
  state = apply(state, batch(1, [{ type: "capture:upsert", records: [{
    record_id: 1, capture_id: 1, selector_kind: "operation", selector_value: 7,
    operation_id: 7, operation: "peer.tick", owner_entity_id: "peer",
    started_ns: 1, finished_ns: 2, duration_ms: 0.001, outcome: "success",
    failure_class: null, revision: 2, diagnostic_capture: true,
  }] }]));
  state = apply(state, batch(2, [{ type: "capture:remove", ids: [1] }]));
  expect(state.capturesById.size).toBe(0);
});
