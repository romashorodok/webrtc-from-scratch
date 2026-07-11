import { expect, test } from "bun:test";
import {
  applyTraceEvents,
  applyTraceSummaryEvents,
  createInitialTraceState,
  formatTraceExport,
  reduceTraceState,
  restoreVisibleTraceParents,
  type TraceRecord,
  type TraceSummary,
} from "./trace";

function traceRecord(traceId: string, parentId: string | null = null): TraceRecord {
  return {
    trace_id: traceId,
    parent_id: parentId,
    name: traceId,
    kind: "task",
    created_at: traceId === "parent" ? 0 : 1,
    started_at: null,
    ended_at: null,
    duration_ms: null,
    status: "completed",
    error: null,
    metadata: { archived_trace: true, deleted_target: traceId !== "parent" },
  };
}

function traceSummary(summaryId: string, deletedAt: number): TraceSummary {
  const parent = traceRecord("parent");
  const child = traceRecord(summaryId, parent.trace_id);
  return {
    summary_id: summaryId,
    aggregate_key: "peer|group|name|task",
    group_key: "group",
    name: "name",
    kind: "task",
    status: "completed",
    error: null,
    avg_duration_ms: deletedAt,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: summaryId,
    deleted_trace_ids: [summaryId],
    deleted_trace: child,
    archived_traces: [parent, child],
    deleted_at: deletedAt,
  };
}

function liveTraceRecord(
  traceId: string,
  parentId: string | null,
  options: Partial<TraceRecord> = {},
): TraceRecord {
  return {
    ...traceRecord(traceId, parentId),
    created_at: options.created_at ?? 0,
    started_at: options.started_at ?? null,
    ended_at: options.ended_at ?? null,
    duration_ms: options.duration_ms ?? null,
    status: options.status ?? "running",
    metadata: options.metadata ?? {},
    transitions: options.transitions,
    ...options,
    trace_id: traceId,
    parent_id: parentId,
  };
}

function peerContextTraceTree() {
  return [
    liveTraceRecord("peer", null, {
      name: "PeerContext-peer",
      kind: "peer",
      created_at: 0,
      started_at: 0.1,
      status: "running",
      transitions: [
        { at: 0, event: "created", status: "created", duration_ms: 0 },
        { at: 0.1, event: "started", status: "running", duration_ms: 0 },
      ],
    }),
    liveTraceRecord("av1", "peer", {
      name: "ws:av1-write-loop",
      kind: "media",
      created_at: 1,
    }),
    liveTraceRecord("rtcp", "av1", {
      name: "ws:rtcp-handler",
      kind: "media",
      created_at: 2,
    }),
    liveTraceRecord("srtp", "av1", {
      name: "srtp:encrypt-rtp-packets",
      kind: "thread",
      created_at: 3,
      metadata: { call_count: 2189, avg_duration_ms: 4.011 },
    }),
    liveTraceRecord("ice", "av1", {
      name: "ice:send-rtp-packets",
      kind: "thread",
      created_at: 4,
      metadata: { call_count: 3154, avg_duration_ms: 5.23 },
    }),
    liveTraceRecord("rtcp-srtp", "rtcp", {
      name: "srtp:decrypt-rtcp-packets",
      kind: "thread",
      created_at: 5,
      status: "created",
    }),
    liveTraceRecord("ice-check", "rtcp", {
      name: "ice:consent-check",
      kind: "thread",
      created_at: 6,
      status: "cancelled",
      duration_ms: 12,
    }),
  ];
}

test("appends deleted summaries with distinct archive ids", () => {
  const first = traceSummary("trace-a", 1);
  const second = traceSummary("trace-b", 2);

  const summaries = applyTraceSummaryEvents([], [
    { event: "trace:summary", data: { summaries: [first] } },
    { event: "trace:summary", data: { summaries: [second] } },
  ]);

  expect(summaries.map((summary) => summary.summary_id)).toEqual(["trace-b", "trace-a"]);
});

test("keeps a bounded live performance feed and resets it with a trace snapshot", () => {
  let state = createInitialTraceState();
  state = reduceTraceState(state, {
    type: "events",
    events: Array.from({ length: 162 }, (_, index) => ({
      event: "trace:performance",
      data: {
        performance: {
          name: "srtp.rtp_decrypt.completed",
          timestamp: index,
          duration_ms: 0.2,
          metadata: { sequence_number: index },
        },
      },
    })),
  });

  expect(state.performanceEvents).toHaveLength(160);
  expect(state.performanceEvents[0]?.metadata.sequence_number).toBe(2);

  state = reduceTraceState(state, {
    type: "events",
    events: [{ event: "trace:init", data: { traces: [] } }],
  });
  expect(state.performanceEvents).toEqual([]);
});

test("keeps deleted summaries across duplicate summary and delete events", () => {
  const summary = traceSummary("trace-a", 1);

  const summaries = applyTraceSummaryEvents([summary], [
    { event: "trace:summary", data: { summaries: [summary] } },
    { event: "trace:delete", data: { trace_ids: ["trace-a"] } },
    { event: "trace:delete", data: { trace_ids: ["trace-a"] } },
  ]);

  expect(summaries).toHaveLength(1);
  expect(summaries[0]?.summary_id).toBe("trace-a");
});

test("deleting a parent removes only explicitly deleted ids from live state", () => {
  const root = traceRecord("root");
  const parent = traceRecord("parent", "root");
  const child = traceRecord("child", "parent");
  const grandchild = traceRecord("grandchild", "child");

  const traces = applyTraceEvents([root, parent, child, grandchild], [
    { event: "trace:delete", data: { trace_ids: ["parent"] } },
  ]);

  expect(traces.map((trace) => trace.trace_id)).toEqual(["root", "child", "grandchild"]);
});

test("late updates for deleted descendants do not reappear as roots", () => {
  const root = traceRecord("root");
  const parent = traceRecord("parent", "root");
  const child = traceRecord("child", "parent");
  const deletedTraceIds = new Set<string>();

  const traces = applyTraceEvents(
    [root, parent, child],
    [{ event: "trace:delete", data: { trace_ids: ["parent"] } }],
    { deletedTraceIds },
  );
  const afterLateUpdate = applyTraceEvents(
    traces,
    [
      {
        event: "trace:update",
        data: {
          trace: {
            ...child,
            status: "running",
            duration_ms: 10,
          },
        },
      },
    ],
    { deletedTraceIds },
  );

  expect(afterLateUpdate.map((trace) => trace.trace_id)).toEqual(["root"]);
});

test("trace state reducer keeps archive frozen after delete despite late updates", () => {
  const peer = {
    ...traceRecord("peer"),
    name: "PeerContext-peer",
    kind: "peer",
    created_at: 0,
    status: "running",
    metadata: {},
  };
  const av1 = {
    ...traceRecord("av1", "peer"),
    name: "ws:av1-write-loop",
    kind: "media",
    created_at: 1,
    status: "running",
    metadata: {},
  };
  const srtp = {
    ...traceRecord("srtp", "av1"),
    name: "srtp:encrypt-rtp-packets",
    kind: "thread",
    created_at: 2,
    status: "running",
    metadata: { call_count: 2189, avg_duration_ms: 4.011 },
  };
  const ice = {
    ...traceRecord("ice", "av1"),
    name: "ice:send-rtp-packets",
    kind: "thread",
    created_at: 3,
    status: "running",
    metadata: { call_count: 3154, avg_duration_ms: 5.23 },
  };
  const summary: TraceSummary = {
    summary_id: "av1",
    group_key: "ws:av1-write-loop",
    name: "ws:av1-write-loop",
    kind: "media",
    status: "running",
    error: null,
    avg_duration_ms: 1,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: "av1",
    deleted_trace_ids: ["av1"],
    deleted_trace: av1,
    deleted_at: 10,
  };

  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces: [peer, av1, srtp, ice] },
    {
      type: "events",
      events: [
        { event: "trace:summary", data: { summaries: [summary] } },
        { event: "trace:delete", data: { trace_ids: ["av1"] } },
      ],
    },
  );
  const afterLateUpdate = reduceTraceState(deleted, {
    type: "events",
    events: [
      {
        event: "trace:update",
        data: {
          trace: {
            ...ice,
            metadata: { call_count: 3155, avg_duration_ms: 5.2 },
          },
        },
      },
    ],
  });
  const archived = afterLateUpdate.summaries[0]?.archived_traces ?? [];
  const output = formatTraceExport(archived, {
    compact: true,
    summary: afterLateUpdate.summaries[0],
  });

  expect(afterLateUpdate.traces.map((trace) => trace.trace_id)).toEqual(["peer", "srtp"]);
  expect(archived).toEqual([]);
  expect(output).toContain("trace_count=0 root_count=0");
  expect(output).toContain("- no traces");
});

test("trace state reducer does not backfill archived traces into pre-existing summaries", () => {
  const peer = {
    ...traceRecord("peer"),
    name: "PeerContext-peer",
    kind: "peer",
    created_at: 0,
    status: "running",
    metadata: {},
  };
  const av1 = {
    ...traceRecord("av1", "peer"),
    name: "ws:av1-write-loop",
    kind: "media",
    created_at: 1,
    status: "running",
    metadata: {},
  };
  const srtp = {
    ...traceRecord("srtp", "av1"),
    name: "srtp:encrypt-rtp-packets",
    kind: "thread",
    created_at: 2,
    status: "running",
    metadata: { call_count: 2189, avg_duration_ms: 4.011 },
  };
  const ice = {
    ...traceRecord("ice", "av1"),
    name: "ice:send-rtp-packets",
    kind: "thread",
    created_at: 3,
    status: "running",
    metadata: { call_count: 3154, avg_duration_ms: 5.23 },
  };
  const summary: TraceSummary = {
    summary_id: "peer",
    group_key: "PeerContext-peer",
    name: "PeerContext-peer",
    kind: "peer",
    status: "running",
    error: null,
    avg_duration_ms: 1,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: "peer",
    deleted_trace_ids: ["peer"],
    deleted_trace: peer,
    deleted_at: 10,
  };

  const state = reduceTraceState(
    { ...createInitialTraceState(), traces: [peer, av1, srtp, ice] },
    {
      type: "events",
      events: [
        { event: "trace:summary", data: { summaries: [summary] } },
        { event: "trace:delete", data: { trace_ids: ["peer", "av1", "srtp", "ice"] } },
      ],
    },
  );
  const archived = state.summaries[0]?.archived_traces ?? [];
  const output = formatTraceExport(archived, {
    compact: true,
    summary: state.summaries[0],
  });

  expect(state.traces).toEqual([]);
  expect(archived).toEqual([]);
  expect(output).toContain("view=deleted");
  expect(output).toContain("trace_count=0 root_count=0");
});

test("trace state reducer synthesizes a deleted PeerContext summary without backend summary", () => {
  const traces = peerContextTraceTree();

  const state = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const summary = state.summaries[0];
  const archived = summary?.archived_traces ?? [];
  const output = formatTraceExport(archived, {
    compact: true,
    summary,
  });

  expect(state.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "ice",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(state.summaries).toHaveLength(1);
  expect(summary?.deleted_trace_id).toBe("peer");
  expect(new Set(summary?.deleted_trace_ids)).toEqual(
    new Set(traces.map((trace) => trace.trace_id)),
  );
  expect(archived.map((trace) => trace.trace_id)).toEqual(
    traces.map((trace) => trace.trace_id),
  );
  expect(archived.find((trace) => trace.trace_id === "peer")?.status).toBe("running");
  expect(archived.find((trace) => trace.trace_id === "rtcp-srtp")?.status).toBe("created");
  expect(archived.find((trace) => trace.trace_id === "ice-check")?.status).toBe("cancelled");
  expect(archived.find((trace) => trace.trace_id === "ice")?.metadata).toMatchObject({
    call_count: 3154,
    avg_duration_ms: 5.23,
  });
  expect(output).toContain("view=deleted");
  expect(output).toContain("trace_count=7 root_count=1");
  expect(output).toContain("- PeerContext-peer [running] peer running");
  expect(output).toContain("  - ws:av1-write-loop [running] media running");
  expect(output).toContain("    - ice:send-rtp-packets [running] thread 3154 calls avg=5.23ms");
});

test("trace state reducer keeps synthesized archive when a delayed summary arrives", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const backendSummary: TraceSummary = {
    summary_id: "peer",
    aggregate_key: "peer|PeerContext-peer|PeerContext-peer|peer",
    group_key: "PeerContext-peer",
    name: "PeerContext-peer",
    kind: "peer",
    status: "completed",
    error: null,
    avg_duration_ms: 42,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: "peer",
    deleted_trace_ids: ["peer"],
    deleted_trace: {
      ...traces[0]!,
      status: "completed",
      ended_at: 10,
      duration_ms: 9900,
    },
    deleted_at: 10,
  };

  const merged = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:summary", data: { summaries: [backendSummary] } }],
  });
  const summary = merged.summaries[0];
  const archived = summary?.archived_traces ?? [];

  expect(merged.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "ice",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(merged.summaries).toHaveLength(1);
  expect(summary?.status).toBe("completed");
  expect(summary?.avg_duration_ms).toBe(42);
  expect(summary?.deleted_trace?.status).toBe("completed");
  expect(new Set(summary?.deleted_trace_ids)).toEqual(
    new Set(traces.map((trace) => trace.trace_id)),
  );
  expect(archived.map((trace) => trace.trace_id)).toEqual(
    traces.map((trace) => trace.trace_id),
  );
});

test("trace state reducer keeps deleted summaries after later trace init events", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const backendSummary: TraceSummary = {
    summary_id: "peer",
    aggregate_key: "peer|PeerContext-peer|PeerContext-peer|peer",
    group_key: "PeerContext-peer",
    name: "PeerContext-peer",
    kind: "peer",
    status: "running",
    error: null,
    avg_duration_ms: 42,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: "peer",
    deleted_trace_ids: traces.map((trace) => trace.trace_id),
    deleted_trace: traces[0],
    archived_traces: traces,
    deleted_at: 10,
  };
  const lateTrace = liveTraceRecord("late", null, {
    name: "post-delete-trace",
    kind: "task",
  });

  const afterLateInit = reduceTraceState(deleted, {
    type: "events",
    events: [
      { event: "trace:summary", data: { summaries: [backendSummary] } },
      { event: "trace:init", data: { trace: lateTrace } },
      { event: "trace:update", data: { trace: lateTrace } },
    ],
  });
  const summary = afterLateInit.summaries.find((item) => item.summary_id === "peer");
  const output = formatTraceExport(summary?.archived_traces ?? [], {
    compact: true,
    summary,
  });

  expect(afterLateInit.summaries).toHaveLength(1);
  expect(summary?.archived_traces?.map((trace) => trace.trace_id)).toEqual(
    traces.map((trace) => trace.trace_id),
  );
  expect(output).toContain("view=deleted");
  expect(output).toContain("trace_count=7 root_count=1");
});

test("trace state reducer does not restore deleted root when late heartbeat arrives", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const lateIceUpdate = {
    ...traces.find((trace) => trace.trace_id === "ice")!,
    status: "running",
    ended_at: null,
    duration_ms: 7000,
  };

  const afterLateUpdate = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { trace: lateIceUpdate } }],
  });

  expect(afterLateUpdate.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(afterLateUpdate.summaries[0]?.archived_traces?.map((trace) => trace.trace_id)).toEqual(
    traces.map((trace) => trace.trace_id),
  );
  expect(
    afterLateUpdate.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "ice")
      ?.duration_ms,
  ).toBeNull();
  expect(
    afterLateUpdate.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "ice")
      ?.metadata,
  ).toMatchObject({ archived_trace: true, deleted_target: true });
});

test("trace state reducer keeps deleted archive snapshot frozen on heartbeat batch", () => {
  const traces = peerContextTraceTree().map((trace) =>
    trace.trace_id === "peer"
      ? { ...trace, duration_ms: 100 }
      : trace.trace_id === "ice"
        ? { ...trace, duration_ms: 100 }
        : trace,
  );
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const peerHeartbeat = {
    ...traces.find((trace) => trace.trace_id === "peer")!,
    status: "running",
    duration_ms: 15000,
  };
  const iceHeartbeat = {
    ...traces.find((trace) => trace.trace_id === "ice")!,
    status: "running",
    duration_ms: 7000,
    metadata: { call_count: 400, avg_duration_ms: 3.5 },
  };

  const restored = reduceTraceState(deleted, {
    type: "events",
    events: [
      { event: "trace:update", data: { trace: peerHeartbeat } },
      { event: "trace:update", data: { trace: iceHeartbeat } },
    ],
  });

  expect(restored.traces.find((trace) => trace.trace_id === "peer")).toBeUndefined();
  expect(
    restored.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "peer")
      ?.duration_ms,
  ).toBe(100);
  expect(
    restored.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "ice")
      ?.duration_ms,
  ).toBe(100);
  expect(
    restored.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "ice")
      ?.metadata,
  ).toMatchObject({
    call_count: 3154,
    avg_duration_ms: 5.23,
  });
});

test("trace state reducer ignores stale delayed summaries", () => {
  const traces = peerContextTraceTree().map((trace) =>
    trace.trace_id === "peer" ? { ...trace, duration_ms: 100 } : trace,
  );
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const heartbeatPeer = {
    ...traces.find((trace) => trace.trace_id === "peer")!,
    duration_ms: 15000,
  };
  const afterHeartbeat = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { trace: heartbeatPeer } }],
  });
  const staleSummary: TraceSummary = {
    ...afterHeartbeat.summaries[0]!,
    avg_duration_ms: 100,
    deleted_trace: {
      ...heartbeatPeer,
      duration_ms: 100,
      metadata: { archived_trace: true, deleted_target: true, deleted_at: 10 },
    },
    archived_traces: afterHeartbeat.summaries[0]!.archived_traces?.map((trace) =>
      trace.trace_id === "peer" ? { ...trace, duration_ms: 100 } : trace,
    ),
  };

  const afterStaleSummary = reduceTraceState(afterHeartbeat, {
    type: "events",
    events: [{ event: "trace:summary", data: { summaries: [staleSummary] } }],
  });

  expect(
    afterStaleSummary.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "peer")
      ?.duration_ms,
  ).toBe(100);
  expect(afterStaleSummary.summaries[0]?.deleted_trace?.duration_ms).toBe(100);
  expect(afterStaleSummary.traces.find((trace) => trace.trace_id === "peer")).toBeUndefined();
});

test("trace state reducer ignores terminal updates for deleted traces", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const heartbeatPeer = {
    ...traces.find((trace) => trace.trace_id === "peer")!,
    duration_ms: 15000,
  };
  const terminalPeer = {
    ...heartbeatPeer,
    status: "completed",
    ended_at: 20,
    duration_ms: 16000,
  };

  const afterTerminal = reduceTraceState(deleted, {
    type: "events",
    events: [
      { event: "trace:update", data: { trace: heartbeatPeer } },
      { event: "trace:complete", data: { trace: terminalPeer } },
    ],
  });

  expect(afterTerminal.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "ice",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(
    afterTerminal.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "peer")
      ?.status,
  ).toBe("running");
  expect(
    afterTerminal.summaries[0]?.archived_traces?.find((trace) => trace.trace_id === "peer")
      ?.duration_ms,
  ).toBeNull();
  expect(afterTerminal.summaries[0]?.deleted_trace?.status).toBe("running");
});

test("trace state reducer keeps live unchanged for completed late descendant updates", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const completedIceUpdate = {
    ...traces.find((trace) => trace.trace_id === "ice")!,
    status: "completed",
    ended_at: 11,
    duration_ms: 7000,
  };

  const afterLateUpdate = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { trace: completedIceUpdate } }],
  });

  expect(afterLateUpdate.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(afterLateUpdate.summaries[0]?.archived_traces?.map((trace) => trace.trace_id)).toEqual(
    traces.map((trace) => trace.trace_id),
  );
});

test("trace state reducer blocks resurrection from late running children", () => {
  const traces = peerContextTraceTree();
  const deleted = reduceTraceState(
    { ...createInitialTraceState(), traces },
    {
      type: "events",
      events: [{ event: "trace:delete", data: { trace_id: "peer" } }],
    },
  );
  const completedParent = liveTraceRecord("late-parent", "peer", {
    name: "completed-parent",
    status: "completed",
    ended_at: 11,
    duration_ms: 5,
  });
  const runningChild = liveTraceRecord("late-child", "late-parent", {
    name: "running-child",
    created_at: 7,
    status: "running",
    duration_ms: 10,
  });

  const afterCompletedParent = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { trace: completedParent } }],
  });
  const afterRunningChild = reduceTraceState(afterCompletedParent, {
    type: "events",
    events: [{ event: "trace:update", data: { trace: runningChild } }],
  });

  expect(afterCompletedParent.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "ice",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(afterCompletedParent.summaries[0]?.archived_traces?.some(
    (trace) => trace.trace_id === "late-parent",
  )).toBe(false);
  expect(afterRunningChild.traces.map((trace) => trace.trace_id)).toEqual([
    "av1",
    "rtcp",
    "srtp",
    "ice",
    "rtcp-srtp",
    "ice-check",
  ]);
  expect(afterRunningChild.traces.find((trace) => trace.trace_id === "late-child")).toBeUndefined();
  expect(afterRunningChild.summaries[0]?.archived_traces?.some(
    (trace) => trace.trace_id === "late-child",
  )).toBe(false);
});

test("restores visible parent links through hidden completed ancestors", () => {
  const peer = liveTraceRecord("peer", null, {
    name: "PeerContext-peer",
    status: "running",
  });
  const runningController = liveTraceRecord("controller", "completed-pair", {
    name: "ice:candidate-pair-controller",
    status: "running",
  });
  const runningDtls = liveTraceRecord("dtls-loop", "completed-handshake", {
    name: "dtls:rtp-receive-loop",
    status: "running",
  });
  const summary: TraceSummary = {
    summary_id: "peer",
    group_key: "PeerContext-peer",
    name: "PeerContext-peer",
    kind: "peer",
    status: "running",
    error: null,
    avg_duration_ms: 1,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: "peer",
    deleted_trace_ids: ["peer"],
    deleted_trace: peer,
    archived_traces: [
      peer,
      liveTraceRecord("completed-pair", "peer", {
        name: "ice:add-candidate-pair",
        status: "completed",
      }),
      runningController,
      liveTraceRecord("completed-event", "controller", {
        name: "event:nominate-transport",
        status: "completed",
      }),
      liveTraceRecord("completed-handshake", "completed-event", {
        name: "dtls:handshake",
        status: "completed",
      }),
      runningDtls,
    ],
    deleted_at: 1,
  };
  const visible = restoreVisibleTraceParents(
    [
      peer,
      { ...runningController, parent_id: null },
      { ...runningDtls, parent_id: null },
    ],
    [summary],
  );

  expect(visible.find((trace) => trace.trace_id === "controller")?.parent_id).toBe("peer");
  expect(visible.find((trace) => trace.trace_id === "dtls-loop")?.parent_id).toBe("controller");
});

test("trace update replaces a running record with live duration", () => {
  const root = liveTraceRecord("peer", null, {
    name: "PeerContext-peer",
    kind: "peer",
    status: "running",
    duration_ms: null,
  });
  const updated = {
    ...root,
    duration_ms: 125.5,
  };

  const traces = applyTraceEvents([root], [
    { event: "trace:update", data: { trace: updated } },
  ]);

  expect(traces).toHaveLength(1);
  expect(traces[0]?.trace_id).toBe("peer");
  expect(traces[0]?.status).toBe("running");
  expect(traces[0]?.duration_ms).toBe(125.5);
});

test("trace state reducer applies large batched heartbeat updates", () => {
  const traces = Array.from({ length: 10000 }, (_, index) =>
    liveTraceRecord(`trace-${index}`, null, {
      created_at: index,
      duration_ms: 1,
      status: "running",
    }),
  );
  const updates = traces.map((trace, index) => ({
    ...trace,
    duration_ms: 1000 + index,
  }));

  const initialized = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{ event: "trace:init", data: { traces } }],
  });
  const updated = reduceTraceState(initialized, {
    type: "events",
    events: [{ event: "trace:update", data: { traces: updates } }],
  });

  expect(updated.traces).toHaveLength(10000);
  expect(updated.tracesById.size).toBe(10000);
  expect(updated.traceOrder).toHaveLength(10000);
  expect(updated.tracesById.get("trace-9999")?.duration_ms).toBe(10999);
});

test("trace state reducer ignores unchanged sparse heartbeat batches", () => {
  const trace = liveTraceRecord("running", null, {
    created_at: 1,
    started_at: 1,
    duration_ms: null,
    status: "running",
  });
  const initialized = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{ event: "trace:init", data: { traces: [trace] } }],
  });
  const heartbeat = {
    ...trace,
    transitions: undefined,
  };
  const updated = reduceTraceState(initialized, {
    type: "events",
    events: [{ event: "trace:update", data: { traces: [heartbeat] } }],
  });

  expect(updated).toBe(initialized);
});

test("compact export shows elapsed duration for running peer context", () => {
  const root = liveTraceRecord("peer", null, {
    name: "PeerContext-peer",
    kind: "peer",
    status: "running",
    duration_ms: 250,
  });

  const output = formatTraceExport([root], { compact: true });

  expect(output).toContain("- PeerContext-peer [running] peer 250ms");
  expect(output).not.toContain("- PeerContext-peer [running] peer running");
});

test("trace state reducer synthesizes deleted roots in every lifecycle state", () => {
  for (const status of ["created", "running", "completed", "failed", "cancelled"] as const) {
    const root = liveTraceRecord(`peer-${status}`, null, {
      name: `PeerContext-${status}`,
      kind: "peer",
      status,
      error: status === "failed" ? "root failed" : null,
      duration_ms: status === "completed" || status === "cancelled" ? 10 : null,
    });

    const state = reduceTraceState(
      { ...createInitialTraceState(), traces: [root] },
      {
        type: "events",
        events: [{ event: "trace:delete", data: { trace_id: root.trace_id } }],
      },
    );

    expect(state.traces).toEqual([]);
    expect(state.summaries[0]?.deleted_trace_id).toBe(root.trace_id);
    expect(state.summaries[0]?.deleted_trace?.status).toBe(status);
    expect(state.summaries[0]?.archived_traces?.[0]?.status).toBe(status);
  }
});

test("preserves archived parent ids for tree reconstruction", () => {
  const summary = traceSummary("child", 1);
  const summaries = applyTraceSummaryEvents([], [
    { event: "trace:summary", data: { summaries: [summary] } },
  ]);

  const archived = summaries[0]?.archived_traces ?? [];
  const child = archived.find((trace) => trace.trace_id === "child");
  expect(child?.parent_id).toBe("parent");
});

test("formats a deterministic trace tree with indentation", () => {
  const parent = {
    ...traceRecord("parent"),
    metadata: { phase: "offer" },
    transitions: [
      { at: 0, event: "created", status: "created", duration_ms: 0 },
      { at: 1, event: "started", status: "running", duration_ms: 0 },
    ],
  };
  const child = {
    ...traceRecord("child", "parent"),
    created_at: 2,
    duration_ms: 12.4,
    transitions: [
      { at: 2, event: "created", status: "created", duration_ms: 0 },
      { at: 3, event: "completed", status: "completed", duration_ms: 12.4 },
    ],
  };

  const output = formatTraceExport([child, parent]);

  expect(output).toContain("WEBRTC ASYNC RUNTIME TRACE\nview=live");
  expect(output).toContain("- parent id=parent parent=- kind=task status=completed");
  expect(output).toContain("  - child id=child parent=parent kind=task status=completed duration_ms=12.4");
  expect(output).toContain("metadata=phase=offer");
  expect(output).toContain("metadata=archived_trace=true deleted_target=true");
});

test("formats archived summaries as the selected deleted tree", () => {
  const summary = traceSummary("child", 5);
  const output = formatTraceExport(summary.archived_traces ?? [], { summary });
  const parentIndex = output.indexOf("- parent id=parent");
  const childIndex = output.indexOf("  - child id=child parent=parent");

  expect(output).toContain("view=deleted");
  expect(output).toContain("summary id=child deleted_trace_id=child deleted_at=5");
  expect(parentIndex).toBeGreaterThanOrEqual(0);
  expect(childIndex).toBeGreaterThan(parentIndex);
});

test("formats transition lines chronologically with status duration and error", () => {
  const trace: TraceRecord = {
    ...traceRecord("failing"),
    error: "ValueError: boom",
    transitions: [
      { at: 3, event: "failed", status: "failed", duration_ms: 22.5, error: "ValueError: boom" },
      { at: 1, event: "created", status: "created", duration_ms: 0 },
      { at: 2, event: "started", status: "running", duration_ms: 0 },
    ],
  };

  const output = formatTraceExport([trace]);
  const createdIndex = output.indexOf("event=created at=1 status=created duration_ms=0");
  const startedIndex = output.indexOf("event=started at=2 status=running duration_ms=0");
  const failedIndex = output.indexOf(
    'event=failed at=3 status=failed duration_ms=22.5 error="ValueError: boom"',
  );

  expect(createdIndex).toBeGreaterThanOrEqual(0);
  expect(startedIndex).toBeGreaterThan(createdIndex);
  expect(failedIndex).toBeGreaterThan(startedIndex);
});

test("uses a snapshot transition when transition history is missing", () => {
  const trace = {
    ...traceRecord("snapshot"),
    created_at: 4,
    started_at: 5,
    ended_at: 6,
    duration_ms: 100,
  };

  const output = formatTraceExport([trace]);

  expect(output).toContain("event=snapshot at=6 status=completed duration_ms=100");
});

test("formats live running duration from backend heartbeat snapshot", () => {
  const trace: TraceRecord = {
    ...traceRecord("running"),
    created_at: 10,
    started_at: 12,
    duration_ms: 3000,
    status: "running",
  };

  const output = formatTraceExport([trace], { compact: true });

  expect(output).toContain("- running [running] task 3000ms");
});

test("formats compact export as grouped ui-style tree without details", () => {
  const trace: TraceRecord = {
    ...traceRecord("ui-group:parent:task:encode:3", "parent"),
    name: "encode",
    duration_ms: 30,
    metadata: {
      ui_group: true,
      call_count: 3,
      avg_duration_ms: 10,
    },
    transitions: [
      { at: 1, event: "grouped", status: "completed", duration_ms: 30 },
    ],
  };
  const parent = {
    ...traceRecord("parent"),
    name: "peer",
  };

  const output = formatTraceExport([parent, trace], { compact: true });

  expect(output).toContain("- peer [completed] task");
  expect(output).toContain("  - encode [completed] task 3 calls avg=10ms");
  expect(output).not.toContain("TRANSITIONS");
  expect(output).not.toContain("metadata=");
  expect(output).not.toContain("id=ui-group");
});

test("trace state reducer caps deleted summary retention", () => {
  let state = createInitialTraceState();
  const summaries = Array.from({ length: 520 }, (_, index): TraceSummary => ({
    summary_id: `summary-${index}`,
    group_key: `group-${index}`,
    name: `deleted-${index}`,
    kind: "task",
    avg_duration_ms: 1,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: 1,
    deleted_trace_id: `trace-${index}`,
    deleted_at: index,
  }));

  state = reduceTraceState(state, {
    type: "events",
    events: [{ event: "trace:summary", data: { summaries } }],
  });

  expect(state.summaries).toHaveLength(512);
  expect(state.summaries[0].summary_id).toBe("summary-519");
  expect(state.summaries.at(-1)?.summary_id).toBe("summary-8");
});
