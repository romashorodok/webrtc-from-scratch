import { parseJson } from "./media";

export type TraceStatus = "created" | "running" | "completed" | "failed" | "cancelled";

export type TraceTransition = {
  at: number;
  event: string;
  status: TraceStatus | string;
  duration_ms: number | null;
  error?: string | null;
};

export type TraceRecord = {
  trace_id: string;
  parent_id: string | null;
  name: string;
  kind: string;
  peer_id: string | null;
  created_at: number;
  started_at: number | null;
  ended_at: number | null;
  duration_ms: number | null;
  status: TraceStatus | string;
  error: string | null;
  metadata: Record<string, unknown>;
  transitions?: TraceTransition[];
};

export type TraceSummary = {
  summary_id: string;
  peer_id: string | null;
  aggregate_key?: string;
  group_key: string;
  name: string;
  kind: string;
  status?: TraceStatus | string;
  error?: string | null;
  avg_duration_ms: number;
  previous_avg_duration_ms: number | null;
  delta_avg_duration_ms: number | null;
  sample_count: number;
  deleted_trace_id: string;
  deleted_trace_ids?: string[];
  deleted_trace?: TraceRecord;
  archived_traces?: TraceRecord[];
  deleted_at: number;
};

type TracePayload = {
  trace?: TraceRecord;
  traces?: TraceRecord[];
  trace_id?: string;
  trace_ids?: string[];
  summary?: TraceSummary;
  summaries?: TraceSummary[];
  deleted_at?: number;
  peer_id?: string | null;
  success_retention_seconds?: number;
  auto_prune?: boolean;
};

export type TraceEventInput = {
  event: string;
  data: unknown;
};

export type TraceApplyOptions = {
  deletedTraceIds?: Set<string>;
  summaries?: TraceSummary[];
};

export type TraceExportOptions = {
  compact?: boolean;
  now?: number;
  summary?: TraceSummary | null;
  title?: string;
  view?: "live" | "deleted";
};

export type TraceState = {
  traces: TraceRecord[];
  summaries: TraceSummary[];
  deletedTraceIds: Set<string>;
  tracesById: Map<string, TraceRecord>;
  traceOrder: string[];
};

export type TraceStateAction = {
  type: "events";
  events: TraceEventInput[];
};

type ArchivedTraceTree = {
  deletedTraceId: string;
  deletedTraceIds: string[];
  archivedTraces: TraceRecord[];
  deletedAt: number;
  synthesizeSummary: boolean;
};

export function createInitialTraceState(): TraceState {
  return {
    traces: [],
    summaries: [],
    deletedTraceIds: new Set<string>(),
    tracesById: new Map<string, TraceRecord>(),
    traceOrder: [],
  };
}

export function reduceTraceState(
  state: TraceState,
  action: TraceStateAction,
): TraceState {
  const deletedTraceIds = new Set(state.deletedTraceIds);
  const archivedTrees = collectArchivedTreesForEvents(state.traces, action.events);
  const summaries = synthesizeArchivedSummaries(
    applyTraceSummaryEvents(state.summaries, action.events),
    archivedTrees,
  );
  const traces = applyTraceEvents(state.traces, action.events, {
    deletedTraceIds,
    summaries,
  });

  const unchanged =
    traces === state.traces &&
    summaries === state.summaries &&
    setsEqual(deletedTraceIds, state.deletedTraceIds);

  if (unchanged) {
    return state;
  }

  return {
    deletedTraceIds,
    summaries,
    traces,
    tracesById: new Map(traces.map((trace) => [trace.trace_id, trace])),
    traceOrder: traces.map((trace) => trace.trace_id),
  };
}

export function restoreVisibleTraceParents(
  traces: TraceRecord[],
  summaries: TraceSummary[],
): TraceRecord[] {
  if (traces.length === 0 || summaries.length === 0) {
    return traces;
  }

  const visibleIds = new Set(traces.map((trace) => trace.trace_id));
  const archivedById = new Map<string, TraceRecord>();
  for (const summary of summaries) {
    for (const trace of archivedTracesForSummary(summary)) {
      archivedById.set(trace.trace_id, trace);
    }
  }

  let changed = false;
  const restored = traces.map((trace) => {
    const archivedParentId = archivedById.get(trace.trace_id)?.parent_id;
    const parentId = nearestVisibleAncestorId(
      archivedParentId ?? trace.parent_id,
      archivedById,
      visibleIds,
    );
    if (parentId === trace.parent_id) {
      return trace;
    }

    changed = true;
    return {
      ...trace,
      parent_id: parentId,
    };
  });

  return changed ? restored : traces;
}

export function applyTraceEvents(
  previous: TraceRecord[],
  events: TraceEventInput[],
  options: TraceApplyOptions = {},
): TraceRecord[] {
  const records = new Map(previous.map((trace) => [trace.trace_id, trace]));
  const deletedTraceIds = options.deletedTraceIds;
  let changed = false;

  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }

    if (item.event === "trace:init" && Array.isArray(payload.traces)) {
      records.clear();
      deletedTraceIds?.clear();
      for (const trace of payload.traces) {
        records.set(trace.trace_id, trace);
      }
      changed = true;
      continue;
    }

    const deletedIds = deletedTraceIdsFromPayload(item.event, payload);
    if (deletedIds.length > 0) {
      changed = deleteLiveTraceIds(records, deletedIds, deletedTraceIds) || changed;
    }

    for (const trace of traceRecordsFromPayload(payload)) {
      if (isDeletedTrace(trace, records, deletedTraceIds)) {
        changed =
          deleteLiveTraceIds(records, [trace.trace_id], deletedTraceIds) || changed;
        continue;
      }
      changed = upsertLiveTraceRecord(records, trace) || changed;
    }
  }

  if (!changed) {
    return previous;
  }

  return [...records.values()].sort((a, b) => a.created_at - b.created_at);
}

function traceRecordsFromPayload(payload: TracePayload) {
  return [
    ...(payload.traces ?? []),
    ...(payload.trace ? [payload.trace] : []),
  ];
}

function upsertLiveTraceRecord(records: Map<string, TraceRecord>, incoming: TraceRecord) {
  const previous = records.get(incoming.trace_id);
  const next = previous ? latestTraceRecord(previous, incoming) : incoming;
  if (previous && traceRecordsEquivalent(previous, next)) {
    return false;
  }
  records.set(incoming.trace_id, next);
  return true;
}

function deletedTraceIdsFromPayload(event: string, payload: TracePayload) {
  const traceIds: string[] = [];

  if (event === "trace:delete") {
    traceIds.push(...(payload.trace_ids ?? (payload.trace_id ? [payload.trace_id] : [])));
  }

  return [...new Set(traceIds.filter(isString))];
}

function deleteLiveTraceIds(
  records: Map<string, TraceRecord>,
  traceIds: string[],
  deletedTraceIds: Set<string> | undefined,
) {
  let changed = false;
  for (const traceId of traceIds) {
    deletedTraceIds?.add(traceId);
    changed = records.delete(traceId) || changed;
  }
  return changed;
}

function deletedTraceIdsForSummary(summary: TraceSummary) {
  return summary.deleted_trace_ids && summary.deleted_trace_ids.length > 0
    ? summary.deleted_trace_ids
    : [summary.deleted_trace_id];
}

function collectArchivedTreesForEvents(
  traces: TraceRecord[],
  events: TraceEventInput[],
) {
  const records = new Map(traces.map((trace) => [trace.trace_id, trace]));
  const archives = new Map<string, ArchivedTraceTree>();

  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }

    if (item.event === "trace:init" && Array.isArray(payload.traces)) {
      records.clear();
      for (const trace of payload.traces) {
        records.set(trace.trace_id, trace);
      }
      continue;
    }

    if (item.event === "trace:delete") {
      if (payload.auto_prune === true) {
        const deletedIds = deletedTraceIdsFromPayload(item.event, payload);
        const deletedRootIds = deletedRootTraceIdsFromPayload(records, payload);
        for (const deletedId of deletedRootIds) {
          addArchivedTraceTree(archives, records, deletedId, {
            deletedAt: deletedAtForPayload(payload, records, deletedId),
            synthesizeSummary: true,
          });
        }
        for (const traceId of deletedIds) {
          records.delete(traceId);
        }
        continue;
      }
      const deletedIds = deletedTraceIdsFromPayload(item.event, payload);
      const deletedRootIds = deletedRootTraceIdsFromPayload(records, payload);
      const deletedSubtreeIds = collectTraceSubtreeIds(records, deletedIds);
      for (const deletedId of deletedRootIds) {
        addArchivedTraceTree(archives, records, deletedId, {
          deletedAt: deletedAtForPayload(payload, records, deletedId),
          synthesizeSummary: true,
        });
      }

      for (const traceId of deletedSubtreeIds) {
        records.delete(traceId);
      }
      continue;
    }

    if (item.event === "trace:summary") {
      for (const summary of payload.summaries ?? []) {
        addArchivedTraceTree(archives, records, summary.deleted_trace_id, {
          deletedAt: summary.deleted_at,
          synthesizeSummary: false,
        });
      }
      if (payload.summary) {
        addArchivedTraceTree(archives, records, payload.summary.deleted_trace_id, {
          deletedAt: payload.summary.deleted_at,
          synthesizeSummary: false,
        });
      }
    }

    for (const trace of traceRecordsFromPayload(payload)) {
      records.set(trace.trace_id, trace);
    }
  }

  return archives;
}

function addArchivedTraceTree(
  archives: Map<string, ArchivedTraceTree>,
  records: Map<string, TraceRecord>,
  deletedTraceId: string,
  options: {
    deletedAt: number;
    synthesizeSummary: boolean;
  },
) {
  const archive = collectTraceArchive(records, deletedTraceId);
  if (archive.length === 0) {
    return;
  }

  const previous = archives.get(deletedTraceId);
  const archivedTraces = mergeTraceRecords(previous?.archivedTraces ?? [], archive);
  const deletedTraceIds = uniqueValues([
    ...(previous?.deletedTraceIds ?? []),
    ...archivedTraces
      .filter((trace) => trace.metadata?.deleted_target === true)
      .map((trace) => trace.trace_id),
  ]);

  archives.set(deletedTraceId, {
    deletedTraceId,
    deletedTraceIds,
    archivedTraces,
    deletedAt: Math.max(previous?.deletedAt ?? 0, options.deletedAt),
    synthesizeSummary: (previous?.synthesizeSummary ?? false) || options.synthesizeSummary,
  });
}

function synthesizeArchivedSummaries(
  summaries: TraceSummary[],
  archivedTrees: Map<string, ArchivedTraceTree>,
) {
  const synthesized: TraceSummary[] = [];
  for (const archive of archivedTrees.values()) {
    if (!archive.synthesizeSummary || archive.archivedTraces.length === 0) {
      continue;
    }
    const existing = summaries.find((summary) =>
      summaryMatchesDeletedTraceId(summary, archive.deletedTraceId),
    );
    if (existing) {
      continue;
    }
    synthesized.push(createDeletedSummaryFromArchive(archive));
  }

  if (synthesized.length === 0) {
    return summaries;
  }

  return [...summaries, ...synthesized].sort((a, b) => b.deleted_at - a.deleted_at);
}

function createDeletedSummaryFromArchive(archive: ArchivedTraceTree): TraceSummary {
  const deletedTrace =
    archive.archivedTraces.find((trace) => trace.trace_id === archive.deletedTraceId) ??
    archive.archivedTraces.find((trace) => trace.metadata?.deleted_target === true) ??
    archive.archivedTraces[0];
  if (!deletedTrace) {
    throw new Error("cannot synthesize a deleted trace summary without archived traces");
  }
  const metadata = deletedTrace.metadata ?? {};
  const groupKey = String(metadata.group_key ?? deletedTrace.name);
  const avgDuration = durationForDeletedTrace(deletedTrace, archive.deletedAt);

  return {
    summary_id: archive.deletedTraceId,
    peer_id: deletedTrace.peer_id,
    aggregate_key: [
      deletedTrace.peer_id ?? "",
      groupKey,
      deletedTrace.name,
      deletedTrace.kind,
    ].join("|"),
    group_key: groupKey,
    name: deletedTrace.name,
    kind: deletedTrace.kind,
    status: deletedTrace.status,
    error: deletedTrace.error,
    avg_duration_ms: avgDuration,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: sampleCountForDeletedTrace(deletedTrace),
    deleted_trace_id: archive.deletedTraceId,
    deleted_trace_ids:
      archive.deletedTraceIds.length > 0 ? archive.deletedTraceIds : [archive.deletedTraceId],
    deleted_trace: deletedTrace,
    archived_traces: archive.archivedTraces,
    deleted_at: archive.deletedAt,
  };
}

function deletedRootTraceIdsFromPayload(
  records: Map<string, TraceRecord>,
  payload: TracePayload,
) {
  if (isString(payload.trace_id)) {
    return [payload.trace_id];
  }

  const deletedIds = deletedTraceIdsFromPayload("trace:delete", payload);
  const deletedIdSet = new Set(deletedIds);
  const rootIds = deletedIds.filter((traceId) => {
    const parentId = records.get(traceId)?.parent_id;
    return !parentId || !deletedIdSet.has(parentId);
  });
  return [...new Set(rootIds.length > 0 ? rootIds : deletedIds)];
}

function deletedAtForPayload(
  payload: TracePayload,
  records: Map<string, TraceRecord>,
  deletedTraceId: string,
) {
  if (typeof payload.deleted_at === "number" && Number.isFinite(payload.deleted_at)) {
    return payload.deleted_at;
  }

  const traceIds = collectTraceSubtreeIds(records, [deletedTraceId]);
  const timestamps = traceIds
    .map((traceId) => records.get(traceId))
    .filter((trace): trace is TraceRecord => Boolean(trace))
    .map(maxTraceTimestamp);
  return Math.max(0, ...timestamps);
}

function maxTraceTimestamp(trace: TraceRecord) {
  const timestamps = [
    trace.created_at,
    trace.started_at,
    trace.ended_at,
    ...(trace.transitions ?? []).map((transition) => transition.at),
  ].filter((value): value is number => typeof value === "number" && Number.isFinite(value));
  return Math.max(0, ...timestamps);
}

function mergeSummaryArchive(
  summary: TraceSummary,
  archivedRecords: TraceRecord[],
): TraceSummary {
  const archivedTraces = mergeTraceRecords(
    archivedRecords,
    archivedTracesForSummary(summary),
  );
  const deletedTraceIds = uniqueValues([
    ...deletedTraceIdsForSummary(summary),
    ...archivedTraces
      .filter((trace) => trace.metadata?.deleted_target === true)
      .map((trace) => trace.trace_id),
  ]);
  const deletedTrace =
    archivedTraces.find((trace) => trace.trace_id === summary.deleted_trace_id) ??
    summary.deleted_trace ??
    archivedTraces.find((trace) => trace.metadata?.deleted_target === true);

  return {
    ...summary,
    archived_traces: archivedTraces,
    deleted_trace: deletedTrace,
    deleted_trace_ids: deletedTraceIds,
  };
}

function summaryMatchesDeletedTraceId(summary: TraceSummary, traceId: string) {
  return (
    summary.deleted_trace_id === traceId ||
    deletedTraceIdsForSummary(summary).includes(traceId)
  );
}

function summariesMatch(left: TraceSummary, right: TraceSummary) {
  return left.summary_id === right.summary_id || left.deleted_trace_id === right.deleted_trace_id;
}

function sampleCountForDeletedTrace(trace: TraceRecord) {
  return Math.max(
    1,
    Math.round(
      numericMetadata(trace, "success_count") ??
        numericMetadata(trace, "call_count") ??
        numericMetadata(trace, "error_count") ??
        numericMetadata(trace, "cancelled_count") ??
        1,
    ),
  );
}

function durationForDeletedTrace(trace: TraceRecord, deletedAt: number) {
  const avgDuration = numericMetadata(trace, "avg_duration_ms");
  if (avgDuration != null) {
    return Math.max(0, avgDuration);
  }
  if (typeof trace.duration_ms === "number" && Number.isFinite(trace.duration_ms)) {
    return Math.max(0, trace.duration_ms);
  }

  const start = trace.started_at ?? trace.created_at;
  return Math.max(0, (deletedAt - start) * 1000);
}

function archivedTracesForSummary(summary: TraceSummary) {
  if (Array.isArray(summary.archived_traces) && summary.archived_traces.length > 0) {
    return summary.archived_traces;
  }
  return summary.deleted_trace ? [summary.deleted_trace] : [];
}

function collectTraceArchive(records: Map<string, TraceRecord>, traceId: string) {
  const subtreeIds = new Set(collectTraceSubtreeIds(records, [traceId]));
  if (subtreeIds.size === 0 && !records.has(traceId)) {
    return [];
  }

  const archiveIds = new Set(subtreeIds);
  const seenAncestors = new Set<string>();
  let parentId = records.get(traceId)?.parent_id ?? null;
  while (parentId && !seenAncestors.has(parentId)) {
    seenAncestors.add(parentId);
    const parent = records.get(parentId);
    if (!parent) {
      break;
    }
    archiveIds.add(parentId);
    parentId = parent.parent_id;
  }

  return [...archiveIds]
    .map((id) => records.get(id))
    .filter((trace): trace is TraceRecord => Boolean(trace))
    .map((trace) => archiveTraceRecord(trace, subtreeIds.has(trace.trace_id)))
    .sort((a, b) => a.created_at - b.created_at);
}

function archiveTraceRecord(trace: TraceRecord, deletedTarget: boolean): TraceRecord {
  return {
    ...trace,
    metadata: {
      ...trace.metadata,
      archived_trace: true,
      deleted_target: deletedTarget || trace.metadata?.deleted_target === true,
    },
    transitions: trace.transitions ? [...trace.transitions] : undefined,
  };
}

function mergeTraceRecords(...groups: TraceRecord[][]) {
  const records = new Map<string, TraceRecord>();
  for (const group of groups) {
    for (const trace of group) {
      const previous = records.get(trace.trace_id);
      records.set(trace.trace_id, previous ? latestTraceRecord(previous, trace) : trace);
    }
  }
  return [...records.values()].sort((a, b) => a.created_at - b.created_at);
}

function latestTraceRecord(previous: TraceRecord, incoming: TraceRecord): TraceRecord {
  const previousTerminal = isTerminalStatus(previous.status);
  const incomingTerminal = isTerminalStatus(incoming.status);
  if (incomingTerminal !== previousTerminal) {
    return incomingTerminal ? incoming : previous;
  }

  const incomingTime = maxTraceTimestamp(incoming);
  const previousTime = maxTraceTimestamp(previous);
  if (incomingTime !== previousTime) {
    return incomingTime > previousTime ? incoming : previous;
  }

  const incomingDuration = finiteNumber(incoming.duration_ms);
  const previousDuration = finiteNumber(previous.duration_ms);
  if (incomingDuration != null || previousDuration != null) {
    return (incomingDuration ?? -1) >= (previousDuration ?? -1) ? incoming : previous;
  }

  return incoming;
}

function traceRecordsEquivalent(left: TraceRecord, right: TraceRecord) {
  return (
    left === right ||
    (left.trace_id === right.trace_id &&
      left.parent_id === right.parent_id &&
      left.name === right.name &&
      left.kind === right.kind &&
      left.peer_id === right.peer_id &&
      left.created_at === right.created_at &&
      left.started_at === right.started_at &&
      left.ended_at === right.ended_at &&
      left.duration_ms === right.duration_ms &&
      left.status === right.status &&
      left.error === right.error &&
      traceMetadataEquivalent(left.metadata, right.metadata) &&
      traceTransitionsEquivalent(left.transitions, right.transitions))
  );
}

function traceMetadataEquivalent(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
) {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  for (const key of leftKeys) {
    if (left[key] !== right[key]) {
      return false;
    }
  }
  return true;
}

function traceTransitionsEquivalent(
  left: TraceTransition[] | undefined,
  right: TraceTransition[] | undefined,
) {
  if (left === right) {
    return true;
  }
  if (!left || !right || left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    const leftTransition = left[index];
    const rightTransition = right[index];
    if (
      !leftTransition ||
      !rightTransition ||
      leftTransition.at !== rightTransition.at ||
      leftTransition.event !== rightTransition.event ||
      leftTransition.status !== rightTransition.status ||
      leftTransition.duration_ms !== rightTransition.duration_ms ||
      leftTransition.error !== rightTransition.error
    ) {
      return false;
    }
  }
  return true;
}

function isTerminalStatus(status: string) {
  return status === "completed" || status === "failed" || status === "cancelled";
}

function finiteNumber(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function setsEqual<T>(left: Set<T>, right: Set<T>) {
  if (left.size !== right.size) {
    return false;
  }
  for (const value of left) {
    if (!right.has(value)) {
      return false;
    }
  }
  return true;
}

function collectTraceSubtreeIds(records: Map<string, TraceRecord>, traceIds: string[]) {
  return collectTraceSubtreeIdsWithChildren(
    buildTraceChildrenByParent(records),
    traceIds,
  );
}

function buildTraceChildrenByParent(records: Map<string, TraceRecord>) {
  const childrenByParent = new Map<string, string[]>();
  for (const trace of records.values()) {
    if (!trace.parent_id) {
      continue;
    }
    const children = childrenByParent.get(trace.parent_id) ?? [];
    children.push(trace.trace_id);
    childrenByParent.set(trace.parent_id, children);
  }
  return childrenByParent;
}

function collectTraceSubtreeIdsWithChildren(
  childrenByParent: Map<string, string[]>,
  traceIds: string[],
) {
  const collected = new Set<string>();
  const pending = [...traceIds];
  let index = 0;
  while (index < pending.length) {
    const traceId = pending[index];
    index += 1;
    if (!traceId || collected.has(traceId)) {
      continue;
    }
    collected.add(traceId);
    pending.push(...(childrenByParent.get(traceId) ?? []));
  }

  return [...collected];
}

function isDeletedTrace(
  trace: TraceRecord,
  records: Map<string, TraceRecord>,
  deletedTraceIds: Set<string> | undefined,
) {
  if (!deletedTraceIds || deletedTraceIds.size === 0) {
    return false;
  }
  if (deletedTraceIds.has(trace.trace_id)) {
    return true;
  }

  const seen = new Set<string>();
  let parentId = trace.parent_id;
  while (parentId && !seen.has(parentId)) {
    if (deletedTraceIds.has(parentId)) {
      return true;
    }
    seen.add(parentId);
    parentId = records.get(parentId)?.parent_id ?? null;
  }
  return false;
}

function nearestVisibleAncestorId(
  parentId: string | null,
  byId: Map<string, TraceRecord>,
  visibleIds: Set<string>,
) {
  const seen = new Set<string>();
  let currentId = parentId;
  while (currentId && !seen.has(currentId)) {
    if (visibleIds.has(currentId)) {
      return currentId;
    }
    seen.add(currentId);
    currentId = byId.get(currentId)?.parent_id ?? null;
  }
  return null;
}

export function applyTraceSummaryEvents(
  previous: TraceSummary[],
  events: TraceEventInput[],
): TraceSummary[] {
  const summaries = new Map(previous.map((summary) => [summary.summary_id, summary]));
  let changed = false;

  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }

    for (const summary of payload.summaries ?? []) {
      upsertTraceSummary(summaries, summary);
      changed = true;
    }

    if (payload.summary) {
      upsertTraceSummary(summaries, payload.summary);
      changed = true;
    }
  }

  if (!changed) {
    return previous;
  }

  return [...summaries.values()].sort((a, b) => b.deleted_at - a.deleted_at);
}

function upsertTraceSummary(
  summaries: Map<string, TraceSummary>,
  incoming: TraceSummary,
) {
  const existing =
    summaries.get(incoming.summary_id) ??
    [...summaries.values()].find((summary) => summariesMatch(summary, incoming));
  const next = existing
    ? mergeSummaryArchive(incoming, archivedTracesForSummary(existing))
    : incoming;

  if (existing && existing.summary_id !== incoming.summary_id) {
    summaries.delete(existing.summary_id);
  }
  summaries.set(next.summary_id, next);
}

export function formatTraceExport(
  traces: TraceRecord[],
  options: TraceExportOptions = {},
): string {
  const summary = options.summary ?? null;
  const view = options.view ?? (summary ? "deleted" : "live");
  const ordered = orderTraces(traces);
  const roots = buildTraceForest(ordered);
  const peers = uniqueValues(ordered.map((trace) => trace.peer_id).filter(isString));
  const statuses = countStatuses(ordered);
  const lines = [
    options.title ?? "WEBRTC ASYNC RUNTIME TRACE",
    `view=${view}`,
    `trace_count=${ordered.length} root_count=${roots.length}`,
    `peer_ids=${peers.length > 0 ? peers.join(",") : "-"}`,
    `statuses=${statuses || "-"}`,
  ];

  if (summary) {
    lines.push(
      [
        "summary",
        `id=${summary.summary_id}`,
        `deleted_trace_id=${summary.deleted_trace_id}`,
        `deleted_at=${formatNumber(summary.deleted_at)}`,
        `status=${summary.status ?? "-"}`,
        `avg_duration_ms=${formatMaybeNumber(summary.avg_duration_ms)}`,
      ].join(" "),
    );
  }

  if (options.compact) {
    lines.push("", "TREE");
    if (roots.length === 0) {
      lines.push("- no traces");
    } else {
      for (const root of roots) {
        appendCompactTraceTreeLines(lines, root, 0);
      }
    }
    return `${lines.join("\n")}\n`;
  }

  lines.push("", "TREE");
  if (roots.length === 0) {
    lines.push("- no traces");
  } else {
    for (const root of roots) {
      appendTraceTreeLines(lines, root, 0);
    }
  }

  lines.push("", "TRANSITIONS");
  const transitions = collectTraceTransitions(ordered);
  if (transitions.length === 0) {
    lines.push("- no transitions");
  } else {
    for (const item of transitions) {
      lines.push(formatTransitionLine(item.trace, item.transition));
    }
  }

  return `${lines.join("\n")}\n`;
}

type OrderedTrace = TraceRecord & { __index: number };

type TraceTreeNode = {
  trace: OrderedTrace;
  children: TraceTreeNode[];
};

type TraceTransitionItem = {
  trace: OrderedTrace;
  transition: TraceTransition;
  index: number;
};

function orderTraces(traces: TraceRecord[]): OrderedTrace[] {
  return traces
    .map((trace, index) => ({ ...trace, __index: index }))
    .sort((a, b) => compareTraceOrder(a, b));
}

function buildTraceForest(traces: OrderedTrace[]): TraceTreeNode[] {
  const nodes = new Map<string, TraceTreeNode>();
  for (const trace of traces) {
    nodes.set(trace.trace_id, { trace, children: [] });
  }

  const roots: TraceTreeNode[] = [];
  for (const trace of traces) {
    const node = nodes.get(trace.trace_id);
    if (!node) {
      continue;
    }
    const parent = trace.parent_id ? nodes.get(trace.parent_id) : null;
    if (parent) {
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  }

  const sortNodes = (items: TraceTreeNode[]) => {
    items.sort((a, b) => compareTraceOrder(a.trace, b.trace));
    for (const item of items) {
      sortNodes(item.children);
    }
  };
  sortNodes(roots);
  return roots;
}

function appendTraceTreeLines(
  lines: string[],
  node: TraceTreeNode,
  depth: number,
) {
  const trace = node.trace;
  const indent = "  ".repeat(depth);
  const parts = [
    `${indent}- ${trace.name}`,
    `id=${trace.trace_id}`,
    `parent=${trace.parent_id ?? "-"}`,
    `kind=${trace.kind}`,
    `status=${trace.status}`,
    `duration_ms=${formatMaybeNumber(trace.duration_ms)}`,
    `peer_id=${trace.peer_id ?? "-"}`,
  ];
  if (trace.error) {
    parts.push(`error=${formatValue(trace.error)}`);
  }
  const metadata = formatMetadata(trace.metadata ?? {});
  if (metadata) {
    parts.push(`metadata=${metadata}`);
  }
  lines.push(parts.join(" "));
  for (const child of node.children) {
    appendTraceTreeLines(lines, child, depth + 1);
  }
}

function appendCompactTraceTreeLines(
  lines: string[],
  node: TraceTreeNode,
  depth: number,
) {
  const trace = node.trace;
  const indent = "  ".repeat(depth);
  const label = compactTraceLabel(trace);
  const parts = [`${indent}- ${trace.name}`, `[${trace.status}]`, trace.kind];
  if (label) {
    parts.push(label);
  }
  if (trace.error) {
    parts.push(`error=${formatValue(trace.error)}`);
  }
  lines.push(parts.join(" "));
  for (const child of node.children) {
    appendCompactTraceTreeLines(lines, child, depth + 1);
  }
}

function compactTraceLabel(trace: TraceRecord) {
  const callCount = numericMetadata(trace, "call_count");
  const avgDuration = numericMetadata(trace, "avg_duration_ms");
  if (callCount != null && callCount > 1 && avgDuration != null) {
    return `${formatNumber(callCount)} calls avg=${formatMaybeNumber(avgDuration)}ms`;
  }
  if (trace.duration_ms != null) {
    return `${formatMaybeNumber(trace.duration_ms)}ms`;
  }
  return trace.status === "running" ? "running" : "";
}

function collectTraceTransitions(traces: OrderedTrace[]): TraceTransitionItem[] {
  const items: TraceTransitionItem[] = [];
  for (const trace of traces) {
    const transitions =
      Array.isArray(trace.transitions) && trace.transitions.length > 0
        ? trace.transitions
        : [snapshotTransition(trace)];
    for (const transition of transitions) {
      items.push({ trace, transition, index: items.length });
    }
  }
  return items.sort((a, b) => {
    const atDelta = safeNumber(a.transition.at) - safeNumber(b.transition.at);
    if (atDelta !== 0) {
      return atDelta;
    }
    const traceDelta = compareTraceOrder(a.trace, b.trace);
    return traceDelta === 0 ? a.index - b.index : traceDelta;
  });
}

function snapshotTransition(trace: TraceRecord): TraceTransition {
  return {
    at: trace.ended_at ?? trace.started_at ?? trace.created_at,
    event: "snapshot",
    status: trace.status,
    duration_ms: trace.duration_ms,
    error: trace.error,
  };
}

function formatTransitionLine(trace: TraceRecord, transition: TraceTransition) {
  const parts = [
    `- trace=${trace.trace_id}`,
    `name=${formatValue(trace.name)}`,
    `event=${transition.event}`,
    `at=${formatNumber(transition.at)}`,
    `status=${transition.status}`,
    `duration_ms=${formatMaybeNumber(transition.duration_ms)}`,
  ];
  const error = transition.error ?? trace.error;
  if (error) {
    parts.push(`error=${formatValue(error)}`);
  }
  return parts.join(" ");
}

function compareTraceOrder(a: OrderedTrace, b: OrderedTrace) {
  const createdDelta = safeNumber(a.created_at) - safeNumber(b.created_at);
  if (createdDelta !== 0) {
    return createdDelta;
  }
  return a.__index - b.__index;
}

function countStatuses(traces: TraceRecord[]) {
  const counts = new Map<string, number>();
  for (const trace of traces) {
    counts.set(trace.status, (counts.get(trace.status) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([status, count]) => `${status}:${count}`)
    .join(",");
}

function formatMetadata(metadata: Record<string, unknown>) {
  return Object.entries(metadata)
    .filter(([, value]) => isMetadataValue(value))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${formatValue(value)}`)
    .join(" ");
}

function numericMetadata(trace: TraceRecord, key: string) {
  const value = trace.metadata?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function formatValue(value: unknown) {
  if (value == null) {
    return "-";
  }
  if (typeof value === "number") {
    return formatNumber(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  const text = String(value);
  if (/^[A-Za-z0-9_.:/@|+-]+$/.test(text)) {
    return text;
  }
  return `"${text.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function formatMaybeNumber(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value) ? formatNumber(value) : "-";
}

function formatNumber(value: number) {
  if (!Number.isFinite(value)) {
    return "-";
  }
  if (Number.isInteger(value)) {
    return String(value);
  }
  return value.toFixed(3).replace(/\.?0+$/, "");
}

function safeNumber(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function uniqueValues(values: string[]) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isMetadataValue(value: unknown) {
  return (
    value == null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}
