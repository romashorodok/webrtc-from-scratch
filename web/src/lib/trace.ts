import { parseJson } from "./media";

const TRACE_SUMMARY_LIMIT = 512;
const ARCHIVED_TRACES_PER_SUMMARY_LIMIT = 512;
const PERFORMANCE_EVENT_LIMIT = 160;
export const NORMALIZED_ARCHIVE_LIMIT = 512;
export const NORMALIZED_TOMBSTONE_LIMIT = 1024;
export const DEFAULT_TRANSITION_JOURNAL_LIMIT = 512;
export const MAX_TRANSITION_JOURNAL_LIMIT = 4096;

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
  task_id: string;
  parent_task_id: string | null;
  name: string;
  kind: string;
  created_at: number;
  started_at: number | null;
  ended_at: number | null;
  duration_ms: number | null;
  status: TraceStatus | string;
  error: string | null;
  metadata: Record<string, unknown>;
  transitions?: TraceTransition[];
};

export type GroupSnapshot = {
  group_id?: number;
  trace_id: string;
  task_id: string;
  owner_entity_id?: string;
  owner_epoch?: number;
  owner_role?: string;
  activity_kind?: "request" | "long-running" | "wait" | "pump" | string;
  parent_ref_type?: string;
  parent_ref_id?: number | string | null;
  operation_id?: number;
  group: string;
  operation: string;
  calls: number;
  in_flight?: number;
  successes?: number;
  cancellations?: number;
  errors?: number;
  total_duration_ms?: number;
  average_duration_ms?: number;
  min_duration_ms?: number;
  max_duration_ms?: number;
  total_queue_ms?: number;
  total_worker_ms?: number;
  latest_failure_class: string | null;
  revision?: number;
  overflow?: boolean;
  exemplars?: Array<Record<string, unknown>>;
  live_age_ms?: number | null;
};

export type TraceEntity = {
  entity_id: string;
  alias: string;
  role: string;
  kind: "machine" | "resource" | "facet-owner" | "owner" | string;
};

export type TraceMachine = {
  entity_id: string;
  machine_type: string;
  state: string;
  machine_epoch: number;
  revision: number;
  cause_id: number | string | null;
  monotonic_ns: number;
};

export type TraceMachineTransition = {
  order: number;
  entity_id: string;
  machine_type: string;
  from_state: string;
  to_state: string;
  state: string;
  machine_epoch: number;
  revision: number;
  cause_id: number | string | null;
  monotonic_ns: number;
};

export type TraceControl = {
  handle_id: string;
  trace_id: string;
  owner_entity_id: string;
  owner_epoch: number;
  name: string;
  cancelable: boolean;
  revision: number;
};

export type TraceFacet = {
  facet_id: string;
  owner_entity_id: string;
  owner_epoch: number;
  value: unknown;
  revision: number;
};

export type TraceCapture = {
  record_id: number;
  capture_id: number;
  selector_kind: "operation" | "entity" | "control" | "facet";
  selector_value: number | string;
  operation_id: number;
  operation: string;
  owner_entity_id: string;
  started_ns: number;
  finished_ns: number | null;
  duration_ms: number;
  outcome: string;
  failure_class: string | null;
  revision: number;
  diagnostic_capture: true;
};

export type NormalizedArchive<T> = {
  recordsById: Map<string, T>;
  order: string[];
};

type EpochRevision = { epoch: number; revision: number };

export type TraceSummary = {
  summary_id: string;
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
  deleted_task_id: string;
  deleted_task_ids?: string[];
  deleted_task?: TraceRecord;
  archived_tasks?: TraceRecord[];
  archived_groups?: GroupSnapshot[];
  deleted_at: number;
};

export type PerformanceEvent = {
  name: string;
  timestamp: number;
  duration_ms: number | null;
  metadata: Record<string, unknown>;
};

type TracePayload = {
  tasks?: TraceRecord[];
  groups?: GroupSnapshot[];
  trace_id?: string;
  task_id?: string;
  task_ids?: string[];
  summary?: TraceSummary;
  summaries?: TraceSummary[];
  deleted_at?: number;
  success_retention_seconds?: number;
  auto_prune?: boolean;
  snapshot?: boolean;
};

export type TraceEventInput = {
  event: string;
  data: unknown;
};

export type TraceApplyOptions = {
  deletedTaskIds?: Set<string>;
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
  tasks: TraceRecord[];
  groups: GroupSnapshot[];
  summaries: TraceSummary[];
  performanceEvents: PerformanceEvent[];
  deletedTaskIds: Set<string>;
  tasksById: Map<string, TraceRecord>;
  taskOrder: string[];
  schema: 2;
  traceId: string | null;
  sequence: number | null;
  serverMonotonicMs: number | null;
  machinesById: Map<string, TraceMachine>;
  entitiesById: Map<string, TraceEntity>;
  transitions: TraceMachineTransition[];
  transitionJournalLimit: number;
  controlsById: Map<string, TraceControl>;
  groupsById: Map<number, GroupSnapshot>;
  facetsById: Map<string, TraceFacet>;
  capturesById: Map<number, TraceCapture>;
  operationNamesById: Map<number, string>;
  groupIdsByOwner: Map<string, number[]>;
  controlIdsByOwner: Map<string, string[]>;
  facetIdsByOwner: Map<string, string[]>;
  groupArchive: NormalizedArchive<GroupSnapshot>;
  machineArchive: NormalizedArchive<TraceMachine>;
  controlArchive: NormalizedArchive<TraceControl>;
  facetArchive: NormalizedArchive<TraceFacet>;
  removedMachineRevisions: Map<string, EpochRevision>;
  removedControlRevisions: Map<string, number>;
  removedGroupRevisions: Map<number, number>;
  removedFacetRevisions: Map<string, EpochRevision>;
  diagnostics: Record<string, number>;
  topologyVersion: number;
  valueVersion: number;
  commitVersion: number;
  resyncRequired: boolean;
  resyncRequestVersion: number;
  resyncReason: string | null;
  terminal: boolean;
};

export type TraceStateAction = {
  type: "events";
  events: TraceEventInput[];
};

type ArchivedTraceTree = {
  deletedTaskId: string;
  deletedTaskIds: string[];
  archivedTasks: TraceRecord[];
  archivedGroups: GroupSnapshot[];
  deletedAt: number;
  synthesizeSummary: boolean;
};

export function createInitialTraceState(): TraceState {
  return {
    tasks: [],
    groups: [],
    summaries: [],
    performanceEvents: [],
    deletedTaskIds: new Set<string>(),
    tasksById: new Map<string, TraceRecord>(),
    taskOrder: [],
    schema: 2,
    traceId: null,
    sequence: null,
    serverMonotonicMs: null,
    machinesById: new Map(),
    entitiesById: new Map(),
    transitions: [],
    transitionJournalLimit: DEFAULT_TRANSITION_JOURNAL_LIMIT,
    controlsById: new Map(),
    groupsById: new Map(),
    facetsById: new Map(),
    capturesById: new Map(),
    operationNamesById: new Map(),
    groupIdsByOwner: new Map(),
    controlIdsByOwner: new Map(),
    facetIdsByOwner: new Map(),
    groupArchive: emptyNormalizedArchive(),
    machineArchive: emptyNormalizedArchive(),
    controlArchive: emptyNormalizedArchive(),
    facetArchive: emptyNormalizedArchive(),
    removedMachineRevisions: new Map(),
    removedControlRevisions: new Map(),
    removedGroupRevisions: new Map(),
    removedFacetRevisions: new Map(),
    diagnostics: {},
    topologyVersion: 0,
    valueVersion: 0,
    commitVersion: 0,
    resyncRequired: false,
    resyncRequestVersion: 0,
    resyncReason: null,
    terminal: false,
  };
}

export function reduceTraceState(
  state: TraceState,
  action: TraceStateAction,
): TraceState {
  const envelope = action.events.length === 1 ? schema2Envelope(action.events[0]) : null;
  return envelope ? reduceNormalizedTraceState(state, envelope.event, envelope.data) : state;
}

type Schema2Snapshot = {
  schema: 2;
  trace_id: string;
  snapshot_sequence: number;
  server_monotonic_ms?: number;
  machines?: TraceMachine[];
  entities?: TraceEntity[];
  transitions?: TraceMachineTransition[];
  transition_journal_limit?: number;
  controls?: TraceControl[];
  groups?: GroupSnapshot[];
  facets?: TraceFacet[];
  captures?: TraceCapture[];
  operation_strings?: Record<string, string>;
  diagnostics?: Record<string, number>;
  terminal?: boolean;
  sequence?: number;
};

type Schema2Patch = {
  schema: 2;
  trace_id: string;
  sequence: number;
  server_monotonic_ms?: number;
  entities?: TraceEntity[];
  operation_strings?: Record<string, string>;
  events?: Array<{
    type?: string;
    records?: unknown[];
    ids?: Array<string | number>;
    values?: Record<string, number>;
    reset?: boolean;
  }>;
};

type Schema2Envelope = {
  event: "trace:snapshot" | "trace:batch" | "trace:resync_required" | "trace:terminal";
  data: Schema2Snapshot | Schema2Patch;
};

function schema2Envelope(input: TraceEventInput | undefined): Schema2Envelope | null {
  if (!input || !["trace:snapshot", "trace:batch", "trace:resync_required", "trace:terminal"].includes(input.event)) {
    return null;
  }
  const data = parseJson<Record<string, unknown>>(input.data);
  if (data?.schema !== 2) {
    return null;
  }
  return { event: input.event as Schema2Envelope["event"], data: data as Schema2Snapshot | Schema2Patch };
}

function reduceNormalizedTraceState(
  state: TraceState,
  event: Schema2Envelope["event"],
  data: Schema2Snapshot | Schema2Patch,
): TraceState {
  if (event === "trace:resync_required") {
    if (state.resyncRequired) {
      return state;
    }
    return requestTraceResync(state, "server_requested_resync");
  }
  if (event === "trace:snapshot" || event === "trace:terminal") {
    return replaceNormalizedSnapshot(state, data as Schema2Snapshot, event === "trace:terminal");
  }

  const patch = data as Schema2Patch;
  if (state.schema !== 2 || state.sequence == null || patch.trace_id !== state.traceId) {
    return requestTraceResync(state, "patch_before_snapshot");
  }
  if (!Number.isSafeInteger(patch.sequence) || patch.sequence <= state.sequence) {
    return state;
  }
  if (state.resyncRequired) {
    return state;
  }
  if (patch.sequence !== state.sequence + 1) {
    return requestTraceResync(state, `sequence_gap:${state.sequence + 1}:${patch.sequence}`);
  }

  let machinesById = state.machinesById;
  const entitiesById = normalizeEntities(patch.entities, state.entitiesById);
  let transitions = state.transitions;
  let controlsById = state.controlsById;
  let groupsById = state.groupsById;
  let facetsById = state.facetsById;
  let capturesById = state.capturesById;
  let removedMachineRevisions = state.removedMachineRevisions;
  let removedControlRevisions = state.removedControlRevisions;
  let removedGroupRevisions = state.removedGroupRevisions;
  let removedFacetRevisions = state.removedFacetRevisions;
  let groupArchive = state.groupArchive;
  let machineArchive = state.machineArchive;
  let controlArchive = state.controlArchive;
  let facetArchive = state.facetArchive;
  let diagnostics = state.diagnostics;
  let topologyChanged = entitiesById !== state.entitiesById;
  let valueChanged = topologyChanged;

  for (const operation of patch.events ?? []) {
    switch (operation.type) {
      case "machine:upsert": {
        for (const record of validRecords<TraceMachine>(operation.records, "entity_id")) {
          const previous = machinesById.get(record.entity_id);
          if (!acceptEpochRevision(previous, record, "machine_epoch", removedMachineRevisions.get(record.entity_id))) continue;
          if (machinesById === state.machinesById) machinesById = new Map(machinesById);
          machinesById.set(record.entity_id, record);
          if (removedMachineRevisions.has(record.entity_id)) {
            if (removedMachineRevisions === state.removedMachineRevisions) removedMachineRevisions = new Map(removedMachineRevisions);
            removedMachineRevisions.delete(record.entity_id);
          }
          topologyChanged ||= !previous || previous.machine_epoch !== record.machine_epoch || previous.machine_type !== record.machine_type;
          valueChanged = true;
        }
        break;
      }
      case "machine:transition": {
        if (operation.reset === true) transitions = [];
        for (const record of validRecords<TraceMachine>(operation.records, "entity_id")) {
          const previous = machinesById.get(record.entity_id);
          if (!acceptEpochRevision(previous, record, "machine_epoch", removedMachineRevisions.get(record.entity_id))) continue;
          if (machinesById === state.machinesById) machinesById = new Map(machinesById);
          machinesById.set(record.entity_id, record);
          if (removedMachineRevisions.has(record.entity_id)) {
            if (removedMachineRevisions === state.removedMachineRevisions) removedMachineRevisions = new Map(removedMachineRevisions);
            removedMachineRevisions.delete(record.entity_id);
          }
          topologyChanged ||= !previous || previous.machine_epoch !== record.machine_epoch || previous.machine_type !== record.machine_type;
          valueChanged = true;
        }
        const committed = validRecords<TraceMachineTransition>(operation.records, "order")
          .filter(validMachineTransition);
        if (committed.length) {
          transitions = appendTransitions(
            transitions, committed, state.transitionJournalLimit,
          );
          topologyChanged = valueChanged = true;
        } else if (operation.reset === true) {
          topologyChanged = valueChanged = true;
        }
        break;
      }
      case "machine:remove": {
        for (const id of stringIds(operation.ids)) {
          const previous = machinesById.get(id);
          if (!previous) continue;
          if (machinesById === state.machinesById) machinesById = new Map(machinesById);
          machinesById.delete(id);
          machineArchive = archiveNormalized(machineArchive, id, previous);
          removedMachineRevisions = recordEpochTombstone(
            removedMachineRevisions, state.removedMachineRevisions, id,
            previous.machine_epoch, previous.revision,
          );
          topologyChanged = valueChanged = true;
        }
        break;
      }
      case "control:upsert": {
        for (const record of validRecords<TraceControl>(operation.records, "handle_id")) {
          const previous = controlsById.get(record.handle_id);
          if (!acceptRevision(previous?.revision, record.revision, removedControlRevisions.get(record.handle_id))) continue;
          if (controlsById === state.controlsById) controlsById = new Map(controlsById);
          controlsById.set(record.handle_id, record);
          topologyChanged ||= !previous || controlTopology(previous) !== controlTopology(record);
          valueChanged = true;
        }
        break;
      }
      case "control:remove": {
        for (const id of stringIds(operation.ids)) {
          const previous = controlsById.get(id);
          if (!previous) continue;
          if (controlsById === state.controlsById) controlsById = new Map(controlsById);
          controlsById.delete(id);
          controlArchive = archiveNormalized(controlArchive, id, previous);
          removedControlRevisions = recordTombstone(removedControlRevisions, state.removedControlRevisions, id, previous.revision);
          topologyChanged = valueChanged = true;
        }
        break;
      }
      case "group:upsert": {
        for (const record of validRecords<GroupSnapshot>(operation.records, "group_id")) {
          if (typeof record.group_id !== "number") continue;
          const id = record.group_id;
          const previous = groupsById.get(id);
          if (!acceptRevision(previous?.revision, record.revision, removedGroupRevisions.get(id))) continue;
          if (groupsById === state.groupsById) groupsById = new Map(groupsById);
          groupsById.set(id, record);
          topologyChanged ||= !previous || groupTopology(previous) !== groupTopology(record);
          valueChanged = true;
        }
        break;
      }
      case "group:remove": {
        for (const id of numberIds(operation.ids)) {
          const previous = groupsById.get(id);
          if (!previous) continue;
          if (groupsById === state.groupsById) groupsById = new Map(groupsById);
          groupsById.delete(id);
          groupArchive = archiveNormalized(groupArchive, String(id), previous);
          removedGroupRevisions = recordTombstone(removedGroupRevisions, state.removedGroupRevisions, id, previous.revision ?? 0);
          topologyChanged = valueChanged = true;
        }
        break;
      }
      case "state:upsert": {
        for (const record of validRecords<TraceFacet>(operation.records, "facet_id")) {
          const previous = facetsById.get(record.facet_id);
          if (!acceptEpochRevision(previous, record, "owner_epoch", removedFacetRevisions.get(record.facet_id))) continue;
          if (facetsById === state.facetsById) facetsById = new Map(facetsById);
          facetsById.set(record.facet_id, record);
          topologyChanged ||= !previous || previous.owner_entity_id !== record.owner_entity_id || previous.owner_epoch !== record.owner_epoch;
          valueChanged = true;
        }
        break;
      }
      case "state:remove": {
        for (const id of stringIds(operation.ids)) {
          const previous = facetsById.get(id);
          if (!previous) continue;
          if (facetsById === state.facetsById) facetsById = new Map(facetsById);
          facetsById.delete(id);
          facetArchive = archiveNormalized(facetArchive, id, previous);
          removedFacetRevisions = recordEpochTombstone(
            removedFacetRevisions, state.removedFacetRevisions, id,
            previous.owner_epoch, previous.revision,
          );
          topologyChanged = valueChanged = true;
        }
        break;
      }
      case "diagnostics:patch":
        if (operation.values) {
          diagnostics = { ...diagnostics, ...operation.values };
          valueChanged = true;
        }
        break;
      case "capture:upsert":
        for (const record of validRecords<TraceCapture>(operation.records, "record_id")) {
          if (typeof record.record_id !== "number" || record.diagnostic_capture !== true) continue;
          const previous = capturesById.get(record.record_id);
          if (previous && previous.revision >= record.revision) continue;
          if (capturesById === state.capturesById) capturesById = new Map(capturesById);
          capturesById.set(record.record_id, record);
          topologyChanged ||= !previous;
          valueChanged = true;
        }
        break;
      case "capture:remove":
        for (const id of numberIds(operation.ids)) {
          if (!capturesById.has(id)) continue;
          if (capturesById === state.capturesById) capturesById = new Map(capturesById);
          capturesById.delete(id);
          topologyChanged = valueChanged = true;
        }
        break;
    }
  }

  const operationNamesById = mergeOperationNames(state.operationNamesById, patch.operation_strings);
  valueChanged ||= operationNamesById !== state.operationNamesById;
  const indexes = topologyChanged
    ? buildNormalizedIndexes(controlsById, groupsById, facetsById)
    : { groupIdsByOwner: state.groupIdsByOwner, controlIdsByOwner: state.controlIdsByOwner, facetIdsByOwner: state.facetIdsByOwner };

  return {
    ...state,
    schema: 2,
    sequence: patch.sequence,
    serverMonotonicMs: finiteNumber(patch.server_monotonic_ms),
    machinesById, entitiesById, transitions, controlsById, groupsById, facetsById, capturesById, operationNamesById,
    ...indexes,
    groups: groupsById === state.groupsById ? state.groups : [...groupsById.values()],
    groupArchive, machineArchive, controlArchive, facetArchive,
    removedMachineRevisions: boundMap(removedMachineRevisions),
    removedControlRevisions: boundMap(removedControlRevisions),
    removedGroupRevisions: boundMap(removedGroupRevisions),
    removedFacetRevisions: boundMap(removedFacetRevisions),
    diagnostics,
    topologyVersion: state.topologyVersion + (topologyChanged ? 1 : 0),
    valueVersion: state.valueVersion + (valueChanged ? 1 : 0),
    commitVersion: state.commitVersion + 1,
  };
}

function replaceNormalizedSnapshot(
  state: TraceState, snapshot: Schema2Snapshot, terminal = false,
): TraceState {
  const machinesById = new Map((snapshot.machines ?? []).map((item) => [item.entity_id, item]));
  const entitiesById = normalizeEntities(snapshot.entities, new Map());
  const controlsById = new Map((snapshot.controls ?? []).map((item) => [item.handle_id, item]));
  const groupsById = new Map(
    (snapshot.groups ?? []).flatMap((item) => typeof item.group_id === "number" ? [[item.group_id, item] as const] : []),
  );
  const facetsById = new Map((snapshot.facets ?? []).map((item) => [item.facet_id, item]));
  const capturesById = new Map((snapshot.captures ?? []).map((item) => [item.record_id, item]));
  const transitionJournalLimit = transitionLimit(snapshot.transition_journal_limit);
  const transitions = appendTransitions(
    [], (snapshot.transitions ?? []).filter(validMachineTransition),
    transitionJournalLimit,
  );
  return {
    ...state,
    schema: 2,
    traceId: snapshot.trace_id,
    sequence: terminal && Number.isSafeInteger(snapshot.sequence)
      ? snapshot.sequence! : snapshot.snapshot_sequence,
    serverMonotonicMs: finiteNumber(snapshot.server_monotonic_ms),
    machinesById, entitiesById, transitions, transitionJournalLimit,
    controlsById, groupsById, facetsById, capturesById,
    operationNamesById: mergeOperationNames(new Map(), snapshot.operation_strings),
    ...buildNormalizedIndexes(controlsById, groupsById, facetsById),
    groups: [...groupsById.values()],
    diagnostics: snapshot.diagnostics ?? {},
    removedMachineRevisions: new Map(),
    removedControlRevisions: new Map(),
    removedGroupRevisions: new Map(),
    removedFacetRevisions: new Map(),
    resyncRequired: false,
    resyncReason: null,
    terminal: terminal || snapshot.terminal === true,
    topologyVersion: state.topologyVersion + 1,
    valueVersion: state.valueVersion + 1,
    commitVersion: state.commitVersion + 1,
  };
}

function transitionLimit(value: number | undefined) {
  if (!Number.isSafeInteger(value) || (value ?? 0) < 1) {
    return DEFAULT_TRANSITION_JOURNAL_LIMIT;
  }
  return Math.min(value!, MAX_TRANSITION_JOURNAL_LIMIT);
}

function normalizeEntities(
  entities: TraceEntity[] | undefined,
  previous: Map<string, TraceEntity>,
) {
  if (!Array.isArray(entities)) return previous;
  const normalized = new Map<string, TraceEntity>();
  for (const entity of entities.slice(0, 4096)) {
    if (!entity || typeof entity.entity_id !== "string" || !entity.entity_id) continue;
    if (typeof entity.alias !== "string" || !/^@\d{1,6}$/.test(entity.alias)) continue;
    if (typeof entity.role !== "string" || !/^[a-z0-9-]{1,64}$/.test(entity.role)) continue;
    if (typeof entity.kind !== "string" || !/^[a-z0-9-]{1,32}$/.test(entity.kind)) continue;
    normalized.set(entity.entity_id, entity);
  }
  if (normalized.size === previous.size && [...normalized].every(([id, entity]) => {
    const old = previous.get(id);
    return old?.alias === entity.alias && old.role === entity.role && old.kind === entity.kind;
  })) return previous;
  return normalized;
}

function validMachineTransition(record: TraceMachineTransition) {
  return Number.isSafeInteger(record.order) && record.order > 0 &&
    typeof record.entity_id === "string" && typeof record.machine_type === "string" &&
    typeof record.from_state === "string" && typeof record.to_state === "string" &&
    Number.isSafeInteger(record.machine_epoch) && Number.isSafeInteger(record.revision);
}

function appendTransitions(
  previous: TraceMachineTransition[], incoming: TraceMachineTransition[], limit: number,
) {
  const byOrder = new Map(previous.map((item) => [item.order, item]));
  for (const item of incoming) byOrder.set(item.order, item);
  return [...byOrder.values()]
    .sort((left, right) => left.order - right.order)
    .slice(-limit);
}

function requestTraceResync(state: TraceState, reason: string): TraceState {
  return {
    ...state,
    resyncRequired: true,
    resyncReason: reason,
    resyncRequestVersion: state.resyncRequestVersion + 1,
    commitVersion: state.commitVersion + 1,
    valueVersion: state.valueVersion + 1,
  };
}

function emptyNormalizedArchive<T>(): NormalizedArchive<T> {
  return { recordsById: new Map(), order: [] };
}

function archiveNormalized<T>(archive: NormalizedArchive<T>, id: string, record: T): NormalizedArchive<T> {
  const recordsById = new Map(archive.recordsById);
  recordsById.set(id, record);
  const order = [...archive.order.filter((item) => item !== id), id];
  while (order.length > NORMALIZED_ARCHIVE_LIMIT) recordsById.delete(order.shift()!);
  return { recordsById, order };
}

function validRecords<T>(records: unknown[] | undefined, id: string): T[] {
  return (records ?? []).filter(
    (record): record is T => record !== null && typeof record === "object" && id in record,
  );
}

function acceptRevision(previous: number | undefined, incoming: number | undefined, tombstone: number | undefined) {
  return typeof incoming === "number" && incoming > (previous ?? tombstone ?? -1);
}

function acceptEpochRevision<T extends { revision: number }>(
  previous: T | undefined,
  incoming: T,
  epochKey: keyof T,
  tombstone: EpochRevision | undefined,
) {
  const newEpoch = Number(incoming[epochKey]);
  if (!previous) {
    return !tombstone || newEpoch > tombstone.epoch || (
      newEpoch === tombstone.epoch && incoming.revision > tombstone.revision
    );
  }
  const oldEpoch = Number(previous[epochKey]);
  return newEpoch > oldEpoch || (newEpoch === oldEpoch && incoming.revision > previous.revision);
}

function recordTombstone<K>(map: Map<K, number>, original: Map<K, number>, id: K, revision: number) {
  const next = map === original ? new Map(map) : map;
  next.set(id, Math.max(next.get(id) ?? -1, revision));
  return next;
}

function recordEpochTombstone<K>(
  map: Map<K, EpochRevision>, original: Map<K, EpochRevision>, id: K,
  epoch: number, revision: number,
) {
  const next = map === original ? new Map(map) : map;
  const previous = next.get(id);
  if (!previous || epoch > previous.epoch || (epoch === previous.epoch && revision > previous.revision)) {
    next.set(id, { epoch, revision });
  }
  return next;
}

function boundMap<K, V>(map: Map<K, V>) {
  if (map.size <= NORMALIZED_TOMBSTONE_LIMIT) return map;
  const next = new Map(map);
  while (next.size > NORMALIZED_TOMBSTONE_LIMIT) next.delete(next.keys().next().value!);
  return next;
}

function stringIds(ids: Array<string | number> | undefined) {
  return (ids ?? []).filter((id): id is string => typeof id === "string");
}

function numberIds(ids: Array<string | number> | undefined) {
  return (ids ?? []).filter((id): id is number => typeof id === "number");
}

function controlTopology(item: TraceControl) {
  return `${item.owner_entity_id}\u0000${item.owner_epoch}\u0000${item.name}`;
}

function groupTopology(item: GroupSnapshot) {
  return `${item.owner_entity_id ?? ""}\u0000${item.owner_epoch ?? 0}\u0000${item.parent_ref_type ?? ""}\u0000${item.parent_ref_id ?? ""}\u0000${item.operation_id ?? item.operation}`;
}

function mergeOperationNames(previous: Map<number, string>, names: Record<string, string> | undefined) {
  if (!names || Object.keys(names).length === 0) return previous;
  let next = previous;
  for (const [key, value] of Object.entries(names)) {
    const id = Number(key);
    if (!Number.isSafeInteger(id) || typeof value !== "string" || previous.get(id) === value) continue;
    if (next === previous) next = new Map(previous);
    next.set(id, value);
  }
  return next;
}

function buildNormalizedIndexes(
  controls: Map<string, TraceControl>,
  groups: Map<number, GroupSnapshot>,
  facets: Map<string, TraceFacet>,
) {
  const groupIdsByOwner = new Map<string, number[]>();
  const controlIdsByOwner = new Map<string, string[]>();
  const facetIdsByOwner = new Map<string, string[]>();
  for (const [id, item] of groups) appendIndex(groupIdsByOwner, item.owner_entity_id ?? "", id);
  for (const [id, item] of controls) appendIndex(controlIdsByOwner, item.owner_entity_id, id);
  for (const [id, item] of facets) appendIndex(facetIdsByOwner, item.owner_entity_id, id);
  return { groupIdsByOwner, controlIdsByOwner, facetIdsByOwner };
}

function appendIndex<T>(index: Map<string, T[]>, owner: string, id: T) {
  const ids = index.get(owner) ?? [];
  ids.push(id);
  index.set(owner, ids);
}

function applyGroupEvents(previous: GroupSnapshot[], events: TraceEventInput[]) {
  let next = previous;
  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }
    if (Array.isArray(payload.groups)) {
      next = payload.groups;
    } else if (item.event === "trace:init" && payload.snapshot === true) {
      next = [];
    }
  }
  return next;
}

function applyPerformanceEvents(
  previous: PerformanceEvent[],
  events: TraceEventInput[],
): PerformanceEvent[] {
  let next = previous;
  for (const item of events) {
    const payload = parseJson<{ performance?: PerformanceEvent; snapshot?: boolean }>(item.data);
    if (item.event === "trace:init" && payload?.snapshot === true) {
      next = [];
      continue;
    }
    if (item.event !== "trace:performance" || !payload?.performance) {
      continue;
    }
    const event = payload.performance;
    if (!event.name || !Number.isFinite(event.timestamp)) {
      continue;
    }
    next = [...next, event].slice(-PERFORMANCE_EVENT_LIMIT);
  }
  return next;
}

export function restoreVisibleTraceParents(
  traces: TraceRecord[],
  summaries: TraceSummary[],
): TraceRecord[] {
  if (traces.length === 0 || summaries.length === 0) {
    return traces;
  }

  const visibleIds = new Set(traces.map((trace) => trace.task_id));
  const archivedById = new Map<string, TraceRecord>();
  for (const summary of summaries) {
    for (const trace of archivedTracesForSummary(summary)) {
      archivedById.set(trace.task_id, trace);
    }
  }

  let changed = false;
  const restored = traces.map((trace) => {
    const archivedParentId = archivedById.get(trace.task_id)?.parent_task_id;
    const parentId = nearestVisibleAncestorId(
      archivedParentId ?? trace.parent_task_id,
      archivedById,
      visibleIds,
    );
    if (parentId === trace.parent_task_id) {
      return trace;
    }

    changed = true;
    return {
      ...trace,
      parent_task_id: parentId,
    };
  });

  return changed ? restored : traces;
}

export function applyTraceEvents(
  previous: TraceRecord[],
  events: TraceEventInput[],
  options: TraceApplyOptions = {},
): TraceRecord[] {
  const records = new Map(previous.map((trace) => [trace.task_id, trace]));
  const deletedTaskIds = options.deletedTaskIds;
  let changed = false;

  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }

    if (item.event === "trace:init" && payload.snapshot === true && Array.isArray(payload.tasks)) {
      records.clear();
      deletedTaskIds?.clear();
      for (const trace of payload.tasks) {
        records.set(trace.task_id, trace);
      }
      changed = true;
      continue;
    }

    const deletedIds = deletedTaskIdsFromPayload(item.event, payload);
    if (deletedIds.length > 0) {
      changed = deleteLiveTaskIds(records, deletedIds, deletedTaskIds) || changed;
    }

    for (const trace of traceRecordsFromPayload(payload)) {
      if (isDeletedTask(trace, records, deletedTaskIds)) {
        changed =
          deleteLiveTaskIds(records, [trace.task_id], deletedTaskIds) || changed;
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
  return payload.tasks ?? [];
}

function upsertLiveTraceRecord(records: Map<string, TraceRecord>, incoming: TraceRecord) {
  const previous = records.get(incoming.task_id);
  const next = previous ? latestTraceRecord(previous, incoming) : incoming;
  if (previous && traceRecordsEquivalent(previous, next)) {
    return false;
  }
  records.set(incoming.task_id, next);
  return true;
}

function deletedTaskIdsFromPayload(event: string, payload: TracePayload) {
  const taskIds: string[] = [];

  if (event === "trace:delete") {
    taskIds.push(...(payload.task_ids ?? (payload.task_id ? [payload.task_id] : [])));
  }

  return [...new Set(taskIds.filter(isString))];
}

function deleteLiveTaskIds(
  records: Map<string, TraceRecord>,
  taskIds: string[],
  deletedTaskIds: Set<string> | undefined,
) {
  let changed = false;
  for (const taskId of taskIds) {
    deletedTaskIds?.add(taskId);
    changed = records.delete(taskId) || changed;
  }
  return changed;
}

function deletedTaskIdsForSummary(summary: TraceSummary) {
  return summary.deleted_task_ids && summary.deleted_task_ids.length > 0
    ? summary.deleted_task_ids
    : [summary.deleted_task_id];
}

function collectArchivedTreesForEvents(
  traces: TraceRecord[],
  groups: GroupSnapshot[],
  events: TraceEventInput[],
) {
  const records = new Map(traces.map((trace) => [trace.task_id, trace]));
  const archives = new Map<string, ArchivedTraceTree>();
  let currentGroups = groups;

  for (const item of events) {
    const payload = parseJson<TracePayload>(item.data);
    if (!payload) {
      continue;
    }
    if (Array.isArray(payload.groups)) {
      currentGroups = payload.groups;
    }

    if (item.event === "trace:init" && payload.snapshot === true && Array.isArray(payload.tasks)) {
      records.clear();
      for (const trace of payload.tasks) {
        records.set(trace.task_id, trace);
      }
      continue;
    }

    if (item.event === "trace:complete") {
      for (const task of traceRecordsFromPayload(payload)) {
        records.set(task.task_id, task);
        addArchivedTraceTree(archives, records, task.task_id, currentGroups, {
          deletedAt: deletedAtForPayload(payload, records, task.task_id),
          synthesizeSummary: true,
        });
      }
      continue;
    }

    if (item.event === "trace:delete") {
      if (payload.auto_prune === true) {
        const deletedIds = deletedTaskIdsFromPayload(item.event, payload);
        const deletedRootIds = deletedRootTraceIdsFromPayload(records, payload);
        for (const deletedId of deletedRootIds) {
          addArchivedTraceTree(archives, records, deletedId, currentGroups, {
            deletedAt: deletedAtForPayload(payload, records, deletedId),
            synthesizeSummary: true,
          });
        }
        for (const traceId of deletedIds) {
          records.delete(traceId);
        }
        continue;
      }
      const deletedIds = deletedTaskIdsFromPayload(item.event, payload);
      const deletedRootIds = deletedRootTraceIdsFromPayload(records, payload);
      const deletedSubtreeIds = collectTraceSubtreeIds(records, deletedIds);
      for (const deletedId of deletedRootIds) {
        addArchivedTraceTree(archives, records, deletedId, currentGroups, {
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
        addArchivedTraceTree(archives, records, summary.deleted_task_id, currentGroups, {
          deletedAt: summary.deleted_at,
          synthesizeSummary: false,
        });
      }
      if (payload.summary) {
        addArchivedTraceTree(archives, records, payload.summary.deleted_task_id, currentGroups, {
          deletedAt: payload.summary.deleted_at,
          synthesizeSummary: false,
        });
      }
    }

    for (const trace of traceRecordsFromPayload(payload)) {
      records.set(trace.task_id, trace);
    }
  }

  return archives;
}

function addArchivedTraceTree(
  archives: Map<string, ArchivedTraceTree>,
  records: Map<string, TraceRecord>,
  deletedTaskId: string,
  groups: GroupSnapshot[],
  options: {
    deletedAt: number;
    synthesizeSummary: boolean;
  },
) {
  const archive = collectTraceArchive(records, deletedTaskId);
  if (archive.length === 0) {
    return;
  }

  const previous = archives.get(deletedTaskId);
  const archivedTasks = mergeTraceRecords(previous?.archivedTasks ?? [], archive);
  const boundedArchivedTasks = limitArchivedTraces(archivedTasks);
  const deletedTaskIds = uniqueValues([
    ...(previous?.deletedTaskIds ?? []),
    ...boundedArchivedTasks
      .filter((trace) => trace.metadata?.deleted_target === true)
      .map((trace) => trace.task_id),
  ]);
  const archivedIds = new Set(boundedArchivedTasks.map((task) => task.task_id));
  const archivedTraceIds = new Set(boundedArchivedTasks.map((task) => task.trace_id));
  const archivedGroups = groups.filter(
    (group) => archivedIds.has(group.task_id) || archivedTraceIds.has(group.trace_id),
  );

  archives.set(deletedTaskId, {
    deletedTaskId,
    deletedTaskIds,
    archivedTasks: boundedArchivedTasks,
    archivedGroups,
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
    if (!archive.synthesizeSummary || archive.archivedTasks.length === 0) {
      continue;
    }
    const existing = summaries.find((summary) =>
      summaryMatchesDeletedTaskId(summary, archive.deletedTaskId),
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
  const deletedTask =
    archive.archivedTasks.find((task) => task.task_id === archive.deletedTaskId) ??
    archive.archivedTasks.find((task) => task.metadata?.deleted_target === true) ??
    archive.archivedTasks[0];
  if (!deletedTask) {
    throw new Error("cannot synthesize a deleted trace summary without archived traces");
  }
  const metadata = deletedTask.metadata ?? {};
  const groupKey = String(metadata.group_key ?? deletedTask.name);
  const avgDuration = durationForDeletedTrace(deletedTask, archive.deletedAt);

  return {
    summary_id: archive.deletedTaskId,
    aggregate_key: [archive.deletedTaskId, groupKey, deletedTask.name, deletedTask.kind].join("|"),
    group_key: groupKey,
    name: deletedTask.name,
    kind: deletedTask.kind,
    status: deletedTask.status,
    error: deletedTask.error,
    avg_duration_ms: avgDuration,
    previous_avg_duration_ms: null,
    delta_avg_duration_ms: null,
    sample_count: sampleCountForDeletedTrace(deletedTask),
    deleted_task_id: archive.deletedTaskId,
    deleted_task_ids:
      archive.deletedTaskIds.length > 0 ? archive.deletedTaskIds : [archive.deletedTaskId],
    deleted_task: deletedTask,
    archived_tasks: archive.archivedTasks,
    archived_groups: archive.archivedGroups,
    deleted_at: archive.deletedAt,
  };
}

function deletedRootTraceIdsFromPayload(
  records: Map<string, TraceRecord>,
  payload: TracePayload,
) {
  if (isString(payload.task_id)) {
    return [payload.task_id];
  }

  const deletedIds = deletedTaskIdsFromPayload("trace:delete", payload);
  const deletedIdSet = new Set(deletedIds);
  const rootIds = deletedIds.filter((traceId) => {
    const parentId = records.get(traceId)?.parent_task_id;
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
  archivedGroups: GroupSnapshot[] = [],
): TraceSummary {
  const archivedTasks = mergeTraceRecords(
    archivedRecords,
    archivedTracesForSummary(summary),
  );
  const boundedArchivedTasks = limitArchivedTraces(archivedTasks);
  const deletedTaskIds = uniqueValues([
    ...deletedTaskIdsForSummary(summary),
    ...boundedArchivedTasks
      .filter((trace) => trace.metadata?.deleted_target === true)
      .map((trace) => trace.task_id),
  ]);
  const deletedTask =
    boundedArchivedTasks.find((task) => task.task_id === summary.deleted_task_id) ??
    summary.deleted_task ??
    boundedArchivedTasks.find((task) => task.metadata?.deleted_target === true);

  return {
    ...summary,
    archived_tasks: boundedArchivedTasks,
    archived_groups:
      summary.archived_groups && summary.archived_groups.length > 0
        ? summary.archived_groups
        : archivedGroups,
    deleted_task: deletedTask,
    deleted_task_ids: deletedTaskIds,
  };
}

function trimTraceSummaries(summaries: TraceSummary[]) {
  return summaries.length > TRACE_SUMMARY_LIMIT
    ? summaries.slice(0, TRACE_SUMMARY_LIMIT)
    : summaries;
}

function limitArchivedTraces(traces: TraceRecord[]) {
  if (traces.length <= ARCHIVED_TRACES_PER_SUMMARY_LIMIT) {
    return traces;
  }
  const targets = traces.filter((trace) => trace.metadata?.deleted_target === true);
  const keep = new Map<string, TraceRecord>();
  for (const trace of targets) {
    keep.set(trace.task_id, trace);
  }
  for (const trace of traces) {
    if (keep.size >= ARCHIVED_TRACES_PER_SUMMARY_LIMIT) {
      break;
    }
    keep.set(trace.task_id, trace);
  }
  return [...keep.values()].sort((a, b) => a.created_at - b.created_at);
}

function summaryMatchesDeletedTaskId(summary: TraceSummary, taskId: string) {
  return (
    summary.deleted_task_id === taskId ||
    deletedTaskIdsForSummary(summary).includes(taskId)
  );
}

function summariesMatch(left: TraceSummary, right: TraceSummary) {
  return left.summary_id === right.summary_id || left.deleted_task_id === right.deleted_task_id;
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
  if (Array.isArray(summary.archived_tasks) && summary.archived_tasks.length > 0) {
    return summary.archived_tasks;
  }
  return summary.deleted_task ? [summary.deleted_task] : [];
}

function collectTraceArchive(records: Map<string, TraceRecord>, traceId: string) {
  const subtreeIds = new Set(collectTraceSubtreeIds(records, [traceId]));
  if (subtreeIds.size === 0 && !records.has(traceId)) {
    return [];
  }

  const archiveIds = new Set(subtreeIds);
  const seenAncestors = new Set<string>();
  let parentId = records.get(traceId)?.parent_task_id ?? null;
  while (parentId && !seenAncestors.has(parentId)) {
    seenAncestors.add(parentId);
    const parent = records.get(parentId);
    if (!parent) {
      break;
    }
    archiveIds.add(parentId);
    parentId = parent.parent_task_id;
  }

  return [...archiveIds]
    .map((id) => records.get(id))
    .filter((trace): trace is TraceRecord => Boolean(trace))
    .map((trace) => archiveTraceRecord(trace, subtreeIds.has(trace.task_id)))
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
      const previous = records.get(trace.task_id);
      records.set(trace.task_id, previous ? latestTraceRecord(previous, trace) : trace);
    }
  }
  return [...records.values()].sort((a, b) => a.created_at - b.created_at);
}

function latestTraceRecord(previous: TraceRecord, incoming: TraceRecord): TraceRecord {
  const previousTerminal = isTerminalTraceStatus(previous.status);
  const incomingTerminal = isTerminalTraceStatus(incoming.status);
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
    (left.task_id === right.task_id &&
      left.trace_id === right.trace_id &&
      left.parent_task_id === right.parent_task_id &&
      left.name === right.name &&
      left.kind === right.kind &&
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

export function isTerminalTraceStatus(status: string) {
  return (
    status === "completed" ||
    status === "failed" ||
    status === "cancelled" ||
    status === "success" ||
    status === "error" ||
    status === "done"
  );
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
    if (!trace.parent_task_id) {
      continue;
    }
    const children = childrenByParent.get(trace.parent_task_id) ?? [];
    children.push(trace.task_id);
    childrenByParent.set(trace.parent_task_id, children);
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

function isDeletedTask(
  trace: TraceRecord,
  _records: Map<string, TraceRecord>,
  deletedTaskIds: Set<string> | undefined,
) {
  return deletedTaskIds?.has(trace.task_id) ?? false;
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
    currentId = byId.get(currentId)?.parent_task_id ?? null;
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

    if (item.event === "trace:init" && payload.snapshot === true) {
      if (summaries.size > 0) {
        summaries.clear();
        changed = true;
      }
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
    ? mergeSummaryArchive(
        incoming,
        archivedTracesForSummary(existing),
        existing.archived_groups ?? [],
      )
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
  const statuses = countStatuses(ordered);
  const lines = [
    options.title ?? "WEBRTC ASYNC RUNTIME TRACE",
    `view=${view}`,
    `trace_count=${ordered.length} root_count=${roots.length}`,
    `statuses=${statuses || "-"}`,
  ];

  if (summary) {
    lines.push(
      [
        "summary",
        `id=${summary.summary_id}`,
        `deleted_task_id=${summary.deleted_task_id}`,
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
    nodes.set(trace.task_id, { trace, children: [] });
  }

  const roots: TraceTreeNode[] = [];
  for (const trace of traces) {
    const node = nodes.get(trace.task_id);
    if (!node) {
      continue;
    }
    const parent = trace.parent_task_id ? nodes.get(trace.parent_task_id) : null;
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
    `task_id=${trace.task_id}`,
    `trace_id=${trace.trace_id}`,
    `parent_task_id=${trace.parent_task_id ?? "-"}`,
    `kind=${trace.kind}`,
    `status=${trace.status}`,
    `duration_ms=${formatMaybeNumber(trace.duration_ms)}`,
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
    `- task=${trace.task_id}`,
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
