import { useCallback, useEffect, useReducer, useRef } from "react";
import {
  createInitialTraceState,
  reduceTraceState,
  type TraceRecord,
} from "./trace";
import { parseJson } from "./media";

type QueuedTraceEvent = {
  event: string;
  data: unknown;
};

type TraceUpdatePayload = {
  tasks?: TraceRecord[];
  snapshot?: boolean;
  task_id?: string;
  task_ids?: string[];
};

export const TERMINAL_TASK_RETENTION_MS = 5_000;

export function useTraceState() {
  const [state, dispatch] = useReducer(
    reduceTraceState,
    undefined,
    createInitialTraceState,
  );
  const terminalDeleteTimers = useRef(new Map<string, number>());

  const cancelTerminalTimers = useCallback(() => {
    for (const timer of terminalDeleteTimers.current.values()) {
      window.clearTimeout(timer);
    }
    terminalDeleteTimers.current.clear();
  }, []);

  const scheduleTerminalDelete = useCallback((taskId: string) => {
    const previous = terminalDeleteTimers.current.get(taskId);
    if (previous != null) {
      window.clearTimeout(previous);
    }
    const timer = window.setTimeout(() => {
      terminalDeleteTimers.current.delete(taskId);
      dispatch({
        type: "events",
        events: [{ event: "trace:delete", data: { task_ids: [taskId], auto_prune: true } }],
      });
    }, TERMINAL_TASK_RETENTION_MS);
    terminalDeleteTimers.current.set(taskId, timer);
  }, []);
  const enqueueTraceEvent = useCallback(
    (event: string, data: unknown) => {
      const payload = parseJson<TraceUpdatePayload>(data);
      if (event === "trace:init" && payload?.snapshot === true) {
        cancelTerminalTimers();
      }
      if (event === "trace:complete") {
        for (const task of payload?.tasks ?? []) {
          scheduleTerminalDelete(task.task_id);
        }
      }
      if (event === "trace:delete") {
        const taskIds = payload?.task_ids ?? (payload?.task_id ? [payload.task_id] : []);
        const immediateTaskIds = taskIds.filter(
          (taskId) => !terminalDeleteTimers.current.has(taskId),
        );
        if (taskIds.length > 0 && immediateTaskIds.length === 0) {
          return;
        }
        if (immediateTaskIds.length !== taskIds.length) {
          data = { ...payload, task_id: undefined, task_ids: immediateTaskIds };
        }
      }
      dispatch({ type: "events", events: [{ event, data }] });
    },
    [cancelTerminalTimers, scheduleTerminalDelete],
  );

  const enqueueTraceEvents = useCallback(
    (events: QueuedTraceEvent[]) => {
      for (const event of events) {
        enqueueTraceEvent(event.event, event.data);
      }
    },
    [enqueueTraceEvent],
  );

  useEffect(() => cancelTerminalTimers, [cancelTerminalTimers]);

  return {
    enqueueTraceEvent,
    enqueueTraceEvents,
    performanceEvents: state.performanceEvents,
    groups: state.groups ?? [],
    summaries: state.summaries,
    tasks: state.tasks ?? [],
  };
}

export function mergeTraceUpdatePayloads(previousData: unknown, nextData: unknown) {
  const previous = parseJson<TraceUpdatePayload>(previousData);
  const next = parseJson<TraceUpdatePayload>(nextData);
  if (!previous || !next) {
    return nextData;
  }

  const tasks = new Map<string, TraceRecord>();
  for (const task of traceRecordsForPayload(previous)) {
    tasks.set(task.task_id, task);
  }
  for (const task of traceRecordsForPayload(next)) {
    tasks.set(task.task_id, task);
  }

  return {
    ...previous,
    ...next,
    tasks: [...tasks.values()],
  };
}

export function traceEventsFromBatch(data: unknown): QueuedTraceEvent[] {
  const payload = parseJson<{ events?: Array<{ event?: unknown; data?: unknown }> }>(data);
  return (payload?.events ?? [])
    .filter((event): event is { event: string; data: unknown } =>
      typeof event.event === "string",
    )
    .map((event) => ({ event: event.event, data: event.data }));
}

function traceRecordsForPayload(payload: TraceUpdatePayload) {
  return payload.tasks ?? [];
}
