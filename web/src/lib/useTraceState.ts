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
  trace?: TraceRecord;
  traces?: TraceRecord[];
};

const TRACE_FLUSH_INTERVAL_MS = 90;

export function useTraceState() {
  const [state, dispatch] = useReducer(
    reduceTraceState,
    undefined,
    createInitialTraceState,
  );
  const queueRef = useRef<QueuedTraceEvent[]>([]);
  const frameRef = useRef<number | null>(null);
  const timeoutRef = useRef<number | null>(null);

  const flush = useCallback(() => {
    frameRef.current = null;
    timeoutRef.current = null;
    const queued = queueRef.current.splice(0);
    if (queued.length === 0) {
      return;
    }

    dispatch({ type: "events", events: queued });
  }, []);

  const enqueueTraceEvent = useCallback(
    (event: string, data: unknown) => {
      const previous = queueRef.current[queueRef.current.length - 1];
      if (event === "trace:update" && previous?.event === "trace:update") {
        previous.data = mergeTraceUpdatePayloads(previous.data, data);
      } else {
        queueRef.current.push({ event, data });
      }
      if (frameRef.current != null || timeoutRef.current != null) {
        return;
      }

      const flushOnNextFrame =
        event === "trace:init" || event === "trace:delete" || event === "trace:delete_result";

      if (flushOnNextFrame) {
        frameRef.current = window.requestAnimationFrame(flush);
        return;
      }

      timeoutRef.current = window.setTimeout(() => {
        frameRef.current = window.requestAnimationFrame(flush);
      }, TRACE_FLUSH_INTERVAL_MS);
    },
    [flush],
  );

  const enqueueTraceEvents = useCallback(
    (events: QueuedTraceEvent[]) => {
      for (const event of events) {
        const previous = queueRef.current[queueRef.current.length - 1];
        if (event.event === "trace:update" && previous?.event === "trace:update") {
          previous.data = mergeTraceUpdatePayloads(previous.data, event.data);
        } else {
          queueRef.current.push(event);
        }
      }
      if (frameRef.current != null || timeoutRef.current != null) {
        return;
      }
      frameRef.current = window.requestAnimationFrame(flush);
    },
    [flush],
  );

  useEffect(
    () => () => {
      if (frameRef.current != null) {
        window.cancelAnimationFrame(frameRef.current);
      }
      if (timeoutRef.current != null) {
        window.clearTimeout(timeoutRef.current);
      }
    },
    [],
  );

  return { enqueueTraceEvent, enqueueTraceEvents, summaries: state.summaries, traces: state.traces };
}

function mergeTraceUpdatePayloads(previousData: unknown, nextData: unknown) {
  const previous = parseJson<TraceUpdatePayload>(previousData);
  const next = parseJson<TraceUpdatePayload>(nextData);
  if (!previous || !next) {
    return nextData;
  }

  const traces = new Map<string, TraceRecord>();
  for (const trace of traceRecordsForPayload(previous)) {
    traces.set(trace.trace_id, trace);
  }
  for (const trace of traceRecordsForPayload(next)) {
    traces.set(trace.trace_id, trace);
  }

  return {
    ...previous,
    ...next,
    trace: undefined,
    traces: [...traces.values()],
  };
}

function traceRecordsForPayload(payload: TraceUpdatePayload) {
  return [
    ...(payload.traces ?? []),
    ...(payload.trace ? [payload.trace] : []),
  ];
}
