import { useCallback, useEffect, useReducer, useRef } from "react";
import {
  createInitialTraceState,
  reduceTraceState,
} from "./trace";

type QueuedTraceEvent = {
  event: string;
  data: unknown;
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
      queueRef.current.push({ event, data });
      if (frameRef.current != null || timeoutRef.current != null) {
        return;
      }

      const flushOnNextFrame =
        event === "trace:init" || event === "trace:delete" || event === "trace:summary";

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

  return { enqueueTraceEvent, summaries: state.summaries, traces: state.traces };
}
