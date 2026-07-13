import { useCallback, useEffect, useReducer, useRef } from "react";
import { createInitialTraceState, reduceTraceState } from "./trace";

export type TraceResyncRequest = {
  trace_id: string | null;
  sequence: number | null;
  reason: string | null;
};

export function useTraceState(onResyncRequest?: (request: TraceResyncRequest) => void) {
  const [state, dispatch] = useReducer(reduceTraceState, undefined, createInitialTraceState);
  const onResyncRequestRef = useRef(onResyncRequest);
  onResyncRequestRef.current = onResyncRequest;

  const enqueueTraceBatch = useCallback((data: unknown) => {
    dispatch({ type: "events", events: [{ event: "trace:batch", data }] });
  }, []);
  const enqueueTraceSnapshot = useCallback((data: unknown) => {
    dispatch({ type: "events", events: [{ event: "trace:snapshot", data }] });
  }, []);
  const enqueueTraceResyncRequired = useCallback((data: unknown) => {
    dispatch({ type: "events", events: [{ event: "trace:resync_required", data }] });
  }, []);

  useEffect(() => {
    if (state.resyncRequestVersion === 0) return;
    onResyncRequestRef.current?.({
      trace_id: state.traceId,
      sequence: state.sequence,
      reason: state.resyncReason,
    });
  }, [state.resyncRequestVersion, state.traceId, state.sequence, state.resyncReason]);

  return {
    enqueueTraceBatch,
    enqueueTraceSnapshot,
    enqueueTraceResyncRequired,
    machinesById: state.machinesById,
    controlsById: state.controlsById,
    groupsById: state.groupsById,
    facetsById: state.facetsById,
    capturesById: state.capturesById,
    operationNamesById: state.operationNamesById,
    topologyVersion: state.topologyVersion,
    valueVersion: state.valueVersion,
    diagnostics: state.diagnostics,
    resyncRequired: state.resyncRequired,
  };
}
