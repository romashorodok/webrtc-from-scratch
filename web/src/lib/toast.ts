export type TraceDeleteResultPayload = {
  success?: boolean;
  trace_id?: string;
  trace_ids?: string[];
  reason?: string | null;
  failed_trace_ids?: string[];
};

export function traceDeleteFailureMessage(payload: TraceDeleteResultPayload): string {
  const failedCount = payload.failed_trace_ids?.length ?? 0;
  if (payload.reason === "non_cancelable_path") {
    if (failedCount > 0) {
      return `Cannot delete trace right now: ${failedCount} running task(s) are non-cancelable (thread/offload).`;
    }
    return "Cannot delete trace right now: it has non-cancelable running work.";
  }
  if (payload.reason === "trace_not_found") {
    return "Trace is already gone.";
  }
  if (payload.reason === "delete_failed") {
    return "Trace deletion failed. Try again.";
  }
  return "Trace deletion was rejected.";
}
