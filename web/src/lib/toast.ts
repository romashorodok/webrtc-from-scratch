export type TraceDeleteResultPayload = {
  success?: boolean;
  task_id?: string;
  task_ids?: string[];
  reason?: string | null;
  failed_task_ids?: string[];
};

export function traceDeleteFailureMessage(payload: TraceDeleteResultPayload): string {
  const failedCount = payload.failed_task_ids?.length ?? 0;
  if (payload.reason === "non_cancelable_path") {
    if (failedCount > 0) {
      return `Cannot delete task right now: ${failedCount} running task(s) are non-cancelable.`;
    }
    return "Cannot delete task right now: it has non-cancelable running work.";
  }
  if (payload.reason === "task_not_found") {
    return "Task is already gone.";
  }
  if (payload.reason === "cancellation_rejected") {
    return "Task cancellation was rejected by the runtime.";
  }
  return "Trace deletion was rejected.";
}
