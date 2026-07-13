import { expect, test } from "bun:test";
import { mergeTraceUpdatePayloads, traceEventsFromBatch } from "./useTraceState";
import { traceDeleteFailureMessage } from "./toast";

function task(taskId: string, duration: number) {
  return {
    trace_id: "shared",
    task_id: taskId,
    parent_task_id: null,
    name: taskId,
    kind: "task",
    created_at: 1,
    started_at: 1,
    ended_at: null,
    duration_ms: duration,
    status: "running",
    error: null,
    metadata: {},
  };
}

test("queued updates merge latest snapshots by task id", () => {
  const merged = mergeTraceUpdatePayloads(
    { tasks: [task("one", 1), task("two", 1)], groups: [{ calls: 1 }] },
    { tasks: [task("two", 2)], groups: [{ calls: 2 }] },
  ) as { tasks: Array<{ task_id: string; duration_ms: number }>; groups: Array<{ calls: number }> };

  expect(merged.tasks.map((item) => [item.task_id, item.duration_ms])).toEqual([
    ["one", 1],
    ["two", 2],
  ]);
  expect(merged.groups).toEqual([{ calls: 2 }]);
});

test("batch parsing accepts only the canonical events envelope", () => {
  expect(traceEventsFromBatch({
    events: [{ event: "trace:update", data: { tasks: [task("one", 1)] } }],
  })).toHaveLength(1);
  expect(traceEventsFromBatch({ tasks: [task("legacy", 1)] })).toEqual([]);
});

test("task deletion failures describe every runtime rejection reason", () => {
  expect(traceDeleteFailureMessage({ reason: "task_not_found" })).toContain("already gone");
  expect(traceDeleteFailureMessage({
    reason: "non_cancelable_path",
    failed_task_ids: ["one"],
  })).toContain("1 running task");
  expect(traceDeleteFailureMessage({ reason: "cancellation_rejected" })).toContain("rejected");
});
