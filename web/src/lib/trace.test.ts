import { expect, test } from "bun:test";
import {
  applyTraceEvents,
  createInitialTraceState,
  formatTraceExport,
  reduceTraceState,
  restoreVisibleTraceParents,
  type GroupSnapshot,
  type TraceRecord,
} from "./trace";
import { groupTraceRecords } from "./TraceOverlay";

function task(
  taskId: string,
  parentTaskId: string | null = null,
  options: Partial<TraceRecord> = {},
): TraceRecord {
  return {
    trace_id: "shared-session",
    task_id: taskId,
    parent_task_id: parentTaskId,
    name: taskId,
    kind: "task",
    created_at: 1,
    started_at: 1,
    ended_at: null,
    duration_ms: null,
    status: "running",
    error: null,
    metadata: {},
    ...options,
  };
}

function group(taskId: string, calls: number): GroupSnapshot {
  return {
    trace_id: "shared-session",
    task_id: taskId,
    group: "runtime",
    operation: "work",
    calls,
    successes: calls,
    cancellations: 0,
    errors: 0,
    total_duration_ms: calls,
    average_duration_ms: 1,
    min_duration_ms: 1,
    max_duration_ms: 1,
    latest_failure_class: null,
  };
}

test("snapshot init replaces stale state while ordinary init appends tasks", () => {
  const stale = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{ event: "trace:init", data: { snapshot: true, tasks: [task("stale")] } }],
  });
  const snapshot = reduceTraceState(stale, {
    type: "events",
    events: [{ event: "trace:init", data: { snapshot: true, tasks: [task("root")] } }],
  });
  const appended = reduceTraceState(snapshot, {
    type: "events",
    events: [{ event: "trace:init", data: { tasks: [task("child", "root")] } }],
  });

  expect(snapshot.tasks.map((item) => item.task_id)).toEqual(["root"]);
  expect(appended.tasks.map((item) => item.task_id)).toEqual(["root", "child"]);
});

test("multiple tasks sharing one trace id retain distinct task identity", () => {
  const state = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{
      event: "trace:init",
      data: { snapshot: true, tasks: [task("one"), task("two")] },
    }],
  });

  expect(state.tasks).toHaveLength(2);
  expect(state.tasksById.get("one")?.trace_id).toBe("shared-session");
  expect(state.tasksById.get("two")?.trace_id).toBe("shared-session");
});

test("updates merge by task id instead of correlation trace id", () => {
  const initialized = applyTraceEvents([], [{
    event: "trace:init",
    data: { snapshot: true, tasks: [task("one"), task("two")] },
  }]);
  const updated = applyTraceEvents(initialized, [{
    event: "trace:update",
    data: { tasks: [task("two", null, { duration_ms: 25 })] },
  }]);

  expect(updated).toHaveLength(2);
  expect(updated.find((item) => item.task_id === "two")?.duration_ms).toBe(25);
});

test("repeated snapshots keep only the latest state for each task id", () => {
  const snapshots = applyTraceEvents([], [
    { event: "trace:update", data: { tasks: [task("one", null, { duration_ms: 1 })] } },
    { event: "trace:update", data: { tasks: [task("one", null, { duration_ms: 2 })] } },
    { event: "trace:update", data: { tasks: [task("one", null, { duration_ms: 3 })] } },
  ]);

  expect(snapshots).toHaveLength(1);
  expect(snapshots[0]?.duration_ms).toBe(3);
});

test("grouped view collapses dense distinct leaf tasks into one stable virtual node", () => {
  const root = task("root");
  const leaves = Array.from({ length: 20 }, (_, index) =>
    task(`leaf-${index}`, "root", { name: `operation-${index}`, kind: "offload" }),
  );
  const first = groupTraceRecords([root, ...leaves]);
  const second = groupTraceRecords([root, ...leaves, task("leaf-20", "root", {
    name: "operation-20",
    kind: "offload",
  })]);

  expect(first).toHaveLength(2);
  expect(first[1]?.metadata.ui_group).toBe(true);
  expect(first[1]?.metadata.call_count).toBe(20);
  expect(second[1]?.task_id).toBe(first[1]?.task_id);
});

test("parent promotion uses parent_task_id", () => {
  const root = task("root");
  const parent = task("parent", "root", { status: "completed" });
  const child = task("child", "parent");
  const summaryState = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [
      { event: "trace:init", data: { snapshot: true, tasks: [root, parent, child] } },
      { event: "trace:complete", data: { tasks: [parent] } },
      { event: "trace:delete", data: { task_ids: ["parent"], auto_prune: true } },
    ],
  });
  const promoted = { ...child, parent_task_id: null };
  const visible = restoreVisibleTraceParents([root, promoted], summaryState.summaries);

  expect(visible.find((item) => item.task_id === "child")?.parent_task_id).toBe("root");
});

test("late updates cannot resurrect deleted task ids", () => {
  const deleted = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [
      { event: "trace:init", data: { snapshot: true, tasks: [task("root"), task("child", "root")] } },
      { event: "trace:delete", data: { task_ids: ["child"] } },
    ],
  });
  const late = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { tasks: [task("child", "root")] } }],
  });

  expect(late.tasks.map((item) => item.task_id)).toEqual(["root"]);
});

test("complete and delete freeze an immutable local archive", () => {
  const running = task("child", "root", { duration_ms: 5 });
  const completed = task("child", "root", {
    status: "completed",
    ended_at: 2,
    duration_ms: 100,
  });
  const deleted = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [
      { event: "trace:init", data: { snapshot: true, tasks: [task("root"), running] } },
      { event: "trace:complete", data: { tasks: [completed] } },
      { event: "trace:delete", data: { task_ids: ["child"], auto_prune: true } },
    ],
  });
  const late = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { tasks: [task("child", "root", { duration_ms: 999 })] } }],
  });

  expect(late.summaries[0]?.deleted_task?.duration_ms).toBe(100);
  expect(late.summaries[0]?.archived_tasks?.find((item) => item.task_id === "child")?.status)
    .toBe("completed");
});

test("terminal snapshots remain until the retention delete is applied", () => {
  const completed = task("done", "root", {
    status: "completed",
    ended_at: 2,
    duration_ms: 100,
  });
  const state = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [
      { event: "trace:init", data: { snapshot: true, tasks: [task("root"), task("done", "root")] } },
      { event: "trace:complete", data: { tasks: [completed] } },
    ],
  });

  expect(state.tasks.map((item) => item.task_id)).toEqual(["root", "done"]);
  expect(state.deletedTaskIds.has("done")).toBe(false);
  expect(state.summaries[0]?.deleted_task?.status).toBe("completed");

  const expired = reduceTraceState(state, {
    type: "events",
    events: [{ event: "trace:delete", data: { task_id: "done", auto_prune: true } }],
  });
  expect(expired.tasks.map((item) => item.task_id)).toEqual(["root"]);
});

test("retention deletes observed-node success and error outcomes", () => {
  const remaining = applyTraceEvents(
    [task("success-node"), task("error-node"), task("running-node")],
    [{
      event: "trace:complete",
      data: {
        tasks: [
          task("success-node", null, { status: "success", ended_at: 2 }),
          task("error-node", null, { status: "error", ended_at: 2 }),
        ],
      },
    }, {
      event: "trace:delete",
      data: { task_ids: ["success-node", "error-node"], auto_prune: true },
    }],
  );

  expect(remaining.map((item) => item.task_id)).toEqual(["running-node"]);
});

test("group snapshots are retained and frozen with local archives", () => {
  const initialized = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [{
      event: "trace:init",
      data: { snapshot: true, tasks: [task("root")], groups: [group("root", 3)] },
    }],
  });
  const deleted = reduceTraceState(initialized, {
    type: "events",
    events: [{ event: "trace:delete", data: { task_id: "root" } }],
  });
  const newerGroups = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:update", data: { tasks: [], groups: [group("root", 9)] } }],
  });

  expect(newerGroups.groups[0]?.calls).toBe(9);
  expect(newerGroups.summaries[0]?.archived_groups?.[0]?.calls).toBe(3);
});

test("task-centric export builds the tree and retains trace correlation", () => {
  const output = formatTraceExport([task("root"), task("child", "root")]);

  expect(output).toContain("task_id=root trace_id=shared-session parent_task_id=-");
  expect(output).toContain("  - child task_id=child");
  expect(output).toContain("- task=root");
});

test("snapshot clears task tombstones so a new session may reuse ids", () => {
  const deleted = reduceTraceState(createInitialTraceState(), {
    type: "events",
    events: [
      { event: "trace:init", data: { snapshot: true, tasks: [task("same")] } },
      { event: "trace:delete", data: { task_id: "same" } },
    ],
  });
  const reset = reduceTraceState(deleted, {
    type: "events",
    events: [{ event: "trace:init", data: { snapshot: true, tasks: [task("same")] } }],
  });

  expect(reset.tasks.map((item) => item.task_id)).toEqual(["same"]);
  expect(reset.deletedTaskIds.size).toBe(0);
});
