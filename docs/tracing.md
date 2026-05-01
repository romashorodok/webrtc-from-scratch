# Trace Viewer Product Requirements

## Purpose

The trace viewer helps a developer understand what the WebRTC runtime is doing during a live session. It shows active work, elapsed time, repeated operation groups, failures, and client-local deleted history without confusing the live tree.

The viewer is primarily for debugging long-running peer sessions, media loops, ICE, DTLS, SRTP, and background/offloaded tasks.

## User Goals

A user should be able to:

- See which tasks are currently running.
- See elapsed time update while tasks are still running.
- Delete noisy traces from the live tree while still inspecting deleted snapshots.
- Understand repeated operations as grouped work, not thousands of separate noisy rows.
- Export a readable snapshot of either the live tree or a deleted trace archive.

## Core Concepts

### Live Tree

The live tree is the main trace view. It contains traces currently visible to the user.

The live tree prioritizes active work:

- Running roots show elapsed time.
- Running children stay visible under their parent.
- Completed/failed/cancelled traces are pruned from live state immediately.
- If a completed parent had live children, those children are reattached to the nearest visible ancestor (parent back-propagation).

### Deleted Archive

When a user deletes a trace, it moves out of the live tree and into a deleted archive snapshot.

Deleting means:

- hide from live tree;
- keep enough delete-time history to inspect/export;
- keep delete-time group summary stable;
- keep deleted archive client-local (no backend archive persistence).

### Groups

Some operations happen many times and should be shown as groups when appropriate.

A group should show:

- call count;
- average duration;
- current status;
- failure information if relevant.

Deleted archive group information is frozen at delete-time.

## Functional Requirements

### 1. Live Elapsed Time

Running traces update elapsed duration before task completion.

Expected behavior:

- Running peer roots (for example `PeerContext-*`) show elapsed time.
- Long-running loops (for example `ws:av1-write-loop`) show elapsed time.
- Detail panel reflects current live duration.
- Compact export shows elapsed time for running non-group traces.

Acceptance criteria:

- Running trace duration increases over time.
- Duration updates do not mark trace complete.
- Duration updates do not add noisy lifecycle entries.

### 2. Trace Deletion

When a user deletes a trace, it disappears from live tree immediately after successful delete.

Expected behavior:

- Delete targets full subtree.
- Delete first attempts to cancel running tasks in subtree.
- Running `kind="thread"` traces are non-cancelable by default.
- Running non-thread traces are cancelable by default.
- `metadata.trace_group=true` traces are explicitly treated as cancelable.
- If cancellation eligibility check fails for any running non-cancelable path, nothing is removed.
- On success, deleted snapshot is available in deleted archive view.

Acceptance criteria:

- Successful delete removes root and descendants from live tree.
- Failed delete keeps live tree unchanged.
- Deleted archive contains deleted target and known descendants from delete-time snapshot.

### 3. Deleted Trace Tombstones And Archive Freeze

Expected behavior:

- Deleted traces are tombstoned from live view.
- Deleted archive preserves delete-time group counters/averages.
- Late updates do not resurrect tombstoned traces.
- Late updates do not mutate archived snapshot metrics/counters.

Acceptance criteria:

- Deleted archive averages/counters do not change after deletion.
- Late trace updates do not restore deleted traces into live state.

### 4. Restore And Append Behavior

Current behavior does not restore deleted running traces back into live view.

Expected behavior:

- Parent-repair is applied only for currently visible live traces and archived ancestry context.
- Deleted/tombstoned traces remain deleted.

Acceptance criteria:

- Late running update for deleted subtree does not re-append subtree into live tree.
- Visible live traces keep valid parent links after completed parent prune.

### 5. Deleted Root Behavior

Current behavior does not auto-restore deleted roots from heartbeat.

Expected behavior:

- Deleting a root removes it from live tree on success.
- Later updates for deleted root remain blocked from live resurrection.
- Deleted archive remains inspectable.

Acceptance criteria:

- Successful root delete can leave live tree empty.
- Deleted root is not auto-restored by late heartbeat.

### 6. Completed Hidden Parents

Completed parents should not clutter live tree.

Expected behavior:

- Terminal traces are pruned from live immediately.
- Live children of a pruned parent are re-parented upward.
- Completed late updates for deleted traces remain non-live.

Acceptance criteria:

- Completed parent disappears from live tree.
- Live descendants remain reachable through re-parenting.

### 7. Group Display

Repeated task groups must stay readable and stable.

Expected behavior:

- Groups display call count and average duration.
- Heartbeats/updates preserve live group metadata.
- Deleted archives preserve group metadata as captured at delete-time.

Acceptance criteria:

- Group labels render like `N calls | avg Xms`.
- Deleted archive group counters/averages stay frozen.

### 8. Export Behavior

Export reflects selected view.

Expected behavior:

- Live export contains current visible live tree.
- Deleted export contains selected deleted archive snapshot.
- Compact export label priority:
  - groups show calls + average duration;
  - running non-group traces show elapsed time;
  - running traces without duration show `running`.

Acceptance criteria:

- Exported live tree matches visible live hierarchy.
- Exported deleted archive preserves delete-time group summary values.

## Event Requirements

The backend provides events required by frontend behavior.

Required events:

- `trace:init` (live traces only; payload may provide full `traces` snapshot or single `trace`)
- `trace:update`
- `trace:complete`
- `trace:delete`
- `trace:delete_result`
- batched transport via `trace:batch`

Required backend behavior:

- Running traces send periodic updates while active.
- Terminal traces are auto-pruned and emit delete with `auto_prune=true`.
- Delete uses all-or-nothing cancelability gating.
- `trace:delete_result` semantics:
  - `success=false` with `reason="trace_not_found"` when delete target is missing.
  - `success=false` with `reason="non_cancelable_path"` and non-empty `failed_trace_ids` when running non-cancelable traces block delete.
  - `success=false` with `reason="delete_failed"` for unexpected delete failure after cancel pass.
  - `success=true` returns removed `trace_ids`.

## Frontend State Requirements

The frontend maintains three logical collections:

- visible live traces;
- deleted summaries/archives (client-local);
- tombstoned deleted trace ids.

Reducer behavior:

- Delete events remove traces from live immediately.
- Delete events synthesize client-local deleted snapshots for manual delete and `auto_prune=true` terminal-prune paths.
- Late updates for deleted traces do not resurrect live traces.
- Archived group counters/averages remain frozen.
- `trace:init` with `traces` refreshes the live set and resets tombstoned ids.
- `trace:init` with single `trace` is treated as a live upsert.
- `trace:init` refresh keeps in-session deleted snapshots/archives client-local.

## Non-Goals

The trace viewer does not need to:

- persist deleted archive across browser refreshes;
- use backend-persisted deleted archive history;
- restore deleted roots/subtrees automatically from late heartbeat;
- depend on backend `trace:summary` for correctness.

## Acceptance Checklist

Before changing trace behavior, verify:

- Running root durations update live.
- Running loop durations update live.
- Terminal traces are pruned immediately from live.
- Completed parent prune reattaches live children to nearest visible ancestor.
- Deleting a cancellable running subtree succeeds and removes it.
- Deleting subtree with active non-cancelable path fails atomically with `trace:delete_result(success=false, reason, failed_trace_ids)`.
- Failed delete keeps live tree unchanged.
- Deleted archive snapshots are synthesized from `trace:delete` events (manual delete and `auto_prune=true`).
- Late updates do not resurrect tombstoned deleted traces.
- Deleted archive group counters/averages remain frozen.
- `trace:delete_result` is handled both direct and inside `trace:batch.events`.
- Tests cover backend prune/delete semantics and frontend reducer race/tombstone behavior.
