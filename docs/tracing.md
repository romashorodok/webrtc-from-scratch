# Trace Viewer Product Requirements

## Purpose

The trace viewer helps a developer understand what the WebRTC runtime is doing during a live session. It should show active work, elapsed time, repeated operation groups, failures, and deleted history without confusing the live tree.

The viewer is primarily for debugging long-running peer sessions, media loops, ICE, DTLS, SRTP, and background/offloaded tasks.

## User Goals

A user should be able to:

- See which tasks are currently running.
- See elapsed time update while tasks are still running.
- Delete noisy traces from the live tree without losing useful history.
- Continue seeing updates for deleted running traces in the deleted/archive view.
- Restore or append deleted running subtrees when they still belong under a visible parent.
- Restore deleted running traces when a later heartbeat proves they are still active.
- Understand repeated operations as grouped work, not thousands of separate noisy rows.
- Export a readable snapshot of either the live tree or a deleted trace archive.

## Core Concepts

### Live Tree

The live tree is the main trace view. It contains traces that are currently visible to the user.

The live tree should prioritize active work:

- Running roots should show elapsed time.
- Running children should stay visible under their parent.
- Completed hidden parents should not clutter the tree.
- If a completed hidden parent has running children, the running children should still be shown under the nearest useful visible ancestor.

### Deleted Archive

When the user deletes a trace, it moves out of the live tree and into a deleted archive.

Deleting does not mean "forget forever." It means:

- hide it from the live tree;
- keep enough history to inspect or export it;
- keep its delete-time summary stable;
- allow the live tree to restore if the underlying task is still running.

### Groups

Some operations happen many times, such as packet encryption or socket sends. These should be shown as groups when appropriate.

A group should show:

- call count;
- average duration;
- current status;
- failure information if relevant.

Group information must not be overwritten by simple elapsed-time updates.

Deleted archive group information is a snapshot. Once the user clicks Delete, archive averages and counters stay at the delete-time values. Heartbeats may restore and update the live tree, but they must not keep changing deleted archive averages.

## Functional Requirements

### 1. Live Elapsed Time

Running traces must update their elapsed duration without waiting for the task to finish.

Expected behavior:

- A running peer root, such as `PeerContext-*`, shows elapsed time.
- Long-running loops, such as `ws:av1-write-loop`, show elapsed time.
- The selected trace detail panel shows the same live duration.
- Compact export should show elapsed time for running non-group traces.

Acceptance criteria:

- A running trace duration increases over time.
- Updating duration does not mark the trace complete.
- Updating duration does not add noisy lifecycle history entries.

### 2. Trace Deletion

When a user deletes a trace, the trace should disappear from the live tree immediately.

Expected behavior:

- Deleted traces are removed from the live tree.
- Deleted descendants are also removed.
- A deleted archive is created so the user can still inspect the deleted trace.
- If the deleted trace was running, its current elapsed duration is preserved in the archive.

Acceptance criteria:

- The live tree no longer shows the deleted trace.
- The deleted archive contains the deleted trace and known descendants.
- The deleted archive shows a non-empty duration for deleted running traces.

### 3. Deleted Running Traces Keep Updating

If a trace is deleted while it is still running, the viewer should continue receiving updates for that trace.

Expected behavior:

- The trace remains hidden from the live tree.
- The deleted archive preserves delete-time group averages and counters.
- Running heartbeats can restore and update the live tree with current duration/status.
- When the task completes, the deleted archive updates to the terminal status.

Acceptance criteria:

- Deleting a running root does not stop updates for its archive.
- Deleted archive averages and counters do not change after deletion.
- Restored live traces can continue changing while the task is still running.
- Completion/failure after deletion updates the archived trace.

### 4. Restore And Append Behavior

The viewer must support restoring or appending deleted running traces when they still belong under a visible live parent.

Expected behavior:

- If a child subtree is deleted but the parent remains visible, a later running update for that child can restore the child path under the visible parent.
- Restored records should keep their correct parent relationship.
- Archive metadata should remain available for export/history.

Acceptance criteria:

- Deleting a child subtree under a visible parent does not permanently block running child updates.
- A later running update restores/appends the subtree under the visible parent.
- Restored live records do not carry deleted/archive-only metadata into the live display.

### 5. Deleted Root Behavior

Deleting a root trace is different from deleting a child subtree.

Expected behavior:

- Deleting a root hides it immediately.
- If a later running heartbeat arrives for the root or one of its running descendants, the root path should be restored into the live tree.
- The restored records should be replaced from the latest heartbeat/archive state, not merged in a way that keeps stale delete-time duration or group values.
- Completed late updates should patch the deleted archive only.

Acceptance criteria:

- Deleting a running root can temporarily leave the live tree empty.
- A later running heartbeat restores the root path into the live tree.
- The live tree updates with the latest heartbeat information.
- The deleted archive keeps delete-time averages/counters while preserving terminal status when completion arrives.
- Completed late updates do not restore the root.

### 6. Completed Hidden Parents

Completed parent traces should not make the live tree noisy.

Expected behavior:

- Completed late updates stay archived when their parent/root was deleted.
- Running children can still be shown if there is a visible anchor.
- If the late update is completed and has no running heartbeat, the update stays in the deleted archive.

Acceptance criteria:

- Completed late updates do not restore deleted traces into the live tree.
- Running children are not lost when they can be attached to a visible parent.
- Deleted-root late children restore the live root only when they are running.

### 7. Group Display

Repeated task groups must stay readable and stable.

Expected behavior:

- Groups show call count and average duration before raw elapsed duration.
- Heartbeat updates must not erase group metadata.
- Live restored groups should update from heartbeat group metadata.
- Deleted archives should preserve group information as it was when Delete was clicked.

Acceptance criteria:

- A grouped trace displays like `N calls avg=Xms`.
- Live group call count and average duration remain current after heartbeat updates.
- Deleted group archives keep the same group summary information from delete time.

### 8. Export Behavior

The export should reflect the same logical view the user sees.

Expected behavior:

- Live export contains the current visible live tree.
- Deleted export contains the selected deleted archive.
- Compact export follows the same label priority as the UI:
  - groups show calls and average duration;
  - running non-group traces show elapsed time;
  - running traces without duration show `running`.

Acceptance criteria:

- Exported live traces include a deleted root again if a running heartbeat restored it.
- Exported deleted archives preserve delete-time averages/counters.
- Exported deleted archives can still show terminal status after completion/failure.
- Compact export stays readable for large trees.

## Event Requirements

The backend should provide trace events that allow the frontend to satisfy the product behavior.

Required events:

- Initial trace snapshot for the session.
- Live trace updates.
- Terminal trace updates.
- Delete notifications.
- Deleted archive/summary updates.

Required backend behavior:

- Running traces send periodic updates while active.
- Deleted running traces continue to send updates for archive refresh.
- Visible snapshots exclude traces hidden by deletion.
- Running snapshots include hidden deleted running traces so their archives stay fresh.

## Frontend State Requirements

The frontend should maintain three logical collections:

- visible live traces;
- deleted summaries/archives;
- ids that should remain hidden from live view.

Reducer behavior:

- Delete events remove traces from the live tree immediately.
- Summary/archive events preserve deleted history.
- Late updates for deleted traces may patch archived status/duration, but not archived group averages/counters.
- Late running updates restore into the live tree only when there is a visible parent/anchor.
- Running heartbeat updates for deleted roots restore them; completed late updates stay archived.

## Non-Goals

The trace viewer does not need to:

- persist trace history across browser refreshes;
- show every heartbeat as a separate timeline entry;
- restore completed deleted roots automatically without a running heartbeat;
- treat deletion as cancellation of the underlying task.

## Acceptance Checklist

Before changing trace behavior, verify:

- Running root durations update live.
- Running loop durations update live.
- Deleting a running child subtree hides it, then can restore it under a visible parent.
- Deleting a running root hides it, then a running heartbeat restores it as a live root.
- Deleted root archives keep delete-time group averages/counters.
- Live restored traces keep latest heartbeat values.
- Completed late updates remain archived.
- Live group labels keep current call count and average duration.
- Deleted group labels keep delete-time call count and average duration.
- Compact export shows elapsed time for running non-group roots.
- Deleted export includes current archived durations/statuses.
- Tests cover backend snapshots, heartbeat behavior, deletion, restore, archive updates, and frontend reducer behavior.
