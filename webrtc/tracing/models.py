from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TaskTrace:
    trace_id: str
    task_id: str
    parent_task_id: str | None
    name: str
    kind: str
    created_at: float = field(default_factory=time.time)
    created_monotonic_ns: int = field(default_factory=time.monotonic_ns)
    started_at: float | None = None
    started_monotonic_ns: int | None = None
    ended_at: float | None = None
    ended_monotonic_ns: int | None = None
    duration_ms: float | None = None
    status: str = "created"
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    transitions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "parent_task_id": self.parent_task_id,
            "name": self.name,
            "kind": self.kind,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error": self.error,
            "metadata": dict(self.metadata),
            "transitions": [dict(item) for item in self.transitions],
        }


@dataclass(slots=True)
class TraceNode:
    node_id: int
    context: TaskTrace
    parent: int | None
    first_child: int | None = None
    last_child: int | None = None
    prev_sibling: int | None = None
    next_sibling: int | None = None
    prev_root: int | None = None
    next_root: int | None = None

    @property
    def task_id(self) -> str:
        return self.context.task_id
