from __future__ import annotations

import time
import threading
from typing import Any, Mapping
from collections import Counter

from .arena import TraceArena
from .models import TaskTrace, TraceNode


class TraceStore:
    """Bounded live-only task tree keyed exclusively by task identity."""

    def __init__(
        self, *, context_limit: int = 4096, diagnostics: Counter[str] | None = None
    ) -> None:
        self.diagnostics: Counter[str] = diagnostics if diagnostics is not None else Counter()
        self.lock = _OwnerGuard(self.diagnostics)
        self.arena = TraceArena()
        self.context_limit = max(1, context_limit)

    def create(self, task: TaskTrace) -> bool:
        with self.lock:
            if len(self.arena.task_to_node) >= self.context_limit:
                # Live nodes are never evicted or lied about. New observation
                # admission is rejected at the hard bound and diagnosed.
                self.diagnostics["live_context_limit_rejections"] += 1
                return False
            parent_node = self.arena.get_node_id(task.parent_task_id) if task.parent_task_id else None
            if task.parent_task_id and parent_node is None:
                task.parent_task_id = None
            self.arena.add(task, parent_node)
            return True

    def update(self, task: TaskTrace) -> bool:
        with self.lock:
            node = self._node_locked(task.task_id)
            if node is None:
                return False
            node.context = task
            return True

    def remove_subtree(self, task_id: str) -> tuple[bool, list[str]]:
        with self.lock:
            node = self._node_locked(task_id)
            if node is None:
                return False, []
            ids = [item.task_id for item in self._walk_locked(node)]
            for child_id in reversed(ids):
                self.arena.remove(child_id)
            return True, ids

    def remove_only(self, task_id: str) -> tuple[bool, list[TaskTrace]]:
        with self.lock:
            node = self._node_locked(task_id)
            if node is None:
                return False, []
            parent_id = node.context.parent_task_id
            promoted_ids = self.arena.remove_and_promote_children(task_id)
            promoted: list[TaskTrace] = []
            for child_id in promoted_ids:
                child = self._context_locked(child_id)
                if child is not None:
                    child.parent_task_id = parent_id
                    promoted.append(child)
            return True, promoted

    def live_tree(self, *, trace_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            tasks = [node.context for node in self._nodes_locked() if trace_id is None or node.context.trace_id == trace_id]
        return self._snapshots(tasks, include_duration=True)

    def live_running(self, *, include_duration: bool = False, trace_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            tasks = [node.context for node in self._nodes_locked()
                     if node.context.status in {"created", "running"}
                     and (trace_id is None or node.context.trace_id == trace_id)]
        return self._snapshots(tasks, include_duration=include_duration)

    def running_signature(self, *, trace_id: str | None = None) -> tuple[tuple[str, str | None, str], ...]:
        with self.lock:
            return tuple((node.context.task_id, node.context.parent_task_id, node.context.status)
                         for node in self._nodes_locked()
                         if node.context.status in {"created", "running"}
                         and (trace_id is None or node.context.trace_id == trace_id))

    def subtree(self, task_id: str) -> list[TaskTrace]:
        with self.lock:
            return [node.context for node in self._walk_locked(self._node_locked(task_id))]

    def all_tasks(self) -> list[TaskTrace]:
        with self.lock:
            return [node.context for node in self._nodes_locked()]

    @staticmethod
    def normalize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
        return {key: value for key, value in (metadata or {}).items()
                if isinstance(key, str) and (value is None or isinstance(value, (bool, int, float, str)))}

    def _node_locked(self, task_id: str) -> TraceNode | None:
        return self.arena.get_node(self.arena.get_node_id(task_id))

    def _context_locked(self, task_id: str) -> TaskTrace | None:
        node = self._node_locked(task_id)
        return node.context if node else None

    def _nodes_locked(self) -> list[TraceNode]:
        nodes: list[TraceNode] = []
        root_id = self.arena.roots.first
        while root_id is not None:
            root = self.arena.get_node(root_id)
            if root is None:
                break
            nodes.extend(self._walk_locked(root))
            root_id = root.next_root
        return nodes

    def _walk_locked(self, root: TraceNode | None) -> list[TraceNode]:
        if root is None:
            return []
        result: list[TraceNode] = []
        stack = [root.node_id]
        while stack:
            node = self.arena.get_node(stack.pop())
            if node is None:
                continue
            result.append(node)
            children: list[int] = []
            child_id = node.first_child
            while child_id is not None:
                child = self.arena.get_node(child_id)
                if child is None:
                    break
                children.append(child.node_id)
                child_id = child.next_sibling
            stack.extend(reversed(children))
        return result

    @staticmethod
    def _snapshots(tasks: list[TaskTrace], *, include_duration: bool) -> list[dict[str, Any]]:
        now = time.monotonic_ns()
        snapshots = []
        for task in tasks:
            item = task.to_dict()
            if include_duration and task.status in {"created", "running"}:
                start = task.started_monotonic_ns or task.created_monotonic_ns
                item["duration_ms"] = max(0.0, (now - start) / 1_000_000)
            snapshots.append(item)
        return snapshots


class _OwnerGuard:
    """Context-manager-shaped loop ownership assertion, not a mutex."""

    __slots__ = ("owner", "diagnostics")

    def __init__(self, diagnostics: Counter[str]) -> None:
        self.owner: int | None = None
        self.diagnostics = diagnostics

    def __enter__(self):
        current = threading.get_ident()
        if self.owner is None:
            self.owner = current
        elif self.owner != current:
            self.diagnostics["trace_store_wrong_thread"] += 1
            raise RuntimeError("TraceStore may only be used by its owning event loop")
        return self

    def __exit__(self, exc_type, exc, tb):
        return False
