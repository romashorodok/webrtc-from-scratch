from __future__ import annotations

import time
from threading import RLock
from typing import Any, Mapping

from .arena import TraceArena
from .models import TaskContext, TraceNode


class TraceStore:
    def __init__(self, *, context_limit: int = 4096) -> None:
        self.lock = RLock()
        self.arena = TraceArena()
        self.context_limit = context_limit

    def create(self, context: TaskContext) -> None:
        with self.lock:
            parent_node = self.arena.get_node_id(context.parent_id) if context.parent_id else None
            if context.parent_id and parent_node is None:
                context.parent_id = None
            self.arena.add(context, parent_node)
            self._trim_locked()

    def start(self, context: TaskContext) -> None:
        with self.lock:
            node = self._node_by_trace_id_locked(context.trace_id)
            if node is not None:
                node.context = context

    def complete(self, context: TaskContext) -> bool:
        with self.lock:
            node = self._node_by_trace_id_locked(context.trace_id)
            if node is None:
                return False
            node.context = context
            return True

    def remove_trace_subtree(self, trace_id: str) -> tuple[bool, list[str]]:
        with self.lock:
            if self._node_by_trace_id_locked(trace_id) is None:
                return False, []
            ids = self._subtree_ids_locked(trace_id)
            for tid in ids:
                self.arena.remove(tid)
            return True, ids

    def remove_trace_only(self, trace_id: str) -> tuple[bool, list[TaskContext]]:
        with self.lock:
            node = self._node_by_trace_id_locked(trace_id)
            if node is None:
                return False, []
            parent_id = node.context.parent_id
            promoted_ids = self.arena.remove_and_promote_children(trace_id)
            promoted_contexts: list[TaskContext] = []
            for child_id in promoted_ids:
                child = self._context_by_id_locked(child_id)
                if child is not None:
                    child.parent_id = parent_id
                    promoted_contexts.append(child)
            return True, promoted_contexts

    def delete_traces(
        self,
        *,
        statuses: set[str] | None = None,
        include_running: bool = False,
    ) -> tuple[int, list[str]]:
        with self.lock:
            ids = [
                node.trace_id
                for node in self._iter_nodes_locked()
                if (statuses is None or node.context.status in statuses)
                and (include_running or node.context.status not in {"created", "running"})
            ]
        removed_ids: list[str] = []
        for tid in ids:
            ok, deleted_ids = self.remove_trace_subtree(tid)
            if ok:
                removed_ids.extend(deleted_ids)
        return len(ids), removed_ids

    def live_tree(self, *, scope_trace_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            nodes = list(self._iter_scope_locked(scope_trace_id))
        return self._contexts_to_dicts([node.context for node in nodes], include_duration=True)

    def live_running(
        self,
        *,
        include_duration: bool = False,
        scope_trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.lock:
            contexts = [
                node.context
                for node in self._iter_scope_locked(scope_trace_id)
                if node.context.status in {"created", "running"}
            ]
        return self._contexts_to_dicts(contexts, include_duration=include_duration)

    def running_signature(
        self,
        *,
        scope_trace_id: str | None = None,
    ) -> tuple[tuple[str, str | None, str], ...]:
        with self.lock:
            return tuple(
                (node.context.trace_id, node.context.parent_id, node.context.status)
                for node in self._iter_scope_locked(scope_trace_id)
                if node.context.status in {"created", "running"}
            )

    @staticmethod
    def normalize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
        if not metadata:
            return {}
        out: dict[str, Any] = {}
        for k, v in metadata.items():
            if isinstance(k, str) and (v is None or isinstance(v, (bool, int, float, str))):
                out[k] = v
        return out

    def subtree_contexts(self, trace_id: str) -> list[TaskContext]:
        with self.lock:
            if self._node_by_trace_id_locked(trace_id) is None:
                return []
            return [node.context for node in self._walk_subtree_locked(self._node_by_trace_id_locked(trace_id))]

    def aggregate_performance_event(
        self,
        trace_id: str,
        name: str,
        duration_ms: float | None,
        metadata: Mapping[str, Any] | None = None,
    ) -> bool:
        """Fold a performance sample into its live trace without emitting per-sample events."""
        with self.lock:
            context = self._context_by_id_locked(trace_id)
            if context is None:
                return False
            metrics = context.metadata.setdefault("performance_metrics", {})
            if not isinstance(metrics, dict):
                metrics = {}
                context.metadata["performance_metrics"] = metrics
            metric = metrics.setdefault(
                name,
                {"count": 0, "duration_count": 0, "total_ms": 0.0, "min_ms": None, "max_ms": None},
            )
            metric["count"] += 1
            if metadata:
                excluded = {"trace_id", "parent_trace_id", "peer_id", "task_name", "task_kind", "operation_id"}
                metric["metadata"] = {
                    key: value
                    for key, value in metadata.items()
                    if key not in excluded
                    and isinstance(key, str)
                    and (value is None or isinstance(value, (bool, int, float, str)))
                }
            if duration_ms is not None:
                metric["duration_count"] += 1
                metric["total_ms"] += duration_ms
                metric["avg_ms"] = metric["total_ms"] / metric["duration_count"]
                metric["min_ms"] = duration_ms if metric["min_ms"] is None else min(metric["min_ms"], duration_ms)
                metric["max_ms"] = duration_ms if metric["max_ms"] is None else max(metric["max_ms"], duration_ms)
            return True

    def root_trace_id(self, trace_id: str) -> str | None:
        with self.lock:
            node = self._node_by_trace_id_locked(trace_id)
            while node is not None and node.parent is not None:
                node = self.arena.get_node(node.parent)
            return node.trace_id if node is not None else None

    def _node_by_trace_id_locked(self, trace_id: str) -> TraceNode | None:
        return self.arena.get_node(self.arena.get_node_id(trace_id))

    def _context_by_id_locked(self, trace_id: str) -> TaskContext | None:
        node = self._node_by_trace_id_locked(trace_id)
        return node.context if node is not None else None

    def _iter_scope_locked(self, scope_trace_id: str | None) -> list[TraceNode]:
        if scope_trace_id is not None:
            node_id = self.arena.get_node_id(scope_trace_id)
            node = self.arena.get_node(node_id)
            return self._walk_subtree_locked(node)
        nodes: list[TraceNode] = []
        root_id = self.arena.roots.first
        while root_id is not None:
            root = self.arena.get_node(root_id)
            if root is None:
                break
            nodes.extend(self._walk_subtree_locked(root))
            root_id = root.next_root
        return nodes

    def _iter_nodes_locked(self) -> list[TraceNode]:
        return self._iter_scope_locked(None)

    def _walk_subtree_locked(self, root: TraceNode | None) -> list[TraceNode]:
        if root is None:
            return []
        out: list[TraceNode] = []
        stack = [root.node_id]
        while stack:
            node = self.arena.get_node(stack.pop())
            if node is None:
                continue
            out.append(node)
            children: list[int] = []
            child_id = node.first_child
            while child_id is not None:
                child = self.arena.get_node(child_id)
                if child is None:
                    break
                children.append(child.node_id)
                child_id = child.next_sibling
            stack.extend(reversed(children))
        return out

    def _subtree_ids_locked(self, trace_id: str) -> list[str]:
        node = self._node_by_trace_id_locked(trace_id)
        return [item.trace_id for item in self._walk_subtree_locked(node)]

    def _trim_locked(self) -> None:
        while len(self.arena.trace_to_node) > self.context_limit:
            terminal = next(
                (node for node in self._iter_nodes_locked() if node.context.ended_at is not None),
                None,
            )
            if terminal is None:
                return
            self.remove_trace_subtree(terminal.trace_id)

    @staticmethod
    def _contexts_to_dicts(contexts: list[TaskContext], *, include_duration: bool) -> list[dict[str, Any]]:
        now_ns = time.monotonic_ns() if include_duration else None
        out: list[dict[str, Any]] = []
        for ctx in contexts:
            item = ctx.to_dict()
            if now_ns is not None and ctx.status in {"created", "running"}:
                start_ns = ctx.started_monotonic_ns or ctx.created_monotonic_ns
                item["duration_ms"] = max(0.0, (now_ns - start_ns) / 1_000_000)
            out.append(item)
        return out
