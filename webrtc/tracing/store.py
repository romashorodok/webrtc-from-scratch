from __future__ import annotations

import time
from collections import deque
from threading import RLock
from typing import Any, Mapping

from .arena import TraceArena
from .models import TaskContext


class TraceStore:
    def __init__(self, *, context_limit: int = 4096) -> None:
        self.lock = RLock()
        self.arena = TraceArena()
        self.context_limit = context_limit
        self.contexts: dict[str, TaskContext] = {}
        self.order: deque[str] = deque()

    def create(self, context: TaskContext) -> None:
        with self.lock:
            parent_node = self.arena.get_node_id(context.parent_id) if context.parent_id else None
            self.arena.add(context.trace_id, parent_node)
            self.contexts[context.trace_id] = context
            self.order.append(context.trace_id)
            self._trim_locked()

    def start(self, context: TaskContext) -> None:
        with self.lock:
            if context.trace_id in self.contexts:
                self.contexts[context.trace_id] = context

    def complete(self, context: TaskContext) -> bool:
        with self.lock:
            if context.trace_id not in self.contexts:
                return False
            self.contexts[context.trace_id] = context
            return True

    def remove_trace_subtree(self, trace_id: str) -> tuple[bool, list[str], str | None]:
        with self.lock:
            if trace_id not in self.contexts:
                return False, [], None
            peer_id = self.contexts[trace_id].peer_id
            ids = self._subtree_ids_locked(trace_id)
            for tid in ids:
                self._drop_trace_locked(tid)
            return True, ids, peer_id

    def remove_trace_only(self, trace_id: str) -> tuple[bool, list[str], str | None]:
        with self.lock:
            context = self.contexts.get(trace_id)
            if context is None:
                return False, [], None
            promoted_ids = self.arena.remove_and_promote_children(trace_id)
            parent_id = context.parent_id
            for child_id in promoted_ids:
                child = self.contexts.get(child_id)
                if child is None:
                    continue
                child.parent_id = parent_id
            self.contexts.pop(trace_id, None)
            try:
                self.order.remove(trace_id)
            except ValueError:
                pass
            return True, promoted_ids, context.peer_id

    def delete_traces(
        self,
        *,
        peer_id: str | None = None,
        statuses: set[str] | None = None,
        include_running: bool = False,
    ) -> tuple[int, list[str], str | None]:
        ids: list[str] = []
        with self.lock:
            for ctx in list(self.contexts.values()):
                if peer_id is not None and ctx.peer_id != peer_id:
                    continue
                if statuses is not None and ctx.status not in statuses:
                    continue
                if not include_running and ctx.status in {"created", "running"}:
                    continue
                ids.append(ctx.trace_id)
        removed_ids: list[str] = []
        for tid in ids:
            ok, deleted_ids, _peer = self.remove_trace_subtree(tid)
            if ok:
                removed_ids.extend(deleted_ids)
        return len(ids), removed_ids, peer_id

    def live_tree(self, *, peer_id: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            items = [
                self.contexts[tid]
                for tid in self.order
                if tid in self.contexts and (peer_id is None or self.contexts[tid].peer_id == peer_id)
            ]
        now_ns = time.monotonic_ns()
        out: list[dict[str, Any]] = []
        for ctx in items:
            item = ctx.to_dict()
            if ctx.status in {"created", "running"}:
                start_ns = ctx.started_monotonic_ns or ctx.created_monotonic_ns
                item["duration_ms"] = max(0.0, (now_ns - start_ns) / 1_000_000)
            out.append(item)
        return out

    def live_running(self, *, peer_id: str | None = None, include_duration: bool = False) -> list[dict[str, Any]]:
        with self.lock:
            items = [
                self.contexts[tid]
                for tid in self.order
                if tid in self.contexts
                and self.contexts[tid].status in {"created", "running"}
                and (peer_id is None or self.contexts[tid].peer_id == peer_id)
            ]
        now_ns = time.monotonic_ns() if include_duration else None
        out: list[dict[str, Any]] = []
        for ctx in items:
            row = ctx.to_dict()
            if now_ns is not None and ctx.status in {"created", "running"}:
                start_ns = ctx.started_monotonic_ns or ctx.created_monotonic_ns
                row["duration_ms"] = max(0.0, (now_ns - start_ns) / 1_000_000)
            out.append(row)
        return out

    @staticmethod
    def normalize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
        if not metadata:
            return {}
        out: dict[str, Any] = {}
        for k, v in metadata.items():
            if isinstance(k, str) and (v is None or isinstance(v, (bool, int, float, str))):
                out[k] = v
        return out

    def subtree_ids(self, trace_id: str) -> list[str]:
        with self.lock:
            if trace_id not in self.contexts:
                return []
            return self._subtree_ids_locked(trace_id)

    def context_by_id(self, trace_id: str) -> TaskContext | None:
        with self.lock:
            return self.contexts.get(trace_id)

    def _subtree_ids_locked(self, trace_id: str) -> list[str]:
        root_node_id = self.arena.get_node_id(trace_id)
        if root_node_id is None:
            return [trace_id]
        ids: list[str] = []
        pending = [root_node_id]
        while pending:
            nid = pending.pop(0)
            node = self.arena.get_node(nid)
            if node is None:
                continue
            ids.append(node.trace_id)
            child = node.first_child
            while child is not None:
                pending.append(child)
                cnode = self.arena.get_node(child)
                child = cnode.next_sibling if cnode else None
        return ids

    def _drop_trace_locked(self, trace_id: str) -> None:
        self.contexts.pop(trace_id, None)
        self.arena.remove(trace_id)
        try:
            self.order.remove(trace_id)
        except ValueError:
            pass

    def _trim_locked(self) -> None:
        while len(self.contexts) > self.context_limit and self.order:
            tid = self.order.popleft()
            ctx = self.contexts.get(tid)
            if ctx is None:
                continue
            if ctx.ended_at is None:
                self.order.append(tid)
                break
            self._drop_trace_locked(tid)
