from __future__ import annotations

from dataclasses import dataclass

from .models import TaskTrace, TraceNode


@dataclass(slots=True)
class RootLinks:
    first: int | None = None
    last: int | None = None


class TraceArena:
    def __init__(self) -> None:
        self.nodes: list[TraceNode | None] = []
        self.free_node_ids: list[int] = []
        self.task_to_node: dict[str, int] = {}
        self.roots = RootLinks()

    def get_node_id(self, task_id: str) -> int | None:
        return self.task_to_node.get(task_id)

    def get_node(self, node_id: int | None) -> TraceNode | None:
        if node_id is None or node_id < 0 or node_id >= len(self.nodes):
            return None
        return self.nodes[node_id]

    def add(self, context: TaskTrace, parent: int | None) -> TraceNode:
        node_id = self.free_node_ids.pop() if self.free_node_ids else len(self.nodes)
        node = TraceNode(node_id=node_id, context=context, parent=parent)
        if node_id == len(self.nodes):
            self.nodes.append(node)
        else:
            self.nodes[node_id] = node
        self.task_to_node[context.task_id] = node_id
        if parent is None:
            self._append_root(node)
        else:
            self._append_child(parent, node)
        return node

    def remove(self, task_id: str) -> TraceNode | None:
        node_id = self.task_to_node.pop(task_id, None)
        if node_id is None:
            return None
        node = self.nodes[node_id]
        if node is None:
            return None
        self._detach(node)
        self.nodes[node_id] = None
        self.free_node_ids.append(node_id)
        return node

    def remove_and_promote_children(self, task_id: str) -> list[str]:
        node_id = self.task_to_node.pop(task_id, None)
        if node_id is None:
            return []
        node = self.nodes[node_id]
        if node is None:
            return []

        child_ids: list[str] = []
        child = node.first_child
        while child is not None:
            child_node = self.get_node(child)
            if child_node is None:
                break
            child_ids.append(child_node.task_id)
            child = child_node.next_sibling

        if node.first_child is not None:
            self._promote_child_chain(node)
        else:
            self._detach(node)
        self.nodes[node_id] = None
        self.free_node_ids.append(node_id)
        return child_ids

    def _append_root(self, node: TraceNode) -> None:
        if self.roots.last is None:
            self.roots.first = node.node_id
            self.roots.last = node.node_id
            return
        last = self.get_node(self.roots.last)
        if last is None:
            self.roots.first = node.node_id
            self.roots.last = node.node_id
            return
        last.next_root = node.node_id
        node.prev_root = last.node_id
        self.roots.last = node.node_id

    def _append_child(self, parent_id: int, node: TraceNode) -> None:
        parent = self.get_node(parent_id)
        if parent is None:
            self._append_root(node)
            node.parent = None
            return
        if parent.last_child is None:
            parent.first_child = node.node_id
            parent.last_child = node.node_id
            return
        last = self.get_node(parent.last_child)
        if last is None:
            parent.first_child = node.node_id
            parent.last_child = node.node_id
            return
        last.next_sibling = node.node_id
        node.prev_sibling = last.node_id
        parent.last_child = node.node_id

    def _detach(self, node: TraceNode) -> None:
        if node.parent is None:
            prev_root = self.get_node(node.prev_root)
            next_root = self.get_node(node.next_root)
            if prev_root is not None:
                prev_root.next_root = node.next_root
            else:
                self.roots.first = node.next_root
            if next_root is not None:
                next_root.prev_root = node.prev_root
            else:
                self.roots.last = node.prev_root
            return

        parent = self.get_node(node.parent)
        if parent is None:
            return
        prev_sibling = self.get_node(node.prev_sibling)
        next_sibling = self.get_node(node.next_sibling)
        if prev_sibling is not None:
            prev_sibling.next_sibling = node.next_sibling
        else:
            parent.first_child = node.next_sibling
        if next_sibling is not None:
            next_sibling.prev_sibling = node.prev_sibling
        else:
            parent.last_child = node.prev_sibling

    def _promote_child_chain(self, node: TraceNode) -> None:
        first_child = self.get_node(node.first_child)
        last_child = self.get_node(node.last_child)
        if first_child is None or last_child is None:
            self._detach(node)
            return
        if node.parent is None:
            prev_root = self.get_node(node.prev_root)
            next_root = self.get_node(node.next_root)
            if prev_root is not None:
                prev_root.next_root = first_child.node_id
            else:
                self.roots.first = first_child.node_id
            first_child.prev_root = node.prev_root
            if next_root is not None:
                next_root.prev_root = last_child.node_id
            else:
                self.roots.last = last_child.node_id
            last_child.next_root = node.next_root
            child: TraceNode | None = first_child
            previous: TraceNode | None = prev_root
            while child is not None:
                next_child = self.get_node(child.next_sibling)
                child.parent = None
                child.prev_root = previous.node_id if previous is not None else None
                child.next_root = next_child.node_id if next_child is not None else node.next_root
                child.prev_sibling = None
                child.next_sibling = None
                previous = child
                child = next_child
            return

        parent = self.get_node(node.parent)
        if parent is None:
            self._detach(node)
            return
        prev_sibling = self.get_node(node.prev_sibling)
        next_sibling = self.get_node(node.next_sibling)
        if prev_sibling is not None:
            prev_sibling.next_sibling = first_child.node_id
            first_child.prev_sibling = prev_sibling.node_id
        else:
            parent.first_child = first_child.node_id
            first_child.prev_sibling = None
        if next_sibling is not None:
            next_sibling.prev_sibling = last_child.node_id
            last_child.next_sibling = next_sibling.node_id
        else:
            parent.last_child = last_child.node_id
            last_child.next_sibling = None
        child = first_child
        while child is not None:
            child.parent = parent.node_id
            child = self.get_node(child.next_sibling)
