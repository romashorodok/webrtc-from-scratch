from webrtc.tracing.models import TaskContext
from webrtc.tracing.store import TraceStore


def context(trace_id: str, parent_id: str | None = None, *, status: str = "running") -> TaskContext:
    return TaskContext(
        trace_id=trace_id,
        parent_id=parent_id,
        name=trace_id,
        kind="task",
        status=status,
    )


def test_store_context_is_owned_by_node_and_indexed_by_trace_id():
    store = TraceStore()
    root = context("root")
    store.create(root)

    root_node = store.arena.get_node(store.arena.get_node_id("root"))
    assert root_node is not None
    assert root_node.context is root
    assert not hasattr(store, "contexts")
    assert not hasattr(store, "order")


def test_create_links_child_by_parent_trace_id():
    store = TraceStore()
    root = context("root")
    child = context("child", "root")
    store.create(root)
    store.create(child)

    root_node = store.arena.get_node(store.arena.get_node_id("root"))
    child_node = store.arena.get_node(store.arena.get_node_id("child"))

    assert root_node is not None
    assert child_node is not None
    assert root_node.first_child == child_node.node_id
    assert child_node.parent == root_node.node_id


def test_live_tree_can_traverse_from_scope_root():
    store = TraceStore()
    for item in [context("a"), context("a-child", "a"), context("b")]:
        store.create(item)

    assert [trace["trace_id"] for trace in store.live_tree(scope_trace_id="a")] == ["a", "a-child"]


def test_parent_promotion_updates_links_and_context_parent_ids():
    store = TraceStore()
    for item in [context("root"), context("child", "root"), context("grandchild", "child")]:
        store.create(item)

    ok, promoted = store.remove_trace_only("child")

    assert ok
    assert [context.trace_id for context in promoted] == ["grandchild"]
    grandchild_node = store.arena.get_node(store.arena.get_node_id("grandchild"))
    assert grandchild_node is not None
    assert grandchild_node.context.parent_id == "root"
    assert [trace["trace_id"] for trace in store.live_tree(scope_trace_id="root")] == ["root", "grandchild"]


def test_root_promotion_preserves_child_order_as_roots():
    store = TraceStore()
    for item in [context("root"), context("left", "root"), context("right", "root"), context("tail")]:
        store.create(item)

    ok, promoted = store.remove_trace_only("root")

    assert ok
    assert [context.trace_id for context in promoted] == ["left", "right"]
    left_node = store.arena.get_node(store.arena.get_node_id("left"))
    right_node = store.arena.get_node(store.arena.get_node_id("right"))
    assert left_node is not None
    assert right_node is not None
    assert left_node.context.parent_id is None
    assert right_node.context.parent_id is None
    assert [trace["trace_id"] for trace in store.live_tree()] == ["left", "right", "tail"]


def test_remove_subtree_removes_only_that_subtree():
    store = TraceStore()
    for item in [context("root"), context("left", "root"), context("left-child", "left"), context("right", "root")]:
        store.create(item)

    ok, ids = store.remove_trace_subtree("left")

    assert ok
    assert ids == ["left", "left-child"]
    assert [trace["trace_id"] for trace in store.live_tree(scope_trace_id="root")] == ["root", "right"]


def test_removed_arena_slots_are_reused():
    store = TraceStore()
    store.create(context("first"))
    first_node_id = store.arena.get_node_id("first")

    ok, ids = store.remove_trace_subtree("first")
    store.create(context("second"))

    assert ok
    assert ids == ["first"]
    assert store.arena.get_node_id("second") == first_node_id
    assert len(store.arena.nodes) == 1


def test_deep_trace_chain_snapshot_is_iterative():
    store = TraceStore()
    parent_id = None
    expected = []
    for index in range(300):
        trace_id = f"trace-{index}"
        expected.append(trace_id)
        store.create(context(trace_id, parent_id))
        parent_id = trace_id

    assert [trace["trace_id"] for trace in store.live_tree()] == expected
