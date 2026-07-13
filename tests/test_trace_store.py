from webrtc.tracing.models import TaskTrace
from webrtc.tracing.store import TraceStore


def task(task_id: str, parent_task_id: str | None = None, *, trace_id="peer", status="running"):
    return TaskTrace(trace_id, task_id, parent_task_id, task_id, "task", status=status)


def test_store_is_keyed_by_task_id_with_shared_trace_id():
    store = TraceStore()
    store.create(task("root"))
    store.create(task("child", "root"))
    snapshots = store.live_tree(trace_id="peer")
    assert [item["task_id"] for item in snapshots] == ["root", "child"]
    assert snapshots[1]["parent_task_id"] == "root"


def test_parent_pruning_promotes_children():
    store = TraceStore()
    store.create(task("root"))
    store.create(task("child", "root"))
    store.create(task("grandchild", "child"))
    ok, promoted = store.remove_only("child")
    assert ok
    assert [item.task_id for item in promoted] == ["grandchild"]
    assert store.live_tree()[1]["parent_task_id"] == "root"


def test_subtree_removal_is_atomic_for_missing_root():
    store = TraceStore()
    store.create(task("root"))
    assert store.remove_subtree("missing") == (False, [])
    assert [item["task_id"] for item in store.live_tree()] == ["root"]


def test_subtree_removal_returns_task_ids():
    store = TraceStore()
    store.create(task("root"))
    store.create(task("left", "root"))
    store.create(task("right", "root"))
    assert store.remove_subtree("root") == (True, ["root", "left", "right"])
    assert store.live_tree() == []


def test_trace_filter_does_not_confuse_trace_and_task_identity():
    store = TraceStore()
    store.create(task("a", trace_id="one"))
    store.create(task("b", trace_id="two"))
    assert [item["task_id"] for item in store.live_tree(trace_id="two")] == ["b"]
