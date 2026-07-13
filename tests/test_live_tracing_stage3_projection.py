import concurrent.futures

from webrtc.activity import ActivityGroupDelta, ActivityGroupStore, DrainedMetricSinkAdapter
from webrtc.observability import (
    ControlHandle,
    ControlHandleStore,
    FacetOp,
    FacetStore,
    MachineStore,
    MachineTransitionOp,
    ProducerDot,
)
from webrtc.state_machine import MachineSpec


SPEC = MachineSpec(
    "test", "new",
    {"new": frozenset({"running"}), "running": frozenset({"done"}),
     "done": frozenset()},
    frozenset({"done"}),
)


def _delta(producer, seq, calls, *, owner="peer", owner_epoch=1):
    return ActivityGroupDelta(
        "trace", owner, owner_epoch, None, 7, "packet", "media",
        ProducerDot(99, producer, seq), calls, calls, calls, calls, 0, 0,
        calls * 10, 10, 10, calls, calls,
    )


def test_activity_components_converge_under_reordering_and_duplicates():
    operations = [_delta(1, 2, 3), _delta(2, 1, 5), _delta(1, 1, 1), _delta(1, 2, 3)]
    first = ActivityGroupStore(runtime_epoch=99)
    second = ActivityGroupStore(runtime_epoch=99)
    for operation in operations:
        first.apply_delta(operation)
    for operation in reversed(operations):
        second.apply_delta(operation)
    left = first.snapshots()[0]
    right = second.snapshots()[0]
    assert (left.calls, left.successes, left.total_duration_ns, left.in_flight) == (8, 8, 80, 0)
    assert (left.calls, left.successes, left.total_duration_ns, left.in_flight) == (
        right.calls, right.successes, right.total_duration_ns, right.in_flight
    )
    assert first.diagnostics["duplicate_projection_ops"] >= 1


def test_machine_reducer_buffers_reordered_edges_and_rejects_invalid_state():
    store = MachineStore(runtime_epoch=99)
    store.register("peer", SPEC, epoch=4)
    done = MachineTransitionOp(
        "peer", "test", "running", "done", 4, 2, ProducerDot(99, 1, 2)
    )
    running = MachineTransitionOp(
        "peer", "test", "new", "running", 4, 1, ProducerDot(99, 1, 1)
    )
    assert not store.apply(done)
    assert store.apply(running)
    assert store.get("peer").state == "done"
    assert store.get("peer").revision == 2
    assert not store.apply(done)

    invalid = MachineTransitionOp(
        "peer", "test", "done", "new", 4, 3, ProducerDot(99, 1, 3)
    )
    assert not store.apply(invalid)
    assert store.get("peer").state == "done"
    assert store.diagnostics["invalid_transitions"] == 1
    assert store.invalid_exemplar == invalid


def test_worker_producers_build_immutable_deltas_concurrently_then_loop_merges():
    def produce(producer):
        return _delta(producer, 1, 100)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        operations = tuple(executor.map(produce, range(1, 9)))
    store = ActivityGroupStore(runtime_epoch=99)
    for operation in operations:
        assert store.apply_delta(operation)
    snapshot = store.snapshots()[0]
    assert snapshot.calls == snapshot.successes == 800
    assert snapshot.in_flight == 0


def test_owner_epoch_cleanup_is_indexed_and_tombstones_are_checkpoint_bounded():
    store = ActivityGroupStore(runtime_epoch=99)
    store.apply_delta(_delta(1, 1, 1, owner="one"))
    store.apply_delta(_delta(2, 1, 2, owner="two"))
    final, removed = store.remove_owner_epoch("one", 1)
    assert len(final) == 1 and final[0].calls == 1
    assert len(removed) == 1
    assert [snapshot.owner_entity_id for snapshot in store.snapshots()] == ["two"]
    assert not store.apply_delta(_delta(1, 2, 3, owner="one"))
    checkpoint = store.removal_checkpoint
    assert store.gc_tombstones(checkpoint - 1) == 0
    assert store.gc_tombstones(checkpoint) == 1


def test_facets_are_epoch_revisioned_and_controls_are_explicit():
    facets = FacetStore(runtime_epoch=99)
    newest = FacetOp("queue", "peer", 2, 5, 2, ProducerDot(99, 1, 2))
    stale = FacetOp("queue", "peer", 2, 4, 1, ProducerDot(99, 1, 1))
    assert facets.apply(newest)
    assert not facets.apply(stale)
    assert facets.snapshots()[0].value == 5
    assert facets.remove_owner("peer", 2) == ("queue",)

    controls = ControlHandleStore(limit=1)
    handle = ControlHandle("cancel", "trace", "peer", 2, "offer", True, "task")
    assert controls.expose(handle)
    assert controls.get("cancel") == handle
    assert controls.remove_owner("peer", 2) == ("cancel",)


def test_external_metric_adapter_emits_only_changed_absolute_snapshots():
    class Sink:
        def __init__(self):
            self.snapshots = []

        def emit_snapshot(self, snapshot):
            self.snapshots.append(snapshot)

    store = ActivityGroupStore(runtime_epoch=99)
    store.apply_delta(_delta(1, 1, 1))
    sink = Sink()
    adapter = DrainedMetricSinkAdapter(sink, store.diagnostics)
    assert adapter.drain(store.snapshots()) == 1
    assert adapter.drain(store.snapshots()) == 0
    store.apply_delta(_delta(1, 2, 2))
    assert adapter.drain(store.snapshots()) == 1
    assert [snapshot.calls for snapshot in sink.snapshots] == [1, 2]


def test_runtime_uses_one_bounded_producer_clock_instead_of_one_producer_per_call():
    from webrtc import Runtime

    runtime = Runtime()
    dots = [runtime.new_producer_dot() for _ in range(10_000)]
    assert {dot.producer_id for dot in dots} == {1}
    assert dots[-1].producer_seq == 10_000


def test_machine_replay_and_pending_state_are_bounded():
    store = MachineStore(runtime_epoch=99, seen_limit=8, pending_limit=4)
    store.register("peer", SPEC, epoch=1)
    for revision in range(10, 30):
        store.apply(MachineTransitionOp(
            "peer", "test", "running", "done", 1, revision,
            ProducerDot(99, 1, revision),
        ))
    assert len(store._seen) == 8
    assert len(store._pending["peer"]) == 4
    assert store.diagnostics["machine_pending_overflow"] > 0


def test_removed_facet_and_control_owner_epochs_reject_late_resurrection():
    facets = FacetStore(runtime_epoch=99)
    facets.remove_owner("peer", 2)
    assert not facets.apply(FacetOp(
        "peer.ready", "peer", 2, True, 1, ProducerDot(99, 1, 1)
    ))
    assert facets.apply(FacetOp(
        "peer.ready", "peer", 3, True, 1, ProducerDot(99, 1, 2)
    ))

    controls = ControlHandleStore()
    controls.remove_owner("peer", 2)
    assert not controls.expose(ControlHandle(
        "stop", "trace", "peer", 2, "Stop", True,
    ))
    assert controls.expose(ControlHandle(
        "stop", "trace", "peer", 3, "Stop", True,
    ))
