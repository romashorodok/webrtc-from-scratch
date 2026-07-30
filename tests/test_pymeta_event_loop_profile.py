"""Stage M0 tests for the event-loop PyMeta application profile."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from queue import Full
from threading import Barrier, get_ident
from typing import Annotated, get_args

import pytest

from pymeta import (
    bounded,
    effects,
    exact_type,
    metadata,
    never,
    normalize,
    owned_by,
    region,
    required,
    serialize,
    stable_hash,
    storage,
    uint,
    wrap,
)
from pymeta.concurrent import (
    BoundedQueue,
    CoalescedNotification,
    LockedAtomic,
    OwnedResource,
    atomic,
    bounded_queue,
    mpsc,
    owned_shard,
    spsc,
)
from pymeta.cpython import cpython_exact, pinned_semantics


def test_profile_descriptors_normalize_and_serialize_stably() -> None:
    ready = storage.fifo | owned_by("reactor") | bounded(min=0)
    equivalent = bounded(min=0) | storage.fifo | owned_by("reactor")
    timer = storage.min_heap(
        key="_when", ordering=pinned_semantics("heapq")
    ) | owned_by("reactor")

    assert ready == equivalent
    assert hash(ready) == hash(equivalent)
    assert serialize(ready) == serialize(equivalent)
    assert stable_hash(ready) == stable_hash(equivalent)
    assert normalize(timer)["descriptor_set"][0]["descriptor"] == "storage.min_heap"
    assert serialize(timer) == serialize(timer)


def test_annotated_metadata_does_not_change_python_values() -> None:
    Counter = Annotated[int, uint[32] | storage.native_field | owned_by("reactor")]
    value: Counter = 7

    assert value == 7
    assert get_args(Counter)[0] is int
    assert "uint[32]" in repr(get_args(Counter)[1])


def test_descriptor_sugar_has_one_normal_form_and_rejects_conflicts() -> None:
    assert uint[16] | wrap == wrap | uint[16]
    assert repr(uint[16] | wrap) == "uint[16](wrap)"

    with pytest.raises(ValueError, match="contradictory descriptors for ownership"):
        owned_by("reactor") | owned_by("worker")
    with pytest.raises(ValueError, match="contradictory descriptors for storage"):
        storage.fifo | storage.native_field
    with pytest.raises(ValueError, match="queue capacity must be positive"):
        bounded_queue(capacity=0)


def test_region_keeps_behavior_and_exposes_structured_effects() -> None:
    contract = effects(
        reads={"loop._ready"},
        writes={"loop._ready"},
        owner="reactor",
        allocate=never,
        suspend=never,
    )

    @region(
        required,
        effects=contract,
        specialize=storage.fifo,
    )
    def execute(value: int) -> int:
        return value + 1

    assert execute(4) == 5
    assert metadata(execute).required is True
    assert metadata(execute).region is required
    assert metadata(execute).mapping["effects"] == contract
    assert contract.reads == frozenset({"loop._ready"})
    with pytest.raises(FrozenInstanceError):
        contract.owner = "worker"  # type: ignore[misc]


def test_exact_pinned_queue_atomic_and_shard_descriptors_are_public() -> None:
    atomic_descriptor = atomic[uint[32]]
    descriptor_values = (
        exact_type(int),
        pinned_semantics("heapq"),
        mpsc | bounded_queue(capacity="config.command_capacity"),
        atomic_descriptor,
        owned_shard(
            key="packet.peer_id",
            workers="config.packet_workers",
            input=spsc,
            output=spsc,
            ordered=True,
        ),
        cpython_exact,
    )

    for descriptor in descriptor_values:
        assert serialize(descriptor)
        assert hash(descriptor)
    atomic_serialized = serialize(atomic_descriptor)
    assert '"bits":32' in atomic_serialized
    assert '"memory_order":"seq_cst"' in atomic_serialized
    assert '"scope":"process"' in atomic_serialized
    assert '"linearization":"compare_exchange"' in atomic_serialized


def test_locked_atomic_compare_exchange_is_linearizable() -> None:
    counter = LockedAtomic(0)
    starts = Barrier(9)

    def increment() -> None:
        starts.wait()
        for _ in range(300):
            while True:
                previous = counter.load()
                _, changed = counter.compare_exchange(previous, previous + 1)
                if changed:
                    break

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(increment) for _ in range(8)]
        starts.wait()
        for future in futures:
            future.result()

    assert counter.load() == 2400
    assert counter.exchange(0) == 2400


def test_bounded_queue_snapshot_is_finite_and_preserves_fifo() -> None:
    queue: BoundedQueue[int] = BoundedQueue(2)
    queue.put_nowait(1)
    queue.put_nowait(2)
    with pytest.raises(Full):
        queue.put_nowait(3)

    assert queue.drain_snapshot() == (1, 2)
    assert queue.empty()
    queue.put_nowait(4)
    queue.close()
    assert queue.closed
    with pytest.raises(RuntimeError, match="queue is closed"):
        queue.put_nowait(5)
    assert queue.get_nowait() == 4


def test_coalesced_notification_has_one_wakeup_per_consumed_burst() -> None:
    wakeups: list[int] = []
    notification = CoalescedNotification(lambda: wakeups.append(1))

    assert notification.notify() is True
    assert notification.notify() is False
    assert wakeups == [1]
    assert notification.consume() is True
    assert notification.consume() is False
    assert notification.notify() is True
    assert wakeups == [1, 1]


def test_owned_resource_rejects_cross_thread_access_and_transfers() -> None:
    resource = OwnedResource(["reactor"])
    assert resource.get() == ["reactor"]

    with ThreadPoolExecutor(max_workers=1) as executor:
        worker_id = executor.submit(get_ident).result()
        resource.transfer(worker_id)
        assert executor.submit(resource.get).result() == ["reactor"]

    with pytest.raises(RuntimeError, match="non-owner"):
        resource.get()
