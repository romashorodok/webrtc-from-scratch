"""Typed bounded queues with Runtime-owned lifecycle and exact load facets."""

from __future__ import annotations

import asyncio
from typing import Generic, TypeVar

from .machine_specs import MACHINE_SPECS
from .observability import MachineTransitionOp
from .runtime_services import OwnedTaskHandle, current_execution_scope
from .state_machine import (
    AsyncStateMachineRunner, MachineCommand, PreparedTransition, ReplyPort,
    TransitionCommit,
)

T = TypeVar("T")


class _QueueRunner(AsyncStateMachineRunner[MachineCommand[str, TransitionCommit]]):
    async def step(self, command):
        target = {"close": "closing", "drain": "drained", "closed": "closed"}[
            command.kind
        ]
        return PreparedTransition(
            self.state, target, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


class RuntimeOwnedQueue(Generic[T]):
    """An asyncio queue whose membership and lifetime are observable machines."""

    def __init__(self, maxsize: int, *, entity_id: str, queue_kind: str) -> None:
        if maxsize < 1:
            raise ValueError("Runtime-owned queue capacity must be positive")
        self._queue: asyncio.Queue[T] = asyncio.Queue(maxsize=maxsize)
        self.entity_id = entity_id
        self.queue_kind = queue_kind
        self._runtime = current_execution_scope()
        self._command_id = 0
        self._high_water = 0
        self._runner = _QueueRunner(
            MACHINE_SPECS["queue"], entity_id=entity_id, mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._project,
        )
        self._handle: OwnedTaskHandle[None] | None = None
        if hasattr(self._runtime, "start_machine"):
            self._runtime.projection.machines.register(entity_id, self._runner.spec)
            self._runtime.register_owner(entity_id, epoch=self._runner.epoch)
            self._handle = self._runtime.start_machine(
                self._runner, owner_entity_id=entity_id,
                owner_epoch=self._runner.epoch,
            )
            self._publish()

    @property
    def maxsize(self) -> int:
        return self._queue.maxsize

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    async def put(self, item: T) -> None:
        await self._queue.put(item)
        self._publish()

    def put_nowait(self, item: T) -> None:
        self._queue.put_nowait(item)
        self._publish()

    async def get(self) -> T:
        item = await self._queue.get()
        self._publish()
        return item

    def get_nowait(self) -> T:
        item = self._queue.get_nowait()
        self._publish()
        return item

    def _project(self, commit: TransitionCommit) -> None:
        if self._runtime is None:
            return
        self._runtime.projection.machines.apply(MachineTransitionOp(
            commit.entity_id, commit.machine_type, commit.from_state,
            commit.to_state, commit.epoch, commit.revision,
            self._runtime.new_producer_dot(), commit.cause, commit.monotonic_ns,
        ))
        self._publish(commit.revision)

    def _publish(self, revision: int | None = None) -> None:
        if self._runtime is None:
            return
        depth = self._queue.qsize()
        self._high_water = max(self._high_water, depth)
        self._runtime.projection.merge_values(
            self.entity_id, self._runtime.new_producer_dot(), {
                "depth": depth, "capacity": self.maxsize,
                "high_water": self._high_water, "queue_kind": self.queue_kind,
            },
            observer_meta="exact", source_entity_id=self.entity_id,
            source_epoch=self._runner.epoch,
            source_revision=(self._runner.revision if revision is None else revision),
            source_order=self._runtime.projection.new_facet_source_order(),
        )

    async def close(self) -> None:
        if self._handle is None or self._runner.snapshot().terminal:
            return
        await self._move("close")
        while not self._queue.empty():
            self._queue.get_nowait()
        self._publish()
        await self._move("drain")
        await self._move("closed")
        await self._handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)

    async def _move(self, kind: str) -> TransitionCommit:
        self._command_id += 1
        reply: ReplyPort[TransitionCommit] = ReplyPort()
        await self._runner.submit(MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=self._runner.revision,
            cause_id=f"{self.entity_id}:{kind}:{self._command_id}",
        ))
        return await reply.wait()
