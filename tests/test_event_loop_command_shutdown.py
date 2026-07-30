from __future__ import annotations

import queue
import threading

import pytest

from webrtc.event_loop.commands import Command, CommandInbox, CommandKind
from webrtc.event_loop.loop import LoopState, WebRTCSelectorEventLoop


class _WakeupProbe:
    def __init__(self) -> None:
        self.writes = 0
        self._lock = threading.Lock()

    def _write_to_self(self) -> None:
        with self._lock:
            self.writes += 1


def test_command_inbox_has_fixed_nonblocking_capacity() -> None:
    inbox = CommandInbox(2)
    loop = _WakeupProbe()
    inbox.publish(loop, Command(CommandKind.STOP, None))  # type: ignore[arg-type]
    inbox.publish(loop, Command(CommandKind.STOP, None))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="inbox is full") as failure:
        inbox.publish(loop, Command(CommandKind.STOP, None))  # type: ignore[arg-type]
    assert isinstance(failure.value.__cause__, queue.Full)
    assert loop.writes == 1
    assert len(inbox.drain_snapshot()) == 2


def test_close_and_publish_race_transfers_every_accepted_command() -> None:
    inbox = CommandInbox(256)
    loop = _WakeupProbe()
    start = threading.Barrier(9)
    accepted: list[Command] = []
    rejected = 0
    lock = threading.Lock()

    def producer(producer_id: int) -> None:
        nonlocal rejected
        start.wait()
        for sequence in range(64):
            command = Command(
                CommandKind.REMOVE_FD, (producer_id, sequence)
            )
            try:
                inbox.publish(loop, command)  # type: ignore[arg-type]
            except RuntimeError as exc:
                assert str(exc) in {
                    "event loop is closing",
                    "event-loop command inbox is full",
                }
                with lock:
                    rejected += 1
            else:
                with lock:
                    accepted.append(command)

    threads = [
        threading.Thread(target=producer, args=(index,)) for index in range(8)
    ]
    for thread in threads:
        thread.start()
    start.wait()
    drained = inbox.close_and_drain()
    for thread in threads:
        thread.join()

    assert inbox.closed
    assert set(drained) == set(accepted)
    assert len(drained) + rejected == 8 * 64
    with pytest.raises(RuntimeError, match="event loop is closing"):
        inbox.publish(loop, Command(CommandKind.STOP, None))  # type: ignore[arg-type]


def test_loop_close_drains_without_running_accepted_callbacks() -> None:
    loop = WebRTCSelectorEventLoop()
    called: list[str] = []
    handle = loop.call_soon_threadsafe(called.append, "unexpected")
    handle.cancel()

    loop.close()

    assert called == []
    assert loop.is_closed()
    assert loop._lifecycle.state is LoopState.CLOSED
    assert loop._command_inbox.closed
    loop.close()

