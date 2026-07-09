from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar

from webrtc.lifecycle import PeerCondition
from webrtc.peer_connection import PeerConnection
from webrtc.peer_context import PeerContext
from webrtc.session_description import SessionDescription, SessionDescriptionAttrKey
from webrtc.tracing import (
    PerformanceRecorder,
    build_performance_summary,
    check_counters,
    check_event_ordering,
    check_forbidden_events,
    check_required_events,
    check_smoke_thresholds,
)

T = TypeVar("T")


BASELINE_DIR = Path(__file__).parent / "baselines"


def load_baseline(name: str) -> dict[str, Any]:
    with (BASELINE_DIR / name).open(encoding="utf-8") as file:
        return json.load(file)


def build_summary_from_baseline(
    recorder: PerformanceRecorder,
    baseline: Mapping[str, Any],
) -> dict[str, Any]:
    return build_performance_summary(
        recorder.events(),
        scenario=str(baseline["scenario"]),
        required_events=baseline.get("required_events", ()),
        forbidden_events=baseline.get("forbidden_events", ()),
        ordering=baseline.get("ordering", ()),
    )


def assert_matches_baseline(
    recorder: PerformanceRecorder,
    summary: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> None:
    checks = [
        check_required_events(recorder.events(), baseline.get("required_events", ())),
        check_forbidden_events(recorder.events(), baseline.get("forbidden_events", ())),
        check_event_ordering(recorder.events(), baseline.get("ordering", ())),
        check_counters(summary["counters"], baseline.get("counters", {})),
        check_smoke_thresholds(summary, baseline.get("smoke_thresholds", {})),
    ]
    failures = [failure for check in checks for failure in check.failures]
    failures.extend(f"failed event present: {name}" for name in summary["failed_events"])
    failures.extend(f"incomplete phase: {name}" for name in summary["incomplete_phases"])

    assert not failures, "performance baseline failed:\n" + "\n".join(failures)


def candidate_strings(desc: SessionDescription) -> list[str]:
    candidates: list[str] = []
    for media in desc.media_descriptions:
        for candidate in media.candidates:
            candidates.append(candidate.to_ice_str())
        for attr in media.attributes:
            if attr.key == SessionDescriptionAttrKey.Candidate.value and attr.value:
                candidates.append(attr.value)
    return candidates


def media_credentials(desc: SessionDescription) -> list[tuple[str, str]]:
    credentials = list(desc.get_media_credentials())
    if credentials:
        return credentials

    for media in desc.media_descriptions:
        ufrag: str | None = None
        pwd: str | None = None
        for attr in media.attributes:
            if attr.key == SessionDescriptionAttrKey.ICEUfrag.value:
                ufrag = attr.value
            elif attr.key == SessionDescriptionAttrKey.ICEPwd.value:
                pwd = attr.value
        if ufrag and pwd:
            credentials.append((ufrag, pwd))
    return credentials


async def wait_for_conditions(
    peer: "PeerDriver",
    conditions: list[PeerCondition],
    *,
    timeout: float,
) -> None:
    for condition in conditions:
        await peer.call(lambda context, condition=condition: context.wait(condition, timeout))


class PeerDriver:
    def __init__(self, pc: PeerConnection, peer_id: str) -> None:
        self.pc = pc
        self.peer_id = peer_id
        self.closed = False
        self.active_routines_after_close: int | None = None
        self._queue: asyncio.Queue[Any] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> "PeerDriver":
        self._task = asyncio.create_task(self._run(), name=f"performance-peer-{self.peer_id}")
        await self.call(lambda context: _noop(context))
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def call(self, func: Callable[[PeerContext], Awaitable[T] | T]) -> T:
        if self._task is None:
            raise RuntimeError("peer driver is not started")
        future: asyncio.Future[T] = asyncio.get_running_loop().create_future()
        await self._queue.put((func, future))
        return await future

    async def close(self) -> None:
        if self._task is None or self.closed:
            return
        future: asyncio.Future[int] = asyncio.get_running_loop().create_future()
        await self._queue.put((None, future))
        self.active_routines_after_close = await future
        await self._task
        self.closed = True

    async def _run(self) -> None:
        async with PeerContext(self.pc, peer_id=self.peer_id) as context:
            while True:
                func, future = await self._queue.get()
                if func is None:
                    await context.aclose("test-complete")
                    if not future.done():
                        future.set_result(context.active_routine_count())
                    return
                try:
                    result = func(context)
                    if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
                        result = await result
                except BaseException as exc:
                    if not future.done():
                        future.set_exception(exc)
                else:
                    if not future.done():
                        future.set_result(result)


async def _noop(context: PeerContext) -> None:
    return None
