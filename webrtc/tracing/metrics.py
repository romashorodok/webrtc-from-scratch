from __future__ import annotations

import asyncio
from collections import defaultdict
from concurrent.futures import Executor
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class MetricDelta:
    key: tuple[str | None, str, str, str]
    duration_ms: float
    status: str


class TraceMetricsAggregator:
    def __init__(self, executor: Executor | None = None) -> None:
        self._executor = executor
        self._queue: asyncio.Queue[MetricDelta] = asyncio.Queue()

    def enqueue(self, delta: MetricDelta) -> None:
        self._queue.put_nowait(delta)

    async def flush(self) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        batch: list[MetricDelta] = []
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not batch:
            return {}

        loop = asyncio.get_running_loop()
        if self._executor is None:
            return self._aggregate(batch)
        return await loop.run_in_executor(self._executor, self._aggregate, batch)

    @staticmethod
    def _aggregate(batch: list[MetricDelta]) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        out: dict[tuple[str | None, str, str, str], dict[str, Any]] = defaultdict(
            lambda: {"call_count": 0, "success_count": 0, "cancelled_count": 0, "error_count": 0, "total_duration_ms": 0.0}
        )
        for delta in batch:
            item = out[delta.key]
            item["call_count"] += 1
            if delta.status == "completed":
                item["success_count"] += 1
                item["total_duration_ms"] += delta.duration_ms
            elif delta.status == "cancelled":
                item["cancelled_count"] += 1
            else:
                item["error_count"] += 1
        for item in out.values():
            success = max(1, int(item["success_count"]))
            item["avg_duration_ms"] = float(item["total_duration_ms"]) / success
        return dict(out)
