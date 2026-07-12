from __future__ import annotations

from collections import OrderedDict, defaultdict
from concurrent.futures import Executor
from dataclasses import dataclass
from threading import RLock
from typing import Any


@dataclass(slots=True)
class MetricDelta:
    key: tuple[str | None, str, str, str]
    duration_ms: float
    status: str


class TraceMetricsAggregator:
    def __init__(self, executor: Executor | None = None, *, max_keys: int = 4096) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be greater than zero")
        self._executor = executor
        self._max_keys = max_keys
        self._lock = RLock()
        self._totals: OrderedDict[tuple[str | None, str, str, str], dict[str, Any]] = OrderedDict()

    def enqueue(self, delta: MetricDelta) -> None:
        # Coalesce at ingestion. A queue retains one object per completed call
        # until somebody flushes it; the live server does not periodically
        # flush metrics, so packet-rate traced work otherwise grows forever.
        with self._lock:
            item = self._totals.get(delta.key)
            if item is None:
                item = self._empty_totals()
                self._totals[delta.key] = item
            self._totals.move_to_end(delta.key)
            self._add(item, delta)
            while len(self._totals) > self._max_keys:
                self._totals.popitem(last=False)

    async def flush(self) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        with self._lock:
            totals, self._totals = self._totals, OrderedDict()
        for item in totals.values():
            success = max(1, int(item["success_count"]))
            item["avg_duration_ms"] = float(item["total_duration_ms"]) / success
        return totals

    @staticmethod
    def _empty_totals() -> dict[str, Any]:
        return {
            "call_count": 0,
            "success_count": 0,
            "cancelled_count": 0,
            "error_count": 0,
            "total_duration_ms": 0.0,
        }

    @staticmethod
    def _add(item: dict[str, Any], delta: MetricDelta) -> None:
        item["call_count"] += 1
        if delta.status == "completed":
            item["success_count"] += 1
            item["total_duration_ms"] += delta.duration_ms
        elif delta.status == "cancelled":
            item["cancelled_count"] += 1
        else:
            item["error_count"] += 1

    @staticmethod
    def _aggregate(batch: list[MetricDelta]) -> dict[tuple[str | None, str, str, str], dict[str, Any]]:
        out: dict[tuple[str | None, str, str, str], dict[str, Any]] = defaultdict(
            TraceMetricsAggregator._empty_totals
        )
        for delta in batch:
            item = out[delta.key]
            TraceMetricsAggregator._add(item, delta)
        for item in out.values():
            success = max(1, int(item["success_count"]))
            item["avg_duration_ms"] = float(item["total_duration_ms"]) / success
        return dict(out)
