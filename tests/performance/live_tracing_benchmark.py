"""Repeatable backend workload for the live-tracing performance profile.

This module intentionally benchmarks the tracing implementation that exists at
each stage.  Stage 0 knows about ``unobserved`` and the current exact-node path;
the aggregate mode is added to the same result schema when Stage 2 implements
it.  Run this file directly so normal pytest runs only execute the small smoke
coverage in ``test_live_tracing_benchmark.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
import threading
import time
import tracemalloc
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil

from webrtc import Runtime
from webrtc.performance import (
    ObservedMeta,
    event_loop,
    performance,
    unobserved,
    worker,
)


SCHEMA_VERSION = 1
DEFAULT_BATCH_CALLS = 256


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    mode: str = "aggregate"
    workload: str = "inline"
    calls: int = 10_000
    groups: int = 10
    subscribers: int = 1
    slow_subscriber: bool = False
    overlay: str = "open"
    allocation_tracking: bool = False
    batch_calls: int = DEFAULT_BATCH_CALLS
    max_groups: int = 4_096

    def __post_init__(self) -> None:
        if self.mode not in {"unobserved", "capture", "aggregate"}:
            raise ValueError(f"unsupported tracing mode: {self.mode}")
        if self.workload not in {"inline", "nested", "worker", "mixed"}:
            raise ValueError(f"unsupported workload: {self.workload}")
        if self.overlay not in {"open", "closed"}:
            raise ValueError(f"unsupported overlay state: {self.overlay}")
        if self.calls < 1 or self.groups < 1 or self.batch_calls < 1:
            raise ValueError("calls, groups, and batch_calls must be positive")
        if self.subscribers < 0:
            raise ValueError("subscribers cannot be negative")


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    schema_version: int
    benchmark: str
    implementation: str
    config: dict[str, Any]
    wall_ms: float
    cpu_ms: float
    calls_per_second: float
    allocated_current_bytes: int | None
    allocated_peak_bytes: int | None
    rss_before_bytes: int
    rss_after_bytes: int
    peak_rss_bytes: int
    trace_store_count: int
    group_count: int
    group_evictions: int
    published_events: int
    delivered_events: int
    encoded_bytes: int
    messages: int
    dropped_messages: int
    resyncs: int | None
    journal_depth: int | None
    diagnostics: dict[str, int]
    limitations: tuple[str, ...]


class _RssSampler:
    def __init__(self, process: psutil.Process) -> None:
        self.process = process
        self.peak = process.memory_info().rss
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._sample, name="trace-benchmark-rss", daemon=True)

    def __enter__(self) -> "_RssSampler":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._done.set()
        self._thread.join()
        self.peak = max(self.peak, self.process.memory_info().rss)

    def _sample(self) -> None:
        while not self._done.wait(0.002):
            self.peak = max(self.peak, self.process.memory_info().rss)


def _make_subject(mode: str, groups: int):
    namespace: dict[str, Any] = {}
    for index in range(groups):
        def invoke(self, value: int, *, _index: int = index) -> int:
            return value + _index

        invoke.__name__ = f"call_{index}"
        invoke.__qualname__ = f"TracingBenchmark.call_{index}"
        if mode == "unobserved":
            decorated = unobserved(invoke)
        else:
            decorated = event_loop(performance(
                name=f"benchmark.call.{index}", group=f"benchmark.group.{index}"
            )(invoke))
        namespace[invoke.__name__] = decorated

        if mode == "unobserved":
            async def worker_invoke(self, value: int, *, _index: int = index) -> int:
                return await asyncio.to_thread(lambda: value + _index)

            worker_decorated = unobserved(worker_invoke)
        else:
            def worker_invoke(self, value: int, *, _index: int = index) -> int:
                return value + _index

            worker_decorated = worker(performance(
                name=f"benchmark.worker.{index}", group=f"benchmark.group.{index}"
            )(worker_invoke))
        worker_invoke.__name__ = f"worker_{index}"
        worker_invoke.__qualname__ = f"TracingBenchmark.worker_{index}"
        namespace[worker_invoke.__name__] = worker_decorated

    async def nested(self, value: int) -> int:
        first = getattr(self, "call_0")(value)
        return getattr(self, f"call_{1 % groups}")(first)

    nested.__qualname__ = "TracingBenchmark.nested"
    namespace["nested"] = unobserved(nested) if mode == "unobserved" else nested
    subject_type = ObservedMeta(f"TracingBenchmark{mode.title()}", (), namespace)
    return subject_type()


async def run_benchmark(config: BenchmarkConfig) -> BenchmarkResult:
    """Run one backend profile and return a JSON-serializable measurement."""
    process = psutil.Process()
    rss_before = process.memory_info().rss
    subject = _make_subject(config.mode, config.groups)
    runtime = Runtime(
        scope_id="live-tracing-benchmark",
        activity_group_limit=config.max_groups,
        trace_capture_limit=max(8, len(type(subject).__observations__)),
        trace_capture_max_calls=config.calls,
        trace_subscriber_batch_interval=0,
    )
    methods = [getattr(subject, f"call_{index}") for index in range(config.groups)]
    worker_methods = [getattr(subject, f"worker_{index}") for index in range(config.groups)]
    counters: Counter[str] = Counter()
    subscriptions = []

    async with runtime:
        if config.mode == "capture":
            for policy in type(subject).__observations__.values():
                runtime.authorize_trace_capture(
                    selector_kind="operation", selector_value=policy.operation_id,
                    duration_seconds=60, call_budget=config.calls,
                )
        if config.overlay == "open":
            for index in range(config.subscribers):
                maxsize = 1 if config.slow_subscriber and index == config.subscribers - 1 else 1024
                subscriptions.append(runtime.trace_patch_subscribe(maxsize=maxsize))

        if config.allocation_tracking:
            tracemalloc.start()
        cpu_started = time.process_time_ns()
        wall_started = time.perf_counter_ns()
        with _RssSampler(process) as sampler:
            for start in range(0, config.calls, config.batch_calls):
                stop = min(config.calls, start + config.batch_calls)
                concurrent = []
                for call_index in range(start, stop):
                    operation = config.workload
                    if operation == "mixed":
                        operation = ("inline", "inline", "nested", "worker")[call_index % 4]
                    if operation == "inline":
                        methods[call_index % len(methods)](call_index)
                    elif operation == "nested":
                        concurrent.append(subject.nested(call_index))
                    else:
                        concurrent.append(worker_methods[call_index % len(worker_methods)](call_index))
                if concurrent:
                    await asyncio.gather(*concurrent)
                for batch in runtime.trace_patch_flush():
                    counters["published_events"] += len(batch["data"].get("events", ()))
                # Make subscriber batching deterministic while retaining the
                # same call_later delivery path used by production.
                await asyncio.sleep(0)
            await asyncio.sleep(0)
        wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
        cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
        allocated_current: int | None = None
        allocated_peak: int | None = None
        if config.allocation_tracking:
            allocated_current, allocated_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        for subscription in subscriptions:
            queue = subscription.subscriber.queue
            while not queue.empty():
                message = queue.get_nowait()
                counters["messages"] += 1
                counters["encoded_bytes"] += len(
                    json.dumps(message, separators=(",", ":"), default=str).encode()
                )
                events = message.get("data", {}).get("events", [])
                counters["delivered_events"] += len(events) if isinstance(events, list) else 0
                if message.get("event") == "trace:resync_required":
                    counters["resyncs"] += 1
            subscription.close()

        # Capture live cardinality before Runtime completes and removes its root.
        trace_store_count = len(runtime.trace_live_tree())
        groups = runtime.activity_groups.snapshots()
        diagnostics = dict(runtime.diagnostics)
        published_events = counters["published_events"]

    rss_after = process.memory_info().rss
    limitations = ()
    return BenchmarkResult(
        schema_version=SCHEMA_VERSION,
        benchmark="live_tracing_backend",
        implementation=config.mode,
        config=asdict(config),
        wall_ms=wall_ms,
        cpu_ms=cpu_ms,
        calls_per_second=config.calls / max(wall_ms / 1000, sys.float_info.min),
        allocated_current_bytes=allocated_current,
        allocated_peak_bytes=allocated_peak,
        rss_before_bytes=rss_before,
        rss_after_bytes=rss_after,
        peak_rss_bytes=sampler.peak,
        trace_store_count=trace_store_count,
        group_count=len(groups),
        group_evictions=(
            runtime.diagnostics["group_cardinality_overflow"]
        ),
        published_events=published_events,
        delivered_events=counters["delivered_events"],
        encoded_bytes=counters["encoded_bytes"],
        messages=counters["messages"],
        dropped_messages=diagnostics.get("trace_resync_required", 0),
        resyncs=counters["resyncs"],
        journal_depth=runtime.trace_transport.journal_depth,
        diagnostics=diagnostics,
        limitations=limitations,
    )


def result_document(result: BenchmarkResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_epoch_seconds": time.time(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "results": [asdict(result)],
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("unobserved", "capture", "aggregate"), default="aggregate"
    )
    parser.add_argument(
        "--workload", choices=("inline", "nested", "worker", "mixed"), default="inline"
    )
    parser.add_argument("--calls", type=int, default=10_000)
    parser.add_argument("--groups", type=int, default=10)
    parser.add_argument("--subscribers", type=int, default=1)
    parser.add_argument("--slow-subscriber", action="store_true")
    parser.add_argument("--overlay", choices=("open", "closed"), default="open")
    parser.add_argument("--track-allocations", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = asyncio.run(run_benchmark(BenchmarkConfig(
        mode=args.mode,
        workload=args.workload,
        calls=args.calls,
        groups=args.groups,
        subscribers=args.subscribers,
        slow_subscriber=args.slow_subscriber,
        overlay=args.overlay,
        allocation_tracking=args.track_allocations,
    )))
    encoded = json.dumps(result_document(result), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
