#!/usr/bin/env python3
"""Isolated, machine-readable microbenchmarks for the WebRTC event loop.

The benchmark deliberately reports measurements rather than deciding whether a
result meets the project's adoption thresholds.  Run stock and automatic modes
in separate processes so selector state, allocator state, and ready queues are
not shared between samples.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Literal


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))


Mode = Literal["asyncio", "auto"]
Scenario = Literal[
    "idle", "timers", "ready", "cancelled", "cross-thread", "udp"
]


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    duration_seconds: float = 0.25
    timer_interval_seconds: float = 0.001
    ready_batch_size: int = 256
    cancelled_timer_count: int = 2_000
    cross_thread_batch_size: int = 64

    def validate(self) -> None:
        if self.duration_seconds <= 0:
            raise ValueError("duration must be positive")
        if self.timer_interval_seconds <= 0:
            raise ValueError("timer interval must be positive")
        if self.ready_batch_size <= 0:
            raise ValueError("ready batch size must be positive")
        if self.cancelled_timer_count <= 0:
            raise ValueError("cancelled timer count must be positive")
        if self.cross_thread_batch_size <= 0:
            raise ValueError("cross-thread batch size must be positive")


def _loop_factory(mode: Mode) -> tuple[Callable[[], asyncio.AbstractEventLoop], str]:
    if mode == "asyncio":
        return asyncio.new_event_loop, "asyncio"
    # Import only in auto workers.  This keeps the stock baseline independent
    # from native-module discovery and import costs.
    from webrtc import event_loop

    return event_loop.new_event_loop, event_loop.event_loop_mode()


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return ordered[index]


class _SelectorProbe:
    def __init__(self, selector: Any) -> None:
        self._selector = selector
        self.polls = 0

    def select(self, timeout: float | None = None) -> Any:
        self.polls += 1
        return self._selector.select(timeout)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._selector, name)


def _run_scenario(
    loop: asyncio.AbstractEventLoop, scenario: Scenario, config: BenchmarkConfig
) -> tuple[int, int, list[float]]:
    callbacks = 0
    wakeups = 0
    latencies: list[float] = []
    deadline = loop.time() + config.duration_seconds

    def record(scheduled: float) -> None:
        nonlocal callbacks
        callbacks += 1
        latencies.append(max(0.0, loop.time() - scheduled))

    if scenario == "idle":
        loop.call_at(deadline, loop.stop)
    elif scenario == "timers":
        def timer_tick(scheduled: float) -> None:
            record(scheduled)
            following = scheduled + config.timer_interval_seconds
            if following < deadline:
                loop.call_at(following, timer_tick, following)
            else:
                loop.stop()

        first = loop.time() + config.timer_interval_seconds
        loop.call_at(first, timer_tick, first)
    elif scenario == "ready":
        remaining = 0

        def schedule_batch() -> None:
            nonlocal remaining
            remaining = config.ready_batch_size
            scheduled = loop.time()
            for _ in range(config.ready_batch_size):
                loop.call_soon(ready_tick, scheduled)

        def ready_tick(scheduled: float) -> None:
            nonlocal remaining
            record(scheduled)
            remaining -= 1
            if remaining == 0:
                if loop.time() < deadline:
                    schedule_batch()
                else:
                    loop.stop()

        schedule_batch()
    elif scenario == "cancelled":
        far_future = deadline + 60.0
        while loop.time() < deadline:
            handles = [
                loop.call_at(far_future + index * 1e-9, record, far_future)
                for index in range(config.cancelled_timer_count)
            ]
            for handle in handles:
                handle.cancel()
            callbacks += len(handles)
        loop.call_soon(loop.stop)
    elif scenario == "cross-thread":
        finished = threading.Event()
        batch_finished = threading.Event()
        batch_lock = threading.Lock()
        batch_remaining = 0

        def thread_callback(scheduled: float) -> None:
            nonlocal batch_remaining, wakeups
            wakeups += 1
            record(scheduled)
            with batch_lock:
                batch_remaining -= 1
                if batch_remaining == 0:
                    batch_finished.set()
            if loop.time() >= deadline:
                finished.set()
                loop.stop()

        def producer() -> None:
            nonlocal batch_remaining
            while not finished.is_set():
                batch_finished.clear()
                with batch_lock:
                    batch_remaining = config.cross_thread_batch_size
                now = time.monotonic()
                for _ in range(config.cross_thread_batch_size):
                    loop.call_soon_threadsafe(thread_callback, now)
                batch_finished.wait(timeout=config.duration_seconds)

        thread = threading.Thread(target=producer, name="event-loop-benchmark")
        thread.start()
        try:
            loop.run_forever()
        finally:
            finished.set()
            thread.join()
        return callbacks, wakeups, latencies
    elif scenario == "udp":
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.setblocking(False)
        address = receiver.getsockname()
        finished = threading.Event()

        def receive() -> None:
            nonlocal callbacks
            while True:
                try:
                    payload = receiver.recv(64)
                except BlockingIOError:
                    break
                callbacks += 1
                if len(payload) == 8:
                    latencies.append(max(0.0, loop.time() - struct.unpack("!d", payload)[0]))
            if loop.time() >= deadline:
                finished.set()
                loop.stop()

        def flood() -> None:
            while not finished.is_set():
                sender.sendto(struct.pack("!d", time.monotonic()), address)

        loop.add_reader(receiver.fileno(), receive)
        thread = threading.Thread(target=flood, name="event-loop-udp-benchmark")
        thread.start()
        loop.call_at(deadline, finished.set)
        loop.call_at(deadline, loop.stop)
        try:
            loop.run_forever()
        finally:
            finished.set()
            thread.join()
            loop.remove_reader(receiver.fileno())
            sender.close()
            receiver.close()
        return callbacks, wakeups, latencies
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    loop.run_forever()
    return callbacks, wakeups, latencies


def run_worker(mode: Mode, scenario: Scenario, config: BenchmarkConfig) -> dict[str, Any]:
    config.validate()
    factory, resolved_mode = _loop_factory(mode)
    loop = factory()
    selector = getattr(loop, "_selector", None)
    probe = _SelectorProbe(selector) if selector is not None else None
    if probe is not None:
        loop._selector = probe  # type: ignore[attr-defined]

    gc.collect()
    tracemalloc.start()
    allocation_before = tracemalloc.take_snapshot()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    try:
        callbacks, wakeups, latencies = _run_scenario(loop, scenario, config)
    finally:
        cpu_seconds = time.process_time() - cpu_start
        wall_seconds = time.perf_counter() - wall_start
        allocation_after = tracemalloc.take_snapshot()
        loop.close()
        tracemalloc.stop()

    allocation_differences = allocation_after.compare_to(
        allocation_before, "traceback"
    )
    allocated_blocks = sum(max(0, item.count_diff) for item in allocation_differences)
    allocated_bytes = sum(max(0, item.size_diff) for item in allocation_differences)
    latency_ms = [sample * 1_000 for sample in latencies]
    return {
        "requested_mode": mode,
        "resolved_mode": resolved_mode,
        "scenario": scenario,
        "config": asdict(config),
        "callbacks": callbacks,
        "wakeups": wakeups,
        "selector_polls": 0 if probe is None else probe.polls,
        "wall_seconds": wall_seconds,
        "process_cpu_seconds": cpu_seconds,
        "callbacks_per_cpu_second": callbacks / cpu_seconds if cpu_seconds else 0.0,
        "allocations": {
            "positive_blocks": allocated_blocks,
            "positive_bytes": allocated_bytes,
        },
        "latency_ms": {
            "sample_count": len(latency_ms),
            "p50": _percentile(latency_ms, 0.50),
            "p95": _percentile(latency_ms, 0.95),
            "p99": _percentile(latency_ms, 0.99),
            "maximum": max(latency_ms, default=0.0),
        },
        "python": sys.version,
        "platform": sys.platform,
    }


def run_controller(
    config: BenchmarkConfig, scenarios: tuple[Scenario, ...], pairs: int
) -> dict[str, Any]:
    if pairs < 3:
        raise ValueError("paired benchmarks require at least three isolated pairs")
    samples: list[dict[str, Any]] = []
    script = Path(__file__).resolve()
    for pair in range(pairs):
        # Alternate order to reduce a monotonic thermal/order bias.
        modes: tuple[Mode, Mode] = (
            ("asyncio", "auto") if pair % 2 == 0 else ("auto", "asyncio")
        )
        for scenario in scenarios:
            for mode in modes:
                command = [
                    sys.executable,
                    str(script),
                    "--worker",
                    "--mode",
                    mode,
                    "--scenario",
                    scenario,
                    "--config-json",
                    json.dumps(asdict(config), sort_keys=True),
                ]
                completed = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    cwd=REPOSITORY_ROOT,
                    env={**os.environ, "PYTHONHASHSEED": "0"},
                )
                sample = json.loads(completed.stdout)
                sample["pair"] = pair
                samples.append(sample)
    return {
        "config": asdict(config),
        "pairs": pairs,
        "scenarios": scenarios,
        "samples": samples,
        "note": (
            "Raw paired measurements only; apply the repository's adoption "
            "thresholds and confidence analysis before selecting native mode."
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--mode", choices=("asyncio", "auto"), default="asyncio")
    parser.add_argument(
        "--scenario",
        choices=("idle", "timers", "ready", "cancelled", "cross-thread", "udp"),
        default="ready",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=("idle", "timers", "ready", "cancelled", "cross-thread", "udp"),
        default=("idle", "timers", "ready", "cancelled", "cross-thread", "udp"),
    )
    parser.add_argument("--pairs", type=int, default=7)
    parser.add_argument("--duration", type=float, default=0.25)
    parser.add_argument("--config-json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.config_json:
        config = BenchmarkConfig(**json.loads(args.config_json))
    else:
        config = BenchmarkConfig(duration_seconds=args.duration)
    if args.worker:
        print(json.dumps(run_worker(args.mode, args.scenario, config), sort_keys=True))
    else:
        print(
            json.dumps(
                run_controller(config, tuple(args.scenarios), args.pairs),
                sort_keys=True,
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
