#!/usr/bin/env python3
"""Strict, isolated performance probes for the WebRTC event loop."""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import itertools
import json
import os
import random
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Literal


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

Mode = Literal["asyncio", "reference", "native-required"]
Scenario = Literal["idle", "timers", "ready", "cancelled", "cross-thread", "udp"]
MODES: tuple[Mode, ...] = ("asyncio", "reference", "native-required")
SCENARIOS: tuple[Scenario, ...] = (
    "idle", "timers", "ready", "cancelled", "cross-thread", "udp"
)


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    duration_seconds: float = 0.25
    timer_interval_seconds: float = 0.001
    ready_batch_size: int = 256
    cancelled_timer_count: int = 2_000
    cross_thread_batch_size: int = 64
    latency_sample_limit: int = 4_096
    allocation_operations: int = 2_048

    def validate(self) -> None:
        positive = {
            "duration": self.duration_seconds,
            "timer interval": self.timer_interval_seconds,
            "ready batch": self.ready_batch_size,
            "cancelled timers": self.cancelled_timer_count,
            "cross-thread batch": self.cross_thread_batch_size,
            "latency sample limit": self.latency_sample_limit,
            "allocation operations": self.allocation_operations,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")


def _loop_factory(mode: Mode) -> tuple[Callable[[], asyncio.AbstractEventLoop], str]:
    if mode == "asyncio":
        return asyncio.new_event_loop, "asyncio"
    from webrtc import event_loop
    if mode == "reference":
        return event_loop.reference_loop_factory, "reference"

    def native() -> asyncio.AbstractEventLoop:
        return event_loop.new_event_loop(require_native=True)

    loop = native()
    loop.close()
    return native, "native-required"


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * fraction)))
    return ordered[index]


class _BoundedLatency:
    """Deterministic bounded sampling; callback volume cannot grow memory."""

    def __init__(self, limit: int) -> None:
        self._samples: deque[float] = deque(maxlen=limit)
        self.observations = 0

    def add(self, seconds: float) -> None:
        self.observations += 1
        self._samples.append(max(0.0, seconds))

    def milliseconds(self) -> list[float]:
        return [sample * 1_000.0 for sample in self._samples]


def _run_scenario(
    loop: asyncio.AbstractEventLoop,
    scenario: Scenario,
    config: BenchmarkConfig,
    *,
    sample_latency: bool,
) -> tuple[int, int, _BoundedLatency]:
    callbacks = 0
    wakeups = 0
    latency = _BoundedLatency(config.latency_sample_limit)
    deadline = loop.time() + config.duration_seconds

    def record(scheduled: float) -> None:
        nonlocal callbacks
        callbacks += 1
        if sample_latency:
            latency.add(loop.time() - scheduled)

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
        lock = threading.Lock()
        remaining = 0

        def delivered(scheduled: float) -> None:
            nonlocal remaining, wakeups
            wakeups += 1
            record(scheduled)
            with lock:
                remaining -= 1
                if remaining == 0:
                    batch_finished.set()
            if loop.time() >= deadline:
                finished.set()
                loop.stop()

        def producer() -> None:
            nonlocal remaining
            while not finished.is_set():
                batch_finished.clear()
                with lock:
                    remaining = config.cross_thread_batch_size
                scheduled = time.monotonic()
                for _ in range(config.cross_thread_batch_size):
                    loop.call_soon_threadsafe(delivered, scheduled)
                batch_finished.wait(timeout=config.duration_seconds)

        thread = threading.Thread(target=producer, name="event-loop-benchmark")
        thread.start()
        try:
            loop.run_forever()
        finally:
            finished.set()
            thread.join()
        return callbacks, wakeups, latency
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
                if sample_latency and len(payload) == 8:
                    latency.add(loop.time() - struct.unpack("!d", payload)[0])
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
        return callbacks, wakeups, latency
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    loop.run_forever()
    return callbacks, wakeups, latency


def _timed_probe(factory: Callable[[], asyncio.AbstractEventLoop], scenario: Scenario,
                 config: BenchmarkConfig, *, latency: bool) -> dict[str, Any]:
    loop = factory()
    cancelled_handles: list[asyncio.TimerHandle] = []
    if scenario == "cancelled":
        far_future = loop.time() + 60.0
        cancelled_handles = [
            loop.call_at(far_future + index * 1e-9, lambda: None)
            for index in range(config.cancelled_timer_count)
        ]
        for handle in cancelled_handles:
            handle.cancel()
    gc_enabled = gc.isenabled()
    gc.disable()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    try:
        if scenario == "cancelled":
            loop.call_soon(loop.stop)
            loop.run_forever()
            callbacks, wakeups = len(cancelled_handles), 0
            samples = _BoundedLatency(config.latency_sample_limit)
        else:
            callbacks, wakeups, samples = _run_scenario(
                loop, scenario, config, sample_latency=latency
            )
    finally:
        cpu_seconds = time.process_time() - cpu_start
        wall_seconds = time.perf_counter() - wall_start
        loop.close()
        if gc_enabled:
            gc.enable()
    latency_ms = samples.milliseconds()
    return {
        "callbacks": callbacks,
        "wakeups": wakeups,
        "wall_seconds": wall_seconds,
        "process_cpu_seconds": cpu_seconds,
        "callbacks_per_cpu_second": callbacks / cpu_seconds if cpu_seconds else 0.0,
        "latency_observations": samples.observations,
        "latency_sample_count": len(latency_ms),
        "p50_ms": _percentile(latency_ms, 0.50),
        "p95_ms": _percentile(latency_ms, 0.95),
        "p99_ms": _percentile(latency_ms, 0.99),
        "maximum_ms": max(latency_ms, default=0.0),
    }


def _trace_category(traceback: object) -> str:
    filenames = tuple(
        str(getattr(frame, "filename", "")).replace("\\", "/")
        for frame in traceback  # type: ignore[union-attr]
    )
    benchmark = str(Path(__file__).resolve()).replace("\\", "/")
    if any(name == benchmark or name.endswith("/tracemalloc.py")
           for name in filenames):
        return "benchmark_harness"
    if any(any(part in name for part in
               ("/asyncio/", "/selectors.py", "/socket.py"))
           for name in filenames):
        return "selector_callback_external"
    if any("/webrtc/" in name or "generated.c" in name
           for name in filenames):
        return "compiler_or_event_loop"
    return "python_runtime_other"


def _allocation_epoch(
    factory: Callable[[], asyncio.AbstractEventLoop],
    scenario: Scenario,
    operations: int,
    *,
    close_loop: bool = True,
    baseline: tracemalloc.Snapshot | None = None,
) -> tuple[int, list[tracemalloc.StatisticDiff], int, int]:
    loop = factory()
    completed = 0
    submitted = 0
    cancelled: list[asyncio.TimerHandle] = []
    receiver: socket.socket | None = None
    sender: socket.socket | None = None

    def callback() -> None:
        nonlocal completed
        completed += 1

    if scenario == "cancelled":
        far_future = loop.time() + 60.0
        cancelled = [
            loop.call_at(far_future + index * 1e-9, callback)
            for index in range(operations)
        ]
        for handle in cancelled:
            handle.cancel()
    elif scenario == "udp":
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.setblocking(False)

        def receive() -> None:
            nonlocal completed
            while completed < operations:
                try:
                    receiver.recv(64)
                except BlockingIOError:
                    break
                completed += 1
            if completed >= operations:
                loop.stop()

        def submit() -> None:
            nonlocal submitted
            assert receiver is not None and sender is not None
            remaining = operations - submitted
            for _ in range(min(64, remaining)):
                sender.sendto(b"x", receiver.getsockname())
                submitted += 1
            if submitted < operations:
                loop.call_soon(submit)

        loop.add_reader(receiver.fileno(), receive)

    owns_trace = baseline is None
    if owns_trace:
        gc.collect()
        tracemalloc.start(16)
        baseline = tracemalloc.take_snapshot()
    if scenario in ("idle", "ready"):
        for _ in range(operations):
            loop.call_soon(callback)
    elif scenario == "timers":
        deadline = loop.time()
        for _ in range(operations):
            loop.call_at(deadline, callback)
    elif scenario == "cancelled":
        completed = len(cancelled)
    elif scenario == "cross-thread":
        for _ in range(operations):
            loop.call_soon_threadsafe(callback)
    elif scenario == "udp":
        loop.call_soon(submit)
    if scenario != "udp":
        loop.call_soon(loop.stop)
    loop.run_forever()
    after = tracemalloc.take_snapshot()
    assert baseline is not None
    differences = after.compare_to(baseline, "traceback")
    current, peak = tracemalloc.get_traced_memory()
    if owns_trace:
        tracemalloc.stop()
    if receiver is not None:
        loop.remove_reader(receiver.fileno())
        receiver.close()
    if sender is not None:
        sender.close()
    if close_loop:
        loop.close()
    return completed, differences, current, peak


def _allocation_probe(factory: Callable[[], asyncio.AbstractEventLoop],
                      scenario: Scenario, operations: int) -> dict[str, Any]:
    epochs: list[dict[str, Any]] = []
    loop = factory()
    # One unreported epoch warms Python, selector, and allocator caches. Five
    # measured epochs make a monotonic retained-growth regression observable.
    try:
        _allocation_epoch(
            lambda: loop, scenario, operations, close_loop=False
        )
        gc.collect()
        tracemalloc.start(16)
        baseline = tracemalloc.take_snapshot()
        for _ in range(5):
            completed, differences, current, peak = _allocation_epoch(
                lambda: loop, scenario, operations, close_loop=False,
                baseline=baseline,
            )
            categories: dict[str, dict[str, int]] = {}
            for item in differences:
                category = _trace_category(item.traceback)
                values = categories.setdefault(category, {"blocks": 0, "bytes": 0})
                values["blocks"] += item.count_diff
                values["bytes"] += item.size_diff
            workload_categories = (
                values for name, values in categories.items()
                if name != "benchmark_harness"
            )
            workload_totals = tuple(workload_categories)
            epochs.append({
                "completed": completed,
                "retained_blocks": sum(
                    values["blocks"] for values in workload_totals
                ),
                "retained_bytes": sum(
                    values["bytes"] for values in workload_totals
                ),
                "peak_traced_bytes": peak,
                "current_traced_bytes": current,
                "trace_categories": categories,
            })
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        loop.close()
    tail = epochs[-3:]
    block_span = max(item["retained_blocks"] for item in tail) - min(
        item["retained_blocks"] for item in tail
    )
    byte_span = max(item["retained_bytes"] for item in tail) - min(
        item["retained_bytes"] for item in tail
    )
    plateau = block_span <= 8 and byte_span <= 4_096
    final = epochs[-1]
    return {
        "scenario": scenario,
        "operations": operations,
        "completed": final["completed"],
        "retained_blocks": final["retained_blocks"],
        "retained_bytes": final["retained_bytes"],
        "peak_traced_bytes": final["peak_traced_bytes"],
        "current_traced_bytes": final["current_traced_bytes"],
        "trace_categories": final["trace_categories"],
        "epochs": epochs,
        "plateau": plateau,
        "plateau_tail_block_span": block_span,
        "plateau_tail_byte_span": byte_span,
    }


def _selector_probe(factory: Callable[[], asyncio.AbstractEventLoop],
                    iterations: int = 32) -> dict[str, int]:
    """Count selector calls without replacing the guarded selector object."""
    loop = factory()
    selector = getattr(loop, "_selector", None)
    polls = 0

    def profile(frame: Any, event: str, _argument: Any) -> None:
        nonlocal polls
        if (
            event == "call"
            and frame.f_code.co_name == "select"
            and frame.f_locals.get("self") is selector
        ):
            polls += 1

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        for _ in range(iterations):
            loop.call_soon(loop.stop)
            loop.run_forever()
    finally:
        sys.setprofile(previous)
        loop.close()
    return {"iterations": iterations, "polls": polls}


def _native_allocation_counters(
    factory: Callable[[], asyncio.AbstractEventLoop],
    scenario: Scenario,
    operations: int,
) -> dict[str, Any]:
    loop = factory()
    try:
        # Extension module functions retain their defining module as
        # ``__self__``.  The validated artifact loader deliberately does not
        # publish that module through sys.modules, so prefer the factory's
        # owner and keep the registry lookup for conventional import paths.
        module = getattr(factory, "__self__", None)
        if module is None:
            module = sys.modules.get(type(loop).__module__)
        if module is None:
            from webrtc import event_loop
            from webrtc.event_loop import compile_policy

            candidates = compile_policy.artifact_candidates()
            if len(candidates) != 1:
                raise RuntimeError("native artifact path is ambiguous")
            cached_factory = event_loop._diagnostic_factories.get(
                candidates[0].expanduser().resolve()
            )
            module = getattr(cached_factory, "__self__", None)
        reader = getattr(module, "__pymeta_native_allocation_counters__", None)
        reset = getattr(
            module, "__pymeta_reset_native_allocation_counters__", None
        )
        if not callable(reader):
            raise RuntimeError(
                "native artifact is not instrumented: missing "
                "__pymeta_native_allocation_counters__"
            )
        if not callable(reset):
            raise RuntimeError(
                "native artifact is not instrumented: missing "
                "__pymeta_reset_native_allocation_counters__"
            )
        # Warm the exact scenario so retained FIFO/heap capacity and generated
        # call caches are established before compiler-internal accounting.
        _allocation_epoch(
            lambda: loop, scenario, operations, close_loop=False
        )
        reset()
        before = dict(reader())
        measured_loop = loop
        loop = None
        _allocation_epoch(
            lambda: measured_loop, scenario, operations, close_loop=False
        )
        after = dict(reader())
        keys = set(before) | set(after)
        return {
            "available": True,
            "before": before,
            "after": after,
            "delta": {key: int(after.get(key, 0)) - int(before.get(key, 0))
                      for key in sorted(keys)},
        }
    finally:
        if 'measured_loop' in locals():
            measured_loop.close()
        if loop is not None:
            loop.close()


def _native_artifact_metadata(factory: Callable[[], asyncio.AbstractEventLoop]) -> dict[str, Any]:
    loop = factory()
    try:
        from webrtc.compiler.module_contract import COMPILER_VERSION, semantic_sha256
        from webrtc.event_loop import compile_policy

        candidates = compile_policy.artifact_candidates()
        if len(candidates) != 1:
            raise RuntimeError("native artifact path is ambiguous")
        artifact = candidates[0].expanduser().resolve()
        source = compile_policy.SOURCE_PATH.read_bytes()
        return {
            "path": str(artifact),
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "validated_compiler_version": COMPILER_VERSION,
            "validated_source_sha256": hashlib.sha256(source).hexdigest(),
            "validated_semantic_sha256": semantic_sha256(
                source, filename=str(compile_policy.SOURCE_PATH)
            ),
            "validated_policy": dict(compile_policy.ARTIFACT_POLICY_METADATA),
            "loop_type_module": type(loop).__module__,
        }
    finally:
        loop.close()


def run_worker(mode: Mode, scenario: Scenario, config: BenchmarkConfig) -> dict[str, Any]:
    config.validate()
    factory, resolved = _loop_factory(mode)
    throughput = _timed_probe(factory, scenario, config, latency=False)
    latency = _timed_probe(factory, scenario, config, latency=True)
    allocations = _allocation_probe(
        factory, scenario, config.allocation_operations
    )
    selector = _selector_probe(factory)
    native_allocations = (_native_allocation_counters(
                              factory, scenario, config.allocation_operations)
                          if mode == "native-required" else {"available": False})
    artifact = (_native_artifact_metadata(factory)
                if mode == "native-required" else None)
    return {
        "requested_mode": mode,
        "resolved_mode": resolved,
        "scenario": scenario,
        "config": asdict(config),
        "throughput": throughput,
        "latency": latency,
        "allocations": allocations,
        "selector": selector,
        "native_allocations": native_allocations,
        "native_artifact": artifact,
        "python": sys.version,
        "platform": sys.platform,
    }


def _bootstrap_lower_bound(ratios: list[float], *, seed: int = 0,
                           iterations: int = 10_000) -> float:
    if not ratios:
        raise ValueError("bootstrap requires paired ratios")
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        estimates.append(statistics.median(
            ratios[generator.randrange(len(ratios))] for _ in ratios
        ))
    return _percentile(estimates, 0.05)


def _summaries(samples: list[dict[str, Any]], scenarios: tuple[Scenario, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for scenario in scenarios:
        scenario_samples = [sample for sample in samples if sample["scenario"] == scenario]
        by_mode = {mode: [sample for sample in scenario_samples if sample["requested_mode"] == mode]
                   for mode in MODES}
        native_by_triple = {sample["triple"]: sample for sample in by_mode["native-required"]}
        comparisons: dict[str, Any] = {}
        for baseline in ("asyncio", "reference"):
            ratios = []
            for sample in by_mode[baseline]:
                native = native_by_triple[sample["triple"]]
                denominator = sample["throughput"]["callbacks_per_cpu_second"]
                ratios.append(native["throughput"]["callbacks_per_cpu_second"] / denominator
                              if denominator else 0.0)
            lower_bound = _bootstrap_lower_bound(ratios)
            comparisons[baseline] = {
                "paired_ratios": ratios,
                "median_ratio": statistics.median(ratios),
                "one_sided_95_percent_lower_bound": lower_bound,
                "meets_1_20_gate": scenario == "idle" or lower_bound >= 1.20,
            }
        p99 = {
            mode: statistics.median(
                float(sample["latency"]["p99_ms"]) for sample in by_mode[mode]
            ) for mode in MODES
        }
        better_p99 = min(p99["asyncio"], p99["reference"])
        latency_limit = better_p99 + max(better_p99 * 0.05, 0.1)
        allocation_medians = {
            mode: {
                field: statistics.median(
                    max(0, int(sample["allocations"][field]))
                    for sample in by_mode[mode]
                )
                for field in ("retained_blocks", "retained_bytes")
            }
            for mode in MODES
        }
        allocation_pass = all(
            allocation_medians["native-required"][field]
            <= min(allocation_medians["asyncio"][field],
                   allocation_medians["reference"][field])
            for field in ("retained_blocks", "retained_bytes")
        )
        counter_samples = [sample["native_allocations"]
                           for sample in by_mode["native-required"]]
        counter_pass = bool(counter_samples) and all(
            sample.get("available") and
            all(value == 0 for key, value in sample.get("delta", {}).items()
                if key.endswith(".allocations"))
            for sample in counter_samples
        )
        plateau_pass = all(
            bool(sample["allocations"].get("plateau"))
            for sample in by_mode["native-required"]
        )
        idle_cpu_pass = True
        if scenario == "idle":
            cpu = {
                mode: statistics.median(
                    float(sample["throughput"]["process_cpu_seconds"])
                    for sample in by_mode[mode]
                ) for mode in MODES
            }
            idle_cpu_pass = cpu["native-required"] <= min(
                cpu["asyncio"], cpu["reference"]
            )
        gates = {
            "throughput": all(item["meets_1_20_gate"]
                              for item in comparisons.values()),
            "latency": p99["native-required"] <= latency_limit,
            "python_allocations": allocation_pass,
            "native_internal_allocations": counter_pass,
            "retained_memory_plateau": plateau_pass,
            "idle_cpu": idle_cpu_pass,
        }
        result[scenario] = {
            "comparisons": comparisons,
            "p99_ms_median": p99,
            "native_p99_limit_ms": latency_limit,
            "allocation_medians": allocation_medians,
            "gates": gates,
            "passes_all_gates": all(gates.values()),
        }
    return result


def run_controller(config: BenchmarkConfig, scenarios: tuple[Scenario, ...],
                   triples: int) -> dict[str, Any]:
    if triples < 3:
        raise ValueError("paired benchmarks require at least three isolated triples")
    samples: list[dict[str, Any]] = []
    script = Path(__file__).resolve()
    orders = tuple(itertools.permutations(MODES))
    for triple in range(triples):
        for scenario in scenarios:
            for mode in orders[triple % len(orders)]:
                completed = subprocess.run(
                    [sys.executable, str(script), "--worker", "--mode", mode,
                     "--scenario", scenario, "--config-json",
                     json.dumps(asdict(config), sort_keys=True)],
                    check=True, capture_output=True, text=True,
                    cwd=REPOSITORY_ROOT,
                    env={**os.environ, "PYTHONHASHSEED": "0"},
                )
                sample = json.loads(completed.stdout)
                sample["triple"] = triple
                sample["order"] = orders[triple % len(orders)]
                samples.append(sample)
    summaries = _summaries(samples, scenarios)
    return {
        "config": asdict(config),
        "triples": triples,
        "scenarios": scenarios,
        "samples": samples,
        "summaries": summaries,
        "adoption_eligible": all(
            summary["passes_all_gates"] for summary in summaries.values()
        ) and set(("ready", "timers", "cancelled", "cross-thread", "udp"))
        .issubset(scenarios),
        "note": "Native adoption requires every correctness, latency, allocation, and throughput gate to pass.",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--mode", choices=MODES, default="asyncio")
    parser.add_argument("--scenario", choices=SCENARIOS, default="ready")
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS)
    parser.add_argument("--triples", "--pairs", dest="triples", type=int, default=15)
    parser.add_argument("--duration", type=float, default=0.25)
    parser.add_argument("--allocation-operations", type=int, default=2_048)
    parser.add_argument("--config-json")
    parser.add_argument("--output", type=Path,
                        default=REPOSITORY_ROOT / "benchmark-results" / "event-loop.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = (BenchmarkConfig(**json.loads(args.config_json)) if args.config_json
              else BenchmarkConfig(duration_seconds=args.duration,
                                   allocation_operations=args.allocation_operations))
    if args.worker:
        print(json.dumps(run_worker(args.mode, args.scenario, config), sort_keys=True))
        return 0
    report = run_controller(config, tuple(args.scenarios), args.triples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
