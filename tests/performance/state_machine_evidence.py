"""Repeatable Stage-7 state-machine performance evidence.

The runner separates structural assertions (safe for every CI job) from a
paired CPU budget (run on an idle, pinned performance worker).  Process CPU is
used throughout: moving work to a thread must not manufacture an improvement.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import inspect
import json
import math
import os
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from webrtc import Runtime
from webrtc.peer_components import AsyncLogDrain
import webrtc.peer_components as peer_components
from webrtc.peer_connection import PeerConnection


SCHEMA_VERSION = 2
BASELINE = Path(__file__).with_name("baselines") / "state_machine_evidence.json"


@dataclass(frozen=True, slots=True)
class Timing:
    process_cpu_ms: float
    wall_ms: float
    rate_per_second: float
    event_loop_lag_p95_ms: float | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    schema_version: int
    calls: int
    tracing_off: Timing
    tracing_on: Timing
    paired_cpu_overhead_samples_percent: tuple[float, ...]
    aggregate_cpu_overhead_percent: float
    worker_projection_disabled: Timing
    worker_projection_enabled: Timing
    worker_lifecycle_transitions: int
    state_counter_scope: str
    state_commands: int
    state_commits: int
    rejected_commands: int
    mailbox_high_water: int
    projection_merges: int
    activity_projection_updates: int
    producer_dot_allocations: int
    packet_exact: Timing
    packet_coalesced: Timing
    packet_exact_projection_merges: int
    packet_coalesced_projection_merges: int
    full_peer_tracing_off: Timing
    full_peer_tracing_on: Timing
    full_peer_cpu_overhead_samples_percent: tuple[float, ...]
    full_peer_cpu_overhead_percent: float
    runnable_tasks_steady: int
    runnable_tasks_after_shutdown: int
    startup_cpu_ms: float
    close_cpu_ms: float
    polling_waiter_tasks: int


class _EvidenceLogger:
    def __init__(self) -> None:
        self.checksum = 0

    def write_events_sync(self, value: int) -> None:
        result = value
        for index in range(16_000):
            result = ((result * 33) ^ index) & 0xFFFFFFFF
        self.checksum ^= result


def _subject() -> AsyncLogDrain:
    """Production allowlisted type without starting its unrelated drain service."""
    return object.__new__(AsyncLogDrain)


async def _call_sample(*, observed: bool, calls: int) -> tuple[Timing, int, int]:
    subject = _subject()
    evidence_logger = _EvidenceLogger()
    lags: list[float] = []
    async with Runtime(scope_id=f"evidence-{'on' if observed else 'off'}",
                       tracing_enabled=observed) as runtime:
        start_sequence = runtime._producer_sequence
        aggregate_updates = 0
        original_begin, original_end = runtime.activity_groups.begin, runtime.activity_groups.end
        runtime.register_owner("evidence:log-drain", epoch=1, role="log-drain")
        runtime.bind_observation(
            subject, entity_id="evidence:log-drain", role="log-drain", owner_epoch=1,
        )
        def count_begin(*args: Any, **kwargs: Any):
            nonlocal aggregate_updates
            aggregate_updates += 1
            return original_begin(*args, **kwargs)
        def count_end(*args: Any, **kwargs: Any):
            nonlocal aggregate_updates
            aggregate_updates += 1
            return original_end(*args, **kwargs)
        runtime.activity_groups.begin = count_begin
        runtime.activity_groups.end = count_end
        # Collection timing depends on allocations from earlier profiles and
        # can dwarf a 5% budget. Collect before, then hold GC state constant
        # across each paired sample (reference counting remains active).
        gc.collect()
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            started_cpu = time.process_time_ns()
            started_wall = time.perf_counter_ns()
            original_logger = peer_components.get_logger
            peer_components.get_logger = lambda: evidence_logger
            batch = 16
            try:
                for start in range(0, calls, batch):
                    scheduled = time.perf_counter_ns()
                    future = asyncio.get_running_loop().create_future()
                    asyncio.get_running_loop().call_soon(
                        lambda f=future, at=scheduled: f.set_result((time.perf_counter_ns() - at) / 1e6)
                    )
                    for value in range(start, min(calls, start + batch)):
                        subject.write_batch(value)
                    lags.append(await future)
                cpu_ms = (time.process_time_ns() - started_cpu) / 1e6
                wall_ms = (time.perf_counter_ns() - started_wall) / 1e6
            finally:
                peer_components.get_logger = original_logger
        finally:
            if was_enabled:
                gc.enable()
        dots = runtime._producer_sequence - start_sequence
        runtime.activity_groups.begin, runtime.activity_groups.end = original_begin, original_end
        if evidence_logger.checksum < 0:  # keep the workload result live
            raise AssertionError(evidence_logger.checksum)
        runtime.remove_owner("evidence:log-drain", 1)
    return Timing(cpu_ms, wall_ms, calls / max(wall_ms / 1000, sys.float_info.min),
                  _percentile(lags, 0.95)), dots, aggregate_updates


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(len(ordered) * quantile) - 1)]


async def _worker_sample(enabled: bool, calls: int) -> tuple[Timing, int, int]:
    async with Runtime(scope_id=f"worker-projection-{enabled}", max_workers=4) as runtime:
        initial_revision = runtime._worker_runner.revision
        if not enabled:
            runtime.worker_lane.set_state_publisher(None)  # type: ignore[arg-type]
        started_cpu = time.process_time_ns()
        started_wall = time.perf_counter_ns()
        for start in range(0, calls, 32):
            await asyncio.gather(*(
                runtime.worker_lane.run(lambda value=value: (value * 17) ^ 3)
                for value in range(start, min(calls, start + 32))
            ))
        await asyncio.sleep(0)
        cpu_ms = (time.process_time_ns() - started_cpu) / 1e6
        wall_ms = (time.perf_counter_ns() - started_wall) / 1e6
        transitions = runtime._worker_runner.revision - initial_revision
        high_water = runtime.worker_lane.load_snapshot()[2]
    return Timing(cpu_ms, wall_ms, calls / max(wall_ms / 1000, sys.float_info.min)), transitions, high_water


async def _packet_sample(exact: bool, packets: int) -> tuple[Timing, int, int]:
    async with Runtime(scope_id=f"packet-{'exact' if exact else 'coalesced'}") as runtime:
        merges = 0
        start_dots = runtime._producer_sequence
        original = runtime.projection.merge_values
        def count_merge(*args: Any, **kwargs: Any):
            nonlocal merges
            merges += 1
            return original(*args, **kwargs)
        runtime.projection.merge_values = count_merge
        started_cpu = time.process_time_ns()
        started_wall = time.perf_counter_ns()
        for packet in range(packets):
            runtime.record_srtp_delivery(
                protocol="srtp-rtp", stream_id="benchmark", delivered=True,
            )
            if exact:
                # Historical exact projection published every packet. The
                # coalesced path publishes the same cumulative facet once.
                runtime._aggregate_facet_adapter.flush_srtp_delivery()
        runtime._aggregate_facet_adapter.flush_srtp_delivery()
        cpu_ms = (time.process_time_ns() - started_cpu) / 1e6
        wall_ms = (time.perf_counter_ns() - started_wall) / 1e6
        runtime.projection.merge_values = original
        dots = runtime._producer_sequence - start_dots
    return Timing(cpu_ms, wall_ms, packets / max(wall_ms / 1000, sys.float_info.min)), merges, dots


def _polling_waiter_count() -> int:
    count = 0
    for task in asyncio.all_tasks():
        for frame in task.get_stack():
            info = inspect.getframeinfo(frame, context=1)
            if info.code_context and "asyncio.sleep(0)" in info.code_context[0]:
                count += 1
                break
    return count


async def _full_peer_sample(observed: bool, calls: int) -> tuple[Timing, int, int, int]:
    """Exercise the complete PeerConnection ownership graph without network I/O."""
    baseline = len(asyncio.all_tasks())
    started_cpu = time.process_time_ns()
    started_wall = time.perf_counter_ns()
    steady = baseline
    polling = 0
    subject = _subject()
    evidence_logger = _EvidenceLogger()
    async with Runtime(scope_id=f"full-peer-evidence-{observed}", tracing_enabled=observed) as runtime:
        runtime.register_owner("full-peer:evidence-log", epoch=1, role="log-drain")
        runtime.bind_observation(
            subject, entity_id="full-peer:evidence-log", role="log-drain", owner_epoch=1,
        )
        async with PeerConnection(peer_id="full-peer-evidence"):
            # All protocol owners, inboxes and cleanup tasks are now runnable;
            # packet-rate evidence is isolated above to avoid network variance.
            steady = len(asyncio.all_tasks())
            polling = _polling_waiter_count()
            original_logger = peer_components.get_logger
            peer_components.get_logger = lambda: evidence_logger
            try:
                for value in range(calls):
                    subject.write_batch(value)
            finally:
                peer_components.get_logger = original_logger
            if evidence_logger.checksum < 0:
                raise AssertionError(evidence_logger.checksum)
        runtime.remove_owner("full-peer:evidence-log", 1)
    cpu_ms = (time.process_time_ns() - started_cpu) / 1e6
    wall_ms = (time.perf_counter_ns() - started_wall) / 1e6
    return (Timing(cpu_ms, wall_ms, 1000 / max(wall_ms, sys.float_info.min)),
            max(steady - baseline, 0), max(len(asyncio.all_tasks()) - baseline, 0), polling)


async def run_evidence(*, calls: int = 512, pairs: int = 5, packets: int = 512) -> Evidence:
    if calls < 32 or pairs < 3 or packets < 32:
        raise ValueError("calls/packets must be >=32 and pairs must be >=3")
    samples: list[float] = []
    off_runs: list[Timing] = []
    on_runs: list[Timing] = []
    dots = activity_updates = 0
    # Warm imports, pools and caches; alternate AB/BA to reduce thermal drift.
    await _call_sample(observed=False, calls=max(32, calls // 8))
    await _call_sample(observed=True, calls=max(32, calls // 8))
    for pair in range(pairs):
        order = (False, True) if pair % 2 == 0 else (True, False)
        measured: dict[bool, Timing] = {}
        for observed in order:
            timing, allocated, group_count = await _call_sample(observed=observed, calls=calls)
            measured[observed] = timing
            if observed:
                dots += allocated
                activity_updates += group_count
        off_runs.append(measured[False]); on_runs.append(measured[True])
        samples.append((measured[True].process_cpu_ms / measured[False].process_cpu_ms - 1) * 100)
    off, on = _median_timing(off_runs), _median_timing(on_runs)
    disabled, disabled_transitions, disabled_high = await _worker_sample(False, calls)
    enabled, enabled_transitions, enabled_high = await _worker_sample(True, calls)
    exact, exact_merges, exact_dots = await _packet_sample(True, packets)
    coalesced, coalesced_merges, coalesced_dots = await _packet_sample(False, packets)
    peer_calls = max(64, calls // 2)
    await _full_peer_sample(False, max(16, peer_calls // 4))
    await _full_peer_sample(True, max(16, peer_calls // 4))
    peer_samples: list[float] = []
    peer_off_runs: list[Timing] = []
    peer_on_runs: list[Timing] = []
    off_steady = on_steady = off_after = on_after = off_polling = on_polling = 0
    for pair in range(pairs):
        measured_peer: dict[bool, Timing] = {}
        order = (False, True) if pair % 2 == 0 else (True, False)
        for observed in order:
            timing, steady_tasks, after_tasks, polling_tasks = await _full_peer_sample(
                observed, peer_calls,
            )
            measured_peer[observed] = timing
            if observed:
                on_steady, on_after, on_polling = steady_tasks, after_tasks, polling_tasks
            else:
                off_steady, off_after, off_polling = steady_tasks, after_tasks, polling_tasks
        peer_off_runs.append(measured_peer[False]); peer_on_runs.append(measured_peer[True])
        peer_samples.append(
            (measured_peer[True].process_cpu_ms / measured_peer[False].process_cpu_ms - 1) * 100
        )
    peer_off, peer_on = _median_timing(peer_off_runs), _median_timing(peer_on_runs)

    before = len(asyncio.all_tasks())
    start_cpu = time.process_time_ns()
    runtime = Runtime(scope_id="startup-close-evidence")
    await runtime.__aenter__()
    startup_cpu = (time.process_time_ns() - start_cpu) / 1e6
    steady = len(asyncio.all_tasks())
    commands_before = runtime._runtime_command_id + runtime._worker_command_id
    commits_before = runtime._runtime_runner.revision + runtime._worker_runner.revision
    mailbox_high_water = 0
    original_submit = runtime._runtime_runner.try_submit
    def count_submit(command: Any):
        nonlocal mailbox_high_water
        original_submit(command)
        mailbox_high_water = max(mailbox_high_water, runtime._runtime_runner.commands.depth)
    runtime._runtime_runner.try_submit = count_submit
    rejected_commands = 0
    try:
        await runtime._move_lifecycle(runtime._runtime_runner, "new")
    except Exception:
        rejected_commands += 1
    close_cpu_start = time.process_time_ns()
    await runtime.__aexit__(None, None, None)
    close_cpu = (time.process_time_ns() - close_cpu_start) / 1e6
    after = len(asyncio.all_tasks())
    state_commands = runtime._runtime_command_id + runtime._worker_command_id - commands_before
    state_commits = runtime._runtime_runner.revision + runtime._worker_runner.revision - commits_before
    runtime._runtime_runner.try_submit = original_submit
    polling = max(off_polling, on_polling)

    return Evidence(
        SCHEMA_VERSION, calls, off, on, tuple(samples), statistics.median(samples),
        disabled, enabled, disabled_transitions + enabled_transitions,
        "isolated runtime lifecycle admission/rejection/close probe",
        state_commands, state_commits, rejected_commands, mailbox_high_water,
        exact_merges + coalesced_merges, activity_updates,
        dots + exact_dots + coalesced_dots,
        exact, coalesced, exact_merges, coalesced_merges, peer_off, peer_on,
        tuple(peer_samples), statistics.median(peer_samples),
        max(off_steady, on_steady, steady - before), max(off_after, on_after, after - before),
        startup_cpu, close_cpu, polling,
    )


def _median_timing(values: list[Timing]) -> Timing:
    lag = [v.event_loop_lag_p95_ms for v in values if v.event_loop_lag_p95_ms is not None]
    return Timing(statistics.median(v.process_cpu_ms for v in values),
                  statistics.median(v.wall_ms for v in values),
                  statistics.median(v.rate_per_second for v in values),
                  statistics.median(lag) if lag else None)


def validate(result: Evidence, budget: dict[str, Any], *, enforce_cpu: bool) -> list[str]:
    errors: list[str] = []
    if result.worker_lifecycle_transitions != 0:
        errors.append("worker calls created lifecycle transitions")
    if result.packet_coalesced_projection_merges >= result.packet_exact_projection_merges:
        errors.append("packet facets were not coalesced")
    if result.runnable_tasks_after_shutdown != 0:
        errors.append("runtime tasks survived shutdown")
    if result.polling_waiter_tasks != 0:
        errors.append("polling waiter tasks detected")
    if enforce_cpu and result.aggregate_cpu_overhead_percent > budget["aggregate_tracing_cpu_overhead_percent_max"]:
        errors.append(f"aggregate CPU overhead {result.aggregate_cpu_overhead_percent:.2f}% exceeds budget")
    if enforce_cpu and result.full_peer_cpu_overhead_percent > budget["aggregate_tracing_cpu_overhead_percent_max"]:
        errors.append(f"full-peer CPU overhead {result.full_peer_cpu_overhead_percent:.2f}% exceeds budget")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=512)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--packets", type=int, default=512)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--enforce-cpu", action="store_true",
                        help="enforce <=5%%; use only on an idle pinned performance worker")
    args = parser.parse_args()
    result = asyncio.run(run_evidence(calls=args.calls, pairs=args.pairs, packets=args.packets))
    payload = asdict(result)
    output = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    budget = json.loads(BASELINE.read_text(encoding="utf-8"))
    errors = validate(result, budget["budget"], enforce_cpu=args.enforce_cpu)
    for error in errors:
        print(error, file=sys.stderr)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
