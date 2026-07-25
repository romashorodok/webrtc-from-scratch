#!/usr/bin/env python3
"""Reproducible Python-versus-native benchmark for the Kernel E source module.

The controller builds ``webrtc/compiler/kernel_e.py`` once, then launches every
timed sample in a fresh interpreter.  Python samples and native samples both
enter through ``webrtc.compiler.runtime.packetize_av1_frame``; only the module
selected by the runtime dispatcher differs.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from webrtc.compiler import kernel_e, runtime  # noqa: E402
from webrtc.compiler.module_compiler import compile_module  # noqa: E402


Mode = Literal["python", "native-required"]


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    duration_seconds: float = 5.0
    warmup_seconds: float = 2.0
    frames_per_second: int = 30
    bitrate_bps_per_peer: int = 2_000_000
    peer_count: int = 1
    mtu: int = 1200
    ticker_interval_seconds: float = 0.001
    allocation_calls: int = 64
    corpus_seed: int = 0x4B45524E
    network_profile: str = "deterministic-null-sink"
    packet_loss_ppm: int = 0

    def validate(self) -> None:
        if self.duration_seconds <= 0 or self.warmup_seconds < 0:
            raise ValueError("duration must be positive and warmup nonnegative")
        if self.frames_per_second <= 0 or self.bitrate_bps_per_peer <= 0:
            raise ValueError("frame rate and bitrate must be positive")
        if self.peer_count <= 0:
            raise ValueError("peer count must be positive")
        if not 3 <= self.mtu <= 65_535:
            raise ValueError("mtu must be in range 3..65535")
        if self.ticker_interval_seconds <= 0:
            raise ValueError("ticker interval must be positive")
        if self.allocation_calls <= 0:
            raise ValueError("allocation calls must be positive")
        if not 0 <= self.packet_loss_ppm <= 1_000_000:
            raise ValueError("packet loss must be in range 0..1000000 ppm")
        if self.network_profile != "deterministic-null-sink":
            raise ValueError("unsupported network profile")


@dataclass(slots=True)
class PeerState:
    rtp_sequence: int
    twcc_sequence: int


@dataclass(slots=True)
class Counters:
    frames: int = 0
    packets: int = 0
    input_bytes: int = 0
    packet_output_bytes: int = 0
    observable_output_copy_bytes: int = 0
    network_accepted_packets: int = 0
    network_accepted_bytes: int = 0
    checksum: int = 0


def _leb128(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append(0x80 | (value & 0x7F))
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _deterministic_payload(length: int, seed: int) -> bytes:
    state = seed & 0xFFFF_FFFF
    result = bytearray(length)
    for index in range(length):
        state ^= (state << 13) & 0xFFFF_FFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFF_FFFF
        result[index] = state & 0xFF
    return bytes(result)


def build_corpus(config: BenchmarkConfig) -> tuple[bytes, ...]:
    """Build a stable, valid AV1 OBU corpus whose mean size matches bitrate."""
    mean_payload = max(
        1, round(config.bitrate_bps_per_peer / 8 / config.frames_per_second)
    )
    proportions = (60, 80, 100, 120, 140)
    frames: list[bytes] = []
    for index, proportion in enumerate(proportions):
        payload_length = max(1, mean_payload * proportion // 100)
        payload = _deterministic_payload(
            payload_length, config.corpus_seed + index * 0x9E37
        )
        # Type 6, has_size_field=1. This is the same ordinary Python input for
        # the interpreted function and the function compiled from that source.
        frames.append(bytes((6 << 3 | 0x02,)) + _leb128(len(payload)) + payload)
    return tuple(frames)


def _configure_mode(mode: Mode, artifact: Path | None) -> None:
    if mode == "python":
        runtime.configure_kernel_e(mode="python")
    else:
        if artifact is None:
            raise ValueError("native-required mode needs an artifact")
        runtime.configure_kernel_e(mode="native-required", library_path=artifact)


def _packet_is_dropped(packet_ordinal: int, loss_ppm: int, seed: int) -> bool:
    if loss_ppm == 0:
        return False
    mixed = (packet_ordinal * 2_654_435_761 + seed) & 0xFFFF_FFFF
    return mixed % 1_000_000 < loss_ppm


def _process_frame(
    frame: bytes,
    peer_index: int,
    state: PeerState,
    config: BenchmarkConfig,
    counters: Counters,
) -> tuple[bytes, ...]:
    packets, state.rtp_sequence, state.twcc_sequence = runtime.packetize_av1_frame(
        frame,
        config.mtu,
        (counters.frames * 3_000) & 0xFFFF_FFFF,
        (0x1020_3000 + peer_index) & 0xFFFF_FFFF,
        state.rtp_sequence,
        state.twcc_sequence,
    )
    counters.frames += 1
    counters.input_bytes += len(frame)
    for packet in packets:
        ordinal = counters.packets
        packet_size = len(packet)
        counters.packets += 1
        counters.packet_output_bytes += packet_size
        # Both implementations promise independently owned immutable bytes.
        # This is the exact observable byte volume materialized at that API
        # boundary; hidden intermediate copies require native instrumentation.
        counters.observable_output_copy_bytes += packet_size
        if not _packet_is_dropped(ordinal, config.packet_loss_ppm, config.corpus_seed):
            counters.network_accepted_packets += 1
            counters.network_accepted_bytes += packet_size
            counters.checksum = (
                (counters.checksum * 1_000_003) ^ packet_size ^ packet[-1]
            ) & 0xFFFF_FFFF_FFFF_FFFF
    return packets


async def _lag_ticker(
    stop: asyncio.Event, interval: float, samples: list[float]
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + interval
    while not stop.is_set():
        await asyncio.sleep(max(0.0, deadline - loop.time()))
        now = loop.time()
        samples.append(max(0.0, now - deadline))
        missed = max(1, math.floor((now - deadline) / interval) + 1)
        deadline += missed * interval


async def _paced_workload(
    config: BenchmarkConfig, corpus: tuple[bytes, ...], duration: float
) -> tuple[Counters, list[float]]:
    loop = asyncio.get_running_loop()
    counters = Counters()
    states = [
        PeerState((peer * 997) & 0xFFFF, (peer * 991) & 0xFFFF)
        for peer in range(config.peer_count)
    ]
    lag_samples: list[float] = []
    stop = asyncio.Event()
    ticker = asyncio.create_task(
        _lag_ticker(stop, config.ticker_interval_seconds, lag_samples)
    )
    ticks = max(1, round(duration * config.frames_per_second))
    start = loop.time()
    try:
        for tick in range(ticks):
            deadline = start + tick / config.frames_per_second
            await asyncio.sleep(max(0.0, deadline - loop.time()))
            frame = corpus[tick % len(corpus)]
            for peer_index, state in enumerate(states):
                _process_frame(frame, peer_index, state, config, counters)
            await asyncio.sleep(0)
    finally:
        stop.set()
        await ticker
    return counters, lag_samples


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered)) - 1
    return ordered[max(0, min(rank, len(ordered) - 1))]


def _allocation_probe(
    config: BenchmarkConfig, corpus: tuple[bytes, ...]
) -> dict[str, int]:
    states = [PeerState(0, 0) for _ in range(config.peer_count)]
    counters = Counters()
    retained: list[tuple[bytes, ...]] = []
    for peer_index, state in enumerate(states):
        _process_frame(corpus[0], peer_index, state, config, counters)
    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    for call_index in range(config.allocation_calls):
        peer_index = call_index % config.peer_count
        retained.append(
            _process_frame(
                corpus[call_index % len(corpus)],
                peer_index,
                states[peer_index],
                config,
                counters,
            )
        )
    after = tracemalloc.take_snapshot()
    _, peak = tracemalloc.get_traced_memory()
    differences = after.compare_to(before, "traceback")
    blocks = sum(max(0, difference.count_diff) for difference in differences)
    size = sum(max(0, difference.size_diff) for difference in differences)
    tracemalloc.stop()
    # Keep retained alive through the second snapshot.
    if len(retained) != config.allocation_calls:
        raise AssertionError("allocation probe did not retain every result")
    return {
        "probe_calls": config.allocation_calls,
        "live_blocks": blocks,
        "live_bytes": size,
        "peak_traced_bytes": peak,
        "observable_output_copy_bytes": counters.observable_output_copy_bytes,
    }


def run_worker(
    mode: Mode, artifact: Path | None, config: BenchmarkConfig
) -> dict[str, Any]:
    config.validate()
    _configure_mode(mode, artifact)
    implementation = runtime.loaded_kernel_e_module()
    corpus = build_corpus(config)
    if config.warmup_seconds:
        asyncio.run(_paced_workload(config, corpus, config.warmup_seconds))
    gc.collect()
    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    try:
        cpu_start = time.process_time_ns()
        wall_start = time.perf_counter_ns()
        counters, lag = asyncio.run(
            _paced_workload(config, corpus, config.duration_seconds)
        )
        wall_seconds = (time.perf_counter_ns() - wall_start) / 1_000_000_000
        cpu_seconds = (time.process_time_ns() - cpu_start) / 1_000_000_000
    finally:
        if gc_was_enabled:
            gc.enable()
    result = asdict(counters)
    result.update(
        {
            "mode": mode,
            "wall_seconds": wall_seconds,
            "process_cpu_seconds": cpu_seconds,
            "process_cpu_percent": cpu_seconds / wall_seconds * 100,
            "machine_cpu_percent": cpu_seconds
            / wall_seconds
            * 100
            / max(1, os.cpu_count() or 1),
            "frames_per_second": counters.frames / wall_seconds,
            "packets_per_second": counters.packets / wall_seconds,
            "cpu_microseconds_per_frame": cpu_seconds
            * 1_000_000
            / counters.frames,
            "event_loop_lag_ms": {
                "sample_count": len(lag),
                "p50": _percentile(lag, 0.50) * 1_000,
                "p95": _percentile(lag, 0.95) * 1_000,
                "p99": _percentile(lag, 0.99) * 1_000,
                "max": max(lag, default=0.0) * 1_000,
            },
            "allocations": _allocation_probe(config, corpus),
            "corpus_sha256": hashlib.sha256(b"".join(corpus)).hexdigest(),
            "corpus_frame_sizes": [len(frame) for frame in corpus],
            "implementation": {
                "module": implementation.__name__,
                "file": str(Path(implementation.__file__).resolve()),
                "source_sha256": getattr(
                    implementation, "__pymeta_source_sha256__", None
                ),
                "semantic_sha256": getattr(
                    implementation, "__pymeta_semantic_sha256__", None
                ),
                "compiler_version": getattr(
                    implementation, "__pymeta_compiler_version__", None
                ),
                "optimization": getattr(
                    implementation, "__pymeta_optimization__", None
                ),
            },
        }
    )
    return result


def _run_worker_process(
    mode: Mode, artifact: Path | None, config_path: Path
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        mode,
        "--config-json",
        str(config_path),
    ]
    if artifact is not None:
        command.extend(("--artifact", str(artifact)))
    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _aggregate(samples: list[dict[str, Any]]) -> dict[str, float]:
    fields = (
        "process_cpu_seconds",
        "process_cpu_percent",
        "machine_cpu_percent",
        "frames_per_second",
        "packets_per_second",
        "cpu_microseconds_per_frame",
    )
    result: dict[str, float] = {}
    for field in fields:
        values = [float(sample[field]) for sample in samples]
        result[f"{field}_median"] = statistics.median(values)
        result[f"{field}_mean"] = statistics.mean(values)
        result[f"{field}_stdev"] = statistics.stdev(values) if len(values) > 1 else 0.0
    for field in ("p99", "max"):
        values = [float(sample["event_loop_lag_ms"][field]) for sample in samples]
        result[f"event_loop_lag_{field}_ms_median"] = statistics.median(values)
    for field in ("live_blocks", "live_bytes", "peak_traced_bytes"):
        values = [float(sample["allocations"][field]) for sample in samples]
        result[f"allocation_{field}_median"] = statistics.median(values)
    return result


def _relative_delta(native: float, python: float) -> float:
    return (native / python - 1.0) * 100 if python else 0.0


def _paired_bootstrap_upper_bound(
    samples: list[dict[str, Any]], *, resamples: int = 10_000
) -> float:
    """Return the deterministic one-sided 95% bound for native-Python CPU."""
    by_pair: dict[int, dict[str, float]] = {}
    for sample in samples:
        by_pair.setdefault(int(sample["pair"]), {})[sample["mode"]] = float(
            sample["cpu_microseconds_per_frame"]
        )
    differences = [
        pair["native-required"] - pair["python"]
        for _, pair in sorted(by_pair.items())
    ]
    rng = random.Random(0x57525443)
    medians = sorted(
        statistics.median(rng.choices(differences, k=len(differences)))
        for _ in range(resamples)
    )
    return medians[math.ceil(0.95 * resamples) - 1]


def run_controller(
    config: BenchmarkConfig, pairs: int, artifact: Path | None
) -> dict[str, Any]:
    config.validate()
    if pairs < 7:
        raise ValueError("isolated benchmark requires at least seven AB/BA pairs")
    source = Path(kernel_e.__file__).resolve()
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="kernel-e-benchmark-") as temporary:
        temporary_path = Path(temporary)
        if artifact is None:
            artifact = compile_module(source, temporary_path / "artifact").artifact_path
        artifact = artifact.resolve()
        artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
        config_path = temporary_path / "config.json"
        config_path.write_text(json.dumps(asdict(config)), encoding="utf-8")
        samples: list[dict[str, Any]] = []
        orders: list[list[str]] = []
        for pair_index in range(pairs):
            order: tuple[Mode, Mode] = (
                ("python", "native-required")
                if pair_index % 2 == 0
                else ("native-required", "python")
            )
            orders.append(list(order))
            for position, mode in enumerate(order):
                sample = _run_worker_process(mode, artifact, config_path)
                sample["pair"] = pair_index + 1
                sample["position"] = position + 1
                samples.append(sample)

    python_samples = [sample for sample in samples if sample["mode"] == "python"]
    native_samples = [
        sample for sample in samples if sample["mode"] == "native-required"
    ]
    reference = python_samples[0]
    parity_fields = (
        "frames",
        "packets",
        "input_bytes",
        "packet_output_bytes",
        "observable_output_copy_bytes",
        "network_accepted_packets",
        "network_accepted_bytes",
        "checksum",
        "corpus_sha256",
        "corpus_frame_sizes",
    )
    for sample in samples[1:]:
        for field in parity_fields:
            if sample[field] != reference[field]:
                raise RuntimeError(
                    f"Python/native workload parity failed for {field}: "
                    f"{sample[field]!r} != {reference[field]!r}"
                )
    for sample in native_samples:
        embedded_source_hash = sample["implementation"]["source_sha256"]
        if embedded_source_hash != source_hash:
            raise RuntimeError(
                "native artifact was not compiled from the benchmarked source: "
                f"{embedded_source_hash!r} != {source_hash!r}"
            )
    python_aggregate = _aggregate(python_samples)
    native_aggregate = _aggregate(native_samples)
    bootstrap_upper = _paired_bootstrap_upper_bound(samples)
    cpu_delta = _relative_delta(
        native_aggregate["cpu_microseconds_per_frame_median"],
        python_aggregate["cpu_microseconds_per_frame_median"],
    )
    block_ratio = (
        native_aggregate["allocation_live_blocks_median"]
        / python_aggregate["allocation_live_blocks_median"]
    )
    byte_ratio = (
        native_aggregate["allocation_live_bytes_median"]
        / python_aggregate["allocation_live_bytes_median"]
    )
    p99_delta_ms = (
        native_aggregate["event_loop_lag_p99_ms_median"]
        - python_aggregate["event_loop_lag_p99_ms_median"]
    )
    return {
        "schema": "wrtc-kernel-e-benchmark/1",
        "source": str(source),
        "source_sha256": source_hash,
        "artifact": str(artifact),
        "artifact_sha256": artifact_hash,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "config": asdict(config),
        "pair_orders": orders,
        "samples": samples,
        "aggregate": {
            "python": python_aggregate,
            "native-required": native_aggregate,
            "native_relative_to_python_percent": {
                "cpu_microseconds_per_frame": _relative_delta(
                    native_aggregate["cpu_microseconds_per_frame_median"],
                    python_aggregate["cpu_microseconds_per_frame_median"],
                ),
                "frames_per_second": _relative_delta(
                    native_aggregate["frames_per_second_median"],
                    python_aggregate["frames_per_second_median"],
                ),
                "event_loop_lag_p99_ms": _relative_delta(
                    native_aggregate["event_loop_lag_p99_ms_median"],
                    python_aggregate["event_loop_lag_p99_ms_median"],
                ),
                "allocation_live_blocks": _relative_delta(
                    native_aggregate["allocation_live_blocks_median"],
                    python_aggregate["allocation_live_blocks_median"],
                ),
            },
        },
        "acceptance": {
            "bootstrap_resamples": 10_000,
            "paired_cpu_difference_95_percent_upper_us_per_frame": bootstrap_upper,
            "cpu_improvement_at_least_5_percent": cpu_delta <= -5.0,
            "paired_bootstrap_upper_below_zero": bootstrap_upper < 0.0,
            "allocation_blocks_at_most_110_percent": block_ratio <= 1.10,
            "allocation_bytes_at_most_110_percent": byte_ratio <= 1.10,
            "event_loop_p99_regression_at_most_1_ms": p99_delta_ms <= 1.0,
            "workload_parity": True,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, default=7)
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--warmup", type=float, default=2.0)
    parser.add_argument("--fps", type=int, default=30)
    parser.add_argument("--bitrate", type=int, default=2_000_000)
    parser.add_argument("--peers", type=int, default=1)
    parser.add_argument("--mtu", type=int, default=1200)
    parser.add_argument("--packet-loss-ppm", type=int, default=0)
    parser.add_argument("--allocation-calls", type=int, default=64)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", choices=("python", "native-required"))
    parser.add_argument("--config-json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.worker:
        if args.config_json is None:
            raise SystemExit("--worker requires --config-json")
        config = BenchmarkConfig(**json.loads(args.config_json.read_text()))
        result = run_worker(args.worker, args.artifact, config)
    else:
        config = BenchmarkConfig(
            duration_seconds=args.duration,
            warmup_seconds=args.warmup,
            frames_per_second=args.fps,
            bitrate_bps_per_peer=args.bitrate,
            peer_count=args.peers,
            mtu=args.mtu,
            allocation_calls=args.allocation_calls,
            packet_loss_ppm=args.packet_loss_ppm,
        )
        result = run_controller(config, args.pairs, args.artifact)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None and not args.worker:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
