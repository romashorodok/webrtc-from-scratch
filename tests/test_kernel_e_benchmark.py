from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).with_name("performance") / "benchmark_kernel_e.py"
SPEC = importlib.util.spec_from_file_location("kernel_e_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


def test_corpus_is_deterministic_and_tracks_requested_bitrate() -> None:
    config = BENCHMARK.BenchmarkConfig(
        bitrate_bps_per_peer=240_000, frames_per_second=30
    )
    first = BENCHMARK.build_corpus(config)
    second = BENCHMARK.build_corpus(config)

    assert first == second
    assert len(first) == 5
    mean_size = sum(map(len, first)) / len(first)
    assert mean_size == pytest.approx(1_000, abs=4)


def test_pair_count_enforces_research_measurement_contract() -> None:
    config = BENCHMARK.BenchmarkConfig(duration_seconds=0.001, warmup_seconds=0)
    with pytest.raises(ValueError, match="at least seven"):
        BENCHMARK.run_controller(config, 6, None)


def test_parser_defaults_to_seven_isolated_pairs() -> None:
    assert BENCHMARK._parser().parse_args([]).pairs == 7


def test_paired_bootstrap_is_deterministic() -> None:
    samples = [
        {"pair": pair, "mode": mode, "cpu_microseconds_per_frame": value}
        for pair, python, native in ((1, 10.0, 8.0), (2, 12.0, 9.0))
        for mode, value in (("python", python), ("native-required", native))
    ]
    assert BENCHMARK._paired_bootstrap_upper_bound(samples) == -2.0


def test_short_python_worker_records_required_metrics() -> None:
    config = BENCHMARK.BenchmarkConfig(
        duration_seconds=0.02,
        warmup_seconds=0,
        frames_per_second=100,
        bitrate_bps_per_peer=80_000,
        peer_count=2,
        allocation_calls=2,
    )

    result = BENCHMARK.run_worker("python", None, config)

    assert result["frames"] == 4
    assert result["packets"] > 0
    assert result["process_cpu_seconds"] > 0
    assert result["frames_per_second"] > 0
    assert result["event_loop_lag_ms"]["sample_count"] > 0
    assert result["allocations"]["probe_calls"] == 2
    assert result["observable_output_copy_bytes"] == result["packet_output_bytes"]
    assert result["corpus_sha256"]
    assert result["implementation"]["module"] == "webrtc.compiler.kernel_e"
    assert result["implementation"]["source_sha256"] is None
    assert __import__("gc").isenabled()
