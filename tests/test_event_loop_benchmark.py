from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).with_name("performance") / "benchmark_event_loop.py"
SPEC = importlib.util.spec_from_file_location("event_loop_benchmark", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


def test_percentiles_are_deterministic_and_include_tail() -> None:
    values = [4.0, 1.0, 3.0, 2.0, 100.0]
    assert BENCHMARK._percentile(values, 0.50) == 3.0
    assert BENCHMARK._percentile(values, 0.99) == 100.0


def test_controller_requires_isolated_pairs() -> None:
    with pytest.raises(ValueError, match="at least three"):
        BENCHMARK.run_controller(BENCHMARK.BenchmarkConfig(), ("ready",), 2)


def test_parser_defaults_to_seven_pairs_and_all_core_scenarios() -> None:
    arguments = BENCHMARK._parser().parse_args([])
    assert arguments.pairs == 7
    assert set(arguments.scenarios) == {
        "idle",
        "timers",
        "ready",
        "cancelled",
        "cross-thread",
        "udp",
    }


@pytest.mark.parametrize("scenario", ("idle", "timers", "ready", "cancelled", "udp"))
def test_short_stock_worker_reports_observed_metrics(scenario: str) -> None:
    config = BENCHMARK.BenchmarkConfig(
        duration_seconds=0.01,
        timer_interval_seconds=0.001,
        ready_batch_size=4,
        cancelled_timer_count=8,
    )
    result = BENCHMARK.run_worker("asyncio", scenario, config)

    assert result["requested_mode"] == result["resolved_mode"] == "asyncio"
    assert result["scenario"] == scenario
    assert result["process_cpu_seconds"] >= 0
    assert result["wall_seconds"] > 0
    assert result["selector_polls"] > 0
    assert result["allocations"]["positive_blocks"] >= 0
    assert result["allocations"]["positive_bytes"] >= 0
    assert result["latency_ms"]["p99"] >= result["latency_ms"]["p50"]


def test_benchmark_reports_measurements_without_claiming_speedup() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"note"' in source
    assert "20%" not in source
    assert "5%" not in source
