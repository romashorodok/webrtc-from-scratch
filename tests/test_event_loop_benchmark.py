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


def test_controller_requires_isolated_triples() -> None:
    with pytest.raises(ValueError, match="at least three"):
        BENCHMARK.run_controller(BENCHMARK.BenchmarkConfig(), ("ready",), 2)


def test_parser_defaults_to_fifteen_triples_and_all_core_scenarios() -> None:
    arguments = BENCHMARK._parser().parse_args([])
    assert arguments.triples == 15
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
    assert result["throughput"]["process_cpu_seconds"] >= 0
    assert result["throughput"]["wall_seconds"] > 0
    assert result["allocations"]["operations"] == config.allocation_operations
    assert result["allocations"]["completed"] == config.allocation_operations
    assert result["selector"]["polls"] == result["selector"]["iterations"]
    assert result["latency"]["p99_ms"] >= result["latency"]["p50_ms"]


def test_benchmark_has_strict_modes_and_deterministic_confidence_gate() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert BENCHMARK.MODES == ("asyncio", "reference", "native-required")
    assert BENCHMARK._bootstrap_lower_bound([1.25] * 15) == 1.25
    assert '"meets_1_20_gate"' in source


def test_latency_sampling_is_bounded() -> None:
    samples = BENCHMARK._BoundedLatency(3)
    for value in range(10):
        samples.add(float(value))
    assert samples.observations == 10
    assert samples.milliseconds() == [7000.0, 8000.0, 9000.0]
