from __future__ import annotations

import asyncio
import json
from pathlib import Path

from live_tracing_benchmark import BenchmarkConfig, run_benchmark


BUDGETS = json.loads(
    (Path(__file__).parent / "baselines" / "live_tracing_budgets.json").read_text(encoding="utf-8")
)


def test_live_tracing_budget_profile_is_machine_readable_and_provisional():
    assert BUDGETS["schema_version"] == 1
    assert BUDGETS["status"] == "provisional"
    assert BUDGETS["profiles"]["call_counts"] == [10_000, 100_000, 1_000_000]
    assert BUDGETS["profiles"]["group_cardinalities"][-1] > BUDGETS["limits"]["groups"]
    assert BUDGETS["acceptance_budgets"]["aggregate_cpu_overhead_percent"]["max"] == 5
    assert BUDGETS["acceptance_budgets"]["frontend_normal_batch_p95_ms"]["max"] == 4
    assert BUDGETS["acceptance_budgets"]["frontend_max_batch_p95_ms"]["max"] == 16
    assert BUDGETS["acceptance_budgets"]["pan_zoom_frame_ms"]["max"] == 16.7
    assert BUDGETS["stage0_structural_baseline"]["current_exact"][
        "published_events_per_successful_inline_call"
    ] == 3
    assert BUDGETS["stage0_structural_baseline"]["aggregate"]["available"] is True


def test_smoke_profile_distinguishes_unobserved_and_bounded_capture_cost_shape():
    baseline = asyncio.run(run_benchmark(BenchmarkConfig(
        mode="unobserved", calls=100, groups=10, overlay="closed"
    )))
    exact = asyncio.run(run_benchmark(BenchmarkConfig(
        mode="capture", calls=100, groups=10, overlay="open", subscribers=1
    )))

    assert baseline.published_events == 0
    assert baseline.group_count == 0
    assert 0 < exact.published_events < exact.config["calls"]
    assert exact.group_count == 10
    assert exact.trace_store_count == 1
    assert exact.encoded_bytes > 0
    assert exact.messages > 0


def test_aggregate_smoke_profile_has_stable_groups_and_no_per_call_publication():
    aggregate = asyncio.run(run_benchmark(BenchmarkConfig(
        mode="aggregate", calls=1_000, groups=10, overlay="open", subscribers=1
    )))

    assert 0 < aggregate.published_events < aggregate.config["calls"]
    assert aggregate.group_count == 10
    assert aggregate.trace_store_count == 1
    assert aggregate.encoded_bytes > 0


def test_slow_subscriber_profile_stays_bounded_and_exposes_current_loss():
    result = asyncio.run(run_benchmark(BenchmarkConfig(
        mode="capture",
        calls=64,
        groups=10,
        subscribers=2,
        slow_subscriber=True,
        batch_calls=8,
    )))

    assert result.dropped_messages > 0
    assert result.resyncs and result.resyncs > 0
    assert result.journal_depth is not None
