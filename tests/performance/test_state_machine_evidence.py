import asyncio
import ast
import json
from dataclasses import asdict
from pathlib import Path

from .state_machine_evidence import BASELINE, SCHEMA_VERSION, run_evidence, validate


def test_checked_performance_evidence_schema_and_structural_budgets():
    budget_file = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert budget_file["schema_version"] == SCHEMA_VERSION
    assert budget_file["budget"]["aggregate_tracing_cpu_overhead_percent_max"] <= 5
    assert budget_file["methodology"]["minimum_pairs"] >= 5

    result = asyncio.run(run_evidence(calls=64, pairs=3, packets=64))
    payload = asdict(result)
    assert set(budget_file["required_evidence"]) <= payload.keys()
    assert result.tracing_off.process_cpu_ms > 0
    assert result.tracing_on.process_cpu_ms > 0
    assert result.worker_projection_disabled.rate_per_second > 0
    assert result.worker_projection_enabled.rate_per_second > 0
    assert result.full_peer_tracing_off.process_cpu_ms > 0
    assert result.full_peer_tracing_on.process_cpu_ms > 0
    assert len(result.full_peer_cpu_overhead_samples_percent) == 3
    assert result.state_commands == result.state_commits + result.rejected_commands
    assert result.state_counter_scope == "isolated runtime lifecycle admission/rejection/close probe"
    assert result.rejected_commands > 0
    # Lifecycle reduction is inline; no permanent runner mailbox is exercised.
    assert result.mailbox_high_water == 0
    assert result.producer_dot_allocations > 0
    assert result.packet_coalesced_projection_merges <= 2
    assert not validate(result, budget_file["budget"], enforce_cpu=False)


def test_state_waiters_do_not_poll_with_asyncio_sleep_zero():
    root = Path(__file__).parents[2] / "webrtc"
    offenders = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for loop in (node for node in ast.walk(tree) if isinstance(node, (ast.While, ast.For, ast.AsyncFor))):
            for node in ast.walk(loop):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                fn = node.func
                if (isinstance(fn, ast.Attribute) and fn.attr == "sleep"
                        and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0):
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert not offenders, "polling state waiters: " + ", ".join(offenders)


def test_checked_in_budget_has_non_flaky_cpu_enforcement_contract():
    budget = json.loads(BASELINE.read_text(encoding="utf-8"))
    methodology = budget["methodology"]
    assert methodology == {
        "clock": "time.process_time_ns",
        "comparison": "median of five paired ratios",
        "order": "alternating AB/BA after warmup",
        "gc": "full collection before each sample, cyclic GC disabled during timed region",
        "ci": "structural checks always; numeric budget on idle pinned performance workers",
        "minimum_pairs": 5,
        "profile": "normal mixed component CPU work; startup and shutdown excluded",
    }
