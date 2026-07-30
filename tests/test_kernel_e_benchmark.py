from __future__ import annotations

import importlib.util
import asyncio
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

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
    arguments = BENCHMARK._parser().parse_args([])
    assert arguments.pairs == 7
    assert arguments.event_loop == "reference"
    assert arguments.event_loop_artifact is None


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
    assert result["event_loop"] == {
        "module": "webrtc.event_loop.loop",
        "class": "WebRTCSelectorEventLoop",
        "mode": "reference",
    }
    assert __import__("gc").isenabled()


def test_compiled_event_loop_mode_loads_explicit_artifact_for_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "event_loop_native.so"
    artifact.write_bytes(b"validated compiled event loop")

    class FakeNativeLoop(asyncio.SelectorEventLoop):
        pass

    FakeNativeLoop.__module__ = "event_loop_native"
    FakeNativeLoop.__qualname__ = "FakeNativeLoop"
    native = SimpleNamespace(
        WebRTCSelectorEventLoop=FakeNativeLoop,
        new_event_loop=FakeNativeLoop,
    )
    observed: dict[str, object] = {}
    monkeypatch.setattr(BENCHMARK, "require_compatible_host", lambda: None)

    def load(path: Path, requirements: object) -> object:
        observed["path"] = path
        observed["requirements"] = requirements
        return native

    monkeypatch.setattr(BENCHMARK, "load_native_artifact", load)
    config = BENCHMARK.BenchmarkConfig(
        duration_seconds=0.01,
        warmup_seconds=0,
        frames_per_second=100,
        bitrate_bps_per_peer=80_000,
        allocation_calls=1,
    )

    result = BENCHMARK.run_worker(
        "python",
        None,
        config,
        event_loop_mode="compiled-required",
        event_loop_artifact=artifact,
    )

    assert observed == {
        "path": artifact.resolve(),
        "requirements": BENCHMARK.NATIVE_REQUIREMENTS,
    }
    assert result["event_loop"] == {
        "module": "event_loop_native",
        "class": "FakeNativeLoop",
        "mode": "compiled-required",
        "artifact": str(artifact.resolve()),
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "production_compatible": True,
    }


def test_compiled_event_loop_mode_requires_artifact() -> None:
    with pytest.raises(ValueError, match="needs an artifact"):
        BENCHMARK._event_loop_factory("compiled-required", None)
    with pytest.raises(ValueError, match="needs an artifact"):
        BENCHMARK.run_controller(
            BENCHMARK.BenchmarkConfig(),
            7,
            None,
            event_loop_mode="compiled-required",
        )


def test_compiled_event_loop_mode_propagates_compatibility_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "event_loop_native.so"
    artifact.write_bytes(b"incompatible")
    monkeypatch.setattr(BENCHMARK, "require_compatible_host", lambda: None)

    def reject(*args: object) -> object:
        raise RuntimeError("incompatible compiled event loop")

    monkeypatch.setattr(BENCHMARK, "load_native_artifact", reject)
    with pytest.raises(RuntimeError, match="incompatible compiled event loop"):
        BENCHMARK._event_loop_factory("compiled-required", artifact)


def test_reference_event_loop_mode_rejects_native_artifact(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not accept an artifact"):
        BENCHMARK._event_loop_factory("reference", tmp_path / "unused.so")


def test_compiled_development_mode_skips_production_host_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "loop_native.so"
    artifact.write_bytes(b"development artifact")

    class FakeNativeLoop(asyncio.SelectorEventLoop):
        pass

    FakeNativeLoop.__module__ = "loop_native"
    FakeNativeLoop.__qualname__ = "FakeNativeLoop"
    native = SimpleNamespace(
        WebRTCSelectorEventLoop=FakeNativeLoop,
        new_event_loop=FakeNativeLoop,
    )

    def forbidden() -> None:
        raise AssertionError("development mode used production host policy")

    monkeypatch.setattr(BENCHMARK, "require_compatible_host", forbidden)
    observed: dict[str, object] = {}

    def load(path: Path, requirements: object) -> object:
        observed["path"] = path
        observed["requirements"] = requirements
        return native

    monkeypatch.setattr(BENCHMARK, "load_native_artifact", load)
    factory, metadata = BENCHMARK._event_loop_factory(
        "compiled-development", artifact
    )
    loop = factory()
    try:
        assert type(loop) is FakeNativeLoop
    finally:
        loop.close()
    assert observed == {
        "path": artifact.resolve(),
        "requirements": BENCHMARK.DEVELOPMENT_REQUIREMENTS,
    }
    assert metadata["mode"] == "compiled-development"
    assert metadata["production_compatible"] is False
