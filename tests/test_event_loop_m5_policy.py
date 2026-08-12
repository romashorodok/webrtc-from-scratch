"""Stage M5 policy and fail-closed production-loader checks."""

from __future__ import annotations

import asyncio
import hashlib
import json

from dataclasses import asdict
from pathlib import Path
from types import ModuleType

import pytest

from webrtc import event_loop
from webrtc.compiler.module_contract import (
    METADATA_ATTRIBUTES,
    runtime_compatibility,
    semantic_sha256,
)
from webrtc.compiler.native_artifact import (
    NativeArtifactCompatibilityError,
    validate_native_artifact,
)
from webrtc.event_loop import compile_policy


@pytest.fixture(autouse=True)
def reset_selection() -> None:
    event_loop._reset_native_selection_for_tests()
    yield
    event_loop._reset_native_selection_for_tests()


def _metadata_complete_module() -> ModuleType:
    module = ModuleType("event_loop_native")
    source = compile_policy.SOURCE_PATH.read_bytes()
    expected = {
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "semantic_sha256": semantic_sha256(
            source, filename=str(compile_policy.SOURCE_PATH)
        ),
        **runtime_compatibility(),
    }
    for key, attribute in METADATA_ATTRIBUTES.items():
        setattr(module, attribute, expected[key])
    for key, value in compile_policy.ARTIFACT_POLICY_METADATA.items():
        setattr(module, f"__pymeta_{key}__", value)
    return module


def test_policy_hash_covers_normalized_target_and_required_surface() -> None:
    document = {
        "target": asdict(compile_policy.event_loop_target),
        "module_name": "event_loop_native",
        "factory": "new_event_loop",
        "native_class": "WebRTCSelectorEventLoop",
        "required_methods": ["_run_once"],
        "sources": [
                "atomic.py",
                "commands.py",
                "config.py",
                "datagrams.py",
            "event_loop.py",
            "loop.py",
            "scheduler.py",
            "workers.py",
        ],
    }
    expected = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert compile_policy.POLICY_SHA256 == expected
    assert compile_policy.ARTIFACT_POLICY_METADATA == {
        "policy_sha256": expected,
        "source_manifest_sha256": compile_policy.SOURCE_MANIFEST_SHA256,
        "event_loop_cpython_revision": (
            "070700ed4d95c16855603cecab3f41f3b587f973"
        ),
        "event_loop_abi": "exact",
        "event_loop_free_threaded": "optional",
        "event_loop_gil": "reactor_thread_confined",
        "event_loop_subinterpreters": "unsupported",
    }


def test_source_manifest_hash_covers_every_behavior_component() -> None:
    digest = hashlib.sha256()
    for path in compile_policy.SOURCE_PATHS:
        name = path.name.encode()
        source = path.read_bytes()
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(source)
    assert compile_policy.SOURCE_MANIFEST_SHA256 == digest.hexdigest()


@pytest.mark.parametrize(
    "key",
    tuple(compile_policy.ARTIFACT_POLICY_METADATA),
)
def test_each_event_loop_policy_mismatch_is_rejected(key: str) -> None:
    module = _metadata_complete_module()
    setattr(module, f"__pymeta_{key}__", "stale")
    with pytest.raises(
        NativeArtifactCompatibilityError,
        match=rf"policy mismatch: .*{key}=",
    ):
        validate_native_artifact(module, compile_policy.NATIVE_REQUIREMENTS)


def test_missing_event_loop_policy_metadata_is_rejected() -> None:
    module = _metadata_complete_module()
    delattr(module, "__pymeta_policy_sha256__")
    with pytest.raises(
        NativeArtifactCompatibilityError,
        match="policy_sha256=missing",
    ):
        validate_native_artifact(module, compile_policy.NATIVE_REQUIREMENTS)


def test_incompatible_host_fails_to_stock_without_importing_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = tmp_path / "event_loop_native.so"
    candidate.write_bytes(b"must not be imported")
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))
    monkeypatch.setattr(
        event_loop,
        "require_compatible_host",
        lambda: (_ for _ in ()).throw(RuntimeError("GIL-enabled host")),
    )

    def forbidden(*args: object) -> object:
        raise AssertionError("incompatible host attempted artifact import")

    monkeypatch.setattr(event_loop, "load_native_artifact", forbidden)
    loop = event_loop.new_event_loop()
    try:
        assert isinstance(loop, asyncio.SelectorEventLoop)
        assert not isinstance(loop, event_loop.WebRTCSelectorEventLoop)
        assert event_loop.event_loop_mode() == "asyncio"
    finally:
        loop.close()


def test_host_policy_allows_gil_enabled_cpython(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = compile_policy.sysconfig.get_config_var

    def config_var(name: str) -> object:
        if name == "Py_GIL_DISABLED":
            return 0
        return original(name)

    monkeypatch.setattr(compile_policy.sysconfig, "get_config_var", config_var)
    assert compile_policy.host_compatibility_error() is None
