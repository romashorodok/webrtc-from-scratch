from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path
from types import ModuleType

import pytest

from webrtc.compiler.module_contract import (
    METADATA_ATTRIBUTES,
    policy_sha256,
    runtime_compatibility,
    semantic_sha256,
    source_manifest_sha256,
)
from webrtc.compiler.native_artifact import (
    NativeArtifactCompatibilityError,
    NativeClassRequirement,
    NativeModuleRequirements,
    validate_native_artifact,
    validate_native_class_profile,
)


def test_runtime_compatibility_captures_cpython_abi_identity() -> None:
    compatibility = runtime_compatibility()

    assert compatibility["cache_tag"] == (sys.implementation.cache_tag or "")
    assert compatibility["abi_flags"] == getattr(sys, "abiflags", "")
    assert compatibility["extension_suffix"]
    assert METADATA_ATTRIBUTES["extension_suffix"] == "__pymeta_extension_suffix__"


def test_native_class_profile_accepts_only_selector_loop_shape() -> None:
    validate_native_class_profile(
        b"import asyncio\n"
        b"class WebRTCSelectorEventLoop(asyncio.SelectorEventLoop):\n"
        b"    _timer_cancelled_count: int\n"
        b"    def _run_once(self):\n"
        b"        pass\n",
        filename="event_loop.py",
    )

    with pytest.raises(
        NativeArtifactCompatibilityError, match="must derive directly"
    ):
        validate_native_class_profile(
            b"class WebRTCSelectorEventLoop(object):\n    pass\n",
            filename="event_loop.py",
        )


def test_surface_validation_rejects_interpreted_factory(
    tmp_path: Path,
) -> None:
    source = tmp_path / "event_loop.py"
    source.write_text("def new_event_loop():\n    return None\n", encoding="utf-8")
    module = ModuleType("event_loop_native")
    for attribute in METADATA_ATTRIBUTES.values():
        setattr(module, attribute, "")

    requirements = NativeModuleRequirements(
        module_name="event_loop_native",
        source_path=source,
        functions=("new_event_loop",),
        classes={
            "WebRTCSelectorEventLoop": NativeClassRequirement(
                asyncio.SelectorEventLoop, ("_run_once",)
            )
        },
    )

    with pytest.raises(
        NativeArtifactCompatibilityError, match="compatibility mismatch"
    ):
        validate_native_artifact(module, requirements)


def test_source_manifest_is_order_independent_and_source_sensitive(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("VALUE = 1\n", encoding="utf-8")
    second.write_text("VALUE = 2\n", encoding="utf-8")

    expected = source_manifest_sha256((first, second))
    assert source_manifest_sha256((second, first)) == expected

    second.write_text("VALUE = 3\n", encoding="utf-8")
    assert source_manifest_sha256((first, second)) != expected


def test_policy_hash_uses_normalized_json() -> None:
    assert policy_sha256({"target": {"abi": "exact"}, "workers": 2}) == policy_sha256(
        {"workers": 2, "target": {"abi": "exact"}}
    )


def test_multi_source_artifact_metadata_is_validated(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "primary.py"
    helper = tmp_path / "helper.py"
    primary.write_text("def operation():\n    return 1\n", encoding="utf-8")
    helper.write_text("VALUE = 2\n", encoding="utf-8")
    module = ModuleType("generic_native")
    expected = {
        "source_sha256": hashlib.sha256(primary.read_bytes()).hexdigest(),
        "semantic_sha256": semantic_sha256(
            primary.read_bytes(), filename=str(primary)
        ),
        **runtime_compatibility(),
    }
    for key, attribute in METADATA_ATTRIBUTES.items():
        setattr(module, attribute, expected[key])
    manifest_hash = source_manifest_sha256((primary, helper))
    module.__pymeta_source_manifest_sha256__ = manifest_hash
    module.__pymeta_policy_sha256__ = "policy"
    requirements = NativeModuleRequirements(
        module_name="generic_native",
        source_path=primary,
        source_paths=(primary, helper),
        metadata={"policy_sha256": "policy"},
    )

    validate_native_artifact(module, requirements)
    helper.write_text("VALUE = 3\n", encoding="utf-8")
    with pytest.raises(
        NativeArtifactCompatibilityError,
        match="source_manifest_sha256",
    ):
        validate_native_artifact(module, requirements)
