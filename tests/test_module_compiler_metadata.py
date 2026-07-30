from __future__ import annotations

import importlib.util
import json
import sysconfig

from pathlib import Path
from types import SimpleNamespace

import pytest

from webrtc.compiler import module_compiler
from webrtc.compiler import kernel_e
from webrtc.compiler.module_contract import source_manifest_sha256


def test_compile_module_passes_normalized_open_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    primary = tmp_path / "primary.py"
    helper = tmp_path / "helper.py"
    primary.write_text("def operation():\n    return 1\n", encoding="utf-8")
    helper.write_text("VALUE = 2\n", encoding="utf-8")
    output = tmp_path / "artifact"
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        module_compiler,
        "build_native_compiler",
        lambda _build: tmp_path / "wrtc-pymeta-compiler-c",
    )

    def run(command: list[str], **kwargs: object) -> object:
        metadata_index = command.index("--metadata-json") + 1
        metadata_path = Path(command[metadata_index])
        captured["metadata"] = json.loads(metadata_path.read_text(encoding="utf-8"))
        captured["command"] = tuple(command)
        output.mkdir()
        artifact = output / (
            "primary_native" + (sysconfig.get_config_var("EXT_SUFFIX") or ".so")
        )
        artifact.write_bytes(b"native")
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "artifact_path": str(artifact),
                    "source_path": str(primary),
                    "source_sha256": "a" * 64,
                    "semantic_sha256": "b" * 64,
                    "module_name": "primary_native",
                    "public_functions": ["operation"],
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(module_compiler.subprocess, "run", run)
    result = module_compiler.compile_module(
        primary,
        output,
        source_paths=(helper, primary),
        artifact_metadata={"policy_sha256": "policy"},
    )

    expected_manifest = source_manifest_sha256((primary, helper))
    assert captured["metadata"] == {
        "policy_sha256": "policy",
        "source_manifest_sha256": expected_manifest,
    }
    assert "--metadata-json" in captured["command"]
    assert result.artifact_metadata == (
        ("policy_sha256", "policy"),
        ("source_manifest_sha256", expected_manifest),
    )


def test_compile_module_rejects_mismatched_source_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")

    with pytest.raises(
        module_compiler.ModuleCompileError,
        match="does not match source_paths",
    ):
        module_compiler.compile_module(
            source,
            tmp_path / "output",
            source_paths=(source,),
            artifact_metadata={"source_manifest_sha256": "stale"},
        )


def test_compiler_embeds_generic_metadata_in_extension(tmp_path: Path) -> None:
    source = Path(kernel_e.__file__).resolve()
    result = module_compiler.compile_module(
        source,
        tmp_path / "output",
        source_paths=(source,),
        artifact_metadata={"policy_sha256": "generic-policy"},
    )
    spec = importlib.util.spec_from_file_location(
        result.module_name, result.artifact_path
    )
    assert spec is not None and spec.loader is not None
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)

    assert native.__pymeta_policy_sha256__ == "generic-policy"
    assert native.__pymeta_source_manifest_sha256__ == source_manifest_sha256(
        (source,)
    )
