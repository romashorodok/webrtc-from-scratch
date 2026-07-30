"""Python build and launch shim for the standalone C17 module compiler."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .module_contract import (
    OPTIMIZATION_MODE,
    normalize_artifact_metadata,
    source_manifest_sha256,
)


class ModuleCompileError(RuntimeError):
    """The C17 compiler could not produce the complete native module."""


@dataclass(frozen=True, slots=True)
class BuiltModule:
    artifact_path: Path
    source_path: Path
    source_sha256: str
    semantic_sha256: str
    module_name: str
    public_functions: tuple[str, ...]
    artifact_metadata: tuple[tuple[str, str], ...] = ()


def build_native_compiler(build_dir: Path) -> Path:
    """Configure and build the stable C17 compiler executable target."""
    build_dir = Path(build_dir).resolve()
    source_dir = Path(__file__).with_name("native_compiler")
    try:
        subprocess.run(
            [
                "cmake",
                "-S",
                str(source_dir),
                "-B",
                str(build_dir),
                "-DCMAKE_BUILD_TYPE=Release",
                f"-DPython3_EXECUTABLE={sys.executable}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "cmake",
                "--build",
                str(build_dir),
                "--config",
                "Release",
                "--target",
                "wrtc-pymeta-compiler-c",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise ModuleCompileError(
            f"could not build C17 compiler executable: {detail.strip()}"
        ) from exc

    executable_name = (
        "wrtc-pymeta-compiler-c.exe" if os.name == "nt" else "wrtc-pymeta-compiler-c"
    )
    candidates = tuple(
        path for path in build_dir.rglob(executable_name) if path.is_file()
    )
    if len(candidates) != 1:
        raise ModuleCompileError(
            f"expected one C17 compiler executable, found {len(candidates)}"
        )
    return candidates[0].resolve()


def compile_module(
    source_path: Path,
    output_dir: Path,
    optimization_mode: str = OPTIMIZATION_MODE,
    *,
    source_paths: Iterable[Path] = (),
    artifact_metadata: Mapping[str, str] | None = None,
) -> BuiltModule:
    """Build and launch the C17 single-module compiler executable."""
    if optimization_mode != OPTIMIZATION_MODE:
        raise ModuleCompileError(f"unsupported optimization mode: {optimization_mode}")
    source_path = Path(source_path).resolve()
    output_dir = Path(output_dir).resolve()
    metadata = dict(artifact_metadata or {})
    manifest_paths = tuple(Path(path).resolve() for path in source_paths)
    if manifest_paths:
        try:
            manifest_hash = source_manifest_sha256(manifest_paths)
        except (OSError, ValueError) as exc:
            raise ModuleCompileError(
                f"cannot resolve artifact source manifest: {exc}"
            ) from exc
        configured = metadata.setdefault("source_manifest_sha256", manifest_hash)
        if configured != manifest_hash:
            raise ModuleCompileError(
                "artifact source_manifest_sha256 does not match source_paths"
            )
    try:
        normalized_metadata = normalize_artifact_metadata(metadata)
    except (TypeError, ValueError) as exc:
        raise ModuleCompileError(f"invalid artifact metadata: {exc}") from exc
    try:
        with tempfile.TemporaryDirectory(prefix="wrtc-pymeta-compiler-c-") as temporary:
            temporary_path = Path(temporary)
            executable = build_native_compiler(temporary_path / "build")
            command = [
                str(executable),
                "--source",
                str(source_path),
                "--output",
                str(output_dir),
                "--result-json",
            ]
            if normalized_metadata:
                metadata_path = temporary_path / "artifact-metadata.json"
                metadata_path.write_text(
                    json.dumps(
                        dict(normalized_metadata),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                command.extend(("--metadata-json", str(metadata_path)))
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        outcome = json.loads(completed.stdout)
        result = BuiltModule(
            artifact_path=Path(outcome["artifact_path"]).resolve(),
            source_path=Path(outcome["source_path"]).resolve(),
            source_sha256=outcome["source_sha256"],
            semantic_sha256=outcome["semantic_sha256"],
            module_name=outcome["module_name"],
            public_functions=tuple(outcome["public_functions"]),
            artifact_metadata=normalized_metadata,
        )
    except (
        OSError,
        subprocess.CalledProcessError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise ModuleCompileError(f"C17 compiler failed: {detail.strip()}") from exc
    if result.artifact_path.parent != output_dir or not result.artifact_path.is_file():
        raise ModuleCompileError("C17 compiler returned an invalid artifact path")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wrtc-pymeta-compiler")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-json", type=Path)
    parser.add_argument("--manifest-source", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    metadata = None
    if args.metadata_json is not None:
        try:
            loaded = json.loads(args.metadata_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read --metadata-json: {exc}")
        if not isinstance(loaded, dict):
            parser.error("--metadata-json must contain a JSON object")
        metadata = loaded
    try:
        result = compile_module(
            args.source,
            args.output,
            source_paths=args.manifest_source,
            artifact_metadata=metadata,
        )
    except ModuleCompileError as exc:
        parser.exit(1, f"wrtc-pymeta-compiler: error: {exc}\n")
    print(result.artifact_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
