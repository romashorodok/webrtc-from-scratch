"""Python build and launch shim for the standalone C17 module compiler."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .module_contract import OPTIMIZATION_MODE


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
) -> BuiltModule:
    """Build and launch the C17 single-module compiler executable."""
    if optimization_mode != OPTIMIZATION_MODE:
        raise ModuleCompileError(f"unsupported optimization mode: {optimization_mode}")
    source_path = Path(source_path).resolve()
    output_dir = Path(output_dir).resolve()
    try:
        with tempfile.TemporaryDirectory(prefix="wrtc-pymeta-compiler-c-") as temporary:
            executable = build_native_compiler(Path(temporary) / "build")
            completed = subprocess.run(
                [
                    str(executable),
                    "--source",
                    str(source_path),
                    "--output",
                    str(output_dir),
                    "--result-json",
                ],
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
    args = parser.parse_args(argv)
    try:
        result = compile_module(args.source, args.output)
    except ModuleCompileError as exc:
        parser.exit(1, f"wrtc-pymeta-compiler: error: {exc}\n")
    print(result.artifact_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
