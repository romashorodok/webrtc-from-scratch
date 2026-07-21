"""End-to-end acceptance for the standalone C module compiler driver."""

from __future__ import annotations

import inspect
import importlib.util
import os
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pytest

from webrtc.compiler import kernel_e, runtime
from webrtc.compiler.module_contract import METADATA_ATTRIBUTES, runtime_compatibility


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NATIVE_COMPILER_SOURCE = REPOSITORY_ROOT / "webrtc/compiler/native_compiler"
KERNEL_SOURCE = Path(kernel_e.__file__).resolve()


def _compiler_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return environment


@dataclass(frozen=True)
class CCompilerBuild:
    executable: Path
    artifact: Path
    output_dir: Path


def _compile_fixture(
    build: CCompilerBuild, tmp_path: Path, name: str, source_text: str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    source = tmp_path / f"{name}.py"
    source.write_text(source_text, encoding="utf-8")
    output = tmp_path / f"{name}-output"
    completed = subprocess.run(
        [
            str(build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    return completed, output


def _load_fixture(artifact: Path, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, artifact)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def c_compiler_build(tmp_path_factory: pytest.TempPathFactory) -> CCompilerBuild:
    root = tmp_path_factory.mktemp("c-pymeta-compiler")
    build_dir = root / "build"
    subprocess.run(
        [
            "cmake",
            "-S",
            str(NATIVE_COMPILER_SOURCE),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build_dir), "--target", "wrtc-pymeta-compiler-c"],
        check=True,
        capture_output=True,
        text=True,
    )
    executable = build_dir / (
        "wrtc-pymeta-compiler-c.exe" if sys.platform == "win32" else "wrtc-pymeta-compiler-c"
    )
    assert executable.is_file()

    output_dir = root / "artifact"
    completed = subprocess.run(
        [
            str(executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=root,
        env=_compiler_environment(),
    )
    artifact = Path(completed.stdout.strip()).resolve()
    return CCompilerBuild(executable, artifact, output_dir)


@pytest.fixture(autouse=True)
def restore_python_dispatch() -> None:
    runtime.configure_kernel_e(mode="python")
    yield
    runtime.configure_kernel_e(mode="python")


def test_c_compiler_produces_exactly_one_extension_without_sidecars(
    c_compiler_build: CCompilerBuild,
) -> None:
    expected_name = f"kernel_e_native{sysconfig.get_config_var('EXT_SUFFIX')}"
    files = sorted(
        path.resolve()
        for path in c_compiler_build.output_dir.rglob("*")
        if path.is_file()
    )
    assert c_compiler_build.artifact == (c_compiler_build.output_dir / expected_name).resolve()
    assert files == [c_compiler_build.artifact]


def test_native_driver_owns_compilation_without_python_compiler_delegation() -> None:
    driver_source = (NATIVE_COMPILER_SOURCE / "main.c").read_text(encoding="utf-8")
    assert "webrtc.compiler.module_compiler" not in driver_source
    assert "_compile_module_in_process" not in driver_source


def test_python_entry_is_only_a_native_driver_build_and_launch_shim() -> None:
    compiler_package = REPOSITORY_ROOT / "webrtc/compiler"
    shim = (compiler_package / "module_compiler.py").read_text(encoding="utf-8")

    assert not (compiler_package / "compiler.py").exists()
    assert not (compiler_package / "build.py").exists()
    assert "import ast" not in shim
    assert "_emit_extension_c" not in shim
    assert "_compile_c_extension" not in shim
    assert "compile_kernel_e" not in shim


def test_runtime_has_no_legacy_per_function_dispatch_slot() -> None:
    runtime_source = (REPOSITORY_ROOT / "webrtc/compiler/runtime.py").read_text(
        encoding="utf-8"
    )
    assert "_implementation" not in runtime_source


def test_c_compiler_rejects_non_ascii_source_stem_before_creating_output(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    source = tmp_path / "kernél.py"
    source.write_bytes(KERNEL_SOURCE.read_bytes())
    output = tmp_path / "non-ascii-output"

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "valid non-keyword Python identifier" in completed.stderr
    assert not output.exists()


def test_c_compiler_rejects_quoted_path_before_creating_output(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    output = tmp_path / 'quoted"output'

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "paths must not contain a double quote" in completed.stderr
    assert not output.exists()


def test_c_compiler_rejects_overlong_path_before_creating_temp_state(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    output = tmp_path / ("x" * 3001)

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "bounded compiler path limit" in completed.stderr
    assert list(tmp_path.iterdir()) == []


def test_c_compiled_extension_hides_all_but_module_initializer(
    c_compiler_build: CCompilerBuild,
) -> None:
    if sys.platform == "darwin":
        command = ["nm", "-gU", str(c_compiler_build.artifact)]
        expected = "_PyInit_kernel_e_native"
    elif sys.platform.startswith("linux"):
        command = ["nm", "-D", "--defined-only", str(c_compiler_build.artifact)]
        expected = "PyInit_kernel_e_native"
    else:
        pytest.skip("defined-export inspection is configured for nm platforms")
    output = subprocess.run(
        command, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    assert {line.split()[-1] for line in output if line.split()} == {expected}


def test_c_compiled_extension_loads_with_discovery_and_metadata(
    c_compiler_build: CCompilerBuild,
) -> None:
    dispatcher = runtime.load_native_module(c_compiler_build.artifact, kernel_e)
    native = dispatcher.module
    function = native.packetize_av1_frame

    assert tuple(native.__all__) == tuple(kernel_e.__all__)
    assert "packetize_av1_frame" in dir(native)
    assert getattr(native, "packetize_av1_frame") is function
    assert inspect.signature(function) == inspect.signature(kernel_e.packetize_av1_frame)
    assert function.__doc__ == kernel_e.packetize_av1_frame.__doc__
    assert function.__annotations__ == kernel_e.packetize_av1_frame.__annotations__
    assert isinstance(native.__pymeta_functions__, MappingProxyType)
    assert dict(native.__pymeta_functions__) == {"packetize_av1_frame": function}
    for key, expected in runtime_compatibility().items():
        assert getattr(native, METADATA_ATTRIBUTES[key]) == expected
    assert len(native.__pymeta_source_sha256__) == 64
    assert len(native.__pymeta_semantic_sha256__) == 64


def test_c_compiled_kernel_matches_python_results_and_errors(
    c_compiler_build: CCompilerBuild,
) -> None:
    valid_cases = (
        (b"", 3, 0, 0, 0, 0),
        (bytes.fromhex("3209010203040506070809"), 3, 1, 2, 0xFFFE, 0xFFFD),
        (bytes.fromhex("0a0201023209010203040506070809"), 6, 0, 0xFFFFFFFF, 0xFE, 0xFFFE),
    )
    native = runtime.load_native_module(c_compiler_build.artifact, kernel_e).module
    for arguments in valid_cases:
        assert native.packetize_av1_frame(*arguments) == kernel_e.packetize_av1_frame(
            *arguments
        )

    malformed = (b"\x32\x02\x01", 1200, 1, 2, 3, 4)
    with pytest.raises(ValueError) as python_error:
        kernel_e.packetize_av1_frame(*malformed)
    with pytest.raises(ValueError) as native_error:
        native.packetize_av1_frame(*malformed)
    assert native_error.value.args == python_error.value.args


def test_c_compiled_dispatch_never_calls_python_implementation(
    c_compiler_build: CCompilerBuild, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("native execution called Python")

    forbidden.__module__ = kernel_e.__name__
    monkeypatch.setattr(kernel_e, "packetize_av1_frame", forbidden)
    runtime.configure_kernel_e(
        mode="native-required", library_path=c_compiler_build.artifact
    )
    assert runtime.packetize_av1_frame(b"", 3, 0, 0, 7, 8) == ((), 7, 8)


def test_c_compiler_accepts_explicit_exports_and_shared_private_helpers(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "generic_explicit",
        '''"""Generic compiler fixture."""
import pymeta
from pymeta import required

__all__ = ["increment", "encode"]

def _offset(value: int) -> int:
    return value + 1

@required
@pymeta.region("increment", value=pymeta.u64)
def increment(value: int) -> int:
    """Increment through a shared private helper."""
    return _offset(value)

@pymeta.region("encode", value=pymeta.buffer(maximum=1024))
def encode(value: bytes) -> bytes:
    return value + bytes([_offset(32)])
''',
    )

    assert completed.returncode == 0, completed.stderr
    artifact = Path(completed.stdout.strip())
    assert artifact.parent == output
    native = _load_fixture(artifact, "generic_explicit_native")
    assert native.increment(4) == 5
    assert native.encode(b"x") == b"x!"
    assert tuple(native.__all__) == ("increment", "encode")
    assert tuple(native.__pymeta_functions__) == ("increment", "encode")
    assert not hasattr(native, "_offset")
    assert str(inspect.signature(native.increment)) == "(value: int) -> int"
    assert native.increment.__doc__ == "Increment through a shared private helper."


def test_c_compiler_discovers_implicit_public_functions(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, _ = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "generic_implicit",
        "import pymeta\n\n"
        "@pymeta.region('first', value=pymeta.u64)\n"
        "def first(value: int) -> int:\n"
        "    return value * 2\n\n"
        "def _private(value: int) -> int:\n"
        "    return value - 1\n\n"
        "@pymeta.region('second', value=pymeta.u64)\n"
        "def second(value: int) -> int:\n"
        "    return _private(value)\n",
    )

    assert completed.returncode == 0, completed.stderr
    native = _load_fixture(Path(completed.stdout.strip()), "generic_implicit_native")
    assert tuple(native.__all__) == ("first", "second")
    assert native.first(6) == 12
    assert native.second(6) == 5
    assert not hasattr(native, "_private")


@pytest.mark.parametrize(
    ("name", "source_text", "location", "message"),
    (
        (
            "duplicate_exports",
            "__all__ = ['run', 'run']\n\ndef run() -> int:\n    return 1\n",
            "1:1",
            "__all__ contains duplicate names",
        ),
        (
            "missing_export",
            "__all__ = ['missing']\n",
            "1:1",
            "exported name 'missing' is missing",
        ),
        (
            "unsafe_import",
            "import os\n\ndef run() -> int:\n    return 1\n",
            "1:1",
            "unsafe import is not supported",
        ),
        (
            "reachable_lambda",
            "def run(value: int) -> int:\n    transform = lambda item: item\n    return transform(value)\n",
            "2:17",
            "unsupported reachable operation Lambda",
        ),
        (
            "recursive_graph",
            "def run(value: int) -> int:\n    return run(value)\n",
            "1:1",
            "recursive function graph is not supported",
        ),
    ),
)
def test_c_compiler_reports_stable_frontend_diagnostics_without_artifacts(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    name: str,
    source_text: str,
    location: str,
    message: str,
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build, tmp_path, name, source_text
    )

    source = tmp_path / f"{name}.py"
    assert completed.returncode != 0
    assert completed.stderr.strip() == f"{source}:{location}: error: {message}"
    assert not output.exists() or not any(output.rglob("*"))


def test_c_compiler_failure_does_not_replace_previous_complete_artifact(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    before = c_compiler_build.artifact.read_bytes()
    changed = tmp_path / "kernel_e.py"
    changed.write_bytes(KERNEL_SOURCE.read_bytes() + b"\nUNSUPPORTED_CHANGE = object()\n")
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(changed),
            "--output",
            str(c_compiler_build.output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert c_compiler_build.artifact.read_bytes() == before
    files = [path for path in c_compiler_build.output_dir.rglob("*") if path.is_file()]
    assert files == [c_compiler_build.artifact]
