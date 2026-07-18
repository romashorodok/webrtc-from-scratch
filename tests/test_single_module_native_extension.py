"""Black-box acceptance tests for the single-module Kernel E compiler slice."""

from __future__ import annotations

import inspect
import subprocess
import sys
import sysconfig
from pathlib import Path
from types import MappingProxyType

import pytest

from webrtc.compiler import kernel_e, runtime
from webrtc.compiler.module_compiler import compile_module
from webrtc.compiler.module_contract import (
    METADATA_ATTRIBUTES,
    runtime_compatibility,
)


SOURCE_PATH = Path(kernel_e.__file__).resolve()


@pytest.fixture(scope="module")
def native_artifact(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("single-module-native")
    artifact = compile_module(SOURCE_PATH, output).artifact_path.resolve()
    assert artifact.parent == output.resolve()
    assert artifact.name == f"kernel_e_native{sysconfig.get_config_var('EXT_SUFFIX')}"
    assert artifact.is_file()
    return artifact


@pytest.fixture(autouse=True)
def restore_python_dispatch() -> None:
    runtime.configure_kernel_e(mode="python")
    yield
    runtime.configure_kernel_e(mode="python")


def test_one_source_retains_exactly_one_extension_and_no_sidecars(
    native_artifact: Path,
) -> None:
    files = [path for path in native_artifact.parent.rglob("*") if path.is_file()]
    assert files == [native_artifact]
    assert not any(
        path.suffix.lower() in {".c", ".h", ".ll", ".bc", ".o", ".obj", ".json"}
        for path in native_artifact.parent.rglob("*")
    )


def test_extension_exports_only_its_cpython_initializer(native_artifact: Path) -> None:
    if sys.platform == "darwin":
        command = ["nm", "-gU", str(native_artifact)]
        expected = "_PyInit_kernel_e_native"
    elif sys.platform.startswith("linux"):
        command = ["nm", "-D", "--defined-only", str(native_artifact)]
        expected = "PyInit_kernel_e_native"
    else:
        pytest.skip("defined-export inspection is configured for nm platforms")

    output = subprocess.run(
        command, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    exported = {line.split()[-1] for line in output if line.split()}
    assert exported == {expected}


def test_extension_recreates_kernel_e_discovery_and_function_surface(
    native_artifact: Path,
) -> None:
    dispatcher = runtime.load_native_module(native_artifact, kernel_e)
    native = dispatcher.module
    name = "packetize_av1_frame"

    assert tuple(native.__all__) == tuple(kernel_e.__all__) == (name,)
    assert name in dir(native)
    assert getattr(native, name) is dispatcher.functions[name]
    assert inspect.signature(getattr(native, name)) == inspect.signature(
        getattr(kernel_e, name)
    )
    assert getattr(native, name).__name__ == getattr(kernel_e, name).__name__
    assert getattr(native, name).__qualname__ == getattr(kernel_e, name).__qualname__


@pytest.mark.parametrize("attribute", ("__doc__", "__annotations__"))
def test_extension_preserves_public_function_attributes(
    native_artifact: Path, attribute: str
) -> None:
    native_function = runtime.load_native_module(
        native_artifact, kernel_e
    ).module.packetize_av1_frame
    assert getattr(native_function, attribute) == getattr(
        kernel_e.packetize_av1_frame, attribute
    )


@pytest.mark.parametrize(
    "constant",
    ("_MAX_FRAME_SIZE", "_MAX_NUM_OBUS_TO_OMIT_SIZE", "_IGNORED_OBU_TYPES"),
)
def test_extension_preserves_required_module_constants(
    native_artifact: Path, constant: str
) -> None:
    native = runtime.load_native_module(native_artifact, kernel_e).module
    assert getattr(native, constant) == getattr(kernel_e, constant)


def test_embedded_function_registry_is_complete_and_immutable(
    native_artifact: Path,
) -> None:
    native = runtime.load_native_module(native_artifact, kernel_e).module
    registry = native.__pymeta_functions__

    assert isinstance(registry, MappingProxyType)
    assert tuple(registry) == tuple(kernel_e.__all__)
    assert registry["packetize_av1_frame"] is native.packetize_av1_frame
    with pytest.raises(TypeError):
        registry["packetize_av1_frame"] = kernel_e.packetize_av1_frame
    with pytest.raises(TypeError):
        del registry["packetize_av1_frame"]


def test_extension_embeds_complete_loader_metadata(native_artifact: Path) -> None:
    native = runtime.load_native_module(native_artifact, kernel_e).module
    compatibility = runtime_compatibility()

    assert len(native.__pymeta_source_sha256__) == 64
    assert len(native.__pymeta_semantic_sha256__) == 64
    for key, expected in compatibility.items():
        assert getattr(native, METADATA_ATTRIBUTES[key]) == expected


def test_loader_rejects_source_metadata_mismatch_before_dispatch(
    native_artifact: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    changed_source = tmp_path / "kernel_e.py"
    changed_source.write_bytes(SOURCE_PATH.read_bytes() + b"\n# semantic drift\n")
    monkeypatch.setattr(kernel_e, "__file__", str(changed_source))

    with pytest.raises(runtime.NativeArtifactError, match=r"compatibility mismatch"):
        runtime.configure_kernel_e(
            mode="native-required", library_path=native_artifact
        )

    assert runtime.kernel_e_mode() == "python"
    assert runtime.loaded_kernel_e_module() is kernel_e


@pytest.mark.parametrize(
    "metadata_key",
    ("compiler_version", "cpython_revision", "target", "architecture", "optimization"),
)
def test_loader_rejects_each_runtime_metadata_mismatch_before_dispatch(
    native_artifact: Path,
    metadata_key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incompatible = runtime_compatibility()
    incompatible[metadata_key] += "-incompatible"
    monkeypatch.setattr(runtime, "runtime_compatibility", lambda: incompatible)

    with pytest.raises(runtime.NativeArtifactError, match=metadata_key):
        runtime.configure_kernel_e(
            mode="native-required", library_path=native_artifact
        )

    assert runtime.kernel_e_mode() == "python"


def test_loader_rejects_semantic_hash_mismatch_before_dispatch(
    native_artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime, "semantic_sha256", lambda *args, **kwargs: "0" * 64)

    with pytest.raises(runtime.NativeArtifactError, match="semantic_sha256"):
        runtime.configure_kernel_e(
            mode="native-required", library_path=native_artifact
        )

    assert runtime.kernel_e_mode() == "python"


@pytest.mark.parametrize("bad_name", ("missing.so", "not-an-extension"))
def test_loader_fails_closed_for_missing_or_non_extension_artifacts(
    tmp_path: Path, bad_name: str
) -> None:
    path = tmp_path / bad_name
    if bad_name == "not-an-extension":
        path.write_bytes(b"not a native module")

    with pytest.raises(runtime.NativeArtifactError):
        runtime.configure_kernel_e(mode="native-required", library_path=path)

    assert runtime.kernel_e_mode() == "python"
    assert runtime.loaded_kernel_e_module() is kernel_e


def test_native_dispatch_does_not_call_the_python_implementation(
    native_artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("native execution called the Python implementation")

    forbidden.__module__ = kernel_e.__name__
    monkeypatch.setattr(kernel_e, "packetize_av1_frame", forbidden)
    runtime.configure_kernel_e(mode="native-required", library_path=native_artifact)

    assert runtime.packetize_av1_frame(
        bytes.fromhex("3203010203"), 1200, 1, 2, 3, 4
    ) == (
        (bytes.fromhex("90ad00040000000100000002bede0001410005001030010203"),),
        4,
        5,
    )


@pytest.mark.parametrize(
    "arguments",
    (
        (b"", 3, 0, 0, 0, 0),
        (bytes.fromhex("3209010203040506070809"), 3, 1, 2, 0xFFFE, 0xFFFD),
        (bytes.fromhex("0a0201023209010203040506070809"), 6, 0, 0xFFFFFFFF, 0xFE, 0xFFFE),
        (bytes.fromhex("12002a0101320202037a00"), 1200, 0xFFFFFFFF, 0, 0, 0),
    ),
)
def test_native_kernel_e_matches_python_results(
    native_artifact: Path, arguments: tuple[bytes, int, int, int, int, int]
) -> None:
    expected = kernel_e.packetize_av1_frame(*arguments)
    runtime.configure_kernel_e(mode="native-required", library_path=native_artifact)
    assert runtime.packetize_av1_frame(*arguments) == expected


@pytest.mark.parametrize(
    "arguments",
    (
        (bytearray(), 1200, 1, 2, 3, 4),
        (b"", 2, 1, 2, 3, 4),
        (b"\x06", 1200, 1, 2, 3, 4),
        (b"\x32\x80", 1200, 1, 2, 3, 4),
        (b"\x32\x02\x01", 1200, 1, 2, 3, 4),
    ),
)
def test_native_kernel_e_matches_python_exception_contract(
    native_artifact: Path, arguments: tuple[object, ...]
) -> None:
    with pytest.raises((TypeError, ValueError)) as python_error:
        kernel_e.packetize_av1_frame(*arguments)  # type: ignore[arg-type]

    runtime.configure_kernel_e(mode="native-required", library_path=native_artifact)
    with pytest.raises(type(python_error.value)) as native_error:
        runtime.packetize_av1_frame(*arguments)  # type: ignore[arg-type]

    assert native_error.value.args == python_error.value.args
