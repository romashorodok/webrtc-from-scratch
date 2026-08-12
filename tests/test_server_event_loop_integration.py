"""Server entry points select their loop through the public production API."""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from webrtc import event_loop


ROOT = Path(__file__).resolve().parents[1]


def _load_serve() -> ModuleType:
    path = ROOT / "examples" / "serve.py"
    spec = importlib.util.spec_from_file_location("test_examples_serve", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_dtls_server() -> ModuleType:
    path = ROOT / "examples" / "dtls_server.py"
    spec = importlib.util.spec_from_file_location("test_examples_dtls_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def reset_selection() -> None:
    event_loop._reset_native_selection_for_tests()
    yield
    event_loop._reset_native_selection_for_tests()


def test_public_import_does_not_import_interpreted_custom_loop() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import webrtc.event_loop; "
                "assert 'webrtc.event_loop.loop' not in sys.modules"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_server_factory_passes_all_public_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve = _load_serve()
    expected_loop = object()
    received: dict[str, object] = {}

    def factory(**kwargs: object) -> object:
        received.update(kwargs)
        return expected_loop

    monkeypatch.setattr(serve.event_loop, "new_event_loop", factory)
    actual = serve.server_loop_factory(
        packet_workers=3,
        packet_queue_capacity=128,
        receive_packet_budget=17,
        receive_time_budget_us=250,
        require_native=True,
    )

    assert actual is expected_loop
    assert received == {
        "packet_workers": 3,
        "packet_queue_capacity": 128,
        "receive_packet_budget": 17,
        "receive_time_budget_us": 250,
        "require_native": True,
        "force_asyncio": False,
    }


def test_dtls_server_factory_passes_all_public_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _load_dtls_server()
    expected_loop = object()
    received: dict[str, object] = {}

    def factory(**kwargs: object) -> object:
        received.update(kwargs)
        return expected_loop

    monkeypatch.setattr(server.event_loop, "new_event_loop", factory)
    actual = server.server_loop_factory(
        packet_workers=4,
        packet_queue_capacity=256,
        receive_packet_budget=23,
        receive_time_budget_us=400,
        require_native=True,
    )

    assert actual is expected_loop
    assert received == {
        "packet_workers": 4,
        "packet_queue_capacity": 256,
        "receive_packet_budget": 23,
        "receive_time_budget_us": 400,
        "require_native": True,
        "force_asyncio": False,
    }


def test_server_factory_can_force_stock_asyncio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve = _load_serve()
    received: dict[str, object] = {}

    def factory(**kwargs: object) -> asyncio.AbstractEventLoop:
        received.update(kwargs)
        return asyncio.new_event_loop()

    monkeypatch.setattr(serve.event_loop, "new_event_loop", factory)
    loop = serve.server_loop_factory(force_asyncio=True)
    try:
        assert received["force_asyncio"] is True
        assert received["require_native"] is False
    finally:
        loop.close()


@pytest.mark.parametrize(
    ("target", "required", "forbidden"),
    (
        ("serve", "--require-native-event-loop", "--force-asyncio-event-loop"),
        (
            "serve-native",
            "--require-native-event-loop",
            "--force-asyncio-event-loop",
        ),
        ("run", "--require-native-event-loop", "--force-asyncio-event-loop"),
        (
            "serve-asyncio",
            "--force-asyncio-event-loop",
            "--require-native-event-loop",
        ),
        ("asyncio", "--force-asyncio-event-loop", "--require-native-event-loop"),
    ),
)
def test_make_server_target_has_explicit_loop_guarantee(
    target: str, required: str, forbidden: str
) -> None:
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", "-C", "examples", target],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    commands = [
        line
        for line in result.stdout.splitlines()
        if "serve.py" in line
    ]
    assert len(commands) == 1
    assert required in commands[0]
    assert forbidden not in commands[0]


def test_make_native_target_builds_for_system_project_environment() -> None:
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", "-C", "examples", "native-event-loop"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        ".venv/bin/python -m webrtc.event_loop.build_native"
    ]


def test_server_runner_is_scoped_repeatable_and_does_not_change_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve = _load_serve()
    policy = asyncio.get_event_loop_policy()
    loops: list[asyncio.AbstractEventLoop] = []
    runs: list[tuple[str, str, int, asyncio.AbstractEventLoop]] = []

    def factory(**_kwargs: object) -> asyncio.AbstractEventLoop:
        loop = asyncio.new_event_loop()
        loops.append(loop)
        return loop

    async def fake_run_server(module: str, app: str, port: int) -> None:
        running = asyncio.get_running_loop()
        runs.append((module, app, port, running))
        reader, writer = socket.socketpair()
        reader.setblocking(False)
        ready = running.create_future()

        def readable() -> None:
            reader.recv(1)
            if not ready.done():
                ready.set_result(None)

        running.add_reader(reader.fileno(), readable)
        try:
            writer.send(b"x")
            await asyncio.wait_for(ready, timeout=1)
            pending = asyncio.create_task(asyncio.sleep(60))
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        finally:
            running.remove_reader(reader.fileno())
            reader.close()
            writer.close()

    monkeypatch.setattr(serve.event_loop, "new_event_loop", factory)
    monkeypatch.setattr(serve.event_loop, "event_loop_mode", lambda: "asyncio")
    monkeypatch.setattr(
        serve.event_loop,
        "event_loop_selection_reason",
        lambda: "test stock selection",
    )
    monkeypatch.setattr(serve, "run_server", fake_run_server)

    serve.server_routine("first", "app", 9001)
    serve.server_routine("second", "app", 9002)

    assert [(module, app, port) for module, app, port, _ in runs] == [
        ("first", "app", 9001),
        ("second", "app", 9002),
    ]
    assert [running for *_, running in runs] == loops
    assert all(loop.is_closed() for loop in loops)
    assert asyncio.get_event_loop_policy() is policy


def test_server_uses_stock_loop_when_native_artifact_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve = _load_serve()
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: ())

    loop = serve.server_loop_factory()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert type(loop).__module__ != "webrtc.event_loop.loop"
        assert "no native" in event_loop.event_loop_selection_reason()
    finally:
        loop.close()


def test_server_reports_stale_artifact_and_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    serve = _load_serve()
    candidate = tmp_path / "event_loop_native.so"
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))

    def stale(_artifact: Path) -> object:
        raise event_loop.NativeArtifactCompatibilityError("stale compiler version")

    monkeypatch.setattr(event_loop, "_validated_native_factory", stale)
    loop = serve.server_loop_factory()
    try:
        assert event_loop.event_loop_mode() == "asyncio"
        assert "stale compiler version" in event_loop.event_loop_selection_reason()
    finally:
        loop.close()


def test_server_uses_compatible_mocked_native_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    serve = _load_serve()
    candidate = tmp_path / "event_loop_native.so"
    native_loop = asyncio.new_event_loop()
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: (candidate,))
    monkeypatch.setattr(
        event_loop,
        "_validated_native_factory",
        lambda _artifact: lambda: native_loop,
    )

    selected = serve.server_loop_factory(require_native=True)
    try:
        assert selected is native_loop
        assert event_loop.event_loop_mode() == "native"
        assert str(candidate) in event_loop.event_loop_selection_reason()
    finally:
        selected.close()


def test_server_strict_native_mode_fails_before_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve = _load_serve()
    monkeypatch.setattr(event_loop, "_artifact_candidates", lambda: ())

    with pytest.raises(
        event_loop.NativeArtifactCompatibilityError,
        match="compatible native event loop is required",
    ):
        serve.server_loop_factory(require_native=True)
