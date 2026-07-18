import asyncio
import inspect
from pathlib import Path

import pytest

from webrtc.dtls.fsm import DTLSConn
from webrtc.performance import ObservedComponent, task
from webrtc.peer_connection import PeerConnection
from webrtc import Runtime
from webrtc.runtime_services import FailurePolicy


def test_peer_start_is_an_ordinary_structured_async_method() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="phase-4") as runtime:
            peer = PeerConnection()
            peer.__compose_runtime__(runtime)

            async def start_gatherer() -> None:
                return None

            peer.gatherer.start = start_gatherer
            started = peer.start()
            assert inspect.isawaitable(started)
            assert not isinstance(started, asyncio.Task)
            await started

    asyncio.run(scenario())


def test_dtls_inbound_runner_is_runtime_owned_and_cancelable() -> None:
    async def scenario() -> None:
        connection = DTLSConn.__new__(DTLSConn)
        connection.record_layer_chan = asyncio.Queue()

        async with Runtime(scope_id="phase-4") as runtime:
            inbound = runtime.start(
                connection.handle_inbound_record_layers,
                name="test:dtls-inbound",
            )
            await asyncio.sleep(0)
            inbound.cancel()
            with pytest.raises(asyncio.CancelledError):
                await inbound

    asyncio.run(scenario())


def test_migrated_components_do_not_use_peer_scheduling_bridges() -> None:
    root = Path(__file__).parents[1] / "webrtc"
    paths = (
        root / "peer_connection.py",
        root / "transceiver.py",
        root / "ice" / "agent.py",
        root / "dtls" / "fsm.py",
        root / "dtls" / "dtlstransport.py",
        root / "ice" / "net" / "udp_mux.py",
        root / "audio" / "analyzer.py",
        root / "srtp" / "session.py",
    )
    forbidden = ("task_scheduler.spawn_factory", "worker_lane.run_observed")
    for path in paths:
        source = path.read_text()
        assert not any(marker in source for marker in forbidden), path
