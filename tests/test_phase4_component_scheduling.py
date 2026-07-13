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
        peer = PeerConnection()

        async def start_gatherer() -> None:
            return None

        peer.gatherer.start = start_gatherer
        await peer.start()
        peer._started = False

        async with Runtime(scope_id="phase-4"):
            started = peer.start()
            assert inspect.isawaitable(started)
            assert not isinstance(started, asyncio.Task)
            await started

    asyncio.run(scenario())


def test_dtls_inbound_runner_cancels_and_awaits_its_fsm_child() -> None:
    stopped = asyncio.Event()

    class FakeFSM(ObservedComponent):
        @task(
            name="test:dtls-fsm",
            kind="dtls",
            failure=FailurePolicy.FAIL_CONNECTION,
        )
        async def run(self) -> None:
            try:
                await asyncio.Future()
            finally:
                stopped.set()

    async def scenario() -> None:
        connection = DTLSConn.__new__(DTLSConn)
        connection.record_layer_chan = asyncio.Queue()
        connection.fsm = FakeFSM()

        async with Runtime(scope_id="phase-4"):
            inbound = connection.handle_inbound_record_layers()
            await asyncio.sleep(0)
            inbound.cancel()
            with pytest.raises(asyncio.CancelledError):
                await inbound
            await asyncio.wait_for(stopped.wait(), timeout=1)

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
