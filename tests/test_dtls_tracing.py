import asyncio

import webrtc_rs

from webrtc.dtls.dtlstransport import DTLSTransport
from webrtc.dtls.fsm import FSM, FSMState, StartHandshake
from webrtc.dtls.flight_state import Flight
from webrtc.tracing import PerformanceRecorder, use_performance_recorder


def _names(recorder: PerformanceRecorder) -> list[str]:
    return [event.name for event in recorder.events()]


def test_dtls_malformed_record_emits_parse_failure():
    async def scenario():
        recorder = PerformanceRecorder()
        transport = DTLSTransport(certificate=webrtc_rs.Certificate())

        with use_performance_recorder(recorder):
            await transport.enqueue_record(b"not-a-dtls-record")

        assert _names(recorder) == [
            "dtls.record.parse.started",
            "dtls.record.parse.failed",
        ]
        assert recorder.events()[-1].metadata["exception_class"] == "ValueError"

    asyncio.run(scenario())


def test_dtls_reconstruction_failure_is_separate_from_parse(monkeypatch):
    class Header:
        content_type = type("ContentType", (), {"name": "HANDSHAKE"})()
        epoch = 0
        sequence_number = 7

    class Record:
        header = Header()

    class BrokenReconstructor:
        def complete(self, record, raw):
            raise RuntimeError("fragment corruption")

    async def scenario():
        recorder = PerformanceRecorder()
        transport = DTLSTransport(certificate=webrtc_rs.Certificate())
        transport._DTLSTransport__handshake_reconstructor = BrokenReconstructor()

        monkeypatch.setattr(
            "webrtc.dtls.dtlstransport.RecordLayerBatch",
            lambda data: [(Record(), data)],
        )

        with use_performance_recorder(recorder):
            await transport.enqueue_record(b"\x16record")

        assert _names(recorder) == [
            "dtls.record.parse.started",
            "dtls.record.parse.completed",
            "dtls.record.rx",
            "dtls.record.reconstruct.started",
            "dtls.record.reconstruct.failed",
        ]

    asyncio.run(scenario())


def test_dtls_fsm_dispatch_uses_typed_command_mailbox():
    async def scenario():
        fsm = object.__new__(FSM)
        fsm.flight = Flight.FLIGHT1
        fsm.handshake_state = FSMState.Preparing
        fsm.commands = asyncio.Queue()
        recorder = PerformanceRecorder()

        with use_performance_recorder(recorder):
            await fsm.dispatch()

        assert _names(recorder) == [
            "dtls.fsm.dispatch.started",
            "dtls.fsm.dispatch.completed",
        ]
        assert isinstance(await fsm.commands.get(), StartHandshake)
        assert fsm.handshake_state is FSMState.Preparing

    asyncio.run(scenario())
