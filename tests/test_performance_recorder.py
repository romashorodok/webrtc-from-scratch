import asyncio

import pytest

from webrtc.runtime import WebRTCRuntimeResources
from webrtc.tracing import (
    PerformanceRecorder,
    get_current_performance_recorder,
    measure_perf,
    measure_perf_async,
    perf_mark,
    perf_measured,
    perf_measured_async,
    use_performance_recorder,
)


def test_recorder_metadata_is_frozen():
    recorder = PerformanceRecorder()
    source = {"nested": {"items": [1, 2]}}
    event = recorder.mark("ice", "gather", "started", metadata=source)

    source["nested"]["items"].append(3)

    assert event.metadata["nested"]["items"] == (1, 2)
    with pytest.raises(TypeError):
        event.metadata["new"] = "value"
    with pytest.raises(TypeError):
        event.metadata["nested"]["new"] = "value"


def test_events_are_sequenced_deterministically():
    recorder = PerformanceRecorder()

    first = recorder.mark("sdp", "offer", "started")
    second = recorder.mark("sdp", "offer", "completed")

    assert first.sequence == 1
    assert second.sequence == 2
    assert [event.sequence for event in recorder.events()] == [1, 2]


def test_perf_mark_is_noop_without_current_recorder():
    assert get_current_performance_recorder() is None
    assert perf_mark("sdp", "offer", "started") is None


def test_current_recorder_context_records_marks_and_resets():
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        assert get_current_performance_recorder() is recorder
        event = perf_mark("dtls", "handshake", "started")

    assert event is not None
    assert event.name == "dtls.handshake.started"
    assert get_current_performance_recorder() is None


def test_measure_perf_records_completion_duration():
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        with measure_perf("ice", "nomination"):
            pass

    events = recorder.events()
    assert [event.name for event in events] == ["ice.nomination.started", "ice.nomination.completed"]
    assert events[1].duration_ms is not None


def test_measure_perf_records_failure_and_reraises():
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        with pytest.raises(ValueError):
            with measure_perf("dtls", "handshake"):
                raise ValueError("bad flight")

    failed = recorder.events()[-1]
    assert failed.name == "dtls.handshake.failed"
    assert failed.metadata["exception_class"] == "ValueError"


def test_async_measurement_helper_and_decorator_record_events():
    async def scenario():
        recorder = PerformanceRecorder()

        @perf_measured_async("srtp", "ready")
        async def ready():
            await asyncio.sleep(0)
            return "ok"

        with use_performance_recorder(recorder):
            async with measure_perf_async("ice", "gather"):
                await asyncio.sleep(0)
            assert await ready() == "ok"

        assert [event.name for event in recorder.events()] == [
            "ice.gather.started",
            "ice.gather.completed",
            "srtp.ready.started",
            "srtp.ready.completed",
        ]

    asyncio.run(scenario())


def test_sync_decorator_records_events():
    recorder = PerformanceRecorder()

    @perf_measured("sdp", "create_offer")
    def create_offer():
        return "offer"

    with use_performance_recorder(recorder):
        assert create_offer() == "offer"

    assert [event.name for event in recorder.events()] == [
        "sdp.create_offer.started",
        "sdp.create_offer.completed",
    ]


def test_perf_events_attach_task_context_peer_metadata():
    runtime = WebRTCRuntimeResources(max_workers=1)
    recorder = PerformanceRecorder()
    try:
        context = runtime.create_task_context(
            name="protocol-task",
            kind="protocol",
            metadata={"peer_id": "peer-a", "component": "ice"},
        )
        runtime.start_task_context(context)

        async def scenario():
            with use_performance_recorder(recorder):
                await runtime.trace_awaitable(
                    _mark_once(),
                    context=context,
                )

        asyncio.run(scenario())
    finally:
        runtime.shutdown()

    event = recorder.events()[0]
    assert event.metadata["trace_id"] == context.trace_id
    assert event.metadata["task_name"] == "protocol-task"
    assert event.metadata["task_kind"] == "protocol"
    assert event.metadata["peer_id"] == "peer-a"
    assert event.metadata["component"] == "ice"


async def _mark_once():
    perf_mark("ice", "gather", "started")
