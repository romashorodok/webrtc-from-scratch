from webrtc.tracing import PerformanceRecorder
from webrtc.tracing.performance_summary import (
    build_performance_summary,
    check_counters,
    check_event_ordering,
    check_forbidden_events,
    check_required_events,
    check_smoke_thresholds,
)


def _completed_events():
    recorder = PerformanceRecorder()
    recorder.mark("sdp", "create_offer", "started")
    recorder.mark("sdp", "create_offer", "completed", duration_ms=2.5)
    recorder.mark("ice", "gather", "started")
    recorder.mark("ice", "gather", "completed", duration_ms=3.0, metadata={"counter.ice.candidates": 2})
    return recorder.events()


def test_summary_builder_handles_completed_event_set():
    summary = build_performance_summary(
        _completed_events(),
        scenario="unit",
        required_events=["sdp.create_offer.completed", "ice.gather.completed"],
        ordering=[["sdp.create_offer.started", "ice.gather.completed"]],
    )

    assert summary["scenario"] == "unit"
    assert summary["status"] == "completed"
    assert summary["phase_ms"] == {"sdp.create_offer": 2.5, "ice.gather": 3.0}
    assert summary["counters"]["events.total"] == 4
    assert summary["counters"]["ice.candidates"] == 2
    assert summary["missing_required_events"] == []
    assert summary["ordering_failures"] == []


def test_summary_builder_handles_incomplete_events():
    recorder = PerformanceRecorder()
    recorder.mark("dtls", "handshake", "started")

    summary = build_performance_summary(
        recorder.events(),
        required_events=["dtls.handshake.completed"],
    )

    assert summary["status"] == "incomplete"
    assert summary["missing_required_events"] == ["dtls.handshake.completed"]
    assert summary["incomplete_phases"] == ["dtls.handshake"]


def test_summary_builder_handles_forbidden_events():
    events = _completed_events()

    summary = build_performance_summary(events, forbidden_events=["ice.gather.completed"])

    assert summary["status"] == "forbidden"
    assert summary["forbidden_events"] == ["ice.gather.completed"]


def test_summary_builder_handles_out_of_order_events():
    events = _completed_events()

    summary = build_performance_summary(
        events,
        ordering=[["ice.gather.completed", "sdp.create_offer.started"]],
    )

    assert summary["status"] == "incomplete"
    assert summary["ordering_failures"] == [
        "event out of order: ice.gather.completed before sdp.create_offer.started"
    ]


def test_baseline_comparison_helpers_return_failures():
    events = _completed_events()
    summary = build_performance_summary(events)

    assert check_required_events(events, ["ice.gather.completed"]).ok
    assert check_required_events(events, ["srtp.ready.completed"]).failures == (
        "missing required event: srtp.ready.completed",
    )
    assert check_forbidden_events(events, ["ice.gather.completed"]).failures == (
        "forbidden event present: ice.gather.completed",
    )
    assert check_event_ordering(events, [["sdp.create_offer.started", "ice.gather.completed"]]).ok
    assert not check_event_ordering(events, [["ice.gather.completed", "sdp.create_offer.started"]]).ok
    assert check_counters(summary["counters"], {"events.total": {"min": 4}}).ok
    assert not check_counters(summary["counters"], {"events.total": {"max": 1}}).ok
    assert check_smoke_thresholds(summary, {"phase_ms.ice.gather": 10.0}).ok
    assert not check_smoke_thresholds(summary, {"phase_ms.ice.gather": 1.0}).ok


def test_summary_accepts_mapping_events_without_mutating_them():
    event = {
        "component": "srtp",
        "phase": "ready",
        "state": "completed",
        "sequence": 2,
        "monotonic_ns": 20,
        "duration_ms": 1.0,
        "metadata": {},
    }

    summary = build_performance_summary([event])

    assert summary["events"] == ["srtp.ready.completed"]
    assert "name" not in event
