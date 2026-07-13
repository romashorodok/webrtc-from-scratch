import asyncio
import math

import pytest

from webrtc import Runtime
from webrtc.performance import ObservedComponent, observe


class CaptureSubject(ObservedComponent):
    @observe(detail="exact")
    async def call(self, outcome="success", entered=None):
        if entered is not None:
            entered.set()
        if outcome == "failure":
            raise LookupError("unbounded secret must not be captured")
        if outcome == "cancel":
            await asyncio.Event().wait()
        return 7


def _operation_id():
    return CaptureSubject.__observations__["call"].operation_id


def test_exact_annotation_is_aggregate_until_server_authorizes_bounded_capture():
    async def scenario():
        async with Runtime() as runtime:
            subject = CaptureSubject()
            assert await subject.call() == 7
            assert runtime.capture_manager.snapshots() == ()
            authorization = runtime.authorize_trace_capture(
                selector_kind="operation", selector_value=_operation_id(),
                duration_seconds=30, call_budget=1,
            )
            assert authorization.call_budget == 1
            assert await subject.call() == 7
            assert await subject.call() == 7
            captures = runtime.capture_manager.snapshots()
            assert len(captures) == 1
            assert captures[0].capture_id == authorization.capture_id
            assert captures[0].outcome == "success"
            assert runtime.capture_manager.active() == ()
            group = runtime.activity_groups.snapshots()[0]
            assert group.calls == group.successes == 3
            snapshot = runtime.trace_snapshot()["data"]
            assert snapshot["schema"] == 2
            assert snapshot["captures"][0]["diagnostic_capture"] is True

    asyncio.run(scenario())


def test_capture_duration_and_call_budgets_are_server_capped_and_expire():
    async def scenario():
        async with Runtime(
            trace_capture_max_seconds=0.01, trace_capture_max_calls=2,
        ) as runtime:
            authorization = runtime.authorize_trace_capture(
                selector_kind="operation", selector_value=_operation_id(),
                duration_seconds=999, call_budget=999,
            )
            assert authorization.call_budget == 2
            assert authorization.expires_ns > 0
            await asyncio.sleep(0.02)
            assert runtime.capture_manager.active() == ()
            assert await CaptureSubject().call() == 7
            assert runtime.capture_manager.snapshots() == ()
            assert runtime.diagnostics["captures_expired"] == 1

    asyncio.run(scenario())


def test_failure_and_cancellation_are_terminal_bounded_capture_records():
    async def scenario():
        async with Runtime() as runtime:
            runtime.authorize_trace_capture(
                selector_kind="operation", selector_value=_operation_id(),
                duration_seconds=30, call_budget=2,
            )
            with pytest.raises(LookupError):
                await CaptureSubject().call("failure")
            entered = asyncio.Event()
            pending = asyncio.create_task(CaptureSubject().call("cancel", entered))
            await entered.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            captures = runtime.capture_manager.snapshots()
            assert [item.outcome for item in captures] == ["error", "cancelled"]
            assert captures[0].failure_class == "LookupError"
            assert "secret" not in repr(captures)
            assert all(item.finished_ns > item.started_ns for item in captures)

    asyncio.run(scenario())


def test_entity_control_and_facet_authorization_are_validated_and_teardown_cancels():
    async def scenario():
        runtime = Runtime(scope_id="peer", trace_capture_limit=4)
        async with runtime:
            entity = runtime.authorize_trace_capture(
                selector_kind="entity", selector_value="peer",
                duration_seconds=30, call_budget=2,
            )
            assert await CaptureSubject().call() == 7
            assert runtime.capture_manager.snapshots()[0].capture_id == entity.capture_id
            with pytest.raises(ValueError, match="unknown capture control"):
                runtime.authorize_trace_capture(
                    selector_kind="control", selector_value="missing",
                    duration_seconds=1, call_budget=1,
                )
            with pytest.raises(ValueError, match="unknown capture facet"):
                runtime.authorize_trace_capture(
                    selector_kind="facet", selector_value="missing",
                    duration_seconds=1, call_budget=1,
                )
            runtime.authorize_trace_capture(
                selector_kind="operation", selector_value=_operation_id(),
                duration_seconds=30, call_budget=10,
            )
        assert runtime.capture_manager.closed
        assert runtime.capture_manager.active() == ()
        assert runtime.diagnostics["captures_teardown_cancelled"] >= 1

    asyncio.run(scenario())


def test_capture_eviction_emits_remove_patch_for_frontend_bound():
    async def scenario():
        async with Runtime(trace_capture_record_limit=1, trace_patch_cadence=60) as runtime:
            subscription = runtime.trace_patch_subscribe(maxsize=8)
            await subscription.get()
            runtime.authorize_trace_capture(
                selector_kind="operation", selector_value=_operation_id(),
                duration_seconds=30, call_budget=2,
            )
            await CaptureSubject().call()
            runtime.trace_patch_flush()
            await subscription.get()
            await CaptureSubject().call()
            batch = runtime.trace_patch_flush()[0]
            events = {event["type"]: event for event in batch["data"]["events"]}
            assert events["capture:remove"]["ids"] == [1]
            assert events["capture:upsert"]["records"][0]["record_id"] == 2
            subscription.close()

    asyncio.run(scenario())


def test_capture_authorization_rejects_non_finite_and_ambiguous_inputs():
    runtime = Runtime()
    for duration in (math.nan, math.inf, -math.inf, True):
        with pytest.raises(ValueError):
            runtime.capture_manager.authorize(
                "operation", _operation_id(), duration_seconds=duration, call_budget=1,
            )
    with pytest.raises(ValueError):
        runtime.capture_manager.authorize(
            "operation", True, duration_seconds=1, call_budget=1,
        )
    with pytest.raises(ValueError):
        runtime.capture_manager.authorize(
            "operation", _operation_id(), duration_seconds=1, call_budget=True,
        )
