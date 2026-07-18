from __future__ import annotations

import asyncio

import pytest

from webrtc.operation_policy import (
    HIGH_RATE_OPERATION_DENYLIST,
    PRODUCTION_OPERATION_ALLOWLIST,
    is_high_rate_suppressed,
    is_production_component,
    production_policy_for,
)
from webrtc.peer_components import AsyncLogDrain
from webrtc.performance import ObservedComponent, TraceDetail, observe_worker
from webrtc.runtime_services import MissingExecutionScope
from webrtc.runtime import Runtime


def test_production_inventory_is_external_explicit_and_private_by_exception():
    expected = {
        "PeerConnection", "Agent", "CandidatePairController", "DTLSTransport",
        "FSM", "DTLSConn", "Session", "RTPReceiver", "RTPTransceiver",
        "MultiUDPMux", "AsyncLogDrain", "AudioAnalyzer",
    }
    assert set(PRODUCTION_OPERATION_ALLOWLIST) == expected
    private = {
        (component, method)
        for component, methods in PRODUCTION_OPERATION_ALLOWLIST.items()
        for method in methods if method.startswith("_")
    }
    assert private == {("DTLSTransport", "_handshake_workflow")}
    assert PRODUCTION_OPERATION_ALLOWLIST["DTLSTransport"][
        "_handshake_workflow"
    ].workflow


def test_exact_requests_and_aggregate_workflows_are_deliberate():
    policy = PRODUCTION_OPERATION_ALLOWLIST
    assert policy["PeerConnection"]["set_remote_description"].detail is TraceDetail.EXACT
    assert policy["Agent"]["gather_candidates"].detail is TraceDetail.AGGREGATE
    assert policy["Agent"]["gather_candidates"].workflow
    assert policy["DTLSTransport"]["start"].detail is TraceDetail.AGGREGATE
    assert policy["RTPTransceiver"]["set_mid"].detail is TraceDetail.EXACT
    assert policy["AsyncLogDrain"]["write_batch"].detail is TraceDetail.AGGREGATE


def test_packet_frame_and_long_running_paths_are_suppressed():
    checks = {
        "PeerConnection": {"send_rtp_packet", "_run_media_send_pump"},
        "DTLSTransport": {"write_rtp_bytes", "_rtp_receive_loop"},
        "Session": {"encrypt", "decrypt", "write_incoming"},
        "AudioAnalyzer": {"analyze_frame"},
        "AsyncLogDrain": {"_run"},
    }
    for component, methods in checks.items():
        for method in methods:
            assert is_high_rate_suppressed(component, method)
            assert method not in PRODUCTION_OPERATION_ALLOWLIST[component]
    assert all(HIGH_RATE_OPERATION_DENYLIST.values())


def test_runtime_binding_uses_authoritative_production_policy():
    async def scenario():
        drain = AsyncLogDrain()
        async with Runtime(scope_id="stage6-policy") as runtime:
            runtime.register_owner("log-owner", epoch=1)
            binding = runtime.bind_observation(
                drain, entity_id="log-owner", role="log-drain", owner_epoch=1,
            )
            assert binding.policy_is_authoritative
            assert set(binding.operation_policy) == {"start", "write_batch", "aclose"}
            assert "_run" not in binding.operation_policy
            runtime.remove_owner("log-owner", 1)

    asyncio.run(scenario())


def test_catalog_is_independent_of_metaclass_observation_table(monkeypatch):
    drain = AsyncLogDrain()
    expected = PRODUCTION_OPERATION_ALLOWLIST["AsyncLogDrain"]
    # Stage 7 removes the metaclass table from production types entirely.  A
    # synthetic compatibility attribute still must not influence the external
    # production catalog.
    assert "__observations__" not in AsyncLogDrain.__dict__
    monkeypatch.setattr(
        AsyncLogDrain, "__observations__", {"poison": object()}, raising=False,
    )
    assert production_policy_for(drain) is expected
    assert set(expected) == {"start", "write_batch", "aclose"}


def test_every_catalogued_production_type_rejects_implicit_root_composition():
    async def probe(self):
        return "must-not-run"

    async def scenario():
        async with Runtime(scope_id="stage6-explicit-composition"):
            for component in PRODUCTION_OPERATION_ALLOWLIST:
                module = {
                    "PeerConnection": "webrtc.peer_connection",
                    "Agent": "webrtc.ice.agent",
                    "CandidatePairController": "webrtc.ice.agent",
                    "DTLSTransport": "webrtc.dtls.dtlstransport",
                    "FSM": "webrtc.dtls.fsm", "DTLSConn": "webrtc.dtls.fsm",
                    "Session": "webrtc.srtp.session",
                    "RTPReceiver": "webrtc.transceiver",
                    "RTPTransceiver": "webrtc.transceiver",
                    "MultiUDPMux": "webrtc.ice.net.udp_mux",
                    "AsyncLogDrain": "webrtc.peer_components",
                    "AudioAnalyzer": "webrtc.audio.analyzer",
                }[component]
                subject_type = type(component, (ObservedComponent,), {
                    "__module__": module, "probe": probe,
                })
                subject = subject_type()
                assert is_production_component(subject)
                with pytest.raises(MissingExecutionScope):
                    await subject.probe()

    asyncio.run(scenario())


@pytest.mark.parametrize("tracing_enabled", [False, True])
def test_unbound_sync_and_async_production_calls_reject_in_every_trace_mode(
    tracing_enabled,
):
    async def scenario():
        drain = AsyncLogDrain()
        from webrtc.peer_connection import PeerConnection
        peer = PeerConnection()
        async with Runtime(
            scope_id=f"stage6-unbound-{tracing_enabled}",
            tracing_enabled=tracing_enabled,
        ):
            with pytest.raises(MissingExecutionScope):
                drain.write_batch([])
            with pytest.raises(MissingExecutionScope):
                await peer.start()

    asyncio.run(scenario())


@pytest.mark.parametrize("tracing_enabled", [False, True])
def test_bound_production_calls_preserve_results_in_every_trace_mode(tracing_enabled):
    async def scenario():
        drain = AsyncLogDrain()
        async with Runtime(
            scope_id=f"stage6-bound-{tracing_enabled}",
            tracing_enabled=tracing_enabled,
        ) as runtime:
            runtime.register_owner("log:bound", epoch=1)
            runtime.bind_observation(
                drain, entity_id="log:bound", role="log-drain", owner_epoch=1,
            )
            assert drain.write_batch([]) is None
            return runtime.activity_groups.snapshots()

    groups = asyncio.run(scenario())
    assert (len(groups) == 1) is tracing_enabled


def test_infrastructure_operation_is_owned_by_its_meaningful_entity():
    async def scenario():
        drain = AsyncLogDrain()
        async with Runtime(scope_id="stage6-owner") as runtime:
            runtime.register_owner("peer:log-drain", epoch=1)
            binding = runtime.bind_observation(
                drain, entity_id="peer:log-drain", role="log-drain", owner_epoch=1,
            )
            assert binding.policy_is_authoritative
            execution = runtime.execution_port("peer:log-drain", 1)
            await observe_worker(
                execution, drain.write_batch, [], name="worker:logger.write",
            )
            groups = runtime.activity_groups.snapshots()
            assert len(groups) == 1
            assert groups[0].operation == "AsyncLogDrain.write_batch"
            assert groups[0].owner_entity_id == "peer:log-drain"
            assert groups[0].owner_role == "log-drain"
            runtime.remove_owner("peer:log-drain", 1)

    asyncio.run(scenario())


def test_external_compatibility_component_keeps_legacy_policy_and_trace_parity():
    class CompatibilitySubject(ObservedComponent):
        async def call(self, value):
            return value + 1

        async def _helper(self, value):
            return value * 2

    assert production_policy_for(CompatibilitySubject()) is None

    async def run(enabled):
        runtime = Runtime(scope_id=f"stage6-parity-{enabled}", tracing_enabled=enabled)
        async with runtime:
            subject = CompatibilitySubject()
            result = await subject.call(3), await subject._helper(4)
        return result, runtime.activity_groups.snapshots()

    disabled, disabled_groups = asyncio.run(run(False))
    enabled, enabled_groups = asyncio.run(run(True))
    assert disabled == enabled == (4, 8)
    assert disabled_groups == ()
    assert len(enabled_groups) == 2


def test_production_protocol_modules_have_no_observation_policy_annotations():
    from pathlib import Path

    root = Path(__file__).parents[1] / "webrtc"
    policy_markers = ("@observe(", "@performance(", "@unobserved")
    offenders = []
    for path in root.rglob("*.py"):
        if path.name in {"performance.py", "operation_policy.py"}:
            continue
        text = path.read_text()
        if any(marker in text for marker in policy_markers):
            offenders.append(path.relative_to(root).as_posix())
    assert offenders == []
