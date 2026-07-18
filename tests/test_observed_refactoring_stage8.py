import asyncio
import ast
import json
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "examples"))

from examples.trace_pump import pump_trace_updates
from webrtc import Runtime
from webrtc.observability import FacetOp, ProducerDot
from webrtc.peer_connection import PeerConnection
from webrtc.state_machine import MachineSpec
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection


def test_python_transport_typescript_normalization_and_compact_export_end_to_end():
    peer_id = "p#7"
    ice_id = "ice/α"
    signaling_registry = "s!g"
    media_registry = "media.registry"
    facet_owner = "q!"

    async def produce():
        runtime = Runtime(scope_id="stage8", trace_patch_cadence=60)
        sent = []

        async def send_json(message):
            # This is the same callback contract used by the FastAPI
            # WebSocket integration; pump_trace_updates owns subscription.
            sent.append(message)

        async with runtime:
            pump = asyncio.create_task(pump_trace_updates(runtime, send_json))
            while not sent:
                await asyncio.sleep(0)

            peer = PeerConnection()
            peer.__compose_runtime__(runtime)

            async def gathered():
                return None

            peer.gatherer.start = gathered
            await peer.start()
            await peer.gatherer.set_remote_credentials("remote", "credential")
            await peer.add_transceiver_from_kind(
                RTPCodecKind.Audio, RTPTransceiverDirection.Recvonly,
            )
            await peer.create_offer()

            machine = MachineSpec("attachment-registry", "open", {
                "open": frozenset(),
            }, frozenset())
            for entity_id, role in (
                (peer_id, "peer-connection"),
                (ice_id, "ice-agent"),
                (signaling_registry, "signaling-attachments"),
                (media_registry, "media-attachments"),
                (facet_owner, "infrastructure"),
            ):
                runtime.register_owner(entity_id, role=role)
            runtime.projection.machines.register(signaling_registry, machine)
            runtime.projection.machines.register(media_registry, machine)

            # The production operations above provide all activity/owner rows.
            # These scalar facets are the only focused setup: production IDs
            # cannot deterministically cover short, punctuated, and Unicode
            # identifier shapes in one repeatable privacy assertion.
            for revision, (name, value) in enumerate((
                (f"queue:{peer_id}", peer_id),
                ("ice.ref", ice_id),
                ("signaling.ref", signaling_registry),
                ("media.ref", media_registry),
            ), 1):
                runtime.projection.facets.apply(FacetOp(
                    name, facet_owner, 1, value, revision,
                    ProducerDot(runtime.runtime_epoch, 91, revision), "aggregate",
                    facet_owner, 1, revision, revision,
                ))
            runtime.trace_patch_flush()
            while len(sent) < 2:
                await asyncio.sleep(0)
        while len(sent) < 3:
            await asyncio.sleep(0)
        pump.cancel()
        with suppress(asyncio.CancelledError):
            await pump
        return sent

    delivered = asyncio.run(produce())
    assert delivered[-1]["event"] == "trace:terminal"
    assert delivered[-1]["data"]["terminal"] is True
    result = subprocess.run(
        ["bun", "run", "src/lib/trace.stage8.fixture.ts"],
        cwd=ROOT / "web", input=json.dumps(delivered), text=True,
        capture_output=True, check=True,
    )
    exported = result.stdout

    for raw_id in (peer_id, ice_id, signaling_registry, media_registry, facet_owner):
        assert raw_id not in exported
    assert "attachment-registry (signaling-attachments)" in exported
    assert "attachment-registry (media-attachments)" in exported
    assert "infrastructure, facet-owner" in exported
    assert "PeerConnection.start" in exported
    assert "Agent.set_remote_credentials" in exported
    assert "RTPTransceiver.set_receiver" in exported
    assert "peer-connection" in exported
    assert "ice-agent" in exported
    assert "rtp-transceiver" in exported
    assert "dtls-transport" in exported
    header = exported.splitlines()[1]
    represented = sum(
        int(part.strip().split()[0])
        for part in header.split(":", 1)[1].split(",")
    )
    assert represented == int(header.split()[0])


def test_production_protocols_do_not_reach_into_runtime_observation_or_trace_identity():
    modules = (
        "webrtc/peer_connection.py", "webrtc/dtls/dtlstransport.py",
        "webrtc/dtls/fsm.py", "webrtc/ice/agent.py",
        "webrtc/ice/net/udp_mux.py", "webrtc/srtp/session.py",
        "webrtc/transceiver.py", "webrtc/audio/analyzer.py",
    )
    forbidden_attributes = {
        "observe_transition", "observe_machine", "bind_observation",
        "observe_facets", "observe_snapshot", "observe_worker", "projection",
        "root_context", "trace_id", "scope_id",
    }
    forbidden_metadata = {
        "observerMeta", "observer_meta", "expected_long_running",
        "operation_id", "producer_dot", "source_order",
    }
    violations = []
    for relative in modules:
        tree = ast.parse((ROOT / relative).read_text(), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in forbidden_attributes:
                violations.append(f"{relative}:{node.lineno}:{node.attr}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in forbidden_metadata:
                    violations.append(f"{relative}:{node.lineno}:{node.value}")
    assert not violations, "protocol observation boundary violations: " + ", ".join(violations)
