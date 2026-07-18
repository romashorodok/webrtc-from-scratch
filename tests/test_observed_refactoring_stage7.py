import ast
import asyncio
import inspect
from pathlib import Path

import pytest

from webrtc.operation_policy import PRODUCTION_OPERATION_ALLOWLIST
from webrtc.peer_components import AsyncLogDrain
from webrtc.performance import ObservedComponent, ObservedMeta
from webrtc.runtime import Runtime


_PRODUCTION_CLASSES = {
    "webrtc/peer_connection.py": {"PeerConnection"},
    "webrtc/ice/agent.py": {"Agent", "CandidatePairController"},
    "webrtc/dtls/dtlstransport.py": {"DTLSTransport"},
    "webrtc/dtls/fsm.py": {"FSM", "DTLSConn"},
    "webrtc/srtp/session.py": {"Session"},
    "webrtc/transceiver.py": {"RTPReceiver", "RTPTransceiver"},
    "webrtc/ice/net/udp_mux.py": {"MultiUDPMux"},
    "webrtc/peer_components.py": {"AsyncLogDrain"},
    "webrtc/audio/analyzer.py": {"AudioAnalyzer"},
}


def test_stage7_production_inventory_has_no_observed_base_or_domain_markers():
    root = Path(__file__).parents[1]
    found = set()
    forbidden_imports = {"ObservedComponent", "ObservedMeta"}
    forbidden_decorators = {
        "observe", "performance", "event_loop", "worker", "task", "unobserved",
    }

    for relative, expected_classes in _PRODUCTION_CLASSES.items():
        tree = ast.parse((root / relative).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith(
                "performance"
            ):
                assert forbidden_imports.isdisjoint(alias.name for alias in node.names)
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                name = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(name, ast.Name):
                    assert name.id not in forbidden_decorators
                elif isinstance(name, ast.Attribute):
                    assert name.attr not in forbidden_decorators

        classes = {
            node.name: node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name in expected_classes
        }
        assert set(classes) == expected_classes
        found.update(classes)
        for node in classes.values():
            assert all(
                not (isinstance(base, ast.Name) and base.id == "ObservedComponent")
                for base in node.bases
            )
            assert not any(keyword.arg == "metaclass" for keyword in node.keywords)

    assert found == set(PRODUCTION_OPERATION_ALLOWLIST)


def test_stage7_loaded_production_type_has_no_metaclass_or_policy_metadata():
    assert not issubclass(AsyncLogDrain, ObservedComponent)
    assert not isinstance(AsyncLogDrain, ObservedMeta)
    assert "__observations__" not in AsyncLogDrain.__dict__
    assert "__worker_owner_binding__" not in AsyncLogDrain.__dict__


@pytest.mark.parametrize("tracing_enabled", [False, True])
def test_stage7_external_adapter_preserves_sync_return_semantics(tracing_enabled):
    async def scenario():
        drain = AsyncLogDrain()
        async with Runtime(
            scope_id=f"stage7-call-{tracing_enabled}",
            tracing_enabled=tracing_enabled,
        ) as runtime:
            runtime.register_owner("stage7:log", epoch=1)
            runtime.bind_observation(
                drain, entity_id="stage7:log", role="log-drain", owner_epoch=1,
            )
            assert drain.write_batch([]) is None
            groups = runtime.activity_groups.snapshots()
            runtime.remove_owner("stage7:log", 1)
        return groups

    groups = asyncio.run(scenario())
    if tracing_enabled:
        assert [(group.operation, group.owner_entity_id) for group in groups] == [
            ("AsyncLogDrain.write_batch", "stage7:log")
        ]
    else:
        assert groups == ()


def test_stage7_peer_start_remains_an_ordinary_coroutine_with_trace_parity():
    from webrtc.peer_connection import PeerConnection

    async def run(enabled):
        async with Runtime(
            scope_id=f"stage7-peer-{enabled}", tracing_enabled=enabled,
        ) as runtime:
            peer = PeerConnection()
            peer.__compose_runtime__(runtime)

            async def start_gatherer():
                return None

            peer.gatherer.start = start_gatherer
            call = peer.start()
            assert inspect.iscoroutine(call)
            assert not isinstance(call, asyncio.Task)
            result = await call
            groups = runtime.activity_groups.snapshots()
            for handle in peer._machine_handles:
                handle.cancel()
            await asyncio.gather(
                *(handle.wait() for handle in peer._machine_handles),
                return_exceptions=True,
            )
        return result, groups, peer.entity_id

    disabled_result, disabled_groups, _ = asyncio.run(run(False))
    enabled_result, enabled_groups, peer_entity_id = asyncio.run(run(True))
    assert disabled_result is enabled_result is None
    assert disabled_groups == ()
    assert any(
        group.operation == "PeerConnection.start"
        and group.owner_entity_id == peer_entity_id
        for group in enabled_groups
    )
