"""Complete Runtime-owned operation policy for production components.

This catalog is compiled independently of ``ObservedMeta``. Protocol classes
do not import it and their ``__observations__`` tables are neither read nor
trusted. Methods absent from a production component's allowlist are OFF.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from .performance import (
    CompiledObservation,
    TraceDetail,
    compile_observation_policy,
    compile_runtime_operation_adapter,
)


def _exact(component: str, method: str, group: str) -> CompiledObservation:
    return compile_observation_policy(
        method=method, operation=f"{component}.{method}",
        detail=TraceDetail.EXACT, group=group,
    )


def _aggregate(
    component: str, method: str, group: str, *, workflow: bool = False,
    cadence_ms: int | None = None,
) -> CompiledObservation:
    return compile_observation_policy(
        method=method, operation=f"{component}.{method}",
        detail=TraceDetail.AGGREGATE, group=group, workflow=workflow,
        cadence_ms=cadence_ms,
    )


def _catalog(component: str, entries: Mapping[str, tuple]) -> Mapping[str, CompiledObservation]:
    result = {}
    for method, entry in entries.items():
        mode, group, *options = entry
        if mode == "exact":
            result[method] = _exact(component, method, group)
        else:
            result[method] = _aggregate(
                component, method, group,
                workflow="workflow" in options,
                cadence_ms=next((item for item in options if isinstance(item, int)), None),
            )
    return MappingProxyType(result)


PRODUCTION_OPERATION_ALLOWLIST: Mapping[
    str, Mapping[str, CompiledObservation]
] = MappingProxyType({
    "PeerConnection": _catalog("PeerConnection", {
        "dial": ("exact", "peer.lifecycle"),
        "accept": ("exact", "peer.lifecycle"),
        "start": ("aggregate", "peer.start", "workflow"),
        "aclose": ("exact", "peer.lifecycle"),
        "add_transceiver_from_track": ("exact", "peer.transceiver"),
        "add_transceiver_from_kind": ("exact", "peer.transceiver"),
        "set_local_description": ("exact", "peer.signaling"),
        "set_remote_description": ("exact", "peer.signaling"),
        "create_offer": ("exact", "peer.signaling"),
        "create_answer": ("exact", "peer.signaling"),
    }),
    "Agent": _catalog("Agent", {
        "gather_candidates": ("aggregate", "ice.gather", "workflow"),
        "connect": ("exact", "ice.connectivity"),
        "dial": ("exact", "ice.connectivity"),
        "accept": ("exact", "ice.connectivity"),
        "add_remote_candidate": ("exact", "ice.candidate"),
        "set_remote_credentials": ("exact", "ice.credentials"),
        "fail": ("exact", "ice.lifecycle"),
        "aclose": ("exact", "ice.lifecycle"),
    }),
    "CandidatePairController": _catalog("CandidatePairController", {
        "start_managed": ("aggregate", "ice.connectivity-check", "workflow"),
        "aclose": ("exact", "ice.pair-lifecycle"),
    }),
    "DTLSTransport": _catalog("DTLSTransport", {
        "bind": ("exact", "dtls.lifecycle"),
        "start": ("aggregate", "dtls.handshake", "workflow"),
        "_handshake_workflow": ("aggregate", "dtls.handshake", "workflow"),
        "aclose": ("exact", "dtls.lifecycle"),
    }),
    "FSM": _catalog("FSM", {
        "run": ("aggregate", "dtls.flight", "workflow"),
        "aclose": ("exact", "dtls.lifecycle"),
    }),
    "DTLSConn": MappingProxyType({}),
    "Session": _catalog("Session", {
        "open_stream": ("exact", "srtp.stream"),
        "accept_stream": ("exact", "srtp.stream"),
        "close": ("exact", "srtp.lifecycle"),
    }),
    "RTPReceiver": _catalog("RTPReceiver", {
        "receive": ("exact", "rtp.receiver"),
        "stop": ("exact", "rtp.receiver"),
        "aclose": ("exact", "rtp.receiver"),
    }),
    "RTPTransceiver": _catalog("RTPTransceiver", {
        "bind": ("aggregate", "transceiver.bind", "workflow"),
        "set_prefered_codec": ("exact", "transceiver.configuration"),
        "set_sender": ("exact", "transceiver.configuration"),
        "set_receiver": ("exact", "transceiver.configuration"),
        "set_mid": ("exact", "transceiver.configuration"),
        "apply_negotiated_snapshot": ("exact", "transceiver.negotiation"),
        "stop": ("exact", "transceiver.lifecycle"),
        "aclose": ("exact", "transceiver.lifecycle"),
    }),
    "MultiUDPMux": _catalog("MultiUDPMux", {
        "accept": ("exact", "udp-mux.lifecycle"),
        "bind": ("exact", "udp-mux.binding"),
        "aclose": ("exact", "udp-mux.lifecycle"),
    }),
    "AsyncLogDrain": _catalog("AsyncLogDrain", {
        "start": ("exact", "logging.lifecycle"),
        "write_batch": ("aggregate", "logging.batch"),
        "aclose": ("exact", "logging.lifecycle"),
    }),
    "AudioAnalyzer": MappingProxyType({}),
})


_PRODUCTION_MODULES = MappingProxyType({
    "PeerConnection": "webrtc.peer_connection",
    "Agent": "webrtc.ice.agent",
    "CandidatePairController": "webrtc.ice.agent",
    "DTLSTransport": "webrtc.dtls.dtlstransport",
    "FSM": "webrtc.dtls.fsm",
    "DTLSConn": "webrtc.dtls.fsm",
    "Session": "webrtc.srtp.session",
    "RTPReceiver": "webrtc.transceiver",
    "RTPTransceiver": "webrtc.transceiver",
    "MultiUDPMux": "webrtc.ice.net.udp_mux",
    "AsyncLogDrain": "webrtc.peer_components",
    "AudioAnalyzer": "webrtc.audio.analyzer",
})


HIGH_RATE_OPERATION_DENYLIST: Mapping[str, frozenset[str]] = MappingProxyType({
    "PeerConnection": frozenset({
        "send_rtp_packet", "send_rtp_packets", "send_rtcp_packet",
        "recv_rtcp_feedback", "_run_media_send_pump", "_execute_media_send",
        "_send_media_packet",
    }),
    "CandidatePairController": frozenset({
        "_receive_loop", "_on_inbound_pkt", "_on_inbound_stun",
        "_on_stun_binding_request", "_on_stun_success_response",
    }),
    "DTLSTransport": frozenset({
        "enqueue_record", "dequeue_record", "encrypt_rtp_bytes",
        "encrypt_rtcp_bytes", "write_rtp_bytes", "write_rtcp_bytes",
        "_record_ingress_loop", "_rtp_receive_loop", "_rtcp_receive_loop",
    }),
    "DTLSConn": frozenset({"handle_inbound_record_layers"}),
    "Session": frozenset({
        "encrypt", "decrypt", "_encrypt_crypto", "_decrypt_crypto",
        "write_incoming", "_ordered_crypto",
    }),
    "RTPReceiver": frozenset({"__rtp_reader"}),
    "AsyncLogDrain": frozenset({"_run"}),
    "AudioAnalyzer": frozenset({"analyze_frame", "_compute_spectrum", "_compute_features"}),
})


def is_production_component(subject: object) -> bool:
    subject_type = type(subject)
    return _PRODUCTION_MODULES.get(subject_type.__name__) == subject_type.__module__


def production_policy_for(subject: object) -> Mapping[str, CompiledObservation] | None:
    if not is_production_component(subject):
        return None
    return PRODUCTION_OPERATION_ALLOWLIST[type(subject).__name__]


def operation_inventory() -> Mapping[str, Mapping[str, CompiledObservation]]:
    return PRODUCTION_OPERATION_ALLOWLIST


def is_high_rate_suppressed(component: str, method: str) -> bool:
    return method in HIGH_RATE_OPERATION_DENYLIST.get(component, ())


def install_subject_operation_adapters(subject: object) -> None:
    """Compose one production type with its external allowlisted call adapter.

    Installation is idempotent, lazy (so optional protocol dependencies are
    not imported by Runtime), and deliberately lives outside protocol modules.
    The wrappers consult only the Runtime sidecar registry; domain objects
    receive no trace policy or owner metadata.
    """
    policy_by_method = production_policy_for(subject)
    if policy_by_method is None:
        return
    cls = type(subject)
    for method, policy in policy_by_method.items():
        fn = getattr(cls, method)
        if getattr(fn, "__runtime_operation_adapter__", False):
            continue
        wrapped = compile_runtime_operation_adapter(fn, policy)
        wrapped.__runtime_operation_adapter__ = True
        setattr(cls, method, wrapped)


def install_loaded_production_operation_adapters() -> None:
    """Adapt catalogued protocol types already present in the process.

    This preserves the explicit-composition guard for objects created before a
    Runtime without importing optional protocol modules as a side effect.
    Types loaded later are adapted when ``Runtime.bind_observation`` composes
    their first instance.
    """
    import sys

    for component, module_name in _PRODUCTION_MODULES.items():
        module = sys.modules.get(module_name)
        if module is None:
            continue
        cls = getattr(module, component, None)
        if cls is None:
            continue
        # Avoid constructing or retaining a representative instance.
        for method, policy in PRODUCTION_OPERATION_ALLOWLIST[component].items():
            fn = getattr(cls, method)
            if getattr(fn, "__runtime_operation_adapter__", False):
                continue
            wrapped = compile_runtime_operation_adapter(fn, policy)
            wrapped.__runtime_operation_adapter__ = True
            setattr(cls, method, wrapped)
