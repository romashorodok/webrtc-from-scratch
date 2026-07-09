from __future__ import annotations

import asyncio
import json
import socket
from unittest.mock import patch

from helpers import (
    PeerDriver,
    assert_matches_baseline,
    build_summary_from_baseline,
    load_baseline,
    media_credentials,
    wait_for_conditions,
)
from webrtc.ice import net
from webrtc.lifecycle import PeerCondition
from webrtc.peer_connection import ICEGatherer, PeerConnection
from webrtc.session_description import SessionDescriptionType
from webrtc.tracing import PerformanceRecorder, use_performance_recorder
from webrtc.transceiver import RTPCodecKind, RTPTransceiverDirection


BASELINE = load_baseline("pc_e2e_loopback_ice_dtls_srtp.json")
READY_CONDITIONS = [
    PeerCondition.ICE_CANDIDATE_PAIR_SUCCEEDED,
    PeerCondition.ICE_NOMINATED,
    PeerCondition.NOMINATED_TRANSPORT_READY,
    PeerCondition.DTLS_HANDSHAKE_COMPLETE,
    PeerCondition.SRTP_READY,
]


def test_peer_connection_loopback_ice_dtls_srtp_perf(record_property):
    loopback_interfaces = net.interface_factory(
        net.InterfaceProvider.PSUTIL,
        [socket.AF_INET],
        True,
    )
    loopback_interfaces = [
        interface
        for interface in loopback_interfaces
        if str(interface.address).startswith("127.")
    ]
    assert loopback_interfaces, "no IPv4 loopback interface available for E2E test"

    original_create_agent = ICEGatherer._ICEGatherer__create_agent

    async def create_loopback_agent(self, port=0, interfaces=None):
        return await original_create_agent(self, port, loopback_interfaces)

    with patch.object(ICEGatherer, "_ICEGatherer__create_agent", create_loopback_agent):
        summary, cleanup, protocol_error, recorder = asyncio.run(_run_loopback_scenario())

    record_property("performance_summary", json.dumps(summary, sort_keys=True))

    assert cleanup == {
        "offerer_closed": True,
        "answerer_closed": True,
        "offerer_active_routines": 0,
        "answerer_active_routines": 0,
    }
    assert_matches_baseline(recorder, summary, BASELINE)
    assert protocol_error is None, protocol_error
    assert summary["status"] == "completed"


async def _run_loopback_scenario():
    recorder = PerformanceRecorder()
    offerer = PeerDriver(PeerConnection(), "pc-e2e-offerer")
    answerer = PeerDriver(PeerConnection(), "pc-e2e-answerer")
    protocol_error: str | None = None

    with use_performance_recorder(recorder):
        try:
            async with offerer, answerer:
                await _negotiate_loopback(offerer, answerer, recorder)
        except BaseException as exc:
            protocol_error = f"{exc.__class__.__name__}: {exc}"

    summary = build_summary_from_baseline(recorder, BASELINE)

    cleanup = {
        "offerer_closed": offerer.closed,
        "answerer_closed": answerer.closed,
        "offerer_active_routines": offerer.active_routines_after_close,
        "answerer_active_routines": answerer.active_routines_after_close,
    }
    return summary, cleanup, protocol_error, recorder


async def _negotiate_loopback(
    offerer: PeerDriver,
    answerer: PeerDriver,
    recorder: PerformanceRecorder,
) -> None:
    await _setup_synthetic_audio(offerer)
    await _setup_synthetic_audio(answerer)
    await offerer.call(lambda peer: peer.start())
    await answerer.call(lambda peer: peer.start())
    await asyncio.gather(
        wait_for_conditions(
            offerer,
            [PeerCondition.ICE_GATHERING_COMPLETE],
            timeout=5.0,
        ),
        wait_for_conditions(
            answerer,
            [PeerCondition.ICE_GATHERING_COMPLETE],
            timeout=5.0,
        ),
    )

    offer = await offerer.call(lambda peer: peer.pc.create_offer())
    await offerer.call(
        lambda peer: peer.pc.set_local_description(
            SessionDescriptionType.Offer,
            offer,
        )
    )

    await _set_remote_credentials(answerer, offer)
    await answerer.call(
        lambda peer: peer.pc.set_remote_description(
            SessionDescriptionType.Offer,
            offer,
        )
    )

    answer = await answerer.call(lambda peer: peer.pc.create_answer())
    await answerer.call(
        lambda peer: peer.pc.set_local_description(
            SessionDescriptionType.Answer,
            answer,
        )
    )

    await _set_remote_credentials(offerer, answer)
    await offerer.call(
        lambda peer: peer.pc.set_remote_description(
            SessionDescriptionType.Answer,
            answer,
        )
    )

    await _exchange_candidates(
        offerer_candidates=await _local_candidate_strings(offerer),
        answerer_candidates=await _local_candidate_strings(answerer),
        offerer=offerer,
        answerer=answerer,
    )
    await _wait_for_event_count(recorder, "ice.candidate_pair.created", 2, timeout=5.0)
    await answerer.call(lambda peer: peer.accept())
    await offerer.call(lambda peer: peer.dial())

    await asyncio.gather(
        wait_for_conditions(offerer, READY_CONDITIONS, timeout=15.0),
        wait_for_conditions(answerer, READY_CONDITIONS, timeout=15.0),
    )


async def _setup_synthetic_audio(peer: PeerDriver) -> None:
    await peer.call(
        lambda context: context.pc.add_transceiver_from_kind(
            RTPCodecKind.Audio,
            RTPTransceiverDirection.Sendrecv,
        )
    )


async def _local_candidate_strings(peer: PeerDriver) -> list[str]:
    candidates = await peer.call(lambda context: context.pc.gatherer.get_local_candidates())
    return [candidate.to_ice_str() for candidate in candidates or []]


async def _set_remote_credentials(peer: PeerDriver, desc) -> None:
    for ufrag, pwd in media_credentials(desc):
        await peer.call(
            lambda context, ufrag=ufrag, pwd=pwd: context.set_remote_credentials(
                ufrag,
                pwd,
            )
        )


async def _exchange_candidates(
    *,
    offerer_candidates: list[str],
    answerer_candidates: list[str],
    offerer: PeerDriver,
    answerer: PeerDriver,
) -> None:
    assert offerer_candidates, "offer SDP did not contain ICE candidates"
    assert answerer_candidates, "answer SDP did not contain ICE candidates"

    for candidate in offerer_candidates:
        await answerer.call(
            lambda context, candidate=candidate: context.add_remote_candidate(candidate)
        )
    for candidate in answerer_candidates:
        await offerer.call(
            lambda context, candidate=candidate: context.add_remote_candidate(candidate)
        )


async def _wait_for_event_count(
    recorder: PerformanceRecorder,
    name: str,
    min_count: int,
    *,
    timeout: float,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        count = sum(1 for event in recorder.events() if event.name == name)
        if count >= min_count:
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(f"timed out waiting for {min_count} {name} events")
        await asyncio.sleep(0.01)
