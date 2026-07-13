import asyncio
from types import SimpleNamespace

import pytest

from webrtc.dtls.dtlstransport import DTLSTransport
from webrtc.ice.agent import Agent, CandidatePairState
from webrtc.lifecycle import ICECondition, PeerCondition, TransportCondition
from webrtc.peer_connection import ICEGatherer, PeerConnection


class PairRegistry:
    def __init__(self, pairs):
        self._pairs = pairs

    def get_pair_list(self):
        return self._pairs


class ControllerRegistry:
    def __init__(self, controllers):
        self._controllers = controllers

    def controllers(self):
        return self._controllers


class FakeWaiter:
    def __init__(self):
        self.calls = []

    async def wait(self, condition, timeout):
        self.calls.append((condition, timeout))


def make_agent_wait_subject(*, gathering_complete=False, pair_state=None, nominated=False):
    agent = Agent.__new__(Agent)
    agent._gathering_complete = asyncio.Event()
    if gathering_complete:
        agent._gathering_complete.set()
    agent._pair_registry = PairRegistry(
        {"pair": SimpleNamespace(state=pair_state)} if pair_state is not None else {}
    )
    agent._controller_registry = ControllerRegistry(
        [SimpleNamespace(nominated=nominated)] if nominated else []
    )
    return agent


@pytest.mark.parametrize(
    "condition,kwargs",
    [
        (ICECondition.GATHERING_COMPLETE, {"gathering_complete": True}),
        (
            ICECondition.CANDIDATE_PAIR_SUCCEEDED,
            {"pair_state": CandidatePairState.SUCCEEDED},
        ),
        (ICECondition.NOMINATED, {"nominated": True}),
        (ICECondition.NOMINATED_TRANSPORT_READY, {"nominated": True}),
    ],
)
def test_agent_wait_conditions(condition, kwargs):
    async def scenario():
        agent = make_agent_wait_subject(**kwargs)
        await agent.wait(condition, timeout=0.05)

    asyncio.run(scenario())


def test_agent_wait_times_out_for_unmet_condition():
    async def scenario():
        agent = make_agent_wait_subject()
        with pytest.raises(asyncio.TimeoutError):
            await agent.wait(ICECondition.NOMINATED, timeout=0.01)

    asyncio.run(scenario())


def test_agent_wait_requires_explicit_timeout():
    async def scenario():
        agent = make_agent_wait_subject(gathering_complete=True)
        with pytest.raises(ValueError):
            await agent.wait(ICECondition.GATHERING_COMPLETE, timeout=None)

    asyncio.run(scenario())


def test_ice_gatherer_wait_delegates_to_agent():
    async def scenario():
        gatherer = ICEGatherer()
        fake_agent = FakeWaiter()
        gatherer._ICEGatherer__agent = fake_agent

        await gatherer.wait(ICECondition.NOMINATED, timeout=1.5)

        assert fake_agent.calls == [(ICECondition.NOMINATED, 1.5)]

    asyncio.run(scenario())


def test_ice_gatherer_wait_requires_explicit_timeout():
    async def scenario():
        gatherer = ICEGatherer()
        gatherer._ICEGatherer__agent = FakeWaiter()

        with pytest.raises(ValueError):
            await gatherer.wait(ICECondition.NOMINATED, timeout=None)

    asyncio.run(scenario())


def make_dtls_wait_subject(*, handshake=False, rtp=False, rtcp=False):
    transport = DTLSTransport.__new__(DTLSTransport)
    transport._DTLSTransport__handshake_complete = asyncio.Event()
    transport._DTLSTransport__handshake_failed = None
    transport._DTLSTransport__srtp_rtp_lock = asyncio.Event()
    transport._DTLSTransport__srtp_rtcp_lock = asyncio.Event()
    transport._srtp_rtp = object() if rtp else None
    transport._srtp_rtcp = object() if rtcp else None
    if handshake:
        transport._DTLSTransport__handshake_complete.set()
    if rtp:
        transport._DTLSTransport__srtp_rtp_lock.set()
    if rtcp:
        transport._DTLSTransport__srtp_rtcp_lock.set()
    return transport


def test_dtls_wait_handshake_complete():
    async def scenario():
        transport = make_dtls_wait_subject(handshake=True)
        await transport.wait(TransportCondition.HANDSHAKE_COMPLETE, timeout=0.05)

    asyncio.run(scenario())


def test_dtls_wait_srtp_ready_requires_rtp_and_rtcp_sessions():
    async def scenario():
        transport = make_dtls_wait_subject(rtp=True, rtcp=True)
        await transport.wait(TransportCondition.SRTP_READY, timeout=0.05)

    asyncio.run(scenario())


def test_dtls_wait_srtp_ready_does_not_pass_with_only_rtp_session():
    async def scenario():
        transport = make_dtls_wait_subject(rtp=True, rtcp=False)
        with pytest.raises(asyncio.TimeoutError):
            await transport.wait(TransportCondition.SRTP_READY, timeout=0.01)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "condition,expected_target,expected_condition",
    [
        (
            PeerCondition.ICE_GATHERING_COMPLETE,
            "ice",
            ICECondition.GATHERING_COMPLETE,
        ),
        (
            PeerCondition.ICE_CANDIDATE_PAIR_SUCCEEDED,
            "ice",
            ICECondition.CANDIDATE_PAIR_SUCCEEDED,
        ),
        (PeerCondition.ICE_NOMINATED, "ice", ICECondition.NOMINATED),
        (
            PeerCondition.DTLS_HANDSHAKE_COMPLETE,
            "dtls",
            TransportCondition.HANDSHAKE_COMPLETE,
        ),
        (PeerCondition.SRTP_READY, "dtls", TransportCondition.SRTP_READY),
    ],
)
def test_peer_connection_wait_routes_conditions(
    condition, expected_target, expected_condition
):
    async def scenario():
        pc = PeerConnection.__new__(PeerConnection)
        pc.gatherer = FakeWaiter()
        pc._dtls_transport = FakeWaiter()
        pc._transport_ready = asyncio.Event()

        await pc.wait(condition, timeout=2.0)

        target = pc.gatherer if expected_target == "ice" else pc._dtls_transport
        assert target.calls == [(expected_condition, 2.0)]

    asyncio.run(scenario())


def test_peer_connection_wait_nominated_transport_ready():
    async def scenario():
        pc = PeerConnection.__new__(PeerConnection)
        pc.gatherer = FakeWaiter()
        pc._dtls_transport = FakeWaiter()
        pc._transport_ready = asyncio.Event()

        pc._transport_ready.set()
        await pc.wait(PeerCondition.NOMINATED_TRANSPORT_READY, timeout=0.05)

    asyncio.run(scenario())


def test_peer_connection_wait_requires_explicit_timeout():
    async def scenario():
        pc = PeerConnection.__new__(PeerConnection)
        pc.gatherer = FakeWaiter()
        pc._dtls_transport = FakeWaiter()
        pc._transport_ready = asyncio.Event()

        with pytest.raises(ValueError):
            await pc.wait(PeerCondition.SRTP_READY, timeout=None)

    asyncio.run(scenario())


def test_peer_connection_wait_srtp_ready_delegates_to_dtls_transport():
    async def scenario():
        pc = PeerConnection.__new__(PeerConnection)
        pc.gatherer = FakeWaiter()
        pc._dtls_transport = FakeWaiter()
        pc._transport_ready = asyncio.Event()

        await pc.wait(PeerCondition.SRTP_READY, timeout=3.0)

        assert pc._dtls_transport.calls == [(TransportCondition.SRTP_READY, 3.0)]

    asyncio.run(scenario())


def test_peer_connection_srtp_wait_requires_explicit_timeout():
    async def scenario():
        pc = PeerConnection.__new__(PeerConnection)
        pc.gatherer = FakeWaiter()
        pc._dtls_transport = FakeWaiter()
        pc._transport_ready = asyncio.Event()

        with pytest.raises(ValueError):
            await pc.wait(PeerCondition.SRTP_READY, timeout=None)

    asyncio.run(scenario())
