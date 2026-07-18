import asyncio
from types import SimpleNamespace

import pytest

from webrtc import Runtime
from webrtc.peer_connection import (
    PeerConnection, _PeerCommand, _PeerCommandPayload,
    _SignalingCommand,
)
from webrtc.session_description import (
    SessionDescription, SessionDescriptionAttr, SessionDescriptionAttrKey,
    SessionDescriptionType,
)
from webrtc.signaling import SignalingState
from webrtc.state_machine import ReplyPort, StaleMachineAccess


class _SnapshotOwner:
    def __init__(self, entity_id: str, machine_type: str, state: str, revision: int):
        self.value = SimpleNamespace(
            entity_id=entity_id, machine_type=machine_type, state=state,
            revision=revision, epoch=1, terminal=state == "closed",
        )

    def snapshot(self):
        return self.value


class _Session:
    def __init__(self, entity_id: str, revision: int):
        self._snapshot = SimpleNamespace(
            entity_id=entity_id, machine_type="srtp-session", state="ready",
            revision=revision, epoch=1, terminal=False,
        )

    def lifecycle_snapshot(self):
        return self._snapshot


class _Gatherer:
    def __init__(self):
        self.started = 0
        self.roles = []

    async def start(self):
        self.started += 1

    async def dial(self):
        self.roles.append("dial")
        return None

    async def accept(self):
        self.roles.append("accept")
        return None

    async def aclose_controllers(self):
        return None

    async def aclose(self):
        return None


class _SelectedTransport:
    def __init__(self, state="ready", revision=2):
        self._runner = _SnapshotOwner(
            "selected-transport:test", "transport", state, revision,
        )

    async def aclose(self):
        return None


class _DtlsTransport:
    def __init__(self, state="connected", revision=4):
        self._runner = _SnapshotOwner(
            "dtls-transport:test", "dtls-transport", state, revision,
        )
        self._srtp_rtp = _Session("srtp:rtp", 2)
        self._srtp_rtcp = _Session("srtp:rtcp", 2)

    async def aclose(self):
        return None


def _replace_stage4_children(peer: PeerConnection) -> None:
    peer.gatherer = _Gatherer()
    peer._ice_transport = _SelectedTransport()
    peer._dtls_transport = _DtlsTransport()


def _facets(runtime: Runtime, entity_id: str) -> dict[str, object]:
    return {
        item.facet_id.rsplit(":", 1)[-1]: item.value
        for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == entity_id
    }


def test_stage4_signaling_commits_descriptions_and_generation_atomically() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-signaling") as runtime:
            async with peer:
                offer = SessionDescription()
                await peer.set_local_description(SessionDescriptionType.Offer, offer)
                first = peer._signaling_runner.signaling
                assert first.state is SignalingState.HaveLocalOffer
                assert first.pending_local.value == offer.marshal()
                assert first.revision == peer._signaling_runner.snapshot().revision == 1
                assert first.negotiation_generation == 1

                answer = SessionDescription()
                await peer.set_remote_description(SessionDescriptionType.Answer, answer)
                second = peer._signaling_runner.signaling
                assert second.state is SignalingState.Stable
                assert second.current_local.value == offer.marshal()
                assert second.current_remote.value == answer.marshal()
                assert second.pending_local is second.pending_remote is None
                assert second.revision == peer._signaling_runner.snapshot().revision == 2

                observed = runtime.projection.machines.get(peer.signaling_entity_id)
                assert observed.state == "stable"
                assert _facets(runtime, peer.signaling_entity_id) == {
                    "description_type": "answer",
                    "negotiation_generation": 1,
                    "media_section_count": 0,
                    "outcome": "committed",
                }
                provenance = [
                    item for item in runtime.projection.facets.snapshots()
                    if item.owner_entity_id == peer.signaling_entity_id
                ]
                assert {item.source_revision for item in provenance} == {observed.revision}

    asyncio.run(scenario())


def test_stage4_stale_signaling_command_cannot_overwrite_newer_offer() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-signaling-stale"):
            async with peer:
                first, stale = ReplyPort(), ReplyPort()
                offer1, offer2 = SessionDescription(), SessionDescription()
                command1 = peer._command(
                    peer._signaling_runner, _SignalingCommand.SET_LOCAL,
                    (SessionDescriptionType.Offer, offer1), reply=first,
                )
                command2 = peer._command(
                    peer._signaling_runner, _SignalingCommand.SET_LOCAL,
                    (SessionDescriptionType.Offer, offer2), reply=stale,
                )
                peer._signaling_runner.try_submit(command1)
                peer._signaling_runner.try_submit(command2)
                await first.wait()
                with pytest.raises(StaleMachineAccess):
                    await stale.wait()
                assert (
                    peer._signaling_runner.signaling.pending_local.value
                    == offer1.marshal()
                )
                assert peer._signaling_runner.snapshot().revision == 1

    asyncio.run(scenario())


def test_stage4_peer_connected_requires_exact_child_revisions() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-readiness") as runtime:
            async with peer:
                selected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.TRANSPORT_SELECTED,
                    _PeerCommandPayload(), cause_id="nomination:3", reply=selected,
                ))
                await selected.wait()
                assert peer._peer_runner.snapshot().state == "connecting"

                stale = ReplyPort()
                ready = peer._peer_readiness_snapshot()
                stale_readiness = type(ready)(
                    type(ready.selected_transport)(
                        ready.selected_transport.entity_id,
                        ready.selected_transport.epoch,
                        ready.selected_transport.revision - 1,
                        ready.selected_transport.required_state,
                    ),
                    ready.dtls, ready.srtp_rtp, ready.srtp_rtcp,
                )
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.CHILDREN_READY,
                    _PeerCommandPayload(readiness=stale_readiness),
                    cause_id="dtls:4", reply=stale,
                ))
                with pytest.raises(StaleMachineAccess):
                    await stale.wait()
                assert peer._peer_runner.snapshot().state == "connecting"

                ready = peer._peer_readiness_snapshot()
                connected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.CHILDREN_READY,
                    _PeerCommandPayload(readiness=ready),
                    cause_id="dtls:4", reply=connected,
                ))
                commit = await connected.wait()
                assert commit.to_state == "connected"
                observed = runtime.projection.machines.get(peer.entity_id)
                assert observed.state == "connected"
                facets = _facets(runtime, peer.entity_id)
                provenance = [
                    item for item in runtime.projection.facets.snapshots()
                    if item.owner_entity_id == peer.entity_id
                ]
                assert {item.source_revision for item in provenance} == {observed.revision}
                assert facets["selected_transport_revision"] == 2
                assert facets["dtls_revision"] == 4
                assert facets["srtp_rtp_revision"] == 2
                assert facets["srtp_rtcp_revision"] == 2

    asyncio.run(scenario())


def test_stage4_readiness_is_revalidated_after_before_commit_checkpoint() -> None:
    async def scenario() -> None:
        from webrtc.state_machine import TransitionController

        peer = PeerConnection()
        _replace_stage4_children(peer)
        controller = TransitionController(timeout=1)
        async with Runtime(scope_id="stage4-readiness-race"):
            async with peer:
                peer._peer_runner.controller = controller
                selected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.TRANSPORT_SELECTED,
                    _PeerCommandPayload(), reply=selected,
                ))
                await selected.wait()
                readiness = peer._peer_readiness_snapshot()
                controller.pause_at("peer", to_state="connected", phase="before_commit")
                reply = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.CHILDREN_READY,
                    _PeerCommandPayload(readiness=readiness), reply=reply,
                ))
                checkpoint = await controller.wait_until(
                    "peer", "connected", phase="before_commit",
                )
                peer._dtls_transport._runner.value.epoch += 1
                peer._dtls_transport._runner.value.revision += 1
                controller.release(checkpoint.checkpoint_id)
                with pytest.raises(StaleMachineAccess):
                    await reply.wait()
                assert peer._peer_runner.snapshot().state == "connecting"

    asyncio.run(scenario())


def test_stage4_connected_facets_use_committed_readiness_effect() -> None:
    async def scenario() -> None:
        from webrtc.state_machine import TransitionController

        peer = PeerConnection()
        _replace_stage4_children(peer)
        controller = TransitionController(timeout=1)
        async with Runtime(scope_id="stage4-exact-facets") as runtime:
            async with peer:
                peer._peer_runner.controller = controller
                selected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.TRANSPORT_SELECTED,
                    _PeerCommandPayload(), reply=selected,
                ))
                await selected.wait()
                readiness = peer._peer_readiness_snapshot()
                controller.pause_at("peer", to_state="connected", phase="after_commit")
                reply = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.CHILDREN_READY,
                    _PeerCommandPayload(readiness=readiness), reply=reply,
                ))
                checkpoint = await controller.wait_until(
                    "peer", "connected", phase="after_commit",
                )
                peer._dtls_transport._runner.value.revision += 9
                controller.release(checkpoint.checkpoint_id)
                await reply.wait()
                assert _facets(runtime, peer.entity_id)["dtls_revision"] == 4

    asyncio.run(scenario())


def test_stage4_signaling_defensively_captures_caller_sdp() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-sdp-copy"):
            async with peer:
                offer = SessionDescription()
                offer.add_attribute(SessionDescriptionAttr(
                    SessionDescriptionAttrKey.Group, "BUNDLE original",
                ))
                await peer.set_local_description(SessionDescriptionType.Offer, offer)
                committed = peer._signaling_runner.signaling.pending_local.value
                offer.add_attribute(SessionDescriptionAttr(
                    SessionDescriptionAttrKey.Group, "BUNDLE mutated",
                ))
                assert peer._signaling_runner.signaling.pending_local.value == committed
                assert b"mutated" not in committed

    asyncio.run(scenario())


def test_stage4_concurrent_role_intents_have_one_typed_winner() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-role-race") as runtime:
            async with peer:
                revision = peer._peer_runner.snapshot().revision
                results = await asyncio.gather(
                    peer.dial(), peer.accept(), return_exceptions=True,
                )
                assert sum(result is None for result in results) == 1
                assert sum(isinstance(result, StaleMachineAccess) for result in results) == 1
                assert peer.gatherer.roles in (["dial"], ["accept"])
                assert "_role" not in peer.__dict__
                assert peer._peer_runner.snapshot().revision == revision
                assert all(
                    item.from_state != item.to_state
                    for item in runtime.projection.machines.transition_snapshots()
                    if item.entity_id == peer.entity_id
                )

    asyncio.run(scenario())


def test_stage4_repeated_role_intent_is_idempotent() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-role-idempotent"):
            async with peer:
                await peer.dial()
                selected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.TRANSPORT_SELECTED,
                    _PeerCommandPayload(), reply=selected,
                ))
                await selected.wait()
                connected = ReplyPort()
                await peer._peer_runner.submit(peer._command(
                    peer._peer_runner, _PeerCommand.CHILDREN_READY,
                    _PeerCommandPayload(readiness=peer._peer_readiness_snapshot()),
                    reply=connected,
                ))
                await connected.wait()
                assert peer.state == "connected"
                await peer.dial()
                assert peer.gatherer.roles == ["dial"]
                with pytest.raises(StaleMachineAccess, match="cannot accept"):
                    await peer.accept()

    asyncio.run(scenario())


def test_stage4_negotiation_generation_has_one_signaling_authority() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-generation") as runtime:
            async with peer:
                await peer.set_local_description(
                    SessionDescriptionType.Offer, SessionDescription(),
                )
                await peer.dial()
                assert peer.generation == 1
                assert (
                    _facets(runtime, peer.entity_id)["negotiation_generation"]
                    == _facets(runtime, peer.signaling_entity_id)[
                        "negotiation_generation"
                    ]
                    == 1
                )

    asyncio.run(scenario())


def test_stage4_create_offer_rejects_changed_signaling_snapshot(monkeypatch) -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        entered, release = asyncio.Event(), asyncio.Event()

        async def paused(_transceivers):
            entered.set()
            await release.wait()
            return SessionDescription()

        monkeypatch.setattr(peer, "_generate_unmatched_sdp", paused)
        async with Runtime(scope_id="stage4-offer-stable"):
            async with peer:
                creating = asyncio.create_task(peer.create_offer())
                await entered.wait()
                await peer.set_local_description(
                    SessionDescriptionType.Offer, SessionDescription(),
                )
                release.set()
                with pytest.raises(StaleMachineAccess):
                    await creating

    asyncio.run(scenario())


def test_stage4_failure_is_one_causal_command_and_terminal_reconciliation() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-failure") as runtime:
            await peer.__aenter__()
            error = LookupError("protocol failed")
            peer._peer_runner.try_submit(peer._command(
                peer._peer_runner, _PeerCommand.FAIL,
                _PeerCommandPayload(reason="dtls", error=error),
                cause_id="dtls-failure:7",
            ))
            await asyncio.wait_for(peer.wait_closed(), 1.0)
            transitions = [
                item for item in runtime.projection.machines.transition_snapshots()
                if item.entity_id == peer.entity_id
            ]
            assert [item.to_state for item in transitions][-3:] == [
                "failed", "closing", "closed",
            ]
            assert all(
                item.cause_id == "dtls-failure:7" for item in transitions[-3:]
            )
            assert peer._peer_runner.commands.capacity == 16
            assert peer._signaling_runner.commands.capacity == 16
            assert "_failure_close_task" not in peer.__dict__
            assert peer.closed

    asyncio.run(scenario())


def test_stage4_close_and_failure_callers_share_terminal_completion() -> None:
    async def scenario() -> None:
        peer = PeerConnection()
        _replace_stage4_children(peer)
        async with Runtime(scope_id="stage4-close-race"):
            await peer.__aenter__()
            terminal = peer._terminal_completion()
            error = RuntimeError("racing failure")
            peer._peer_runner.try_submit(peer._command(
                peer._peer_runner, _PeerCommand.FAIL,
                _PeerCommandPayload(
                    completion=terminal, reason="dtls", error=error,
                ),
                cause_id="dtls-failure:race",
            ))
            results = await asyncio.gather(
                peer.aclose("caller-one"), peer.aclose("caller-two"),
                return_exceptions=True,
            )
            assert results == [None, None]
            assert peer.closed
            assert peer._close_completion is terminal

    asyncio.run(scenario())
