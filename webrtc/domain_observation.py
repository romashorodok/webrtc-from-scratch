"""Pure Runtime-side translations of immutable, commit-time evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SelectedTransportEvidence:
    selected_pair_id: str
    nomination_entity_id: str
    nomination_revision: int


@dataclass(frozen=True, slots=True)
class PeerEvidence:
    negotiation_generation: int
    role: str | None
    readiness_revisions: tuple[int, int, int, int] | None = None


@dataclass(frozen=True, slots=True)
class IceNominationEvidence:
    selected_pair_id: str
    nomination_entity_id: str
    nomination_revision: int


@dataclass(frozen=True, slots=True)
class DtlsReadinessEvidence:
    handshake_ready: bool
    srtp_rtp_ready: bool
    srtp_rtcp_ready: bool


@dataclass(frozen=True, slots=True)
class SrtpReadinessEvidence:
    protocol: str


@dataclass(frozen=True, slots=True)
class TransceiverEvidence:
    direction: str
    kind: str
    mid: str | None
    codecs: tuple[str, ...]
    sender_id: str | None
    receiver_id: str | None


def capture_selected_transport(
    _subject: Any, _commit: Any, effects: Any,
) -> SelectedTransportEvidence | None:
    if effects is None:
        return None
    transport, nomination = effects
    return SelectedTransportEvidence(
        transport.entity_id, nomination.entity_id, nomination.revision,
    )


def selected_transport(commit: Any, evidence: SelectedTransportEvidence | None):
    if commit.to_state != "ready" or evidence is None:
        return None
    return {
        "selected": True,
        "selected_pair_id": evidence.selected_pair_id,
        "nomination_entity_id": evidence.nomination_entity_id,
        "nomination_revision": evidence.nomination_revision,
    }


def capture_peer(subject: Any, commit: Any, effects: Any) -> PeerEvidence:
    revisions = None
    if commit.to_state == "connected" and getattr(effects, "readiness", None) is not None:
        rtp = subject._dtls_transport._srtp_rtp
        rtcp = subject._dtls_transport._srtp_rtcp
        revisions = (
            subject._ice_transport._runner.snapshot().revision,
            subject._dtls_transport._runner.snapshot().revision,
            rtp._observation_revision(), rtcp._observation_revision(),
        )
    return PeerEvidence(subject.generation, subject._peer_runner.role, revisions)


def peer_lifecycle(_commit: Any, evidence: PeerEvidence):
    values: dict[str, Any] = {
        "negotiation_generation": evidence.negotiation_generation,
        "role": evidence.role,
    }
    if evidence.readiness_revisions is not None:
        revisions = evidence.readiness_revisions
        values.update({
            "selected_transport_revision": revisions[0],
            "dtls_revision": revisions[1],
            "srtp_rtp_revision": revisions[2],
            "srtp_rtcp_revision": revisions[3],
        })
    return values


def capture_peer_configuration(subject: Any) -> dict[str, Any]:
    return {
        "negotiation_generation": subject.generation,
        "role": subject._peer_runner.role,
    }


def signaling(commit: Any, effect: Any):
    snapshot = effect.snapshot
    description_type = effect.description_type
    return {
        "description_type": description_type.value if description_type is not None else None,
        "negotiation_generation": snapshot.negotiation_generation,
        "media_section_count": effect.media_section_count,
        "outcome": "failed" if commit.to_state == "failed" else "committed",
    }


def capture_ice_nomination(_subject: Any, _commit: Any, pair_commit: Any):
    if pair_commit is None:
        return None
    return IceNominationEvidence(
        pair_commit.entity_id, pair_commit.entity_id, pair_commit.revision,
    )


def ice_nomination(commit: Any, evidence: IceNominationEvidence | None):
    if commit.to_state != "nominated" or evidence is None:
        return None
    return {
        "nominated": True,
        "selected_pair_id": evidence.selected_pair_id,
        "nomination_entity_id": evidence.nomination_entity_id,
        "nomination_revision": evidence.nomination_revision,
    }


def capture_dtls(subject: Any, _commit: Any, _effects: Any) -> DtlsReadinessEvidence:
    snapshot = subject.authoritative_snapshot()
    return DtlsReadinessEvidence(
        snapshot.handshake_ready, snapshot.srtp_rtp_ready,
        snapshot.srtp_rtcp_ready,
    )


def dtls_readiness(commit: Any, evidence: DtlsReadinessEvidence):
    if commit.to_state != "connected":
        return None
    return {
        "srtp_keys_ready": evidence.handshake_ready,
        "srtp_rtp_ready": evidence.srtp_rtp_ready,
        "srtp_rtcp_ready": evidence.srtp_rtcp_ready,
    }


def capture_srtp(subject: Any, _commit: Any, _effects: Any):
    return SrtpReadinessEvidence("rtp" if subject.is_rtp else "rtcp")


def srtp_readiness(commit: Any, evidence: SrtpReadinessEvidence):
    return {
        "keys_ready": commit.to_state in {"ready", "draining"},
        "protocol": evidence.protocol,
    }


def capture_transceiver(subject: Any, _commit: Any, _effects: Any) -> TransceiverEvidence:
    negotiated = subject._negotiated
    return TransceiverEvidence(
        negotiated.direction.value, subject._kind.value, negotiated.mid,
        tuple(codec.mime_type for codec in negotiated.codecs),
        getattr(negotiated.sender, "entity_id", None),
        getattr(negotiated.receiver, "entity_id", None),
    )


def transceiver(commit: Any, evidence: TransceiverEvidence):
    return {
        "direction": evidence.direction,
        "kind": evidence.kind,
        "active": commit.to_state == "active",
        "mid": evidence.mid,
        "codecs": ",".join(evidence.codecs),
        "sender_id": evidence.sender_id,
        "receiver_id": evidence.receiver_id,
    }
