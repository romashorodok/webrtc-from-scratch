from . import dtls
from . import ice

import itertools
from typing import Callable

from .transceiver import RTPTransceiver, RTPTransceiverDirection, MediaCaps
from .session_description import (
    SessionDescription,
    SessionDescriptionAttr,
    SessionDescriptionAttrKey,
    MediaDescription,
)
from .peer_connection_types import (
    ConnectionRole,
    ICEParameters,
    RTPComponent,
)


class MediaSection:
    def __init__(
        self,
        mid: str,
        transceivers: list[RTPTransceiver],
    ) -> None:
        self.id = mid
        self.rid = mid
        self.transceivers = transceivers
        self.data = False


def flatten_media_section_transceivers(media_sections: list[MediaSection]):
    transivers = map(lambda t: t.transceivers, media_sections)
    return list(itertools.chain(*transivers))


def add_candidate_to_media_descriptions(
    media: MediaDescription,
    candidates: list[ice.CandidateProtocol] | None,
):
    def append_candidate_if_new(
        candidate: ice.CandidateProtocol, attributes: list[SessionDescriptionAttr]
    ):
        nonlocal media

        for attr in attributes:
            if attr.value and attr.value == candidate.to_ice_str():
                return

        media.add_attribute(
            SessionDescriptionAttr(
                SessionDescriptionAttrKey.Candidate, candidate.to_ice_str()
            )
        )

    if not candidates:
        return

    for candidate in candidates:
        candidate.set_component(RTPComponent.RTP)
        append_candidate_if_new(candidate, media.attributes)

        candidate.set_component(RTPComponent.RTCP)
        append_candidate_if_new(candidate, media.attributes)

        candidate.set_component(RTPComponent.RTP)

    for attr in media.attributes:
        if attr.key == SessionDescriptionAttrKey.EndOfCandidates.value:
            return

    media.add_attribute(
        SessionDescriptionAttr(SessionDescriptionAttrKey.EndOfCandidates)
    )


def add_sender_sdp(desc: MediaDescription, media_section: MediaSection):
    for t in media_section.transceivers:
        sender = t.sender
        if sender is None:
            continue

        track = sender.track
        if track is None:
            continue

        send_params = sender.get_parameters()
        if not send_params:
            print("empty sender encodings. Possible empty track")
            continue

        for encoding in send_params.encodings:
            desc.add_media_source(
                encoding.ssrc, track.stream_id, track.stream_id, track.id
            )
            desc.add_attribute(
                SessionDescriptionAttr(f"msid:{track.stream_id} {track.id}")
            )

        if send_params.encodings:
            for encoding in send_params.encodings:
                desc.add_attribute(
                    SessionDescriptionAttr(
                        SessionDescriptionAttrKey.RID, f"{encoding.rid} send"
                    )
                )

        break


def add_transceiver_media_description(
    desc: SessionDescription,
    media_section: MediaSection,
    should_add_candidates: bool,
    fingerprints: list[dtls.Fingerprint],
    mid: str,
    ice_params: ICEParameters,
    candidates: list[ice.CandidateProtocol] | None,
    role: ConnectionRole,
    caps: MediaCaps,
) -> bool:
    transceivers = media_section.transceivers
    if len(transceivers) < 1:
        return False

    t = transceivers[0]

    if t.mid is None:
        return False

    codecs = t.get_codecs()
    if codecs is None:
        return False

    media = MediaDescription(
        media=t.kind.value,
        port=9,
        protocols=["UDP", "TLS", "RTP", "SAVPF"],
    )

    media.add_attribute(
        SessionDescriptionAttr(
            SessionDescriptionAttrKey.ConnectionSetup,
            role.value,
        )
    )
    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.MID, mid))
    media.add_attribute(SessionDescriptionAttr("ice-ufrag", ice_params.local_ufrag))
    media.add_attribute(SessionDescriptionAttr("ice-pwd", ice_params.local_pwd))

    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPMux))
    media.add_attribute(SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPRsize))

    for codec in codecs:
        media.add_codec(codec)
        for feedback in codec.rtcp_feedbacks:
            media.add_rtcp_feedback(codec, feedback)

    directions = list[RTPTransceiverDirection]()

    if t.sender:
        directions.append(RTPTransceiverDirection.Sendonly)
    if t.receiver:
        directions.append(RTPTransceiverDirection.Recvonly)

    media.direction = t.direction

    # ext_map_stub = [
    #     ExtMap(value=1, uri="urn:ietf:params:rtp-hdrext:sdes:mid"),
    #     ExtMap(
    #         value=3, uri="http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
    #     ),
    # ]
    # negotiated_parameters = caps.get_rtp_parameters_by_kind(t.kind, directions)
    # for rtp_ext in negotiated_parameters.header_extensions:
    # for rtp_ext in ext_map_stub:
    #     media.add_attribute(SessionDescriptionAttr(rtp_ext.marshal()))

    if RTPTransceiverDirection.Recvonly in directions:
        media.add_attribute(
            SessionDescriptionAttr(
                SessionDescriptionAttrKey.RID, f"{media_section.rid} recv"
            )
        )

    # if media_section.rid_map:
    #     for rid in media_section.rid_map.items():
    #         media.add_attribute(
    #             SessionDescriptionAttr(SessionDescriptionAttrKey.RID, f"{rid} recv")
    #         )

    add_sender_sdp(media, media_section)

    print("Current direction ", t.direction.value)
    media.add_attribute(SessionDescriptionAttr(t.direction.value))

    for fingerprint in fingerprints:
        media.add_attribute(
            SessionDescriptionAttr(
                "fingerprint", fingerprint.algorithm + " " + fingerprint.value.upper()
            )
        )

    if should_add_candidates and candidates:
        add_candidate_to_media_descriptions(media, candidates)

    desc.add_media_description(media)

    return True


def bundle_match_from_remote(bundle_group: str | None) -> Callable[[str], bool]:
    if bundle_group is None:
        return lambda _: True

    bundle_tags = bundle_group.split(" ")
    return lambda mid: mid in bundle_tags


def populate_session_descriptor(
    desc: SessionDescription,
    # is_plan_b: bool,
    fingerprints: list[dtls.Fingerprint],
    is_extmap_allow_mixed: bool,
    role: ConnectionRole,
    candidates: list[ice.CandidateProtocol] | None,
    ice_params: ICEParameters,
    media_sections: list[MediaSection],
    match_bundle_group: str | None,
    caps: MediaCaps,
):
    bundle_value: str = "BUNDLE"
    bundle_count: int = 0

    bundle_matcher = bundle_match_from_remote(match_bundle_group)

    def bundle_appender(mid: str):
        nonlocal bundle_value, bundle_count
        bundle_value += " " + mid
        bundle_count += 1

    for _, media in enumerate(media_sections):
        # should_add_candidates = idx == 0
        should_add_candidates = False

        if media.data:
            print("media session desc contain SCTP. Not supported")
            continue

        should_add_id = add_transceiver_media_description(
            desc,
            media,
            should_add_candidates,
            fingerprints,
            media.id,
            ice_params,
            candidates,
            role,
            caps,
        )

        if should_add_id:
            if bundle_matcher(media.id):
                bundle_appender(media.id)

    if fingerprints:
        for fingerprint in fingerprints:
            desc.add_attribute(
                SessionDescriptionAttr(
                    SessionDescriptionAttrKey.Fingerprint,
                    fingerprint.algorithm + " " + fingerprint.value.upper(),
                )
            )

    if is_extmap_allow_mixed:
        desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.ExtMapAllowMixed)
        )

    if bundle_count > 0:
        desc.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.Group, bundle_value)
        )

    return desc
