from . import dtls
from . import ice

import itertools
from typing import Callable

from .transceiver import RTPTransceiver, RTPTransceiverDirection, MediaCaps, RTPCodecParameters
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
from .logger import Component, get_logger


class ExtMap:
    def __init__(
        self,
        value: int,
        direction: RTPTransceiverDirection | None = None,
        uri: str | None = None,
        ext_attr: str | None = None,
    ) -> None:
        self.value = value
        self.direction = direction
        self.uri = uri
        self.ext_attr = ext_attr

    def marshal(self) -> str:
        out = f"extmap:{self.value}"

        if self.uri:
            out += f" {self.uri}"

        if self.ext_attr:
            out += f" {self.ext_attr}"

        return out


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
            get_logger().debug(
                Component.SDP,
                "Skipping sender SDP with no encodings",
                track_id=track.id,
            )
            continue

        for encoding in send_params.encodings:
            desc.add_media_source(
                encoding.ssrc, track.stream_id, track.stream_id, track.id
            )
            desc.add_attribute(
                SessionDescriptionAttr(f"msid:{track.stream_id} {track.id}")
            )

        # NOTE: rid is only for simulcast - don't include for single stream
        # if send_params.encodings:
        #     for encoding in send_params.encodings:
        #         desc.add_attribute(
        #             SessionDescriptionAttr(
        #                 SessionDescriptionAttrKey.RID, f"{encoding.rid} send"
        #             )
        #         )

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
    remote_media: MediaDescription | None = None,
) -> bool:
    transceivers = media_section.transceivers
    if len(transceivers) < 1:
        return False

    t = transceivers[0]

    if t.mid is None:
        return False

    # When creating an answer, use the codecs from the offer (remote_media)
    # to ensure payload types match what the offerer expects
    if remote_media and remote_media.codecs:
        # Filter remote codecs to only include ones we support
        local_codecs = t.get_codecs() or []
        codecs = []
        for remote_codec in remote_media.codecs:
            # Check if we support this codec (fuzzy match by mime type)
            for local_codec in local_codecs:
                if remote_codec.mime_type.lower() == local_codec.mime_type.lower():
                    # Use remote codec's payload type with our RTCP feedback
                    negotiated_codec = RTPCodecParameters(
                        mime_type=remote_codec.mime_type,
                        clock_rate=remote_codec.clock_rate,
                        refresh_rate=local_codec.refresh_rate,
                        channels=remote_codec.channels,
                        sdp_fmtp_line=local_codec.sdp_fmtp_line or remote_codec.sdp_fmtp_line,
                        payload_type=remote_codec.payload_type,  # Use offer's payload type!
                        stats_id=local_codec.stats_id,
                    )
                    negotiated_codec.rtcp_feedbacks = local_codec.rtcp_feedbacks.copy()
                    codecs.append(negotiated_codec)
                    break
    else:
        codecs = t.get_codecs()

    if not codecs:
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

    # For answers, use extmap IDs from the offer
    # For offers, use our default values
    ext_maps: list[ExtMap] = []

    if remote_media:
        # Extract extmap attributes from the offer
        for attr in remote_media.attributes:
            if attr.key == SessionDescriptionAttrKey.ExtMap.value and attr.value:
                # Parse extmap value: "id uri" or "id/direction uri"
                parts = attr.value.split(" ", 1)
                if len(parts) >= 2:
                    id_part = parts[0]
                    uri = parts[1].split(" ")[0]  # URI is the second part
                    # Handle "id/direction" format
                    if "/" in id_part:
                        ext_id = int(id_part.split("/")[0])
                    else:
                        ext_id = int(id_part)
                    ext_maps.append(ExtMap(value=ext_id, uri=uri))

    if not ext_maps:
        # Default extmap for offers
        ext_maps = [
            ExtMap(
                value=4,
                uri="http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
            )
        ]

    for rtp_ext in ext_maps:
        media.add_attribute(SessionDescriptionAttr(rtp_ext.marshal()))

    # NOTE: rid is only for simulcast - don't include for single stream
    # if RTPTransceiverDirection.Recvonly in directions:
    #     media.add_attribute(
    #         SessionDescriptionAttr(
    #             SessionDescriptionAttrKey.RID, f"{media_section.rid} recv"
    #         )
    #     )

    # if media_section.rid_map:
    #     for rid in media_section.rid_map.items():
    #         media.add_attribute(
    #             SessionDescriptionAttr(SessionDescriptionAttrKey.RID, f"{rid} recv")
    #         )

    add_sender_sdp(media, media_section)

    get_logger().debug(Component.SDP, "Adding media direction", direction=t.direction.value)
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
    remote_description: SessionDescription | None = None,
):
    bundle_value: str = "BUNDLE"
    bundle_count: int = 0

    bundle_matcher = bundle_match_from_remote(match_bundle_group)

    # Build a map of MID -> remote media for codec negotiation
    remote_media_by_mid: dict[str, MediaDescription] = {}
    if remote_description:
        for remote_media in remote_description.media_descriptions:
            mid = remote_media.get_attribute_value(SessionDescriptionAttrKey.MID.value)
            if mid:
                remote_media_by_mid[mid] = remote_media

    def bundle_appender(mid: str):
        nonlocal bundle_value, bundle_count
        bundle_value += " " + mid
        bundle_count += 1

    for _, media in enumerate(media_sections):
        # should_add_candidates = idx == 0
        should_add_candidates = False

        if media.data:
            get_logger().debug(Component.SDP, "Skipping unsupported SCTP media section")
            continue

        # Get the corresponding remote media for this MID (for codec negotiation)
        remote_media = remote_media_by_mid.get(media.id)

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
            remote_media,
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
