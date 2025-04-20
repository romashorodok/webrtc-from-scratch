from enum import Enum
from typing import Self

from . import ice
from .ice.stun import utils as byteops

from . import dtls
from . import utils

import re
import secrets

from .transceiver import (
    RTPCodecParameters,
    RTPTransceiverDirection,
    RTPTransceiverDirectionList,
    RTCPFeedback,
    RTPCodecKind,
)


class SessionDescriptionType(Enum):
    Offer = "offer"
    Answer = "answer"
    Rollback = "rollback"
    Pranswer = "pranswer"


class SessionDescriptionAttrKey(Enum):
    Candidate = "candidate"
    EndOfCandidates = "end-of-candidates"
    Identity = "identity"
    Group = "group"
    SSRC = "ssrc"
    SSRCGroup = "ssrc-group"
    Msid = "msid"
    MsidSemantic = "msid-semantic"
    ConnectionSetup = "setup"
    MID = "mid"
    ICELite = "ice-lite"
    RTCPMux = "rtcp-mux"
    RTCPRsize = "rtcp-rsize"
    Inactive = "inactive"
    RecvOnly = "recvonly"
    SendOnly = "sendonly"
    SendRecv = "sendrecv"
    ExtMap = "extmap"
    ExtMapAllowMixed = "extmap-allow-mixed"
    Fingerprint = "fingerprint"
    RTPMap = "rtpmap"
    FMTP = "fmtp"
    RTCPfb = "rtcp-fb"
    RID = "rid"
    ICEUfrag = "ice-ufrag"
    ICEPwd = "ice-pwd"


class SessionDescriptionAttr:
    def __init__(
        self, key: SessionDescriptionAttrKey | str, value: str | None = None
    ) -> None:
        if isinstance(key, SessionDescriptionAttrKey):
            self.key: str = key.value
        else:
            self.key = key

        self.value = value

    def __repr__(self) -> str:
        return f"SessionDescriptionAttr(key={self.key}, value={self.value})"

    def marshal(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.key))
        if self.value and len(self.value) > 0:
            m.extend(byteops.pack_string(":" + self.value))
        return m


def _desc_marshal_key_value(data: bytearray, key: str, value: bytes):
    data.extend(byteops.pack_string(key))
    data.extend(value)
    data.extend(b"\r\n")


def _append_list(lst: list[str], sep: str) -> str:
    b = []
    for i, p in enumerate(lst):
        if i != 0:
            b.append(sep)
        b.append(p)
    return "".join(b)


def grouplines(sdp: str) -> tuple[list[str], list[list[str]]]:
    # Ensure the SDP data is a string (decode if it's a bytestring)
    if isinstance(sdp, bytes):
        sdp = sdp.decode()

    session = []
    media = []
    for line in sdp.splitlines():
        if line.startswith("m="):
            media.append([line])
        elif len(media):
            media[-1].append(line)
        else:
            session.append(line)
    return session, media


def ipaddress_from_sdp(sdp: str) -> tuple[str, str]:
    m = re.match("^IN (IP4|IP6) ([^ ]+)$", sdp)
    assert m
    return (m.group(1), m.group(2))


def parse_attr(line: str) -> tuple[str, str | None]:
    if ":" in line:
        bits = line[2:].split(":", 1)
        return bits[0], bits[1]
    else:
        return line[2:], None


class MediaDescription:
    def __init__(
        self,
        media: str,
        port: int,
        protocols: list[str],
        # formats: list[str],
        # network_type: str,
        # address_type: str,
        # address: str,
    ) -> None:
        self.kind = media
        self.port = port
        self.port_end: int | None = None
        self.protocols = protocols
        # Mean which codec payload formats may be used
        self.formats = list[str]()

        self.network_type = "IN"
        self.address_type = "IP4"
        self.address_host = "0.0.0.0"

        self.ice_ufrag: str | None = None
        self.ice_pwd: str | None = None

        # a=<attribute>
        # a=<attribute>:<value>
        # https://tools.ietf.org/html/rfc4566#section-5.13
        self._attributes = list[SessionDescriptionAttr]()

        self.direction: RTPTransceiverDirection = RTPTransceiverDirection.Unknown
        self.candidates = list[ice.CandidateProtocol]()
        self.codecs = list[RTPCodecParameters]()
        self.fingerprints = list[dtls.Fingerprint]()

    def __repr__(self) -> str:
        return f"MediaDescription(ice_ufrag={self.ice_ufrag}, ice_pwd={self.ice_pwd}, _attributes={self._attributes})"

    def add_codec(self, codec: RTPCodecParameters):
        self.formats.append(str(codec.payload_type))
        name = codec.mime_type.removeprefix("audio/")
        name = name.removeprefix("video/")
        rtpmap = f"{codec.payload_type} {name}/{codec.clock_rate}"
        if codec.channels > 0:
            rtpmap += f"/{codec.channels}"
        self.codecs.append(codec)
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.RTPMap, rtpmap)
        )
        if codec.sdp_fmtp_line:
            fmtp = f"{codec.payload_type} {codec.sdp_fmtp_line}"
            self.add_attribute(
                SessionDescriptionAttr(SessionDescriptionAttrKey.FMTP, fmtp)
            )

    def add_rtcp_feedback(self, codec: RTPCodecParameters, rtcp_feedback: RTCPFeedback):
        feedback = (
            f"{codec.payload_type} {rtcp_feedback.rtcp_type} {rtcp_feedback.parameter}"
        )
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.RTCPfb, feedback)
        )

    def add_media_source(self, ssrc: int, cname: str, stream_label: str, label: str):
        value = f"{ssrc} cname:{cname}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )
        value = f"{ssrc} msid:{stream_label} {label}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )
        value = f"{ssrc} label:{label}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )
        value = f"{ssrc} mslabel:{stream_label}"
        self.add_attribute(
            SessionDescriptionAttr(SessionDescriptionAttrKey.SSRC, value)
        )

    @property
    def attributes(self) -> list[SessionDescriptionAttr]:
        return self._attributes

    def add_attribute(self, attr: SessionDescriptionAttr):
        self._attributes.append(attr)

    def get_attribute_value(self, key: str) -> str | None:
        for attr in self.attributes:
            if key == attr.key:
                return attr.value
        return

    @classmethod
    def parse(cls, media_lines: list[str]) -> Self | None:
        # TODO: add port range matching
        m = re.match("^m=([^ ]+) ([0-9]+) ([A-Z/]+) (.+)$", media_lines[0])
        if not m:
            return

        media_kind = m.group(1)
        port = int(m.group(2))
        protocols = m.group(3).split("/")
        fmt = m.group(4).split()

        media = cls(
            media=media_kind,
            port=port,
            protocols=protocols,
        )

        media.formats.extend(fmt)

        for line in media_lines[1:]:
            if line.startswith("c="):
                address_type, address_host = ipaddress_from_sdp(line[2:])
                media.address_type = address_type
                media.address_host = address_host
            elif line.startswith("a="):
                attr, value = parse_attr(line)

                if attr in RTPTransceiverDirectionList:
                    print("Parse direction", attr)
                    media.direction = RTPTransceiverDirection(attr)
                elif attr == SessionDescriptionAttrKey.Candidate.value and value:
                    candidate = ice.parse_candidate_str(value)
                    if not candidate:
                        continue
                    media.candidates.append(candidate)
                elif attr == SessionDescriptionAttrKey.RTPMap.value and value:
                    payload_id, payload_desc = value.split(" ", 1)
                    bits = payload_desc.split("/")
                    refresh_rate = 1 / 30

                    if media_kind == RTPCodecKind.Audio.value:
                        refresh_rate = 0.020
                        if len(bits) > 2:
                            channels = int(bits[2])
                        else:
                            channels = 1
                    else:
                        channels = 0
                        refresh_rate = 1 / 30

                    payload_name = bits[0]
                    clock_rate = bits[1]

                    codec = RTPCodecParameters(
                        mime_type=f"{media_kind}/{payload_name}",
                        clock_rate=int(clock_rate),
                        refresh_rate=refresh_rate,
                        channels=channels,
                        payload_type=int(payload_id),
                        sdp_fmtp_line="",
                        stats_id=f"RTPCodec-{utils.current_ntp_time() >> 32}",
                    )
                    media.add_codec(codec)

                elif attr == SessionDescriptionAttrKey.ICEUfrag.value and value:
                    media.ice_ufrag = value
                elif attr == SessionDescriptionAttrKey.ICEPwd.value and value:
                    media.ice_pwd = value

                elif attr == SessionDescriptionAttrKey.Fingerprint.value and value:
                    algorithm, fingerprint = value.split()
                    media.fingerprints.append(dtls.Fingerprint(algorithm, fingerprint))

                else:
                    media.attributes.append(
                        SessionDescriptionAttr(key=attr, value=value)
                    )

        return media

    def _marshal_ports(self) -> bytes:
        m = bytearray()

        m.extend(byteops.pack_string(str(self.port)))
        if self.port_end:
            m.extend(byteops.pack_string("/"))
            m.extend(byteops.pack_string(str(self.port_end)))

        return m

    def _marshal_name(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.kind + " "))
        m.extend(self._marshal_ports())
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.protocols, "/")))
        m.extend(byteops.pack_string(" "))
        m.extend(byteops.pack_string(_append_list(self.formats, " ")))
        self.kind

        return m

    def marshal(self) -> bytes:
        m = bytearray()
        _desc_marshal_key_value(m, "m=", self._marshal_name())
        _desc_marshal_key_value(
            m,
            "c=",
            byteops.pack_string(
                f"{self.network_type} {self.address_type} {self.address_host}"
            ),
        )
        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())
        return m


class Origin:
    def __init__(self):
        self.username = "-"
        self.session_id = self._new_session_id()
        self.session_version = utils.current_ntp_time() >> 32
        self.network_type = "IN"
        self.address_type = "IP4"
        self.unicast_address = "0.0.0.0"

    def _new_session_id(self):
        # https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-26#section-5.2.1
        # Session ID is recommended to be constructed by generating a 64-bit
        # quantity with the highest bit set to zero and the remaining 63-bits
        # being cryptographically random.
        id = secrets.randbits(64)
        # Set the highest bit to zero
        # Set the highest bit to zero
        id &= ~(1 << 63)
        return id

    def marshal(self) -> bytes:
        m = bytearray()
        m.extend(byteops.pack_string(self.username + " "))
        m.extend(byteops.pack_string(str(self.session_id) + " "))
        m.extend(byteops.pack_string(str(self.session_version) + " "))
        m.extend(byteops.pack_string(self.network_type + " "))
        m.extend(byteops.pack_string(self.address_type + " "))
        m.extend(byteops.pack_string(self.unicast_address))
        return m


# API to match draft-ietf-rtcweb-jsep.
# Some settings that are required by the JSEP spec.
class SessionDescription:
    def __init__(self) -> None:
        # o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
        # https://tools.ietf.org/html/rfc4566#section-5.2
        self.origin = Origin()
        # v=0
        # https://tools.ietf.org/html/rfc4566#section-5.1
        self.version = 0
        # s=<session name>
        # https://tools.ietf.org/html/rfc4566#section-5.3
        self.session_name = "-"
        # https://tools.ietf.org/html/rfc4566#section-5.9
        # https://tools.ietf.org/html/rfc4566#section-5.10
        # self.time_descriptions = list[TimeDescription]([TimeDescription()])
        # a=<attribute>
        # a=<attribute>:<value>
        # https://tools.ietf.org/html/rfc4566#section-5.13
        self.attributes = list[SessionDescriptionAttr]()
        self.media_descriptions = list[MediaDescription]()

    def add_attribute(self, attr: SessionDescriptionAttr):
        self.attributes.append(attr)

    def get_attribute_value(self, key: str) -> str | None:
        for attr in self.attributes:
            if key == attr.key:
                return attr.value
        return

    def add_media_description(self, desc: MediaDescription):
        self.media_descriptions.append(desc)

    @classmethod
    def parse(cls, sdp: str):
        dtls_fingerprints = []

        session_lines, media_groups = grouplines(sdp)

        print("media_groups", media_groups)
        print("session_lines", session_lines)

        sdp_attrs = []

        session = cls()

        for line in session_lines:
            if line.startswith("v="):
                session.version = int(line.strip()[2:])
            elif line.startswith("o="):
                session.origin = Origin()
            elif line.startswith("s="):
                pass
            elif line.startswith("c="):
                pass
            elif line.startswith("t="):
                pass
            elif line.startswith("a="):
                attr, value = parse_attr(line)
                sdp_attrs.append((attr, value))

                if attr == "fingerprint" and value:
                    algorithm, fingerprint = value.split()
                    dtls_fingerprints.append((algorithm, fingerprint))
                elif attr == "group" and value:
                    session.add_attribute(
                        SessionDescriptionAttr(SessionDescriptionAttrKey.Group, value)
                    )

        for media_lines in media_groups:
            media = MediaDescription.parse(media_lines)
            if media is None:
                continue
            session.add_media_description(media)

        return session

    def __repr__(self) -> str:
        return f"SessionDescription(media={self.media_descriptions})"

    def get_media_credentials(self):
        for media in self.media_descriptions:
            if not media.ice_ufrag or not media.ice_pwd:
                continue
            yield (media.ice_ufrag, media.ice_pwd)

    def get_media_fingerprints(self) -> list[dtls.Fingerprint]:
        result = []
        for media in self.media_descriptions:
            result.extend(media.fingerprints)
        return result

    def marshal(self) -> bytes:
        # https://tools.ietf.org/html/rfc4566#section-5
        # session description
        #
        # v=  (protocol version)
        # o=  (originator and session identifier)
        # s=  (session name)
        # i=* (session information)
        # u=* (uri of description)
        # e=* (email address)
        # p=* (phone number)
        # c=* (connection information -- not required if included in
        # all media)
        # b=* (zero or more bandwidth information lines)
        # one or more time descriptions ("t=" and "r=" lines; see below)
        # z=* (time zone adjustments)
        # k=* (encryption key)
        # a=* (zero or more session attribute lines)
        # zero or more media descriptions
        #
        # time description
        #
        # t=  (time the session is active)
        # r=* (zero or more repeat times)
        #
        # media description, if present
        #
        # m=  (media name and transport address)
        # i=* (media title)
        # c=* (connection information -- optional if included at
        # session level)
        # b=* (zero or more bandwidth information lines)
        # k=* (encryption key)
        # a=* (zero or more media attribute lines)

        m = bytearray()
        _desc_marshal_key_value(m, "v=", byteops.pack_string(str(self.version)))
        _desc_marshal_key_value(m, "o=", self.origin.marshal())
        _desc_marshal_key_value(m, "s=", byteops.pack_string(self.session_name))
        _desc_marshal_key_value(m, "t=", byteops.pack_string("0 0"))

        for attr in self.attributes:
            _desc_marshal_key_value(m, "a=", attr.marshal())

        for media in self.media_descriptions:
            m.extend(media.marshal())

        return bytes(m)
