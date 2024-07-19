import binascii

from .net.types import (
    CandidateProtocol,
    NetworkType,
    get_network_type_from_str,
    CandidateType,
)
from webrtc.utils.types import impl_protocol
from . import stun as stun


# TODO: what is prflx and prflx active candidates


def get_candidate_type_preference(candidate_type: CandidateType) -> int:
    match candidate_type:
        case CandidateType.Host:
            return 126
        case CandidateType.PeerReflexive:
            return 110
        case CandidateType.ServerReflexive:
            return 100
        case CandidateType.Relay:
            return 0
        case _:
            return 0


class TCPType:
    Unspecified = 0
    Active = 1
    Passive = 2
    SimultaneousOpen = 3


_DEFAULT_LOCAL_PREFERENCE = 65535


def _tcp_type_direction_pref(candidate_type: CandidateType, tcp_type: TCPType) -> int:
    match candidate_type:
        case CandidateType.Host, CandidateType.Relay:
            match tcp_type:
                case TCPType.Active:
                    return 6
                case TCPType.Passive:
                    return 4
                case TCPType.SimultaneousOpen:
                    return 2
                case _:
                    return 0
        case CandidateType.PeerReflexive, CandidateType.ServerReflexive:
            match tcp_type:
                case TCPType.SimultaneousOpen:
                    return 6
                case TCPType.Active:
                    return 4
                case TCPType.Passive:
                    return 2
                case _:
                    return 0
        case _:
            return 0


def get_candidate_local_preference(
    candidate_type: CandidateType,
    network_type: NetworkType,
    tcp_type: TCPType | None = None,
) -> int:
    """
    RFC 6544, section 4.2

    In Section 4.1.2.1 of [RFC5245], a recommended formula for UDP ICE
    candidate prioritization is defined.  For TCP candidates, the same
    formula and candidate type preferences SHOULD be used, and the
    RECOMMENDED type preferences for the new candidate types defined in
    this document (see Section 5) are 105 for NAT-assisted candidates and
    75 for UDP-tunneled candidates.

    (...)

    With TCP candidates, the local preference part of the recommended
    priority formula is updated to also include the directionality
    (active, passive, or simultaneous-open) of the TCP connection.  The
    RECOMMENDED local preference is then defined as:

        local preference = (2^13) * direction-pref + other-pref

    The direction-pref MUST be between 0 and 7 (both inclusive), with 7
    being the most preferred.  The other-pref MUST be between 0 and 8191
    (both inclusive), with 8191 being the most preferred.  It is
    RECOMMENDED that the host, UDP-tunneled, and relayed TCP candidates
    have the direction-pref assigned as follows: 6 for active, 4 for
    passive, and 2 for S-O.  For the NAT-assisted and server reflexive
    candidates, the RECOMMENDED values are: 6 for S-O, 4 for active, and
    2 for passive.

    (...)

    If any two candidates have the same type-preference and direction-
    pref, they MUST have a unique other-pref.  With this specification,
    this usually only happens with multi-homed hosts, in which case
    other-pref is the preference for the particular IP address from which
    the candidate was obtained.  When there is only a single IP address,
    this value SHOULD be set to the maximum allowed value (8191).
    """

    if network_type == NetworkType.TCP and tcp_type:
        other_pref = 8191
        direction_pref = _tcp_type_direction_pref(candidate_type, tcp_type)
        return (1 << 13) * direction_pref + other_pref

    return _DEFAULT_LOCAL_PREFERENCE


def get_candidate_type(candidate_type: CandidateType) -> str:
    match candidate_type:
        case CandidateType.Host:
            return "host"
        case CandidateType.PeerReflexive:
            return "prflx"
        case CandidateType.ServerReflexive:
            return "srflx"
        case CandidateType.Relay:
            return "relay"
        case _:
            raise ValueError("Unhandled candidate type")


def get_candidate_type_from_str(raw: str) -> CandidateType:
    match raw:
        case "host":
            return CandidateType.Host
        case "prflx":
            return CandidateType.PeerReflexive
        case "srflx":
            return CandidateType.ServerReflexive
        case "relay":
            return CandidateType.Relay
        case _:
            return CandidateType.Unspecified


@impl_protocol(CandidateProtocol)
class CandidateBase:
    def __init__(self) -> None:
        self._priority = 0
        self._component = 1
        self._candidate_type = CandidateType.Host
        self._network_type = NetworkType.UDP
        self._address: str | None = None
        self._port: int = 0

    def to_ice_str(self) -> str:
        checksum_str = f"{self._candidate_type}{self._address}{self._network_type}"
        foundation = binascii.crc32(checksum_str.encode())
        # TODO: handle active, passive tcp
        return f"{foundation} {self._component} {self._network_type} {self.priority} {self._address} {self._port} typ {self.candidate_type}"

    @property
    def candidate_type(self) -> str:
        return get_candidate_type(self._candidate_type)

    def set_network_type(self, network_type: NetworkType):
        self._network_type = network_type

    def set_candidate_type(self, candidate_type: CandidateType):
        self._candidate_type = candidate_type

    @property
    def port(self) -> int:
        if not self._port:
            raise ValueError("The candidate doesn't have an address")
        return self._port

    def set_port(self, port: int):
        self._port = port

    @property
    def address(self) -> str:
        if not self._address:
            raise ValueError("The candidate doesn't have an address")
        return self._address

    def set_address(self, address: str):
        self._address = address

    @property
    def priority(self) -> int:
        """
        Priority computes the priority for this ICE Candidate
        See: https://www.rfc-editor.org/rfc/rfc8445#section-5.1.2.1

        The local preference MUST be an integer from 0 (lowest preference) to
        65535 (highest preference) inclusive. When there is only a single IP
        address, this value SHOULD be set to 65535.  If there are multiple
        candidates for a particular component for a particular data stream
        that have the same type, the local preference MUST be unique for each
        one.
        """
        if self._priority:
            return self._priority

        preference = get_candidate_type_preference(self._candidate_type)
        # TODO: This make same candidate priority for same candidate
        # Need also handle unique addr calc
        # On candidate CandidateBase: 3507499342 1 udp 2130706431 127.0.0.1 9999 host
        # On candidate CandidateBase: 2698115102 1 udp 2130706431 192.168.0.101 9999 host
        return (
            (1 << 24) * preference
            + (1 << 8)
            * get_candidate_local_preference(self._candidate_type, self._network_type)
            + (1 << 0) * (256 - self._component)
        )

    def set_priority(self, priority: int):
        self._priority = priority

    def set_component(self, component: int):
        """
        The component ID MUST be an integer between 1 and 256 inclusive.
        """
        self._component = component

    def get_network_type(self) -> NetworkType:
        return self._network_type

    def __eq__(self, value: object) -> bool:
        if isinstance(value, CandidateBase):
            return value.to_ice_str() == self.to_ice_str()
        return False


# candidate:2130706431 1 udp 2130706431 142.250.82.212 19305 typ host generation 0
def parse_candidate_str(raw: str) -> CandidateBase | None:
    parts = raw.split()

    if len(raw) != 0 and raw[0] == " ":
        foundation = list[str](" ")
        foundation.extend(parts)
        parts = foundation

    if len(parts) < 8:
        raise ValueError("Raw candidate too short")

    foundation = parts[0]
    component = int(parts[1])
    protocol = parts[2]
    priority = int(parts[3])
    address = parts[4]
    port = int(parts[5])
    typ = parts[7]

    # if len(parts) > 8:
    # raise ValueError("Not supported rich candidate types")

    candidate_type = get_candidate_type_from_str(typ)
    network_type = get_network_type_from_str(protocol)
    if network_type is NetworkType.TCP:
        print("Found unsupported tcp candidate type")
        return

    match candidate_type:
        case CandidateType.Host:
            candidate = CandidateBase()
            if network_type:
                candidate.set_network_type(network_type)
            else:
                candidate.set_network_type(NetworkType.UDP)

            candidate.set_address(address)
            candidate.set_port(port)
            candidate.set_component(component)
            candidate.set_priority(priority)
            candidate.set_candidate_type(candidate_type)
            return candidate
        case _, CandidateType.Unspecified:
            pass

    raise ValueError("Unhandled candidate type")
