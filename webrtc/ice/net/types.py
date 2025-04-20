from enum import StrEnum, Enum
from typing import Protocol


class NetworkType(StrEnum):
    UDP = "udp"
    TCP = "tcp"


class CandidateType(Enum):
    Unspecified = 0
    Host = 1
    PeerReflexive = 2
    ServerReflexive = 3
    Relay = 4


def get_network_type_from_str(value: str) -> NetworkType | None:
    match value:
        case "udp":
            return NetworkType.UDP
        case "tcp":
            return NetworkType.TCP


def is_rtcp(msg: bytes) -> bool:
    return len(msg) >= 2 and msg[1] >= 192 and msg[1] <= 208


class Address:
    def __init__(self, address: str, port: int) -> None:
        self.address = address
        self.port = port


class Packet:
    def __init__(self, source: Address, data: bytes) -> None:
        self._data = data
        self._source = source

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def source(self) -> Address:
        return self._source


class MuxConnProtocol(Protocol):
    def sendto(self, data: bytes | bytearray | bytes): ...
    async def recvfrom(self) -> Packet: ...


class CandidateProtocol(Protocol):
    """
    Related to string representation of the ICECandidate
    """

    def to_ice_str(self) -> str: ...
    def set_candidate_type(self, candidate_type: CandidateType): ...
    def set_network_type(self, network_type: NetworkType): ...
    def set_port(self, port: int): ...
    def set_address(self, address: str): ...
    def set_priority(self, priority: int): ...
    def set_component(self, component: int): ...

    def get_network_type(self) -> NetworkType: ...

    @property
    def priority(self) -> int: ...

    @property
    def address(self) -> str: ...

    @property
    def port(sefl) -> int: ...


class MuxProtocol(Protocol):
    """
    Represent local candidate at networking protocols to provide traffic
    from remote candidate.
    """

    def intercept(self, remote: CandidateProtocol) -> MuxConnProtocol:
        """
        Local candidate must intercept remote candidate traffic
        """
        ...


class LocalCandidate:
    def __init__(self, candidate: CandidateProtocol, mux: MuxProtocol) -> None:
        self._candidate = candidate
        self._mux = mux

    @property
    def unwrap(self) -> CandidateProtocol:
        return self._candidate

    @property
    def mux(self) -> MuxProtocol:
        return self._mux


class RemoteCandidate:
    def __init__(
        self,
        candidate: CandidateProtocol,
        conn: MuxConnProtocol,
    ) -> None:
        self._candidate = candidate
        self._conn = conn

    @property
    def unwrap(self) -> CandidateProtocol:
        return self._candidate

    @property
    def conn(self) -> MuxConnProtocol:
        return self._conn
