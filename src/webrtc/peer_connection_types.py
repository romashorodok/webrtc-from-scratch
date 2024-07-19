from enum import Enum, IntEnum
from dataclasses import dataclass


class ConnectionRole(Enum):
    # Endpoint will initiate an outgoing connection
    Active = "active"
    # Endpoint will accept an incoming connection
    Passive = "passive"
    # Endpoint is willing to accept an incoming connection or to initiate an outgoing connection
    Actpass = "actpass"
    # Endpoint does not want the connection to be established for the time being
    Holdconn = "holdconn"


class ICETransportState(Enum):
    UNKNOWN = "unknow"
    # Not allocated transports. Indicate that no one transports allocated.
    NEW = "new"
    # All transport must be in checking state, and no other.
    Checking = "checking"
    # At least one transport in connected state, there may be other transports in "connected", "completed" or "closed"
    Connected = "connected"
    # At least one transport in completed state, there may be other transports  in "completed" or "closed"
    Completed = "completed"
    # Any of transports in "disconnected" state and none  in "failed"
    Disconnected = "Disconnected"
    Failed = "failed"
    # PeerConnection is closed
    Closed = "closed"


class ICEGatherPolicy(Enum):
    # Use any type of candidate
    All = "all"
    # Use only TURN based candidates
    Relay = "relay"


class ICEGatherState(Enum):
    UNKNOWN = "unknow"
    # Gatherer has been create but gather has not been called
    NEW = "new"
    # Gather has been called mean state which gathering in process
    Gathering = "gathering"
    # Gathered with candidate
    Complete = "completed"
    Closed = "closed"


@dataclass
class ICEParameters:
    local_ufrag: str
    local_pwd: str


class RTPComponent(IntEnum):
    RTP = 1
    RTCP = 2
