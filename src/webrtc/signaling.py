from enum import Enum

from .session_description import SessionDescriptionType


class SignalingState(Enum):
    Unknown = "unknown"
    # Stable indicates there is no offer/answer exchange in
    # progress. This is also the initial state, in which case the local and
    # remote descriptions are nil.
    Stable = "stable"
    # HaveLocalOffer indicates that a local description, of
    # type "offer", has been successfully applied.
    HaveLocalOffer = "have-local-offer"
    # HaveRemoteOffer indicates that a remote description, of
    # type "offer", has been successfully applied.
    HaveRemoteOffer = "have-remote-offer"
    # HaveLocalPranswer indicates that a remote description
    # of type "offer" has been successfully applied and a local description
    # of type "pranswer" has been successfully applied.
    HaveLocalPranswer = "have-local-pranswer"
    # HaveRemotePranswer indicates that a local description
    # of type "offer" has been successfully applied and a remote description
    # of type "pranswer" has been successfully applied.
    HaveRemotePranswer = "have-remote-pranswer"
    # Closed indicates The PeerConnection has been closed.
    Closed = "closed"


class SignalingChangeOperation(Enum):
    SetLocal = "set-local"
    SetRemote = "set-remote"


class SignalingStateTransitionError(Exception):
    def __init__(self, message):
        super().__init__(message)


# https://www.w3.org/TR/webrtc/#rtcsignalingstate-enum
def ensure_next_signaling_state(
    curr_state: SignalingState,
    next_state: SignalingState,
    operation: SignalingChangeOperation,
    desc_type: SessionDescriptionType,
):
    if (
        desc_type == SessionDescriptionType.Rollback
        and curr_state == SignalingState.Stable
    ):
        raise SignalingStateTransitionError("Cannot rollback stable state")

    if curr_state == SignalingState.Stable:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Offer
                and next_state == SignalingState.HaveLocalOffer
            ):
                return next_state
        elif operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Offer
                and next_state == SignalingState.HaveRemoteOffer
            ):
                return next_state
    elif curr_state == SignalingState.HaveLocalOffer:
        if operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
            elif (
                desc_type == SessionDescriptionType.Pranswer
                and next_state == SignalingState.HaveRemotePranswer
            ):
                return next_state
    elif curr_state == SignalingState.HaveRemotePranswer:
        if operation == SignalingChangeOperation.SetRemote:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
    elif curr_state == SignalingState.HaveRemoteOffer:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state
            elif (
                desc_type == SessionDescriptionType.Pranswer
                and next_state == SignalingState.HaveLocalPranswer
            ):
                return next_state
    elif curr_state == SignalingState.HaveLocalPranswer:
        if operation == SignalingChangeOperation.SetLocal:
            if (
                desc_type == SessionDescriptionType.Answer
                and next_state == SignalingState.Stable
            ):
                return next_state

    raise SignalingStateTransitionError(
        f"Invalid state transition: {curr_state}->{operation}({desc_type})->{next_state}"
    )
