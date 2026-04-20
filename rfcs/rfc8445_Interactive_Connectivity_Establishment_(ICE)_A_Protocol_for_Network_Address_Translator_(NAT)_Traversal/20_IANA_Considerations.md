# 20.  IANA Considerations

The original ICE specification registered four STUN attributes and
one new STUN error response.  The STUN attributes and error response
are reproduced here.  In addition, this specification registers a new
ICE option.

## 20.1.  STUN Attributes

IANA has registered four STUN attributes:

    0x0024 PRIORITY
    0x0025 USE-CANDIDATE
    0x8029 ICE-CONTROLLED
    0x802A ICE-CONTROLLING

## 20.2.  STUN Error Responses

IANA has registered the following STUN error-response code:

487   Role Conflict: The client asserted an ICE role (controlling or
        controlled) that is in conflict with the role of the server.

## 20.3.  ICE Options

IANA has registered the following ICE option in the "ICE Options"
subregistry of the "Interactive Connectivity Establishment (ICE)"
registry, following the procedures defined in [RFC6336].

ICE Option name:
    ice2

Contact:
    Name:    IESG
    Email:   iesg@ietf.org

Change Controller:
    IESG

Description:
    The ICE option indicates that the ICE agent using the ICE option
    is implemented according to RFC 8445.

Reference:
    RFC 8445

# 21.  Changes from RFC 5245

The purpose of this updated ICE specification is to:

o  Clarify procedures in RFC 5245.

o  Make technical changes, due to discovered flaws in RFC 5245 and
    feedback from the community that has implemented and deployed ICE
    applications based on RFC 5245.

o  Make the procedures independent of the signaling protocol, by
    removing the SIP and SDP procedures.  Procedures specific to a
    signaling protocol will be defined in separate usage documents.
    [ICE-SIP-SDP] defines ICE usage with SIP and SDP.

The following technical changes have been done:

o  Aggressive nomination removed.

o  The procedures for calculating candidate pair states and
    scheduling connectivity checks modified.

o  Procedures for calculation of Ta and RTO modified.

o  Active checklist and Frozen checklist definitions removed.

o  'ice2' ICE option added.

o  IPv6 considerations modified.

o  Usage with no-op for keepalives, and keepalives with non-ICE
    peers, removed.
