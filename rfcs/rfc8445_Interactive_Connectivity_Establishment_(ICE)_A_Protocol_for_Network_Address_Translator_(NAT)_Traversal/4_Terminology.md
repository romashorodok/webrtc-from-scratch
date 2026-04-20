Readers need to be familiar with the terminology defined in [RFC5389]
and NAT Behavioral requirements for UDP [RFC4787].

This specification makes use of the following additional terminology:

ICE Session:  An ICE session consists of all ICE-related actions
    starting with the candidate gathering, followed by the
    interactions (candidate exchange, connectivity checks,
    nominations, and keepalives) between the ICE agents until all the
    candidates are released or an ICE restart is triggered.

ICE Agent, Agent:  An ICE agent (sometimes simply referred to as an
    "agent") is the protocol implementation involved in the ICE
    candidate exchange.  There are two agents involved in a typical
    candidate exchange.

Initiating Peer, Initiating Agent, Initiator:  An initiating agent is
    an ICE agent that initiates the ICE candidate exchange process.

Responding Peer, Responding Agent, Responder:  A responding agent is
    an ICE agent that receives and responds to the candidate exchange
    process initiated by the initiating agent.

ICE Candidate Exchange, Candidate Exchange:  The process where ICE
    agents exchange information (e.g., candidates and passwords) that
    is needed to perform ICE.  Offer/Answer with SDP encoding
    [RFC3264] is one example of a protocol that can be used for
    exchanging the candidate information.

Peer:  From the perspective of one of the ICE agents in a session,
    its peer is the other agent.  Specifically, from the perspective
    of the initiating agent, the peer is the responding agent.  From
    the perspective of the responding agent, the peer is the
    initiating agent.

Transport Address:  The combination of an IP address and the
    transport protocol (such as UDP or TCP) port.

Data, Data Stream, Data Session:  When ICE is used to set up data
    sessions, the data is transported using some protocol.  Media is
    usually transported over RTP, composed of a stream of RTP packets.
    Data session refers to data packets that are exchanged between the
    peer on the path created and tested with ICE.

Candidate, Candidate Information:  A transport address that is a
    potential point of contact for receipt of data.  Candidates also
    have properties -- their type (server reflexive, relayed, or
    host), priority, foundation, and base.

Component:  A component is a piece of a data stream.  A data stream
    may require multiple components, each of which has to work in
    order for the data stream as a whole to work.  For RTP/RTCP data
    streams, unless RTP and RTCP are multiplexed in the same port,
    there are two components per data stream -- one for RTP, and one
    for RTCP.  A component has a candidate pair, which cannot be used
    by other components.

Host Candidate:  A candidate obtained by binding to a specific port
    from an IP address on the host.  This includes IP addresses on
    physical interfaces and logical ones, such as ones obtained
    through VPNs.

Server-Reflexive Candidate:  A candidate whose IP address and port
    are a binding allocated by a NAT for an ICE agent after it sends a
    packet through the NAT to a server, such as a STUN server.

Peer-Reflexive Candidate:  A candidate whose IP address and port are
    a binding allocated by a NAT for an ICE agent after it sends a
    packet through the NAT to its peer.

Relayed Candidate:  A candidate obtained from a relay server, such as
    a TURN server.

Base:  The transport address that an ICE agent sends from for a
    particular candidate.  For host, server-reflexive, and peer-
    reflexive candidates, the base is the same as the host candidate.
    For relayed candidates, the base is the same as the relayed
    candidate (i.e., the transport address used by the TURN server to
    send from).

Related Address and Port:  A transport address related to a
    candidate, which is useful for diagnostics and other purposes.  If
    a candidate is server or peer reflexive, the related address and
    port is equal to the base for that server or peer-reflexive
    candidate.  If the candidate is relayed, the related address and
    port are equal to the mapped address in the Allocate response that
    provided the client with that relayed candidate.  If the candidate
    is a host candidate, the related address and port is identical to
    the host candidate.

Foundation:  An arbitrary string used in the freezing algorithm to
    group similar candidates.  It is the same for two candidates that
    have the same type, base IP address, protocol (UDP, TCP, etc.),
    and STUN or TURN server.  If any of these are different, then the
    foundation will be different.


Local Candidate:  A candidate that an ICE agent has obtained and may
    send to its peer.

Remote Candidate:  A candidate that an ICE agent received from its
    peer.

Default Destination/Candidate:  The default destination for a
    component of a data stream is the transport address that would be
    used by an ICE agent that is not ICE aware.  A default candidate
    for a component is one whose transport address matches the default
    destination for that component.

Candidate Pair:  A pair containing a local candidate and a remote
    candidate.

Check, Connectivity Check, STUN Check:  A STUN Binding request for
    the purpose of verifying connectivity.  A check is sent from the
    base of the local candidate to the remote candidate of a candidate
    pair.

Checklist:  An ordered set of candidate pairs that an ICE agent will
    use to generate checks.

Ordinary Check:  A connectivity check generated by an ICE agent as a
    consequence of a timer that fires periodically, instructing it to
    send a check.

Triggered Check:  A connectivity check generated as a consequence of
    the receipt of a connectivity check from the peer.

Valid Pair:  A candidate pair whose local candidate equals the mapped
    address of a successful connectivity-check response and whose
    remote candidate equals the destination address to which the
    connectivity-check request was sent.

Valid List:  An ordered set of candidate pairs for a data stream that
    have been validated by a successful STUN transaction.

Checklist Set:  The ordered list of all checklists.  The order is
    determined by each ICE usage.

Full Implementation:  An ICE implementation that performs the
    complete set of functionality defined by this specification.

Lite Implementation:  An ICE implementation that omits certain
    functions, implementing only as much as is necessary for a peer
    that is not a lite implementation to gain the benefits of ICE.
    Lite implementations do not maintain any of the state machines and
    do not generate connectivity checks.

Controlling Agent:  The ICE agent that nominates a candidate pair.
    In any session, there is always one controlling agent and one
    controlled agent.

Controlled Agent:  The ICE agent that waits for the controlling agent
    to nominate a candidate pair.

Nomination:  The process of the controlling agent indicating to the
    controlled agent which candidate pair the ICE agents will use for
    sending and receiving data.  The nomination process defined in
    this specification was referred to as "regular nomination" in RFC
    5245.  The nomination process that was referred to as "aggressive
    nomination" in RFC 5245 has been deprecated in this specification.

Nominated, Nominated Flag:  Once the nomination of a candidate pair
    has succeeded, the candidate pair has become nominated, and the
    value of its nominated flag is set to true.

Selected Pair, Selected Candidate Pair:  The candidate pair used for
    sending and receiving data for a component of a data stream is
    referred to as the "selected pair".  Before selected pairs have
    been produced for a data stream, any valid pair associated with a
    component of a data stream can be used for sending and receiving
    data for the component.  Once there are nominated pairs for each
    component of a data stream, the nominated pairs become the
    selected pairs for the data stream.  The candidates associated
    with the selected pairs are referred to as "selected candidates".

Using Protocol, ICE Usage:  The protocol that uses ICE for NAT
    traversal.  A usage specification defines the protocol-specific
    details on how the procedures defined here are applied to that
    protocol.

Timer Ta:  The timer for generating new STUN or TURN transactions.

Timer RTO (Retransmission Timeout):  The retransmission timer for a
    given STUN or TURN transaction.