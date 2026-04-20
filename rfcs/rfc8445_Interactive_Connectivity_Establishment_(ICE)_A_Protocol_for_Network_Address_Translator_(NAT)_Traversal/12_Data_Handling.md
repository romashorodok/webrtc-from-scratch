# 12.  Data Handling

## 12.1.  Sending Data

An ICE agent MAY send data on any valid pair before selected pairs
have been produced for the data stream.

Once selected pairs have been produced for a data stream, an agent
MUST send data on those pairs only.

An agent sends data from the base of the local candidate to the
remote candidate.  In the case of a local relayed candidate, data is
forwarded through the base (located in the TURN server), using the
procedures defined in [RFC5766].

If the local candidate is a relayed candidate, it is RECOMMENDED that
an agent creates a channel on the TURN server towards the remote
candidate.  This is done using the procedures for channel creation as
defined in Section 11 of [RFC5766].

The selected pair for a component of a data stream is:

o  empty if the state of the checklist for that data stream is
    Running, and there is no previous selected pair for that component
    due to an ICE restart

o  equal to the previous selected pair for a component of a data
    stream if the state of the checklist for that data stream is
    Running, and there was a previous selected pair for that component
    due to an ICE restart

Unless an agent is able to produce a selected pair for each component
associated with a data stream, the agent MUST NOT continue sending
data for any component associated with that data stream.

### 12.1.1.  Procedures for Lite Implementations

A lite implementation MUST NOT send data until it has a valid list
that contains a candidate pair for each component of that data
stream.  Once that happens, the ICE agent MAY begin sending data
packets.  To do that, it sends data to the remote candidate in the
pair (setting the destination address and port of the packet equal to
that remote candidate) and will send it from the base associated with
the candidate pair used for sending data.  In case of a relayed
candidate, data is sent from the agent and forwarded through the base
(located in the TURN server), using the procedures defined in
[RFC5766].

## 12.2.  Receiving Data

Even though ICE agents are only allowed to send data using valid
candidate pairs (and, once selected pairs have been produced, only on
the selected pairs), ICE implementations SHOULD by default be
prepared to receive data on any of the candidates provided in the
most recent candidate exchange with the peer.  ICE usages MAY define
rules that differ from this, e.g., by defining that data will not be
sent until selected pairs have been produced for a data stream.

When an agent receives an RTP packet with a new source or destination
IP address for a particular RTP/RTCP data stream, it is RECOMMENDED
that the agent readjust its jitter buffers.

Section 8.2 of RFC 3550 [RFC3550] describes an algorithm for
detecting synchronization source (SSRC) collisions and loops.  These
algorithms are based, in part, on seeing different source transport
addresses with the same SSRC.  However, when ICE is used, such
changes will sometimes occur as the data streams switch between
candidates.  An agent will be able to determine that a data stream is
from the same peer as a consequence of the STUN exchange that
proceeds media data transmission.  Thus, if there is a change in the
source transport address, but the media data packets come from the
same peer agent, this MUST NOT be treated as an SSRC collision.