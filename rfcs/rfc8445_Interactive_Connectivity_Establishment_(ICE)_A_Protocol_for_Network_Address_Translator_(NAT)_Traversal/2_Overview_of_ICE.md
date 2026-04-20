# 2. Overview of ICE

In a typical ICE deployment, there are two endpoints (ICE agents)
that want to communicate.  Note that ICE is not intended for NAT
traversal for the signaling protocol, which is assumed to be provided
via another mechanism.  ICE assumes that the agents are able to
establish a signaling connection between each other.

Initially, the agents are ignorant of their own topologies.  In
particular, the agents may or may not be behind NATs (or multiple
tiers of NATs).  ICE allows the agents to discover enough information
about their topologies to potentially find one or more paths by which
they can establish a data session.

Figure 1 shows a typical ICE deployment.  The agents are labeled L
and R.  Both L and R are behind their own respective NATs, though
they may not be aware of it.  The type of NAT and its properties are
also unknown.  L and R are capable of engaging in a candidate
exchange process, whose purpose is to set up a data session between L
and R.  Typically, this exchange will occur through a signaling
server (e.g., a SIP proxy).

In addition to the agents, a signaling server, and NATs, ICE is
typically used in concert with STUN or TURN servers in the network.
Each agent can have its own STUN or TURN server, or they can be the
same.

                               +---------+
             +--------+        |Signaling|         +--------+
             | STUN   |        |Server   |         | STUN   |
             | Server |        +---------+         | Server |
             +--------+       /           \        +--------+
                             /             \
                            /               \
                           / <- Signaling -> \
                          /                   \
                   +--------+               +--------+
                   |  NAT   |               |  NAT   |
                   +--------+               +--------+
                      /                             \
                     /                               \
                 +-------+                       +-------+
                 | Agent |                       | Agent |
                 |   L   |                       |   R   |
                 +-------+                       +-------+

                     Figure 1: ICE Deployment Scenario

The basic idea behind ICE is as follows: each agent has a variety of
candidate transport addresses (combination of IP address and port for
a particular transport protocol, which is always UDP in this
specification) it could use to communicate with the other agent.
These might include:

o  A transport address on a directly attached network interface

o  A translated transport address on the public side of a NAT (a
    "server-reflexive" address)

o  A transport address allocated from a TURN server (a "relayed
    address")

Potentially, any of L's candidate transport addresses can be used to
communicate with any of R's candidate transport addresses.  In
practice, however, many combinations will not work.  For instance, if
L and R are both behind NATs, their directly attached interface
addresses are unlikely to be able to communicate directly (this is
why ICE is needed, after all!).  The purpose of ICE is to discover
which pairs of addresses will work.  The way that ICE does this is to
systematically try all possible pairs (in a carefully sorted order)
until it finds one or more that work.

## 2.1.  Gathering Candidates

In order to execute ICE, an ICE agent identifies and gathers one or
more address candidates.  A candidate has a transport address -- a
combination of IP address and port for a particular transport
protocol (with only UDP specified here).  There are different types
of candidates; some are derived from physical or logical network
interfaces, and others are discoverable via STUN and TURN.

The first category of candidates are those with a transport address
obtained directly from a local interface.  Such a candidate is called
a "host candidate".  The local interface could be Ethernet or Wi-Fi,
or it could be one that is obtained through a tunnel mechanism, such
as a Virtual Private Network (VPN) or Mobile IP (MIP).  In all cases,
such a network interface appears to the agent as a local interface
from which ports (and thus candidates) can be allocated.

Next, the agent uses STUN or TURN to obtain additional candidates.
These come in two flavors: translated addresses on the public side of
a NAT (server-reflexive candidates) and addresses on TURN servers
(relayed candidates).  When TURN servers are utilized, both types of
candidates are obtained from the TURN server.  If only STUN servers
are utilized, only server-reflexive candidates are obtained from
them.  The relationship of these candidates to the host candidate is

shown in Figure 2.  In this figure, both types of candidates are
discovered using TURN.  In the figure, the notation X:x means IP
address X and UDP port x.


                      To Internet

                          |
                          |
                          |  /------------  Relayed
                      Y:y | /               Address
                      +--------+
                      |        |
                      |  TURN  |
                      | Server |
                      |        |
                      +--------+
                          |
                          |
                          | /------------  Server
                   X1':x1'|/               Reflexive
                    +------------+         Address
                    |    NAT     |
                    +------------+
                          |
                          | /------------  Local
                      X:x |/               Address
                      +--------+
                      |        |
                      | Agent  |
                      |        |
                      +--------+


                     Figure 2: Candidate Relationships

When the agent sends a TURN Allocate request from IP address and port
X:x, the NAT (assuming there is one) will create a binding X1':x1',
mapping this server-reflexive candidate to the host candidate X:x.
Outgoing packets sent from the host candidate will be translated by
the NAT to the server-reflexive candidate.  Incoming packets sent to
the server-reflexive candidate will be translated by the NAT to the
host candidate and forwarded to the agent.  The host candidate
associated with a given server-reflexive candidate is the "base".

    Note: "Base" refers to the address an agent sends from for a
    particular candidate.  Thus, as a degenerate case, host candidates
    also have a base, but it's the same as the host candidate.

When there are multiple NATs between the agent and the TURN server,
the TURN request will create a binding on each NAT, but only the
outermost server-reflexive candidate (the one nearest the TURN
server) will be discovered by the agent.  If the agent is not behind
a NAT, then the base candidate will be the same as the server-
reflexive candidate, and the server-reflexive candidate is redundant
and will be eliminated.

The Allocate request then arrives at the TURN server.  The TURN
server allocates a port y from its local IP address Y, and generates
an Allocate response, informing the agent of this relayed candidate.
The TURN server also informs the agent of the server-reflexive
candidate, X1':x1', by copying the source transport address of the
Allocate request into the Allocate response.  The TURN server acts as
a packet relay, forwarding traffic between L and R.  In order to send
traffic to L, R sends traffic to the TURN server at Y:y, and the TURN
server forwards that to X1':x1', which passes through the NAT where
it is mapped to X:x and delivered to L.

When only STUN servers are utilized, the agent sends a STUN Binding
request [RFC5389] to its STUN server.  The STUN server will inform
the agent of the server-reflexive candidate X1':x1' by copying the
source transport address of the Binding request into the Binding
response.

## 2.2.  Connectivity Checks

Once L has gathered all of its candidates, it orders them by highest-
to-lowest priority and sends them to R over the signaling channel.
When R receives the candidates from L, it performs the same gathering
process and responds with its own list of candidates.  At the end of
this process, each ICE agent has a complete list of both its
candidates and its peer's candidates.  It pairs them up, resulting in
candidate pairs.  To see which pairs work, each agent schedules a
series of connectivity checks.  Each check is a STUN request/response
transaction that the client will perform on a particular candidate
pair by sending a STUN request from the local candidate to the remote
candidate.

The basic principle of the connectivity checks is simple:

   1.  Sort the candidate pairs in priority order.

   2.  Send checks on each candidate pair in priority order.

   3.  Acknowledge checks received from the other agent.


   With both agents performing a check on a candidate pair, the result
   is a 4-way handshake:

                  L                        R
                  -                        -
                  STUN request ->             \  L's
                            <- STUN response  /  check

                             <- STUN request  \  R's
                  STUN response ->            /  check

                    Figure 3: Basic Connectivity Check

It is important to note that STUN requests are sent to and from the
exact same IP addresses and ports that will be used for data (e.g.,
RTP, RTCP, or other protocols).  Consequently, agents demultiplex
STUN and data using the contents of the packets rather than the port
on which they are received.

Because a STUN Binding request is used for the connectivity check,
the STUN Binding response will contain the agent's translated
transport address on the public side of any NATs between the agent
and its peer.  If this transport address is different from that of
other candidates the agent already learned, it represents a new
candidate (peer-reflexive candidate), which then gets tested by ICE
just the same as any other candidate.

Because the algorithm above searches all candidate pairs, if a
working pair exists, the algorithm will eventually find it no matter
what order the candidates are tried in.  In order to produce faster
(and better) results, the candidates are sorted in a specified order.
The resulting list of sorted candidate pairs is called the
"checklist".

The agent works through the checklist by sending a STUN request for
the next candidate pair on the list periodically.  These are called
"ordinary checks".  When a STUN transaction succeeds, one or more
candidate pairs will become so-called "valid pairs" and will be added
to a candidate-pair list called the "valid list".

As an optimization, as soon as R gets L's check message, R schedules
a connectivity-check message to be sent to L on the same candidate
pair.  This is called a "triggered check", and it accelerates the
process of finding valid pairs.

At the end of this handshake, both L and R know that they can send
(and receive) messages end to end in both directions.

In general, the priority algorithm is designed so that candidates of
a similar type get similar priorities so that more direct routes
(that is, routes without data relays or NATs) are preferred over
indirect routes (routes with data relays or NATs).  Within those
guidelines, however, agents have a fair amount of discretion about
how to tune their algorithms.

A data stream might consist of multiple components (pieces of a data
stream that require their own set of candidates, e.g., RTP and RTCP).

## 2.3.  Nominating Candidate Pairs and Concluding ICE

ICE assigns one of the ICE agents in the role of the controlling
agent, and the other in the role of the controlled agent.  For each
component of a data stream, the controlling agent nominates a valid
pair (from the valid list) to be used for data.  The exact timing of
the nomination is based on local policy.

When nominating, the controlling agent lets the checks continue until
at least one valid pair for each component of a data stream is found,
and then it picks a valid pair and sends a STUN request on that pair,
using an attribute to indicate to the controlled peer that it has
been nominated.  This is shown in Figure 4.

             L                        R
             -                        -
             STUN request ->             \  L's
                       <- STUN response  /  check

                        <- STUN request  \  R's
             STUN response ->            /  check

             STUN request + attribute -> \  L's
                       <- STUN response  /  check

                           Figure 4: Nomination

Once the controlled agent receives the STUN request with the
attribute, it will check (unless the check has already been done) the
same pair.  If the transactions above succeed, the agents will set
the nominated flag for the pairs and will cancel any future checks
for that component of the data stream.  Once an agent has set the
nominated flag for each component of a data stream, the pairs become
the selected pairs.  After that, only the selected pairs will be used
for sending and receiving data associated with that data stream.

## 2.4.  ICE Restart

Once ICE is concluded, it can be restarted at any time for one or all
of the data streams by either ICE agent.  This is done by sending
updated candidate information indicating a restart.

## 2.5.  Lite Implementations

Certain ICE agents will always be connected to the public Internet
and have a public IP address at which it can receive packets from any
correspondent.  To make it easier for these devices to support ICE,
ICE defines a special type of implementation called "lite" (in
contrast to the normal full implementation).  Lite agents only use
host candidates and do not generate connectivity checks or run state
machines, though they need to be able to respond to connectivity
checks.

## 3.  ICE Usage

This document specifies generic use of ICE with protocols that
provide means to exchange candidate information between ICE agents.
The specific details (i.e., how to encode candidate information and
the actual candidate exchange process) for different protocols using
ICE (referred to as "using protocol") are described in separate usage
documents.

One mechanism that allows agents to exchange candidate information is
the utilization of Offer/Answer semantics (which are based on
[RFC3264]) as part of the SIP protocol [RFC3261] [ICE-SIP-SDP].

[RFC7825] defines an ICE usage for the Real-Time Streaming Protocol
(RTSP).  Note, however, that the ICE usage is based on RFC 5245.

