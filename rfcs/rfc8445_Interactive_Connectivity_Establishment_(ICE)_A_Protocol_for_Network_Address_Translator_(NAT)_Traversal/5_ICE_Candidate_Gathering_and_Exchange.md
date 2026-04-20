# 5.  ICE Candidate Gathering and Exchange

As part of ICE processing, both the initiating and responding agents
gather candidates, prioritize and eliminate redundant candidates, and
exchange candidate information with the peer as defined by the using
protocol (ICE usage).  Specifics of the candidate-encoding mechanism
and the semantics of candidate information exchange is out of scope
of this specification.

## 5.1.  Full Implementation

### 5.1.1.  Gathering Candidates

An ICE agent gathers candidates when it believes that communication
is imminent.  An initiating agent can do this based on a user
interface cue or on an explicit request to initiate a session.  Every
candidate has a transport address.  It also has a type and a base.
Four types are defined and gathered by this specification -- host
candidates, server-reflexive candidates, peer-reflexive candidates,
and relayed candidates.  The server-reflexive candidates are gathered
using STUN or TURN, and relayed candidates are obtained through TURN.
Peer-reflexive candidates are obtained in later phases of ICE, as a
consequence of connectivity checks.

The process for gathering candidates at the responding agent is
identical to the process for the initiating agent.  It is RECOMMENDED
that the responding agent begin this process immediately on receipt
of the candidate information, prior to alerting the user of the
application associated with the ICE session.

#### 5.1.1.1.  Host Candidates

Host candidates are obtained by binding to ports on an IP address
attached to an interface (physical or virtual, including VPN
interfaces) on the host.

For each component of each data stream the ICE agent wishes to use,
the agent SHOULD obtain a candidate on each IP address that the host
has, with the exceptions listed below.  The agent obtains each
candidate by binding to a UDP port on the specific IP address.  A
host candidate (and indeed every candidate) is always associated with
a specific component for which it is a candidate.

Each component has an ID assigned to it, called the "component ID".
For RTP/RTCP data streams, unless both RTP and RTCP are multiplexed
in the same UDP port (RTP/RTCP multiplexing), the RTP itself has a
component ID of 1, and RTCP has a component ID of 2.  In case of RTP/
RTCP multiplexing, a component ID of 1 is used for both RTP and RTCP.

When candidates are obtained, unless the agent knows for sure that
RTP/RTCP multiplexing will be used (i.e., the agent knows that the
other agent also supports, and is willing to use, RTP/RTCP
multiplexing), or unless the agent only supports RTP/RTCP
multiplexing, the agent MUST obtain a separate candidate for RTCP.
If an agent has obtained a candidate for RTCP, and ends up using RTP/
RTCP multiplexing, the agent does not need to perform connectivity
checks on the RTCP candidate.  Absence of a component ID 2 as such
does not imply use of RTCP/RTP multiplexing, as it could also mean
that RTCP is not used.

If an agent is using separate candidates for RTP and RTCP, it will
end up with 2*K host candidates if an agent has K IP addresses.

Note that the responding agent, when obtaining its candidates, will
typically know if the other agent supports RTP/RTCP multiplexing, in
which case it will not need to obtain a separate candidate for RTCP.
However, absence of a component ID 2 as such does not imply use of
RTCP/RTP multiplexing, as it could also mean that RTCP is not used.

The use of multiple components, other than for RTP/RTCP streams, is
discouraged as it increases the complexity of ICE processing.  If
multiple components are needed, the component IDs SHOULD start with 1
and increase by 1 for each component.

The base for each host candidate is set to the candidate itself.

The host candidates are gathered from all IP addresses with the
following exceptions:

o  Addresses from a loopback interface MUST NOT be included in the
    candidate addresses.

o  Deprecated IPv4-compatible IPv6 addresses [RFC4291] and IPv6 site-
    local unicast addresses [RFC3879] MUST NOT be included in the
    address candidates.

o  IPv4-mapped IPv6 addresses SHOULD NOT be included in the address
    candidates unless the application using ICE does not support IPv4
    (i.e., it is an IPv6-only application [RFC4038]).

o  If gathering one or more host candidates that correspond to an
    IPv6 address that was generated using a mechanism that prevents
    location tracking [RFC7721], host candidates that correspond to
    IPv6 addresses that do allow location tracking, are configured on
    the same interface, and are part of the same network prefix MUST
    NOT be gathered.  Similarly, when host candidates corresponding to an IPv6 address generated using a mechanism that prevents location
    tracking are gathered, then host candidates corresponding to IPv6
    link-local addresses [RFC4291] MUST NOT be gathered.

The IPv6 default address selection specification [RFC6724] specifies
that temporary addresses [RFC4941] are to be preferred over permanent addresses.

#### 5.1.1.2.  Server-Reflexive and Relayed Candidates

An ICE agent SHOULD gather server-reflexive and relayed candidates.
However, use of STUN and TURN servers may be unnecessary in certain
networks and use of TURN servers may be expensive, so some
deployments may elect not to use them.  If an agent does not gather
server-reflexive or relayed candidates, it is RECOMMENDED that the
functionality be implemented and just disabled through configuration,
so that it can be re-enabled through configuration if conditions
change in the future.

The agent pairs each host candidate with the STUN or TURN servers
with which it is configured or has discovered by some means.  It is
RECOMMENDED that a domain name be configured, the DNS procedures in
[RFC5389] (using SRV records with the "stun" service) be used to
discover the STUN server, and the DNS procedures in [RFC5766] (using
SRV records with the "turn" service) be used to discover the TURN
server.

When multiple STUN or TURN servers are available (or when they are
learned through DNS records and multiple results are returned), the
agent MAY gather candidates for all of them and SHOULD gather
candidates for at least one of them (one STUN server and one TURN
server).  It does so by pairing host candidates with STUN or TURN
servers, and for each pair, the agent sends a Binding or Allocate
request to the server from the host candidate.  Binding requests to a
STUN server are not authenticated, and any ALTERNATE-SERVER attribute
in a response is ignored.  Agents MUST support the backwards-
compatibility mode for the Binding request defined in [RFC5389].
Allocate requests SHOULD be authenticated using a long-term
credential obtained by the client through some other means.

The gathering process is controlled using a timer, Ta.  Every time Ta
expires, the agent can generate another new STUN or TURN transaction.
This transaction can be either a retry of a previous transaction that
failed with a recoverable error (such as authentication failure) or a
transaction for a new host candidate and STUN or TURN server pair.
The agent SHOULD NOT generate transactions more frequently than once
per each ta expiration.  See Section 14 for guidance on how to set Ta and the STUN retransmit timer, RTO.

The agent will receive a Binding or Allocate response.  A successful
Allocate response will provide the agent with a server-reflexive
candidate (obtained from the mapped address) and a relayed candidate
in the XOR-RELAYED-ADDRESS attribute.  If the Allocate request is
rejected because the server lacks resources to fulfill it, the agent
SHOULD instead send a Binding request to obtain a server-reflexive
candidate.  A Binding response will provide the agent with only a
server-reflexive candidate (also obtained from the mapped address).
The base of the server-reflexive candidate is the host candidate from
which the Allocate or Binding request was sent.  The base of a
relayed candidate is that candidate itself.  If a relayed candidate
is identical to a host candidate (which can happen in rare cases),
the relayed candidate MUST be discarded.

If an IPv6-only agent is in a network that utilizes NAT64 [RFC6146]
and DNS64 [RFC6147] technologies, it may also gather IPv4 server-
reflexive and/or relayed candidates from IPv4-only STUN or TURN
servers.  IPv6-only agents SHOULD also utilize IPv6 prefix discovery
[RFC7050] to discover the IPv6 prefix used by NAT64 (if any) and
generate server-reflexive candidates for each IPv6-only interface,
accordingly.  The NAT64 server-reflexive candidates are prioritized
like IPv4 server-reflexive candidates.

#### 5.1.1.3.  Computing Foundations

The ICE agent assigns each candidate a foundation.  Two candidates
have the same foundation when all of the following are true:

o  They have the same type (host, relayed, server reflexive, or peer
    reflexive).

o  Their bases have the same IP address (the ports can be different).

o  For reflexive and relayed candidates, the STUN or TURN servers
    used to obtain them have the same IP address (the IP address used
    by the agent to contact the STUN or TURN server).

o  They were obtained using the same transport protocol (TCP, UDP).

Similarly, two candidates have different foundations if their types
are different, their bases have different IP addresses, the STUN or
TURN servers used to obtain them have different IP addresses (the IP
addresses used by the agent to contact the STUN or TURN server), or
their transport protocols are different.

#### 5.1.1.4.  Keeping Candidates Alive

Once server-reflexive and relayed candidates are allocated, they MUST
be kept alive until ICE processing has completed, as described in
Section 8.3.  For server-reflexive candidates learned through a
Binding request, the bindings MUST be kept alive by additional
Binding requests to the server.  Refreshes for allocations are done
using the Refresh transaction, as described in [RFC5766].  The
Refresh requests will also refresh the server-reflexive candidate.

Host candidates do not time out, but the candidate addresses may
change or disappear for a number of reasons.  An ICE agent SHOULD
monitor the interfaces it uses, invalidate candidates whose base has
gone away, and acquire new candidates as appropriate when new IP
addresses (on new or currently used interfaces) appear.

### 5.1.2.  Prioritizing Candidates

The prioritization process results in the assignment of a priority to
each candidate.  Each candidate for a data stream MUST have a unique
priority that MUST be a positive integer between 1 and (2**31 - 1).
This priority will be used by ICE to determine the order of the
connectivity checks and the relative preference for candidates.
Higher-priority values give more priority over lower values.

An ICE agent SHOULD compute this priority using the formula in
Section 5.1.2.1 and choose its parameters using the guidelines in
Section 5.1.2.2.  If an agent elects to use a different formula, ICE
may take longer to converge since the agents will not be coordinated
in their checks.

The process for prioritizing candidates is common across the
initiating and the responding agent.

#### 5.1.2.1.  Recommended Formula

The recommended formula combines a preference for the candidate type
(server reflexive, peer reflexive, relayed, and host), a preference
for the IP address for which the candidate was obtained, and a
component ID using the following formula:

priority = (2^24)*(type preference) +
            (2^8)*(local preference) +
            (2^0)*(256 - component ID)

The type preference MUST be an integer from 0 (lowest preference) to
126 (highest preference) inclusive, MUST be identical for all
candidates of the same type, and MUST be different for candidates of different types.
The type preference for peer-reflexive candidates
MUST be higher than that of server-reflexive candidates.  Setting the
value to 0 means that candidates of this type will only be used as a
last resort.  Note that candidates gathered based on the procedures
of Section 5.1.1 will never be peer-reflexive candidates; candidates
of this type are learned from the connectivity checks performed by
ICE.

The local preference MUST be an integer from 0 (lowest preference) to
65535 (highest preference) inclusive.  When there is only a single IP
address, this value SHOULD be set to 65535.  If there are multiple
candidates for a particular component for a particular data stream
that have the same type, the local preference MUST be unique for each
one.  If an ICE agent is dual stack, the local preference SHOULD be
set according to the current best practice described in [RFC8421].

The component ID MUST be an integer between 1 and 256 inclusive.

#### 5.1.2.2.  Guidelines for Choosing Type and Local Preferences

The RECOMMENDED values for type preferences are 126 for host
candidates, 110 for peer-reflexive candidates, 100 for server-
reflexive candidates, and 0 for relayed candidates.

If an ICE agent is multihomed and has multiple IP addresses, the
recommendations in [RFC8421] SHOULD be followed.  If multiple TURN
servers are used, local priorities for the candidates obtained from
the TURN servers are chosen in a similar fashion as for multihomed
local candidates: the local preference value is used to indicate a
preference among different servers, but the preference MUST be unique
for each one.

When choosing type preferences, agents may take into account factors
such as latency, packet loss, cost, network topology, security,
privacy, and others.

### 5.1.3.  Eliminating Redundant Candidates

Next, the ICE agents (initiating and responding) eliminate redundant
candidates.  Two candidates can have the same transport address yet
different bases, and these would not be considered redundant.
Frequently, a server-reflexive candidate and a host candidate will be
redundant when the agent is not behind a NAT.  A candidate is
redundant if and only if its transport address and base equal those
of another candidate.  The agent SHOULD eliminate the redundant
candidate with the lower priority.


## 5.2.  Lite Implementation Procedures

Lite implementations only utilize host candidates.  For each IP
address, independent of an IP address family, there MUST be zero or
one candidate.  With the lite implementation, ICE cannot be used to
dynamically choose amongst candidates.  Therefore, including more
than one candidate from a particular IP address family is NOT
RECOMMENDED, since only a connectivity check can truly determine
whether to use one address or the other.  Instead, it is RECOMMENDED
that agents that have multiple public IP addresses run full ICE
implementations to ensure the best usage of its addresses.

Each component has an ID assigned to it, called the "component ID".
For RTP/RTCP data streams, unless RTCP is multiplexed in the same
port with RTP, the RTP itself has a component ID of 1 and RTCP a
component ID of 2.  If an agent is using RTCP without multiplexing,
it MUST obtain candidates for it.  However, absence of a component ID
2 as such does not imply use of RTCP/RTP multiplexing, as it could
also mean that RTCP is not used.

Each candidate is assigned a foundation.  The foundation MUST be
different for two candidates allocated from different IP addresses;
otherwise, it MUST be the same.  A simple integer that increments for
each IP address will suffice.  In addition, each candidate MUST be
assigned a unique priority amongst all candidates for the same data
stream.  If the formula in Section 5.1.2.1 is used to calculate the
priority, the type preference value SHOULD be set to 126.  If a host
is IPv4 only, the local preference value SHOULD be set to 65535.  If
a host is IPv6 or dual stack, the local preference value SHOULD be
set to the precedence value for IP addresses described in RFC 6724
[RFC6724].

Next, an agent chooses a default candidate for each component of each
data stream.  If a host is IPv4 only, there would only be one
candidate for each component of each data stream; therefore, that
candidate is the default.  If a host is IPv6 only, the default
candidate would typically be a globally scoped IPv6 address.  Dual-
stack hosts SHOULD allow configuration whether IPv4 or IPv6 is used
for the default candidate, and the configuration needs to be based on
which one its administrator believes has a higher chance of success
in the current network environment.

The procedures in this section are common across the initiating and
responding agents.

## 5.3.  Exchanging Candidate Information

ICE agents (initiating and responding) need the following information
about candidates to be exchanged.  Each ICE usage MUST define how the
information is exchanged with the using protocol.  This section
describes the information that needs to be exchanged.

Candidates:   One or more candidates.  For each candidate:

    Address:  The IP address and transport protocol port of the
        candidate.

    Transport:  The transport protocol of the candidate.  This MAY be
        omitted if the using protocol only runs over a single transport
        protocol.

    Foundation:  A sequence of up to 32 characters.

    Component ID:  The component ID of the candidate.  This MAY be
        omitted if the using protocol does not use the concept of
        components.

    Priority:  The 32-bit priority of the candidate.

    Type:  The type of the candidate.

    Related Address and Port:  The related IP address and port of the
        candidate.  These MAY be omitted or set to invalid values if
        the agent does not want to reveal them, e.g., for privacy
        reasons.

    Extensibility Parameters:  The using protocol might define means
        for adding new per-candidate ICE parameters in the future.

Lite or Full:   Whether the agent is a lite agent or full agent.

Connectivity-Check Pacing Value:  The pacing value for connectivity
    checks that the agent wishes to use.  This MAY be omitted if the
    agent wishes to use a defined default value.

Username Fragment and Password:  Values used to perform connectivity
    checks.  The values MUST be unguessable, with at least 128 bits of
    random number generator output used to generate the password, and
    at least 24 bits of output to generate the username fragment.

Extensions:  New media-stream or session-level attributes (ICE
    options).

If the using protocol is vulnerable to, and able to detect, ICE
mismatch (Section 5.4), a way is needed for the detecting agent to
convey this information to its peer.  It is a boolean flag.

The using protocol may (or may not) need to deal with backwards
compatibility with older implementations that do not support ICE.  If
a fallback mechanism to non-ICE is supported and is being used, then
presumably the using protocol provides a way of conveying the default
candidate (its IP address and port) in addition to the ICE
parameters.

Once an agent has sent its candidate information, it MUST be prepared
to receive both STUN and data packets on each candidate.  As
discussed in Section 12.1, data packets can be sent to a candidate
prior to its appearance as the default destination for data.

## 5.4.  ICE Mismatch

Certain middleboxes, such as ALGs, can alter signaling information in
ways that break ICE (e.g., by rewriting IP addresses in SDP).  This
is referred to as "ICE mismatch".  If the using protocol is
vulnerable to ICE mismatch, the responding agent needs to be able to
detect it and inform the peer ICE agent about the ICE mismatch.

Each using protocol needs to define whether the using protocol is
vulnerable to ICE mismatch, how ICE mismatch is detected, and whether
specific actions need to be taken when ICE mismatch is detected.