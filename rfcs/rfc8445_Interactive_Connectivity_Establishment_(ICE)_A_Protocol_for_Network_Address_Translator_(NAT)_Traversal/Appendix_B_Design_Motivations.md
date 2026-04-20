# Appendix B.  Design Motivations

ICE contains a number of normative behaviors that may themselves be
simple but derive from complicated or non-obvious thinking or use
cases that merit further discussion.  Since these design motivations
are not necessary to understand for purposes of implementation, they
are discussed here.  This appendix is non-normative.

## B.1.  Pacing of STUN Transactions

STUN transactions used to gather candidates and to verify
connectivity are paced out at an approximate rate of one new
transaction every Ta milliseconds.  Each transaction, in turn, has a
retransmission timer RTO that is a function of Ta as well.  Why are
these transactions paced, and why are these formulas used?

Sending of these STUN requests will often have the effect of creating
bindings on NAT devices between the client and the STUN servers.
Experience has shown that many NAT devices have upper limits on the
rate at which they will create new bindings.  Discussions in the IETF
ICE WG during the work on this specification concluded that once
every 5 ms is well supported.  This is why Ta has a lower bound of
5 ms.  Furthermore, transmission of these packets on the network
makes use of bandwidth and needs to be rate limited by the ICE agent.
Deployments based on earlier draft versions of [RFC5245] tended to
overload rate-constrained access links and perform poorly overall, in
addition to negatively impacting the network.  As a consequence, the
pacing ensures that the NAT device does not get overloaded and that
traffic is kept at a reasonable rate.

The definition of a "reasonable" rate is that STUN MUST NOT use more
bandwidth than the RTP itself will use, once data starts flowing.
The formula for Ta is designed so that, if a STUN packet were sent
every Ta seconds, it would consume the same amount of bandwidth as
RTP packets, summed across all data streams.  Of course, STUN has
retransmits, and the desire is to pace those as well.  For this
reason, RTO is set such that the first retransmit on the first
transaction happens just as the first STUN request on the last
transaction occurs.  Pictorially:

              First Packets              Retransmits



                    |                        |
                    |                        |
             -------+------           -------+------
            /               \        /               \
           /                 \      /                 \

           +--+    +--+    +--+    +--+    +--+    +--+
           |A1|    |B1|    |C1|    |A2|    |B2|    |C2|
           +--+    +--+    +--+    +--+    +--+    +--+

        ---+-------+-------+-------+-------+-------+------------ Time
           0       Ta      2Ta     3Ta     4Ta     5Ta


In this picture, there are three transactions that will be sent (for
example, in the case of candidate gathering, there are three host
candidate/STUN server pairs).  These are transactions A, B, and C.
The retransmit timer is set so that the first retransmission on the
first transaction (packet A2) is sent at time 3Ta.

Subsequent retransmits after the first will occur even less
frequently than Ta milliseconds apart, since STUN uses an exponential
backoff on its retransmissions.

This mechanism of a global minimum pacing interval of 5 ms is not
generally applicable to transport protocols, but it is applicable to
ICE based on the following reasoning.

o  Start with the following rules that would be generally applicable
    to transport protocols:

    1.  Let MaxBytes be the maximum number of bytes allowed to be
        outstanding in the network at startup, which SHOULD be 14600,
        as defined in Section 2 of [RFC6928].

    2.  Let HTO be the transaction timeout, which SHOULD be 2*RTT if
        RTT is known or 500 ms otherwise.  This is based on the RTO
        for STUN messages from [RFC5389] and the TCP initial RTO,
        which is 1 sec in [RFC6298].

    3.  Let MinPacing be the minimum pacing interval between
        transactions, which is 5 ms (see above).


   o  Observe that agents typically do not know the RTT for ICE
      transactions (connectivity checks in particular), meaning that HTO
      will almost always be 500 ms.

   o  Observe that a MinPacing of 5 ms and HTO of 500 ms gives at most
      100 packets/HTO, which for a typical ICE check of less than 120
      bytes means a maximum of 12000 outstanding bytes in the network,
      which is less than the maximum expressed by rule 1.

   o  Thus, for ICE, the rule set reduces to just the MinPacing rule,
      which is equivalent to having a global Ta value.

## B.2.  Candidates with Multiple Bases

Section 5.1.3 talks about eliminating candidates that have the same
transport address and base.  However, candidates with the same
transport addresses but different bases are not redundant.  When can
an ICE agent have two candidates that have the same IP address and
port but different bases?  Consider the topology of Figure 11:

          +----------+
          | STUN Srvr|
          +----------+
               |
               |
             -----
           //     \\
          |         |
         |  B:net10  |
          |         |
           \\     //
             -----
               |
               |
          +----------+
          |   NAT    |
          +----------+
               |
               |
             -----
           //     \\
          |    A    |
         |192.168/16 |
          |         |
           \\     //
             -----
               |
               |
               |192.168.1.100      -----
          +----------+           //     \\             +----------+
          |          |          |         |            |          |
          | Initiator|---------|  C:net10  |-----------| Responder|
          |          |10.0.1.100|         | 10.0.1.101 |          |
          +----------+           \\     //             +----------+
                                   -----

           Figure 11: Identical Candidates with Different Bases


In this case, the initiating agent is multihomed.  It has one IP
address, 10.0.1.100, on network C, which is a net 10 private network.
The responding agent is on this same network.  The initiating agent
is also connected to network A, which is 192.168/16, and has an IP
address of 192.168.1.100.  There is a NAT on this network, natting
into network B, which is another net 10 private network, but it is
not connected to network C.  There is a STUN server on network B.

The initiating agent obtains a host candidate on its IP address on
network C (10.0.1.100:2498) and a host candidate on its IP address on
network A (192.168.1.100:3344).  It performs a STUN query to its
configured STUN server from 192.168.1.100:3344.  This query passes
through the NAT, which happens to assign the binding 10.0.1.100:2498.
The STUN server reflects this in the STUN Binding response.  Now, the
initiating agent has obtained a server-reflexive candidate with a
transport address that is identical to a host candidate
(10.0.1.100:2498).  However, the server-reflexive candidate has a
base of 192.168.1.100:3344, and the host candidate has a base of
10.0.1.100:2498.

## B.3.  Purpose of the Related-Address and Related-Port Attributes

The candidate attribute contains two values that are not used at all
by ICE itself -- related address and related port.  Why are they
present?

There are two motivations for its inclusion.  The first is
diagnostic.  It is very useful to know the relationship between the
different types of candidates.  By including it, an ICE agent can
know which relayed candidate is associated with which reflexive
candidate, which in turn is associated with a specific host
candidate.  When checks for one candidate succeed but not for others,
this provides useful diagnostics on what is going on in the network.

The second reason has to do with off-path Quality-of-Service (QoS)
mechanisms.  When ICE is used in environments such as PacketCable
2.0, proxies will, in addition to performing normal SIP operations,
inspect the SDP in SIP messages and extract the IP address and port
for data traffic.  They can then interact, through policy servers,
with access routers in the network, to establish guaranteed QoS for
the data flows.  This QoS is provided by classifying the RTP traffic
based on 5-tuple and then providing it a guaranteed rate, or marking
its DSCP appropriately.  When a residential NAT is present, and a
relayed candidate gets selected for data, this relayed candidate will
be a transport address on an actual TURN server.  That address says
nothing about the actual transport address in the access router that
would be used to classify packets for QoS treatment.  Rather, the
server-reflexive candidate towards the TURN server is needed.  By
carrying the translation in the SDP, the proxy can use that transport
address to request QoS from the access router.

## B.4.  Importance of the STUN Username

ICE requires the usage of message integrity with STUN using its
short-term credential functionality.  The actual short-term
credential is formed by exchanging username fragments in the
candidate exchange.  The need for this mechanism goes beyond just
security; it is actually required for correct operation of ICE in the
first place.

Consider ICE agents L, R, and Z.  L and R are within private
enterprise 1, which is using 10.0.0.0/8.  Z is within private
enterprise 2, which is also using 10.0.0.0/8.  As it turns out, R and
Z both have IP address 10.0.1.1.  L sends candidates to Z.  Z
responds to L with its host candidates.  In this case, those
candidates are 10.0.1.1:8866 and 10.0.1.1:8877.  As it turns out, R
is in a session at that same time and is also using 10.0.1.1:8866 and
10.0.1.1:8877 as host candidates.  This means that R is prepared to
accept STUN messages on those ports, just as Z is.  L will send a
STUN request to 10.0.1.1:8866 and another to 10.0.1.1:8877.  However,
these do not go to Z as expected.  Instead, they go to R!  If R just
replied to them, L would believe it has connectivity to Z, when in
fact it has connectivity to a completely different user, R.  To fix
this, STUN short-term credential mechanisms are used.  The username
fragments are sufficiently random; thus it is highly unlikely that R
would be using the same values as Z.  Consequently, R would reject
the STUN request since the credentials were invalid.  In essence, the
STUN username fragments provide a form of transient host identifiers,
bound to a particular session established as part of the candidate
exchange.

An unfortunate consequence of the non-uniqueness of IP addresses is
that, in the above example, R might not even be an ICE agent.  It
could be any host, and the port to which the STUN packet is directed
could be any ephemeral port on that host.  If there is an application
listening on this socket for packets, and it is not prepared to
handle malformed packets for whatever protocol is in use, the
operation of that application could be affected.  Fortunately, since
the ports exchanged are ephemeral and usually drawn from the dynamic
or registered range, the odds are good that the port is not used to
run a server on host R, but rather is the agent side of some
protocol.  This decreases the probability of hitting an allocated
port, due to the transient nature of port usage in this range.
However, the possibility of a problem does exist, and network
deployers need to be prepared for it.  Note that this is not a
problem specific to ICE; stray packets can arrive at a port at any
time for any type of protocol, especially ones on the public
Internet.  As such, this requirement is just restating a general
design guideline for Internet applications -- be prepared for unknown
packets on any port.


## B.5.  The Candidate Pair Priority Formula

The priority for a candidate pair has an odd form.  It is:

    pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

Why is this?  When the candidate pairs are sorted based on this
value, the resulting sorting has the MAX/MIN property.  This means
that the pairs are first sorted based on decreasing value of the
minimum of the two priorities.  For pairs that have the same value of
the minimum priority, the maximum priority is used to sort amongst
them.  If the max and the min priorities are the same, the
controlling agent's priority is used as the tiebreaker in the last
part of the expression.  The factor of 2*32 is used since the
priority of a single candidate is always less than 2*32, resulting in
the pair priority being a "concatenation" of the two component
priorities.  This creates the MAX/MIN sorting.  MAX/MIN ensures that,
for a particular ICE agent, a lower-priority candidate is never used
until all higher-priority candidates have been tried.

## B.6.  Why Are Keepalives Needed?

Once data begins flowing on a candidate pair, it is still necessary
to keep the bindings alive at intermediate NATs for the duration of
the session.  Normally, the data stream packets themselves (e.g.,
RTP) meet this objective.  However, several cases merit further
discussion.  Firstly, in some RTP usages, such as SIP, the data
streams can be "put on hold".  This is accomplished by using the SDP
"sendonly" or "inactive" attributes, as defined in RFC 3264
[RFC3264].  RFC 3264 directs implementations to cease transmission of
data in these cases.  However, doing so may cause NAT bindings to
time out, and data won't be able to come off hold.

Secondly, some RTP payload formats, such as the payload format for
text conversation [RFC4103], may send packets so infrequently that
the interval exceeds the NAT binding timeouts.

Thirdly, if silence suppression is in use, long periods of silence
may cause data transmission to cease sufficiently long for NAT
bindings to time out.

For these reasons, the data packets themselves cannot be relied upon.
ICE defines a simple periodic keepalive utilizing STUN Binding
Indications.  This makes its bandwidth requirements highly
predictable and thus amenable to QoS reservations.

## B.7.  Why Prefer Peer-Reflexive Candidates?

Section 5.1.2 describes procedures for computing the priority of a
candidate based on its type and local preferences.  That section
requires that the type preference for peer-reflexive candidates
always be higher than server reflexive.  Why is that?  The reason has
to do with the security considerations in Section 19.  It is much
easier for an attacker to cause an ICE agent to use a false server-
reflexive candidate rather than a false peer-reflexive candidate.
Consequently, attacks against address gathering with Binding requests
are thwarted by ICE by preferring the peer-reflexive candidates.

## B.8.  Why Are Binding Indications Used for Keepalives?

Data keepalives are described in Section 11.  These keepalives make
use of STUN when both endpoints are ICE capable.  However, rather
than using a Binding request transaction (which generates a
response), the keepalives use an Indication.  Why is that?

The primary reason has to do with network QoS mechanisms.  Once data
begins flowing, network elements will assume that the data stream has
a fairly regular structure, making use of periodic packets at fixed
intervals, with the possibility of jitter.  If an ICE agent is
sending data packets, and then receives a Binding request, it would
need to generate a response packet along with its data packets.  This
will increase the actual bandwidth requirements for the 5-tuple
carrying the data packets and introduce jitter in the delivery of
those packets.  Analysis has shown that this is a concern in certain
Layer 2 access networks that use fairly tight packet schedulers for
data.

Additionally, using a Binding Indication allows integrity to be
disabled, which may result in better performance.  This is useful for
large-scale endpoints, such as Public Switched Telephone Network
(PSTN) gateways and Session Border Controllers (SBCs).

## B.9.  Selecting Candidate Type Preference

One criterion for selecting type and local preference values is the
use of a data intermediary, such as a TURN server, a tunnel service
such as a VPN server, or NAT.  With a data intermediary, if data is
sent to that candidate, it will first transit the data intermediary
before being received.  One type of candidate that involves a data
intermediary is the relayed candidate.  Another type is the host
candidate, which is obtained from a VPN interface.  When data is
transited through a data intermediary, it can have a positive or
negative effect on the latency between transmission and reception.
It may or may not increase the packet losses, because of the
additional router hops that may be taken.  It may increase the cost
of providing service, since data will be routed in and right back out
of a data intermediary run by a provider.  If these concerns are
important, the type preference for relayed candidates needs to be
carefully chosen.

Another criterion for selecting preferences is the IP address family.
ICE works with both IPv4 and IPv6.  It provides a transition
mechanism that allows dual-stack hosts to prefer connectivity over
IPv6 but to fall back to IPv4 in case the v6 networks are
disconnected.  Implementation SHOULD follow the guidelines from
[RFC8421] to avoid excessive delays in the connectivity-check phase
if broken paths exist.

Another criterion for selecting preferences is topological awareness.
This is beneficial for candidates that make use of intermediaries.
In those cases, if an ICE agent has preconfigured or dynamically
discovered knowledge of the topological proximity of the
intermediaries to itself, it can use that to assign higher local
preferences to candidates obtained from closer intermediaries.

Another criterion for selecting preferences might be security or
privacy.  If a user is a telecommuter, and therefore connected to a
corporate network and a local home network, the user may prefer their
voice traffic to be routed over the VPN or similar tunnel in order to
keep it on the corporate network when communicating within the
enterprise but may use the local network when communicating with
users outside of the enterprise.  In such a case, a VPN address would
have a higher local preference than any other address.
