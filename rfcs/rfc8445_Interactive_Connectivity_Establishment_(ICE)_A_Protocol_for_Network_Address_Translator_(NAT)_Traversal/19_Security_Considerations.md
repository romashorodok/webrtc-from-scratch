# 19.  Security Considerations

## 19.1.  IP Address Privacy

The process of probing for candidates reveals the source addresses of
the client and its peer to any on-network listening attacker, and the
process of exchanging candidates reveals the addresses to any
attacker that is able to see the negotiation.  Some addresses, such
as the server-reflexive addresses gathered through the local
interface of VPN users, may be sensitive information.  If these
potential attacks cannot be mitigated, ICE usages can define
mechanisms for controlling which addresses are revealed to the
negotiation and/or probing process.  Individual implementations may
also have implementation-specific rules for controlling which
addresses are revealed.  For example, [WebRTC-IP-HANDLING] provides
additional information about the privacy aspects of revealing IP
addresses via ICE for WebRTC applications.  ICE implementations where
such issues can arise are RECOMMENDED to provide a programmatic or
user interface that provides control over which network interfaces
are used to generate candidates.

Based on the types of candidates provided by the peer, and the
results of the connectivity tests performed against those candidates,
the peer might be able to determine characteristics of the local
network, e.g., if different timings are apparent to the peer.  Within
the limit, the peer might be able to probe the local network.

There are several types of attacks possible in an ICE system.  The
subsections consider these attacks and their countermeasures.

## 19.2.  Attacks on Connectivity Checks

An attacker might attempt to disrupt the STUN connectivity checks.
Ultimately, all of these attacks fool an ICE agent into thinking
something incorrect about the results of the connectivity checks.
Depending on the type of attack, the attacker needs to have different
capabilities.  In some cases, the attacker needs to be on the path of
the connectivity checks.  In other cases, the attacker does not need
to be on the path, as long as it is able to generate STUN
connectivity checks.  While attacks on connectivity checks are
typically performed by network entities, if an attacker is able to
control an endpoint, it might be able to trigger connectivity-check
attacks.  The possible false conclusions an attacker can try and
cause are:

False Invalid:  An attacker can fool a pair of agents into thinking a
    candidate pair is invalid, when it isn't.  This can be used to
    cause an agent to prefer a different candidate (such as one
    injected by the attacker) or to disrupt a call by forcing all
    candidates to fail.

False Valid:  An attacker can fool a pair of agents into thinking a
    candidate pair is valid, when it isn't.  This can cause an agent
    to proceed with a session but then not be able to receive any
    data.

False Peer-Reflexive Candidate:  An attacker can cause an agent to
    discover a new peer-reflexive candidate when it is not expected
    to.  This can be used to redirect data streams to a DoS target or
    to the attacker, for eavesdropping or other purposes.

False Valid on False Candidate:  An attacker has already convinced an
    agent that there is a candidate with an address that does not
    actually route to that agent (e.g., by injecting a false peer-
    reflexive candidate or false server-reflexive candidate).  The
    attacker then launches an attack that forces the agents to believe
    that this candidate is valid.

    If an attacker can cause a false peer-reflexive candidate or false
    valid on a false candidate, it can launch any of the attacks
    described in [RFC5389].

To force the false invalid result, the attacker has to wait for the
connectivity check from one of the agents to be sent.  When it is,
the attacker needs to inject a fake response with an unrecoverable
error response (such as a 400), or drop the response so that it never
reaches the agent.  However, since the candidate is, in fact, valid,
the original request may reach the peer agent and result in a success
response.  The attacker needs to force this packet or its response to
be dropped through a DoS attack, a Layer 2 network disruption, or
another technique.  If it doesn't do this, the success response will
also reach the originator, alerting it to a possible attack.  The
ability for the attacker to generate a fake response is mitigated
through the STUN short-term credential mechanism.  In order for this
response to be processed, the attacker needs the password.  If the
candidate exchange signaling is secured, the attacker will not have
the password, and its response will be discarded.

Spoofed ICMP Hard Errors (Type 3, codes 2-4) can also be used to
create false invalid results.  If an ICE agent implements a response
to these ICMP errors, the attacker is capable of generating an ICMP
message that is delivered to the agent sending the connectivity
check.  The validation of the ICMP error message by the agent is its
only defense.  For Type 3 code=4, the outer IP header provides no
validation, unless the connectivity check was sent with DF=0.  For
codes 2 or 3, which are originated by the host, the address is
expected to be any of the remote agent's host, reflexive, or relay
candidate IP addresses.  The ICMP message includes the IP header and
UDP header of the message triggering the error.  These fields also
need to be validated.  The IP destination and UDP destination port
need to match either the targeted candidate address and port or the
candidate's base address.  The source IP address and port can be any
candidate for the same base address of the agent sending the
connectivity check.  Thus, any attacker having access to the exchange
of the candidates will have the necessary information.  Hence, the
validation is a weak defense, and the sending of spoofed ICMP attacks
is also possible for off-path attackers from a node in a network
without source address validation.

Forcing the fake valid result works in a similar way.  The attacker
needs to wait for the Binding request from each agent and inject a
fake success response.  Again, due to the STUN short-term credential
mechanism, in order for the attacker to inject a valid success
response, the attacker needs the password.  Alternatively, the
attacker can route (e.g., using a tunneling mechanism) a valid
success response, which normally would be dropped or rejected by the
network, to the agent.

Forcing the false peer-reflexive candidate result can be done with
either fake requests or responses, or with replays.  We consider the
fake requests and responses case first.  It requires the attacker to
send a Binding request to one agent with a source IP address and port
for the false candidate.  In addition, the attacker needs to wait for
a Binding request from the other agent and generate a fake response
with a XOR-MAPPED-ADDRESS attribute containing the false candidate.
Like the other attacks described here, this attack is mitigated by
the STUN message integrity mechanisms and secure candidate exchanges.

Forcing the false peer-reflexive candidate result with packet replays
is different.  The attacker waits until one of the agents sends a
check.  It intercepts this request and replays it towards the other
agent with a faked source IP address.  It also needs to prevent the
original request from reaching the remote agent, by either launching
a DoS attack to cause the packet to be dropped or forcing it to be
dropped using Layer 2 mechanisms.  The replayed packet is received at
the other agent, and accepted, since the integrity check passes (the
integrity check cannot and does not cover the source IP address and
port).  It is then responded to.  This response will contain a XOR-
MAPPED-ADDRESS with the false candidate, and it will be sent to that
false candidate.  The attacker then needs to receive it and relay it
towards the originator.


The other agent will then initiate a connectivity check towards that
false candidate.  This validation needs to succeed.  This requires
the attacker to force a false valid on a false candidate.  The
injecting of fake requests or responses to achieve this goal is
prevented using the integrity mechanisms of STUN and the candidate
exchange.  Thus, this attack can only be launched through replays.
To do that, the attacker needs to intercept the check towards this
false candidate and replay it towards the other agent.  Then, it
needs to intercept the response and replay that back as well.

This attack is very hard to launch unless the attacker is identified
by the fake candidate.  This is because it requires the attacker to
intercept and replay packets sent by two different hosts.  If both
agents are on different networks (e.g., across the public Internet),
this attack can be hard to coordinate, since it needs to occur
against two different endpoints on different parts of the network at
the same time.

If the attacker itself is identified by the fake candidate, the
attack is easier to coordinate.  However, if the data path is secured
(e.g., using the Secure Real-time Transport Protocol (SRTP)
[RFC3711]), the attacker will not be able to process the data
packets, but will only be able to discard them, effectively disabling
the data stream.  However, this attack requires the agent to disrupt
packets in order to block the connectivity check from reaching the
target.  In that case, if the goal is to disrupt the data stream,
it's much easier to just disrupt it with the same mechanism, rather
than attack ICE.

## 19.3.  Attacks on Server-Reflexive Address Gathering

ICE endpoints make use of STUN Binding requests for gathering server-
reflexive candidates from a STUN server.  These requests are not
authenticated in any way.  As a consequence, there are numerous
techniques an attacker can employ to provide the client with a false
server-reflexive candidate:

o  An attacker can compromise the DNS, causing DNS queries to return
    a rogue STUN server address.  That server can provide the client
    with fake server-reflexive candidates.  This attack is mitigated
    by DNS security, though DNSSEC is not required to address it.

o  An attacker that can observe STUN messages (such as an attacker on
    a shared network segment, like Wi-Fi) can inject a fake response
    that is valid and will be accepted by the client.

o  An attacker can compromise a STUN server and cause it to send
    responses with incorrect mapped addresses.

A false mapped address learned by these attacks will be used as a
server-reflexive candidate in the establishment of the ICE session.
For this candidate to actually be used for data, the attacker also
needs to attack the connectivity checks, and in particular, force a
false valid on a false candidate.  This attack is very hard to launch
if the false address identifies a fourth party (neither the
initiator, responder, nor attacker), since it requires attacking the
checks generated by each ICE agent in the session and is prevented by
SRTP if it identifies the attacker itself.

If the attacker elects not to attack the connectivity checks, the
worst it can do is prevent the server-reflexive candidate from being
used.  However, if the peer agent has at least one candidate that is
reachable by the agent under attack, the STUN connectivity checks
themselves will provide a peer-reflexive candidate that can be used
for the exchange of data.  Peer-reflexive candidates are generally
preferred over server-reflexive candidates.  As such, an attack
solely on the STUN address gathering will normally have no impact on
a session at all.

## 19.4.  Attacks on Relayed Candidate Gathering

An attacker might attempt to disrupt the gathering of relayed
candidates, forcing the client to believe it has a false relayed
candidate.  Exchanges with the TURN server are authenticated using a
long-term credential.  Consequently, injection of fake responses or
requests will not work.  In addition, unlike Binding requests,
Allocate requests are not susceptible to replay attacks with modified
source IP addresses and ports, since the source IP address and port
are not utilized to provide the client with its relayed candidate.

Even if an attacker has caused the client to believe in a false
relayed candidate, the connectivity checks cause such a candidate to
be used only if they succeed.  Thus, an attacker needs to launch a
false valid on a false candidate, per above, which is a very
difficult attack to coordinate.

## 19.5.  Insider Attacks

In addition to attacks where the attacker is a third party trying to
insert fake candidate information or STUN messages, there are attacks
possible with ICE when the attacker is an authenticated and valid
participant in the ICE exchange.

### 19.5.1.  STUN Amplification Attack

The STUN amplification attack is similar to a "voice hammer" attack,
where the attacker causes other agents to direct voice packets to the
attack target.  However, instead of voice packets being directed to
the target, STUN connectivity checks are directed to the target.  The
attacker sends a large number of candidates, say, 50.  The responding
agent receives the candidate information and starts its checks, which
are directed at the target, and consequently, never generate a
response.  In the case of WebRTC, the user might not even be aware
that this attack is ongoing, since it might be triggered in the
background by malicious JavaScript code that the user has fetched.
The answerer will start a new connectivity check every Ta ms (say,
Ta=50ms).  However, the retransmission timers are set to a large
number due to the large number of candidates.  As a consequence,
packets will be sent at an interval of one every Ta milliseconds and
then with increasing intervals after that.  Thus, STUN will not send
packets at a rate faster than data would be sent, and the STUN
packets persist only briefly, until ICE fails for the session.
Nonetheless, this is an amplification mechanism.

It is impossible to eliminate the amplification, but the volume can
be reduced through a variety of heuristics.  ICE agents SHOULD limit
the total number of connectivity checks they perform to 100.
Additionally, agents MAY limit the number of candidates they will
accept.

Frequently, protocols that wish to avoid these kinds of attacks force
the initiator to wait for a response prior to sending the next
message.  However, in the case of ICE, this is not possible.  It is
not possible to differentiate the following two cases:

o  There was no response because the initiator is being used to
    launch a DoS attack against an unsuspecting target that will not
    respond.

o  There was no response because the IP address and port are not
    reachable by the initiator.

In the second case, another check will be sent at the next
opportunity, while in the former case, no further checks will be
sent.
