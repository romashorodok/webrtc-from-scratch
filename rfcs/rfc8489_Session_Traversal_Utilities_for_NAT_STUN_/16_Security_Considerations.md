# 16.  Security Considerations

Implementations and deployments of a STUN Usage using TLS or DTLS
MUST follow the recommendations in [BCP195].

Implementations and deployments of a STUN Usage using the long-term
credential mechanism (Section 9.2) MUST follow the recommendations in
Section 5 of [RFC7616].

## 16.1.  Attacks against the Protocol

### 16.1.1.  Outside Attacks

An attacker can try to modify STUN messages in transit, in order to
cause a failure in STUN operation.  These attacks are detected for
both requests and responses through the message-integrity mechanism,
using either a short-term or long-term credential.  Of course, once
detected, the manipulated packets will be dropped, causing the STUN
transaction to effectively fail.  This attack is possible only by an
on-path attacker.

An attacker that can observe, but not modify, STUN messages in-
transit (for example, an attacker present on a shared access medium,
such as Wi-Fi) can see a STUN request and then immediately send a
STUN response, typically an error response, in order to disrupt STUN
processing.  This attack is also prevented for messages that utilize
MESSAGE-INTEGRITY.  However, some error responses, those related to
authentication in particular, cannot be protected by MESSAGE-
INTEGRITY.  When STUN itself is run over a secure transport protocol
(e.g., TLS), these attacks are completely mitigated.

Depending on the STUN Usage, these attacks may be of minimal
consequence and thus do not require message integrity to mitigate.
For example, when STUN is used to a basic STUN server to discover a
server reflexive candidate for usage with ICE, authentication and
message integrity are not required since these attacks are detected
during the connectivity check phase.  The connectivity checks
themselves, however, require protection for proper operation of ICE
overall.  As described in Section 13, STUN Usages describe when
authentication and message integrity are needed.

Since STUN uses the HMAC of a shared secret for authentication and
integrity protection, it is subject to offline dictionary attacks.
When authentication is utilized, it SHOULD be with a strong password
that is not readily subject to offline dictionary attacks.
Protection of the channel itself, using TLS or DTLS, mitigates these
attacks.

STUN supports both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256,
which makes STUN subject to bid-down attacks by an on-path attacker.
An attacker could strip the MESSAGE-INTEGRITY-SHA256 attribute,
leaving only the MESSAGE-INTEGRITY attribute and thus exploiting a
potential vulnerability.  Protection of the channel itself, using TLS
or DTLS, mitigates these attacks.  Timely removal of the support of
MESSAGE-INTEGRITY in a future version of STUN is necessary.

Note: The use of SHA-256 for password hashing does not meet modern
standards, which are aimed at slowing down exhaustive password
searches by providing a relatively slow minimum time to compute the
hash.  Although better algorithms such as Argon2 [Argon2] are
available, SHA-256 was chosen for consistency with [RFC7616].

### 16.1.2.  Inside Attacks

A rogue client may try to launch a DoS attack against a server by
sending it a large number of STUN requests.  Fortunately, STUN
requests can be processed statelessly by a server, making such
attacks hard to launch effectively.

A rogue client may use a STUN server as a reflector, sending it
requests with a falsified source IP address and port.  In such a
case, the response would be delivered to that source IP and port.
There is no amplification of the number of packets with this attack
(the STUN server sends one packet for each packet sent by the
client), though there is a small increase in the amount of data,
since STUN responses are typically larger than requests.  This attack
is mitigated by ingress source address filtering.

Revealing the specific software version of the agent through the
SOFTWARE attribute might allow them to become more vulnerable to
attacks against software that is known to contain security holes.
Implementers SHOULD make usage of the SOFTWARE attribute a
configurable option.

### 16.1.3.  Bid-Down Attacks

This document adds the possibility of selecting different algorithms
to protect the confidentiality of the passwords stored on the server
side when using the long-term credential mechanism while still

ensuring compatibility with MD5, which was the algorithm used in
[RFC5389].  This selection works by having the server send to the
client the list of algorithms supported in a PASSWORD-ALGORITHMS
attribute and having the client send back a PASSWORD-ALGORITHM
attribute containing the algorithm selected.

Because the PASSWORD-ALGORITHMS attribute has to be sent in an
unauthenticated response, an on-path attacker wanting to exploit an
eventual vulnerability in MD5 can just strip the PASSWORD-ALGORITHMS
attribute from the unprotected response, thus making the server
subsequently act as if the client was implementing the version of
this protocol defined in [RFC5389].

To protect against this attack and other similar bid-down attacks,
the nonce is enriched with a set of security bits that indicates
which security features are in use.  In the case of the selection of
the password algorithm, the matching bit is set in the nonce returned
by the server in the same response that contains the PASSWORD-
ALGORITHMS attribute.  Because the nonce used in subsequent
authenticated transactions is verified by the server to be identical
to what was originally sent, it cannot be modified by an on-path
attacker.  Additionally, the client is mandated to copy the received
PASSWORD-ALGORITHMS attribute in the next authenticated transaction
to that server.

An on-path attack that removes the PASSWORD-ALGORITHMS will be
detected because the client will not be able to send it back to the
server in the next authenticated transaction.  The client will detect
that attack because the security bit is set but the matching
attribute is missing; this will end the session.  A client using an
older version of this protocol will not send the PASSWORD-ALGORITHMS
back but can only use MD5 anyway, so the attack is inconsequential.

The on-path attack may also try to remove the security bit together
with the PASSWORD-ALGORITHMS attribute, but the server will discover
that when the next authenticated transaction contains an invalid
nonce.

An on-path attack that removes some algorithms from the PASSWORD-
ALGORITHMS attribute will be equally defeated because that attribute
will be different from the original one when the server verifies it
in the subsequent authenticated transaction.

Note that the bid-down protection mechanism introduced in this
document is inherently limited by the fact that it is not possible to
detect an attack until the server receives the second request after
the 401 (Unauthenticated) response.


SHA-256 was chosen as the new default for password hashing for its
compatibility with [RFC7616], but because SHA-256 (like MD5) is a
comparatively fast algorithm, it does little to deter brute-force
attacks.  Specifically, this means that if the user has a weak
password, an attacker that captures a single exchange can use a
brute-force attack to learn the user's password and then potentially
impersonate the user to the server and to other servers where the
same password was used.  Note that such an attacker can impersonate
the user to the server itself without any brute-force attack.

A stronger (which is to say, slower) algorithm, like Argon2 [Argon2],
would help both of these cases; however, in the first case, it would
only help after the database entry for this user is updated to
exclusively use that stronger mechanism.

The bid-down defenses in this protocol prevent an attacker from
forcing the client and server to complete a handshake using weaker
algorithms than they jointly support, but only if the weakest joint
algorithm is strong enough that it cannot be compromised by a brute-
force attack.  However, this does not defend against many attacks on
those algorithms; specifically, an on-path attacker might perform a
bid-down attack on a client that supports both Argon2 [Argon2] and
SHA-256 for password hashing and use that to collect a MESSAGE-
INTEGRITY-SHA256 value that it can then use for an offline brute-
force attack.  This would be detected when the server receives the
second request, but that does not prevent the attacker from obtaining
the MESSAGE-INTEGRITY-SHA256 value.

Similarly, an attack against the USERHASH mechanism will not succeed
in establishing a session as the server will detect that the feature
was discarded on path, but the client would still have been convinced
to send its username in the clear in the USERNAME attribute, thus
disclosing it to the attacker.

Finally, when the bid-down protection mechanism is employed for a
future upgrade of the HMAC algorithm used to protect messages, it
will offer only a limited protection if the current HMAC algorithm is
already compromised.

## 16.2.  Attacks Affecting the Usage

This section lists attacks that might be launched against a usage of
STUN.  Each STUN Usage must consider whether these attacks are
applicable to it and, if so, discuss countermeasures.

Most of the attacks in this section revolve around an attacker
modifying the reflexive address learned by a STUN client through a
Binding request/response transaction.  Since the usage of the

reflexive address is a function of the usage, the applicability and
remediation of these attacks are usage-specific.  In common
situations, modification of the reflexive address by an on-path
attacker is easy to do.  Consider, for example, the common situation
where STUN is run directly over UDP.  In this case, an on-path
attacker can modify the source IP address of the Binding request
before it arrives at the STUN server.  The STUN server will then
return this IP address in the XOR-MAPPED-ADDRESS attribute to the
client and send the response back to that (falsified) IP address and
port.  If the attacker can also intercept this response, it can
direct it back towards the client.  Protecting against this attack by
using a message-integrity check is impossible, since a message-
integrity value cannot cover the source IP address and the
intervening NAT must be able to modify this value.  Instead, one
solution to prevent the attacks listed below is for the client to
verify the reflexive address learned, as is done in ICE [RFC8445].

Other usages may use other means to prevent these attacks.

### 16.2.1.  Attack I: Distributed DoS (DDoS) against a Target

In this attack, the attacker provides one or more clients with the
same faked reflexive address that points to the intended target.
This will trick the STUN clients into thinking that their reflexive
addresses are equal to that of the target.  If the clients hand out
that reflexive address in order to receive traffic on it (for
example, in SIP messages), the traffic will instead be sent to the
target.  This attack can provide substantial amplification,
especially when used with clients that are using STUN to enable
multimedia applications.  However, it can only be launched against
targets for which packets from the STUN server to the target pass
through the attacker, limiting the cases in which it is possible.

### 16.2.2.  Attack II: Silencing a Client

In this attack, the attacker provides a STUN client with a faked
reflexive address.  The reflexive address it provides is a transport
address that routes to nowhere.  As a result, the client won't
receive any of the packets it expects to receive when it hands out
the reflexive address.  This exploitation is not very interesting for
the attacker.  It impacts a single client, which is frequently not
the desired target.  Moreover, any attacker that can mount the attack
could also deny service to the client by other means, such as
preventing the client from receiving any response from the STUN
server, or even a DHCP server.  As with the attack described in
Section 16.2.1, this attack is only possible when the attacker is on
path for packets sent from the STUN server towards this unused IP
address.

### 16.2.3.  Attack III: Assuming the Identity of a Client

This attack is similar to attack II.  However, the faked reflexive
address points to the attacker itself.  This allows the attacker to
receive traffic that was destined for the client.

### 16.2.4.  Attack IV: Eavesdropping

In this attack, the attacker forces the client to use a reflexive
address that routes to itself.  It then forwards any packets it
receives to the client.  This attack allows the attacker to observe
all packets sent to the client.  However, in order to launch the
attack, the attacker must have already been able to observe packets
from the client to the STUN server.  In most cases (such as when the
attack is launched from an access network), this means that the
attacker could already observe packets sent to the client.  This
attack is, as a result, only useful for observing traffic by
attackers on the path from the client to the STUN server, but not
generally on the path of packets being routed towards the client.

Note that this attack can be trivially launched by the STUN server
itself, so users of STUN servers should have the same level of trust
in the users of STUN servers as any other node that can insert itself
into the communication flow.

## 16.3.  Hash Agility Plan

This specification uses HMAC-SHA256 for computation of the message
integrity, sometimes in combination with HMAC-SHA1.  If, at a later
time, HMAC-SHA256 is found to be compromised, the following remedy
should be applied:

o  Both a new message-integrity attribute and a new STUN Security
    Feature bit will be allocated in a Standards Track document.  The
    new message-integrity attribute will have its value computed using
    a new hash.  The STUN Security Feature bit will be used to
    simultaneously 1) signal to a STUN client using the long-term
    credential mechanism that this server supports this new hash
    algorithm and 2) prevent bid-down attacks on the new message-
    integrity attribute.

o  STUN clients and servers using the short-term credential mechanism
    will need to update the external mechanism that they use to signal
    what message-integrity attributes are in use.

The bid-down protection mechanism described in this document is new
and thus cannot currently protect against a bid-down attack that
lowers the strength of the hash algorithm to HMAC-SHA1.  This is why,

after a transition period, a new document updating this one will
assign a new STUN Security Feature bit for deprecating HMAC-SHA1.
When used, this bit will signal that HMAC-SHA1 is deprecated and
should no longer be used.

Similarly, if HMAC-SHA256 is found to be compromised, a new userhash
attribute and a new STUN Security Feature bit will be allocated in a
Standards Track document.  The new userhash attribute will have its
value computed using a new hash.  The STUN Security Feature bit will
be used to simultaneously 1) signal to a STUN client using the long-
term credential mechanism that this server supports this new hash
algorithm for the userhash attribute and 2) prevent bid-down attacks
on the new userhash attribute.