# 6.  Base Protocol Procedures

This section defines the base procedures of the STUN protocol.  It
describes how messages are formed, how they are sent, and how they
are processed when they are received.  It also defines the detailed
processing of the Binding method.  Other sections in this document
describe optional procedures that a usage may elect to use in certain
situations.  Other documents may define other extensions to STUN, by
adding new methods, new attributes, or new error response codes.

## 6.1.  Forming a Request or an Indication

When formulating a request or indication message, the agent MUST
follow the rules in Section 5 when creating the header.  In addition,
the message class MUST be either "Request" or "Indication" (as
appropriate), and the method must be either Binding or some method
defined in another document.

The agent then adds any attributes specified by the method or the
usage.  For example, some usages may specify that the agent use an
authentication method (Section 9) or the FINGERPRINT attribute
(Section 7).

If the agent is sending a request, it SHOULD add a SOFTWARE attribute
to the request.  Agents MAY include a SOFTWARE attribute in
indications, depending on the method.  Extensions to STUN should
discuss whether SOFTWARE is useful in new indications.  Note that the
inclusion of a SOFTWARE attribute may have security implications; see
Section 16.1.2 for details.

For the Binding method with no authentication, no attributes are
required unless the usage specifies otherwise.

All STUN messages sent over UDP or DTLS-over-UDP [RFC6347] SHOULD be
less than the path MTU, if known.

If the path MTU is unknown for UDP, messages SHOULD be the smaller of
576 bytes and the first-hop MTU for IPv4 [RFC1122] and 1280 bytes for
IPv6 [RFC8200].  This value corresponds to the overall size of the IP
packet.  Consequently, for IPv4, the actual STUN message would need
to be less than 548 bytes (576 minus 20-byte IP header, minus 8-byte
UDP header, assuming no IP options are used).

If the path MTU is unknown for DTLS-over-UDP, the rules described in
the previous paragraph need to be adjusted to take into account the
size of the (13-byte) DTLS Record header, the Message Authentication
Code (MAC) size, and the padding size.

STUN provides no ability to handle the case where the request is
smaller than the MTU but the response is larger than the MTU.  It is
not envisioned that this limitation will be an issue for STUN.  The
MTU limitation is a SHOULD, not a MUST, to account for cases where
STUN itself is being used to probe for MTU characteristics [RFC5780].
See also [STUN-PMTUD] for a framework that uses STUN to add Path MTU
Discovery to protocols that lack such a mechanism.  Outside of this
or similar applications, the MTU constraint MUST be followed.

## 6.2.  Sending the Request or Indication

The agent then sends the request or indication.  This document
specifies how to send STUN messages over UDP, TCP, TLS-over-TCP, or
DTLS-over-UDP; other transport protocols may be added in the future.
The STUN Usage must specify which transport protocol is used and how
the agent determines the IP address and port of the recipient.
Section 8 describes a DNS-based method of determining the IP address
and port of a server that a usage may elect to use.

At any time, a client MAY have multiple outstanding STUN requests
with the same STUN server (that is, multiple transactions in
progress, with different transaction IDs).  Absent other limits to
the rate of new transactions (such as those specified by ICE for
connectivity checks or when STUN is run over TCP), a client SHOULD
limit itself to ten outstanding transactions to the same server.

### 6.2.1.  Sending over UDP or DTLS-over-UDP

When running STUN over UDP or STUN over DTLS-over-UDP [RFC7350], it
is possible that the STUN message might be dropped by the network.
Reliability of STUN request/response transactions is accomplished
through retransmissions of the request message by the client
application itself.  STUN indications are not retransmitted; thus,
indication transactions over UDP or DTLS-over-UDP are not reliable.

A client SHOULD retransmit a STUN request message starting with an
interval of RTO ("Retransmission TimeOut"), doubling after each
retransmission.  The RTO is an estimate of the round-trip time (RTT)
and is computed as described in [RFC6298], with two exceptions.
First, the initial value for RTO SHOULD be greater than or equal to
500 ms.  The exception cases for this "SHOULD" are when other
mechanisms are used to derive congestion thresholds (such as the ones
defined in ICE for fixed-rate streams) or when STUN is used in non-
Internet environments with known network capacities.  In fixed-line
access links, a value of 500 ms is RECOMMENDED.  Second, the value of
RTO SHOULD NOT be rounded up to the nearest second.  Rather, a 1 ms
accuracy SHOULD be maintained.  As with TCP, the usage of Karn's
algorithm is RECOMMENDED [KARN87].  When applied to STUN, it means
that RTT estimates SHOULD NOT be computed from STUN transactions that
result in the retransmission of a request.

The value for RTO SHOULD be cached by a client after the completion
of the transaction and used as the starting value for RTO for the
next transaction to the same server (based on equality of IP
address).  The value SHOULD be considered stale and discarded if no
transactions have occurred to the same server in the last 10 minutes.

Retransmissions continue until a response is received or until a
total of Rc requests have been sent.  Rc SHOULD be configurable and
SHOULD have a default of 7.  If, after the last request, a duration
equal to Rm times the RTO has passed without a response (providing
ample time to get a response if only this final request actually
succeeds), the client SHOULD consider the transaction to have failed.
Rm SHOULD be configurable and SHOULD have a default of 16.  A STUN
transaction over UDP or DTLS-over-UDP is also considered failed if
there has been a hard ICMP error [RFC1122].  For example, assuming an
RTO of 500 ms, requests would be sent at times 0 ms, 500 ms, 1500 ms,
3500 ms, 7500 ms, 15500 ms, and 31500 ms.  If the client has not
received a response after 39500 ms, the client will consider the
transaction to have timed out.

### 6.2.2.  Sending over TCP or TLS-over-TCP

For TCP and TLS-over-TCP [RFC8446], the client opens a TCP connection
to the server.

In some usages of STUN, STUN is the only protocol over the TCP
connection.  In this case, it can be sent without the aid of any
additional framing or demultiplexing.  In other usages, or with other
extensions, it may be multiplexed with other data over a TCP
connection.  In that case, STUN MUST be run on top of some kind of
framing protocol, specified by the usage or extension, which allows
for the agent to extract complete STUN messages and complete
application-layer messages.  The STUN service running on the well-
known port or ports discovered through the DNS procedures in
Section 8 is for STUN alone, and not for STUN multiplexed with other
data.  Consequently, no framing protocols are used in connections to
those servers.  When additional framing is utilized, the usage will
specify how the client knows to apply it and what port to connect to.
For example, in the case of ICE connectivity checks, this information
is learned through out-of-band negotiation between client and server.

Reliability of STUN over TCP and TLS-over-TCP is handled by TCP
itself, and there are no retransmissions at the STUN protocol level.
However, for a request/response transaction, if the client has not
received a response by Ti seconds after it sent the request message,
it considers the transaction to have timed out.  Ti SHOULD be
configurable and SHOULD have a default of 39.5 s.  This value has
been chosen to equalize the TCP and UDP timeouts for the default
initial RTO.

In addition, if the client is unable to establish the TCP connection,
or the TCP connection is reset or fails before a response is
received, any request/response transaction in progress is considered
to have failed.

The client MAY send multiple transactions over a single TCP (or TLS-
over-TCP) connection, and it MAY send another request before
receiving a response to the previous request.  The client SHOULD keep
the connection open until it:

o  has no further STUN requests or indications to send over that
    connection,

o  has no plans to use any resources (such as a mapped address
    (MAPPED-ADDRESS or XOR-MAPPED-ADDRESS) or relayed address
    [RFC5766]) that were learned though STUN requests sent over that
    connection,


o  if multiplexing other application protocols over that port, has
    finished using those other protocols,

o  if using that learned port with a remote peer, has established
    communications with that remote peer, as is required by some TCP
    NAT traversal techniques (e.g., [RFC6544]).

The details of an eventual keep-alive mechanism are left to each STUN
Usage.  In any case, if a transaction fails because an idle TCP
connection doesn't work anymore, the client SHOULD send a RST and try
to open a new TCP connection.

At the server end, the server SHOULD keep the connection open and let
the client close it, unless the server has determined that the
connection has timed out (for example, due to the client
disconnecting from the network).  Bindings learned by the client will
remain valid in intervening NATs only while the connection remains
open.  Only the client knows how long it needs the binding.  The
server SHOULD NOT close a connection if a request was received over
that connection for which a response was not sent.  A server MUST NOT
ever open a connection back towards the client in order to send a
response.  Servers SHOULD follow best practices regarding connection
management in cases of overload.

### 6.2.3.  Sending over TLS-over-TCP or DTLS-over-UDP

When STUN is run by itself over TLS-over-TCP or DTLS-over-UDP, the
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 and
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ciphersuites MUST be
implemented (for compatibility with older versions of this protocol),
except if deprecated by rules of a specific STUN usage.  Other
ciphersuites MAY be implemented.  Note that STUN clients and servers
that implement TLS version 1.3 [RFC8446] or subsequent versions are
also required to implement mandatory ciphersuites from those
specifications and SHOULD disable usage of deprecated ciphersuites
when they detect support for those specifications.  Perfect Forward
Secrecy (PFS) ciphersuites MUST be preferred over non-PFS
ciphersuites.  Ciphersuites with known weaknesses, such as those
based on (single) DES and RC4, MUST NOT be used.  Implementations
MUST disable TLS-level compression.

These recommendations are just a part of the recommendations in
[BCP195] that implementations and deployments of a STUN Usage using
TLS or DTLS MUST follow.

When it receives the TLS Certificate message, the client MUST verify
the certificate and inspect the site identified by the certificate.
If the certificate is invalid or revoked, or if it does not identify

the appropriate party, the client MUST NOT send the STUN message or
otherwise proceed with the STUN transaction.  The client MUST verify
the identity of the server.  To do that, it follows the
identification procedures defined in [RFC6125], with a certificate
containing an identifier of type DNS-ID or CN-ID, optionally with a
wildcard character as the leftmost label, but not of type SRV-ID or
URI-ID.

When STUN is run multiplexed with other protocols over a TLS-over-TCP
connection or a DTLS-over-UDP association, the mandatory ciphersuites
and TLS handling procedures operate as defined by those protocols.

## 6.3.  Receiving a STUN Message

This section specifies the processing of a STUN message.  The
processing specified here is for STUN messages as defined in this
specification; additional rules for backwards compatibility are
defined in Section 11.  Those additional procedures are optional, and
usages can elect to utilize them.  First, a set of processing
operations is applied that is independent of the class.  This is
followed by class-specific processing, described in the subsections
that follow.

When a STUN agent receives a STUN message, it first checks that the
message obeys the rules of Section 5.  It checks that the first two
bits are 0, that the Magic Cookie field has the correct value, that
the message length is sensible, and that the method value is a
supported method.  It checks that the message class is allowed for
the particular method.  If the message class is "Success Response" or
"Error Response", the agent checks that the transaction ID matches a
transaction that is still in progress.  If the FINGERPRINT extension
is being used, the agent checks that the FINGERPRINT attribute is
present and contains the correct value.  If any errors are detected,
the message is silently discarded.  In the case when STUN is being
multiplexed with another protocol, an error may indicate that this is
not really a STUN message; in this case, the agent should try to
parse the message as a different protocol.

The STUN agent then does any checks that are required by a
authentication mechanism that the usage has specified (see
Section 9).

Once the authentication checks are done, the STUN agent checks for
unknown attributes and known-but-unexpected attributes in the
message.  Unknown comprehension-optional attributes MUST be ignored
by the agent.  Known-but-unexpected attributes SHOULD be ignored by
the agent.  Unknown comprehension-required attributes cause
processing that depends on the message class and is described below.

At this point, further processing depends on the message class of the
request.

### 6.3.1.  Processing a Request

If the request contains one or more unknown comprehension-required
attributes, the server replies with an error response with an error
code of 420 (Unknown Attribute) and includes an UNKNOWN-ATTRIBUTES
attribute in the response that lists the unknown comprehension-
required attributes.

Otherwise, the server then does any additional checking that the
method or the specific usage requires.  If all the checks succeed,
the server formulates a success response as described below.

When run over UDP or DTLS-over-UDP, a request received by the server
could be the first request of a transaction or could be a
retransmission.  The server MUST respond to retransmissions such that
the following property is preserved: if the client receives the
response to the retransmission and not the response that was sent to
the original request, the overall state on the client and server is
identical to the case where only the response to the original
retransmission is received or where both responses are received (in
which case the client will use the first).  The easiest way to meet
this requirement is for the server to remember all transaction IDs
received over UDP or DTLS-over-UDP and their corresponding responses
in the last 40 seconds.  However, this requires the server to hold
state and is inappropriate for any requests that are not
authenticated.  Another way is to reprocess the request and recompute
the response.  The latter technique MUST only be applied to requests
that are idempotent (a request is considered idempotent when the same
request can be safely repeated without impacting the overall state of
the system) and result in the same success response for the same
request.  The Binding method is considered to be idempotent.  Note
that there are certain rare network events that could cause the
reflexive transport address value to change, resulting in a different
mapped address in different success responses.  Extensions to STUN
MUST discuss the implications of request retransmissions on servers
that do not store transaction state.

#### 6.3.1.1.  Forming a Success or Error Response

When forming the response (success or error), the server follows the
rules of Section 6.  The method of the response is the same as that
of the request, and the message class is either "Success Response" or
"Error Response".

For an error response, the server MUST add an ERROR-CODE attribute
containing the error code specified in the processing above.  The
reason phrase is not fixed but SHOULD be something suitable for the
error code.  For certain errors, additional attributes are added to
the message.  These attributes are spelled out in the description
where the error code is specified.  For example, for an error code of
420 (Unknown Attribute), the server MUST include an UNKNOWN-
ATTRIBUTES attribute.  Certain authentication errors also cause
attributes to be added (see Section 9).  Extensions may define other
errors and/or additional attributes to add in error cases.

If the server authenticated the request using an authentication
mechanism, then the server SHOULD add the appropriate authentication
attributes to the response (see Section 9).

The server also adds any attributes required by the specific method
or usage.  In addition, the server SHOULD add a SOFTWARE attribute to
the message.

For the Binding method, no additional checking is required unless the
usage specifies otherwise.  When forming the success response, the
server adds an XOR-MAPPED-ADDRESS attribute to the response; this
attribute contains the source transport address of the request
message.  For UDP or DTLS-over-UDP, this is the source IP address and
source UDP port of the request message.  For TCP and TLS-over-TCP,
this is the source IP address and source TCP port of the TCP
connection as seen by the server.

#### 6.3.1.2.  Sending the Success or Error Response

The response (success or error) is sent over the same transport as
the request was received on.  If the request was received over UDP or
DTLS-over-UDP, the destination IP address and port of the response
are the source IP address and port of the received request message,
and the source IP address and port of the response are equal to the
destination IP address and port of the received request message.  If
the request was received over TCP or TLS-over-TCP, the response is
sent back on the same TCP connection as the request was received on.

The server is allowed to send responses in a different order than it
received the requests.

### 6.3.2.  Processing an Indication

If the indication contains unknown comprehension-required attributes,
the indication is discarded and processing ceases.

Otherwise, the agent then does any additional checking that the
method or the specific usage requires.  If all the checks succeed,
the agent then processes the indication.  No response is generated
for an indication.

For the Binding method, no additional checking or processing is
required, unless the usage specifies otherwise.  The mere receipt of
the message by the agent has refreshed the bindings in the
intervening NATs.

Since indications are not re-transmitted over UDP or DTLS-over-UDP
(unlike requests), there is no need to handle re-transmissions of
indications at the sending agent.

### 6.3.3.  Processing a Success Response

If the success response contains unknown comprehension-required
attributes, the response is discarded and the transaction is
considered to have failed.

Otherwise, the client then does any additional checking that the
method or the specific usage requires.  If all the checks succeed,
the client then processes the success response.

For the Binding method, the client checks that the XOR-MAPPED-ADDRESS
attribute is present in the response.  The client checks the address
family specified.  If it is an unsupported address family, the
attribute SHOULD be ignored.  If it is an unexpected but supported
address family (for example, the Binding transaction was sent over
IPv4, but the address family specified is IPv6), then the client MAY
accept and use the value.

### 6.3.4.  Processing an Error Response

If the error response contains unknown comprehension-required
attributes, or if the error response does not contain an ERROR-CODE
attribute, then the transaction is simply considered to have failed.

Otherwise, the client then does any processing specified by the
authentication mechanism (see Section 9).  This may result in a new
transaction attempt.

The processing at this point depends on the error code, the method,
and the usage; the following are the default rules:

o  If the error code is 300 through 399, the client SHOULD consider
    the transaction as failed unless the ALTERNATE-SERVER extension
    (Section 10) is being used.

o  If the error code is 400 through 499, the client declares the
    transaction failed; in the case of 420 (Unknown Attribute), the
    response should contain a UNKNOWN-ATTRIBUTES attribute that gives
    additional information.

o  If the error code is 500 through 599, the client MAY resend the
    request; clients that do so MUST limit the number of times they do
    this.  Unless a specific error code specifies a different value,
    the number of retransmissions SHOULD be limited to 4.

Any other error code causes the client to consider the transaction
failed.

# 7.  FINGERPRINT Mechanism

This section describes an optional mechanism for STUN that aids in
distinguishing STUN messages from packets of other protocols when the
two are multiplexed on the same transport address.  This mechanism is
optional, and a STUN Usage must describe if and when it is used.  The
FINGERPRINT mechanism is not backwards compatible with RFC 3489 and
cannot be used in environments where such compatibility is required.

In some usages, STUN messages are multiplexed on the same transport
address as other protocols, such as the Real-Time Transport Protocol
(RTP).  In order to apply the processing described in Section 6, STUN
messages must first be separated from the application packets.

Section 5 describes three fixed fields in the STUN header that can be
used for this purpose.  However, in some cases, these three fixed
fields may not be sufficient.

When the FINGERPRINT extension is used, an agent includes the
FINGERPRINT attribute in messages it sends to another agent.
Section 14.7 describes the placement and value of this attribute.

When the agent receives what it believes is a STUN message, then, in
addition to other basic checks, the agent also checks that the
message contains a FINGERPRINT attribute and that the attribute
contains the correct value.  Section 6.3 describes when in the
overall processing of a STUN message the FINGERPRINT check is
performed.  This additional check helps the agent detect messages of
other protocols that might otherwise seem to be STUN messages.

