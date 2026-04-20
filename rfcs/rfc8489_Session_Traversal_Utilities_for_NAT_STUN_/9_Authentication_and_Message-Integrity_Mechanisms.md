# 9.  Authentication and Message-Integrity Mechanisms

This section defines two mechanisms for STUN that a client and server
can use to provide authentication and message integrity; these two
mechanisms are known as the short-term credential mechanism and the
long-term credential mechanism.  These two mechanisms are optional,
and each usage must specify if and when these mechanisms are used.
Consequently, both clients and servers will know which mechanism (if
any) to follow based on knowledge of which usage applies.  For
example, a STUN server on the public Internet supporting ICE would
have no authentication, whereas the STUN server functionality in an
agent supporting connectivity checks would utilize short-term
credentials.  An overview of these two mechanisms is given in
Section 2.

Each mechanism specifies the additional processing required to use
that mechanism, extending the processing specified in Section 6.  The
additional processing occurs in three different places: when forming
a message, when receiving a message immediately after the basic
checks have been performed, and when doing the detailed processing of
error responses.

Note that agents MUST ignore all attributes that follow MESSAGE-
INTEGRITY, with the exception of the MESSAGE-INTEGRITY-SHA256 and
FINGERPRINT attributes.  Similarly, agents MUST ignore all attributes
that follow the MESSAGE-INTEGRITY-SHA256 attribute if the MESSAGE-
INTEGRITY attribute is not present, with the exception of the
FINGERPRINT attribute.

## 9.1.  Short-Term Credential Mechanism

The short-term credential mechanism assumes that, prior to the STUN
transaction, the client and server have used some other protocol to
exchange a credential in the form of a username and password.  This
credential is time-limited.  The time limit is defined by the usage.
As an example, in the ICE usage [RFC8445], the two endpoints use out-
of-band signaling to agree on a username and password, and this
username and password are applicable for the duration of the media
session.

This credential is used to form a message-integrity check in each
request and in many responses.  There is no challenge and response as
in the long-term mechanism; consequently, replay is limited by virtue
of the time-limited nature of the credential.

### 9.1.1.  HMAC Key

For short-term credentials, the Hash-Based Message Authentication
Code (HMAC) key is defined as follow:

                    key = OpaqueString(password)

where the OpaqueString profile is defined in [RFC8265].  The encoding
used is UTF-8 [RFC3629].

### 9.1.2.  Forming a Request or Indication

For a request or indication message, the agent MUST include the
USERNAME, MESSAGE-INTEGRITY-SHA256, and MESSAGE-INTEGRITY attributes
in the message unless the agent knows from an external mechanism
which message integrity algorithm is supported by both agents.  In
this case, either MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 MUST
be included in addition to USERNAME.  The HMAC for the MESSAGE-
INTEGRITY attribute is computed as described in Section 14.5, and the
HMAC for the MESSAGE-INTEGRITY-SHA256 attributes is computed as
described in Section 14.6.  Note that the password is never included
in the request or indication.

### 9.1.3.  Receiving a Request or Indication

After the agent has done the basic processing of a message, the agent
performs the checks listed below in the order specified:

o  If the message does not contain 1) a MESSAGE-INTEGRITY or a
    MESSAGE-INTEGRITY-SHA256 attribute and 2) a USERNAME attribute:


    *  If the message is a request, the server MUST reject the request
        with an error response.  This response MUST use an error code
        of 400 (Bad Request).

    *  If the message is an indication, the agent MUST silently
        discard the indication.

o  If the USERNAME does not contain a username value currently valid
    within the server:

    *  If the message is a request, the server MUST reject the request
        with an error response.  This response MUST use an error code
        of 401 (Unauthenticated).

    *  If the message is an indication, the agent MUST silently
        discard the indication.

o  If the MESSAGE-INTEGRITY-SHA256 attribute is present, compute the
    value for the message integrity as described in Section 14.6,
    using the password associated with the username.  If the MESSAGE-
    INTEGRITY-SHA256 attribute is not present, then use the same
    password to compute the value for the message integrity as
    described in Section 14.5.  If the resulting value does not match
    the contents of the corresponding attribute (MESSAGE-INTEGRITY-
    SHA256 or MESSAGE-INTEGRITY):

    *  If the message is a request, the server MUST reject the request
        with an error response.  This response MUST use an error code
        of 401 (Unauthenticated).

    *  If the message is an indication, the agent MUST silently
        discard the indication.

If these checks pass, the agent continues to process the request or
indication.  Any response generated by a server to a request that
contains a MESSAGE-INTEGRITY-SHA256 attribute MUST include the
MESSAGE-INTEGRITY-SHA256 attribute, computed using the password
utilized to authenticate the request.  Any response generated by a
server to a request that contains only a MESSAGE-INTEGRITY attribute
MUST include the MESSAGE-INTEGRITY attribute, computed using the
password utilized to authenticate the request.  This means that only
one of these attributes can appear in a response.  The response MUST
NOT contain the USERNAME attribute.


If any of the checks fail, a server MUST NOT include a MESSAGE-
INTEGRITY-SHA256, MESSAGE-INTEGRITY, or USERNAME attribute in the
error response.  This is because, in these failure cases, the server
cannot determine the shared secret necessary to compute the MESSAGE-
INTEGRITY-SHA256 or MESSAGE-INTEGRITY attributes.

### 9.1.4.  Receiving a Response

The client looks for the MESSAGE-INTEGRITY or the MESSAGE-INTEGRITY-
SHA256 attribute in the response.  If present and if the client only
sent one of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
attributes in the request (because of the external indication in
Section 9.1.2 or because this is a subsequent request as defined in
Section 9.1.5), the algorithm in the response has to match;
otherwise, the response MUST be discarded.

The client then computes the message integrity over the response as
defined in Section 14.5 for the MESSAGE-INTEGRITY attribute or
Section 14.6 for the MESSAGE-INTEGRITY-SHA256 attribute, using the
same password it utilized for the request.  If the resulting value
matches the contents of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-
SHA256 attribute, respectively, the response is considered
authenticated.  If the value does not match, or if both MESSAGE-
INTEGRITY and MESSAGE-INTEGRITY-SHA256 are absent, the processing
depends on whether the request was sent over a reliable or an
unreliable transport.

If the request was sent over an unreliable transport, the response
MUST be discarded, as if it had never been received.  This means that
retransmits, if applicable, will continue.  If all the responses
received are discarded, then instead of signaling a timeout after
ending the transaction, the layer MUST signal that the integrity
protection was violated.

If the request was sent over a reliable transport, the response MUST
be discarded, and the layer MUST immediately end the transaction and
signal that the integrity protection was violated.

### 9.1.5.  Sending Subsequent Requests

A client sending subsequent requests to the same server MUST send
only the MESSAGE-INTEGRITY-SHA256 or the MESSAGE-INTEGRITY attribute
that matches the attribute that was received in the response to the
initial request.  Here, "same server" means same IP address and port
number, not just the same URI or SRV lookup result.

## 9.2.  Long-Term Credential Mechanism

The long-term credential mechanism relies on a long-term credential,
in the form of a username and password that are shared between client
and server.  The credential is considered long-term since it is
assumed that it is provisioned for a user and remains in effect until
the user is no longer a subscriber of the system or until it is
changed.  This is basically a traditional "log-in" username and
password given to users.

Because these usernames and passwords are expected to be valid for
extended periods of time, replay prevention is provided in the form
of a digest challenge.  In this mechanism, the client initially sends
a request, without offering any credentials or any integrity checks.
The server rejects this request, providing the user a realm (used to
guide the user or agent in selection of a username and password) and
a nonce.  The nonce provides a limited replay protection.  It is a
cookie, selected by the server and encoded in such a way as to
indicate a duration of validity or client identity from which it is
valid.  Only the server needs to know about the internal structure of
the cookie.  The client retries the request, this time including its
username and the realm and echoing the nonce provided by the server.
The client also includes one of the message-integrity attributes
defined in this document, which provides an HMAC over the entire
request, including the nonce.  The server validates the nonce and
checks the message integrity.  If they match, the request is
authenticated.  If the nonce is no longer valid, it is considered
"stale", and the server rejects the request, providing a new nonce.

In subsequent requests to the same server, the client reuses the
nonce, username, realm, and password it used previously.  In this
way, subsequent requests are not rejected until the nonce becomes
invalid by the server, in which case the rejection provides a new
nonce to the client.

Note that the long-term credential mechanism cannot be used to
protect indications, since indications cannot be challenged.  Usages
utilizing indications must either use a short-term credential or omit
authentication and message integrity for them.

To indicate that it supports this specification, a server MUST
prepend the NONCE attribute value with the character string composed
of "obMatJos2" concatenated with the (4-character) base64 [RFC4648]
encoding of the 24-bit STUN Security Features as defined in
Section 18.1.  The 24-bit Security Feature set is encoded as 3 bytes,
with bit 0 as the most significant bit of the first byte and bit 23
as the least significant bit of the third byte.  If no security
features are used, then a byte array with all 24 bits set to zero

MUST be encoded instead.  For the remainder of this document, the
term "nonce cookie" will refer to the complete 13-character string
prepended to the NONCE attribute value.

Since the long-term credential mechanism is susceptible to offline
dictionary attacks, deployments SHOULD utilize passwords that are
difficult to guess.  In cases where the credentials are not entered
by the user, but are rather placed on a client device during device
provisioning, the password SHOULD have at least 128 bits of
randomness.  In cases where the credentials are entered by the user,
they should follow best current practices around password structure.

### 9.2.1.  Bid-Down Attack Prevention

This document introduces two new security features that provide the
ability to choose the algorithm used for password protection as well
as the ability to use an anonymous username.  Both of these
capabilities are optional in order to remain backwards compatible
with previous versions of the STUN protocol.

These new capabilities are subject to bid-down attacks whereby an
attacker in the message path can remove these capabilities and force
weaker security properties.  To prevent these kinds of attacks from
going undetected, the nonce is enhanced with additional information.

The value of the "nonce cookie" will vary based on the specific STUN
Security Feature bits selected.  When this document makes reference
to the "nonce cookie" in a section discussing a specific STUN
Security Feature it is understood that the corresponding STUN
Security Feature bit in the "nonce cookie" is set to 1.

For example, when the PASSWORD-ALGORITHMS security feature (defined
in Section 9.2.4) is used, the corresponding "Password algorithms"
bit (defined in Section 18.1) is set to 1 in the "nonce cookie".

### 9.2.2.  HMAC Key

For long-term credentials that do not use a different algorithm, as
specified by the PASSWORD-ALGORITHM attribute, the key is 16 bytes:

            key = MD5(username ":" OpaqueString(realm)
                ":" OpaqueString(password))

Where MD5 is defined in [RFC1321] and [RFC6151], and the OpaqueString
profile is defined in [RFC8265].  The encoding used is UTF-8
[RFC3629].


The 16-byte key is formed by taking the MD5 hash of the result of
concatenating the following five fields: (1) the username, with any
quotes and trailing nulls removed, as taken from the USERNAME
attribute (in which case OpaqueString has already been applied); (2)
a single colon; (3) the realm, with any quotes and trailing nulls
removed and after processing using OpaqueString; (4) a single colon;
and (5) the password, with any trailing nulls removed and after
processing using OpaqueString.  For example, if the username is
'user', the realm is 'realm', and the password is 'pass', then the
16-byte HMAC key would be the result of performing an MD5 hash on the
string 'user:realm:pass', the resulting hash being
0x8493fbc53ba582fb4c044c456bdc40eb.

The structure of the key when used with long-term credentials
facilitates deployment in systems that also utilize SIP [RFC3261].
Typically, SIP systems utilizing SIP's digest authentication
mechanism do not actually store the password in the database.
Rather, they store a value called "H(A1)", which is equal to the key
defined above.  For example, this mechanism can be used with the
authentication extensions defined in [RFC5090].

When a PASSWORD-ALGORITHM is used, the key length and algorithm to
use are described in Section 18.5.1.

### 9.2.3.  Forming a Request

The first request from the client to the server (as identified by
hostname if the DNS procedures of Section 8 are used and by IP
address if not) is handled according to the rules in Section 9.2.3.1.
When the client initiates a subsequent request once a previous
request/response transaction has completed successfully, it follows
the rules in Section 9.2.3.2.  Forming a request as a consequence of
a 401 (Unauthenticated) or 438 (Stale Nonce) error response is
covered in Section 9.2.5 and is not considered a "subsequent request"
and thus does not utilize the rules described in Section 9.2.3.2.
Each of these types of requests have a different mandatory
attributes.

#### 9.2.3.1.  First Request

If the client has not completed a successful request/response
transaction with the server, it MUST omit the USERNAME, USERHASH,
MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, REALM, NONCE, PASSWORD-
ALGORITHMS, and PASSWORD-ALGORITHM attributes.  In other words, the
first request is sent as if there were no authentication or message
integrity applied.

#### 9.2.3.2.  Subsequent Requests

Once a request/response transaction has completed, the client will
have been presented a realm and nonce by the server and selected a
username and password with which it authenticated.  The client SHOULD
cache the username, password, realm, and nonce for subsequent
communications with the server.  When the client sends a subsequent
request, it MUST include either the USERNAME or USERHASH, REALM,
NONCE, and PASSWORD-ALGORITHM attributes with these cached values.
It MUST include a MESSAGE-INTEGRITY attribute or a MESSAGE-INTEGRITY-
SHA256 attribute, computed as described in Sections 14.5 and 14.6
using the cached password.  The choice between the two attributes
depends on the attribute received in the response to the first
request.

### 9.2.4.  Receiving a Request

After the server has done the basic processing of a request, it
performs the checks listed below in the order specified.  Note that
it is RECOMMENDED that the REALM value be the domain name of the
provider of the STUN server:

o  If the message does not contain a MESSAGE-INTEGRITY or MESSAGE-
    INTEGRITY-SHA256 attribute, the server MUST generate an error
    response with an error code of 401 (Unauthenticated).  This
    response MUST include a REALM value.  The response MUST include a
    NONCE, selected by the server.  The server MUST NOT choose the
    same NONCE for two requests unless they have the same source IP
    address and port.  The server MAY support alternate password
    algorithms, in which case it can list them in preferential order
    in a PASSWORD-ALGORITHMS attribute.  If the server adds a
    PASSWORD-ALGORITHMS attribute, it MUST set the STUN Security
    Feature "Password algorithms" bit to 1.  The server MAY support
    anonymous username, in which case it MUST set the STUN Security
    Feature "Username anonymity" bit set to 1.  The response SHOULD
    NOT contain a USERNAME, USERHASH, MESSAGE-INTEGRITY, or MESSAGE-
    INTEGRITY-SHA256 attribute.

    Note: Reusing a NONCE for different source IP addresses or ports
    was not explicitly forbidden in [RFC5389].

o  If the message contains a MESSAGE-INTEGRITY or a MESSAGE-
    INTEGRITY-SHA256 attribute, but is missing either the USERNAME or
    USERHASH, REALM, or NONCE attribute, the server MUST generate an
    error response with an error code of 400 (Bad Request).  This
    response SHOULD NOT include a USERNAME, USERHASH, NONCE, or REALM
    attribute.  The response cannot contain a MESSAGE-INTEGRITY or
    MESSAGE-INTEGRITY-SHA256 attribute, as the attributes required to
    generate them are missing.

o  If the NONCE attribute starts with the "nonce cookie" with the
    STUN Security Feature "Password algorithms" bit set to 1, the
    server performs these checks in the order specified:

    *  If the request contains neither the PASSWORD-ALGORITHMS nor the
        PASSWORD-ALGORITHM algorithm, then the request is processed as
        though PASSWORD-ALGORITHM were MD5.

    *  Otherwise, unless (1) PASSWORD-ALGORITHM and PASSWORD-
        ALGORITHMS are both present, (2) PASSWORD-ALGORITHMS matches
        the value sent in the response that sent this NONCE, and (3)
        PASSWORD-ALGORITHM matches one of the entries in PASSWORD-
        ALGORITHMS, the server MUST generate an error response with an
        error code of 400 (Bad Request).

o  If the value of the USERNAME or USERHASH attribute is not valid,
    the server MUST generate an error response with an error code of
    401 (Unauthenticated).  This response MUST include a REALM value.
    The response MUST include a NONCE, selected by the server.  The
    response MUST include a PASSWORD-ALGORITHMS attribute.  The
    response SHOULD NOT contain a USERNAME or USERHASH attribute.  The
    response MAY include a MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-
    SHA256 attribute, using the previous key to calculate it.

o  If the MESSAGE-INTEGRITY-SHA256 attribute is present, compute the
    value for the message integrity as described in Section 14.6,
    using the password associated with the username.  Otherwise, using
    the same password, compute the value for the MESSAGE-INTEGRITY
    attribute as described in Section 14.5.  If the resulting value
    does not match the contents of the MESSAGE-INTEGRITY attribute or
    the MESSAGE-INTEGRITY-SHA256 attribute, the server MUST reject the
    request with an error response.  This response MUST use an error
    code of 401 (Unauthenticated).  It MUST include the REALM and
    NONCE attributes and SHOULD NOT include the USERNAME, USERHASH,
    MESSAGE-INTEGRITY, or MESSAGE-INTEGRITY-SHA256 attribute.

o  If the NONCE is no longer valid, the server MUST generate an error
    response with an error code of 438 (Stale Nonce).  This response
    MUST include NONCE, REALM, and PASSWORD-ALGORITHMS attributes and
    SHOULD NOT include the USERNAME and USERHASH attributes.  The
    NONCE attribute value MUST be valid.  The response MAY include a
    MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, using the



    previous NONCE to calculate it.  Servers can revoke nonces in
    order to provide additional security.  See Section 5.4 of
    [RFC7616] for guidelines.

If these checks pass, the server continues to process the request.
Any response generated by the server MUST include the MESSAGE-
INTEGRITY-SHA256 attribute, computed using the username and password
utilized to authenticate the request, unless the request was
processed as though PASSWORD-ALGORITHM was MD5 (because the request
contained neither PASSWORD-ALGORITHMS nor PASSWORD-ALGORITHM).  In
that case, the MESSAGE-INTEGRITY attribute MUST be used instead of
the MESSAGE-INTEGRITY-SHA256 attribute, and the REALM, NONCE,
USERNAME, and USERHASH attributes SHOULD NOT be included.

### 9.2.5.  Receiving a Response

If the response is an error response with an error code of 401
(Unauthenticated) or 438 (Stale Nonce), the client MUST test if the
NONCE attribute value starts with the "nonce cookie".  If so and the
"nonce cookie" has the STUN Security Feature "Password algorithms"
bit set to 1 but no PASSWORD-ALGORITHMS attribute is present, then
the client MUST NOT retry the request with a new transaction.

If the response is an error response with an error code of 401
(Unauthenticated), the client SHOULD retry the request with a new
transaction.  This request MUST contain a USERNAME or a USERHASH,
determined by the client as the appropriate username for the REALM
from the error response.  If the "nonce cookie" is present and has
the STUN Security Feature "Username anonymity" bit set to 1, then the
USERHASH attribute MUST be used; else, the USERNAME attribute MUST be
used.  The request MUST contain the REALM, copied from the error
response.  The request MUST contain the NONCE, copied from the error
response.  If the response contains a PASSWORD-ALGORITHMS attribute,
the request MUST contain the PASSWORD-ALGORITHMS attribute with the
same content.  If the response contains a PASSWORD-ALGORITHMS
attribute, and this attribute contains at least one algorithm that is
supported by the client, then the request MUST contain a PASSWORD-
ALGORITHM attribute with the first algorithm supported on the list.
If the response contains a PASSWORD-ALGORITHMS attribute, and this
attribute does not contain any algorithm that is supported by the
client, then the client MUST NOT retry the request with a new
transaction.  The client MUST NOT perform this retry if it is not
changing the USERNAME, USERHASH, REALM, or its associated password
from the previous attempt.

If the response is an error response with an error code of 438 (Stale
Nonce), the client MUST retry the request, using the new NONCE
attribute supplied in the 438 (Stale Nonce) response.  This retry
MUST also include either the USERNAME or USERHASH, the REALM, and
either the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute.

For all other responses, if the NONCE attribute starts with the
"nonce cookie" with the STUN Security Feature "Password algorithms"
bit set to 1 but PASSWORD-ALGORITHMS is not present, the response
MUST be ignored.

If the response is an error response with an error code of 400 (Bad
Request) and does not contain either the MESSAGE-INTEGRITY or
MESSAGE-INTEGRITY-SHA256 attribute, then the response MUST be
discarded, as if it were never received.  This means that
retransmits, if applicable, will continue.

    Note: In this case, the 400 response will never reach the
    application, resulting in a timeout.

The client looks for the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-
SHA256 attribute in the response (either success or failure).  If
present, the client computes the message integrity over the response
as defined in Sections 14.5 or 14.6, using the same password it
utilized for the request.  If the resulting value matches the
contents of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
attribute, the response is considered authenticated.  If the value
does not match, or if both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-
SHA256 are absent, the processing depends on the request being sent
over a reliable or an unreliable transport.

If the request was sent over an unreliable transport, the response
MUST be discarded, as if it had never been received.  This means that
retransmits, if applicable, will continue.  If all the responses
received are discarded, then instead of signaling a timeout after
ending the transaction, the layer MUST signal that the integrity
protection was violated.

If the request was sent over a reliable transport, the response MUST
be discarded, and the layer MUST immediately end the transaction and
signal that the integrity protection was violated.

If the response contains a PASSWORD-ALGORITHMS attribute, all the
subsequent requests MUST be authenticated using MESSAGE-INTEGRITY-
SHA256 only.