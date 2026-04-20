# 12.  Basic Server Behavior

This section defines the behavior of a basic, stand-alone STUN
server.

Historically, "classic STUN" [RFC3489] only defined the behavior of a
server that was providing clients with server reflexive transport
addresses by receiving and replying to STUN Binding requests.
[RFC5389] redefined the protocol as an extensible framework, and the
server functionality became the sole STUN Usage defined in that
document.  This STUN Usage is also known as "Basic STUN Server".

The STUN server MUST support the Binding method.  It SHOULD NOT
utilize the short-term or long-term credential mechanism.  This is
because the work involved in authenticating the request is more than
the work in simply processing it.  It SHOULD NOT utilize the
ALTERNATE-SERVER mechanism for the same reason.  It MUST support UDP
and TCP.  It MAY support STUN over TCP/TLS or STUN over UDP/DTLS;
however, DTLS and TLS provide minimal security benefits in this basic
mode of operation.  It does not require a keep-alive mechanism
because a TCP or TLS-over-TCP connection is closed after the end of
the Binding transaction.  It MAY utilize the FINGERPRINT mechanism
but MUST NOT require it.  Since the stand-alone server only runs
STUN, FINGERPRINT provides no benefit.  Requiring it would break
compatibility with RFC 3489, and such compatibility is desirable in a
stand-alone server.  Stand-alone STUN servers SHOULD support
backwards compatibility with clients using [RFC3489], as described in
Section 11.

It is RECOMMENDED that administrators of STUN servers provide DNS
entries for those servers as described in Section 8.  If both A and
AAAA resource records are returned, then the client can
simultaneously send STUN Binding requests to the IPv4 and IPv6
addresses (as specified in [RFC8305]), as the Binding request is
idempotent.  Note that the MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
attributes that are returned will not necessarily match the address
family of the server address used.

A basic STUN server is not a solution for NAT traversal by itself.
However, it can be utilized as part of a solution through STUN
Usages.  This is discussed further in Section 13.
