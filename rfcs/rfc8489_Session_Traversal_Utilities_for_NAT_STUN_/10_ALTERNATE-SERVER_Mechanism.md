# 10.  ALTERNATE-SERVER Mechanism

This section describes a mechanism in STUN that allows a server to
redirect a client to another server.  This extension is optional, and
a usage must define if and when this extension is used.  The
ALTERNATE-SERVER attribute carries an IP address.

A server using this extension redirects a client to another server by
replying to a request message with an error response message with an
error code of 300 (Try Alternate).  The server MUST include at least
one ALTERNATE-SERVER attribute in the error response, which MUST
contain an IP address of the same address family as the source IP
address of the request message.  The server SHOULD include an
additional ALTERNATE-SERVER attribute, after the mandatory one, that
contains an IP address of the address family other than the source IP
address of the request message.  The error response message MAY be
authenticated; however, there are use cases for ALTERNATE-SERVER
where authentication of the response is not possible or practical.
If the transaction uses TLS or DTLS, if the transaction is
authenticated by a MESSAGE-INTEGRITY-SHA256 attribute, and if the
server wants to redirect to a server that uses a different
certificate, then it MUST include an ALTERNATE-DOMAIN attribute
containing the name inside the subjectAltName of that certificate.
This series of conditions on the MESSAGE-INTEGRITY-SHA256 attribute
indicates that the transaction is authenticated and that the client
implements this specification and therefore can process the
ALTERNATE-DOMAIN attribute.

A client using this extension handles a 300 (Try Alternate) error
code as follows.  The client looks for an ALTERNATE-SERVER attribute
in the error response.  If one is found, then the client considers
the current transaction as failed and reattempts the request with the
server specified in the attribute, using the same transport protocol
used for the previous request.  That request, if authenticated, MUST
utilize the same credentials that the client would have used in the
request to the server that performed the redirection.  If the
transport protocol uses TLS or DTLS, then the client looks for an
ALTERNATE-DOMAIN attribute.  If the attribute is found, the domain
MUST be used to validate the certificate using the recommendations in
[RFC6125].  The certificate MUST contain an identifier of type DNS-ID
or CN-ID (eventually with wildcards) but not of type SRV-ID or URI-
ID.  If the attribute is not found, the same domain that was used for
the original request MUST be used to validate the certificate.  If
the client has been redirected to a server to which it has already
sent this request within the last five minutes, it MUST ignore the
redirection and consider the transaction to have failed.  This
prevents infinite ping-ponging between servers in case of redirection
loops.

# 11.  Backwards Compatibility with RFC 3489

In addition to the backward compatibility already described in
Section 12 of [RFC5389], DTLS MUST NOT be used with [RFC3489]
(referred to as "classic STUN").  Any STUN request or indication
without the magic cookie (see Section 6 of [RFC5389]) over DTLS MUST
be considered invalid: all requests MUST generate a 500 (Server
Error) error response, and indications MUST be ignored.