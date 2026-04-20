# 13.  STUN Usages

STUN by itself is not a solution to the NAT traversal problem.
Rather, STUN defines a tool that can be used inside a larger
solution.  The term "STUN Usage" is used for any solution that uses
STUN as a component.

A STUN Usage defines how STUN is actually utilized -- when to send
requests, what to do with the responses, and which optional
procedures defined here (or in an extension to STUN) are to be used.
A usage also defines:

o  Which STUN methods are used.

o  What transports are used.  If DTLS-over-UDP is used, then
    implementing the denial-of-service countermeasure described in
    Section 4.2.1 of [RFC6347] is mandatory.

o  What authentication and message-integrity mechanisms are used.

o  The considerations around manual vs. automatic key derivation for
    the integrity mechanism, as discussed in [RFC4107].

o  What mechanisms are used to distinguish STUN messages from other
    messages.  When STUN is run over TCP or TLS-over-TCP, a framing
    mechanism may be required.

o  How a STUN client determines the IP address and port of the STUN
    server.

o  How simultaneous use of IPv4 and IPv6 addresses (Happy Eyeballs
    [RFC8305]) works with non-idempotent transactions when both
    address families are found for the STUN server.

o  Whether backwards compatibility to RFC 3489 is required.

o  What optional attributes defined here (such as FINGERPRINT and
    ALTERNATE-SERVER) or in other extensions are required.

o  If MESSAGE-INTEGRITY-SHA256 truncation is permitted, and the
    limits permitted for truncation.

o  The keep-alive mechanism if STUN is run over TCP or TLS-over-TCP.

o  If anycast addresses can be used for the server in case 1) TCP or
    TLS-over-TCP or 2) authentication is used.

In addition, any STUN Usage must consider the security implications
of using STUN in that usage.  A number of attacks against STUN are
known (see the Security Considerations section in this document), and
any usage must consider how these attacks can be thwarted or
mitigated.

Finally, a usage must consider whether its usage of STUN is an
example of the Unilateral Self-Address Fixing approach to NAT
traversal and, if so, address the questions raised in RFC 3424
[RFC3424].
