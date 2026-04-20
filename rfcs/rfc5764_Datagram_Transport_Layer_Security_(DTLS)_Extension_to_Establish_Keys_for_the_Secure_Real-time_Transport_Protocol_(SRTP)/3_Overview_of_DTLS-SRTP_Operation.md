DTLS-SRTP is defined for point-to-point media sessions, in which
there are exactly two participants.  Each DTLS-SRTP session contains
a single DTLS association (called a "connection" in TLS jargon), and
either two SRTP contexts (if media traffic is flowing in both
directions on the same host/port quartet) or one SRTP context (if
media traffic is only flowing in one direction).  All SRTP traffic
flowing over that pair in a given direction uses a single SRTP
context.  A single DTLS-SRTP session only protects data carried over
a single UDP source and destination port pair.

The general pattern of DTLS-SRTP is as follows.  For each RTP or RTCP
flow the peers do a DTLS handshake on the same source and destination
port pair to establish a DTLS association.  Which side is the DTLS
client and which side is the DTLS server must be established via some
out-of-band mechanism such as SDP.  The keying material from that
handshake is fed into the SRTP stack.  Once that association is
established, RTP packets are protected (becoming SRTP) using that
keying material.

RTP and RTCP traffic is usually sent on two separate UDP ports.  When
symmetric RTP [RFC4961] is used, two bidirectional DTLS-SRTP sessions
are needed, one for the RTP port, one for the RTCP port.  When RTP
flows are not symmetric, four unidirectional DTLS-SRTP sessions are
needed (for inbound and outbound RTP, and inbound and outbound RTCP).

Symmetric RTP [RFC4961] is the case in which there are two RTP
sessions that have their source and destination ports and addresses
reversed, in a manner similar to the way that a TCP connection uses
its ports.  Each participant has an inbound RTP session and an
outbound RTP session.  When symmetric RTP is used, a single DTLS-SRTP
session can protect both of the RTP sessions.  It is RECOMMENDED that
symmetric RTP be used with DTLS-SRTP.

RTP and RTCP traffic MAY be multiplexed on a single UDP port
[RFC5761].  In this case, both RTP and RTCP packets may be sent over
the same DTLS-SRTP session, halving the number of DTLS-SRTP sessions
needed.  This improves the cryptographic performance of DTLS, but may
cause problems when RTCP and RTP are subject to different network
treatment (e.g., for bandwidth reservation or scheduling reasons).

Between a single pair of participants, there may be multiple media
sessions.  There MUST be a separate DTLS-SRTP session for each
distinct pair of source and destination ports used by a media session
(though the sessions can share a single DTLS session and hence
amortize the initial public key handshake!).

A DTLS-SRTP session may be indicated by an external signaling
protocol like SIP.  When the signaling exchange is integrity-
protected (e.g., when SIP Identity protection via digital signatures
is used), DTLS-SRTP can leverage this integrity guarantee to provide
complete security of the media stream.  A description of how to
indicate DTLS-SRTP sessions in SIP and SDP [RFC4566], and how to
authenticate the endpoints using fingerprints can be found in
[RFC5763].

In a naive implementation, when there are multiple media sessions,
there is a new DTLS session establishment (complete with public key
cryptography) for each media channel.  For example, a videophone may
be sending both an audio stream and a video stream, each of which
would use a separate DTLS session establishment exchange, which would
proceed in parallel.  As an optimization, the DTLS-SRTP
implementation SHOULD use the following strategy: a single DTLS
association is established, and all other DTLS associations wait
until that connection is established before proceeding with their
handshakes.  This strategy allows the later sessions to use DTLS
session resumption, which allows the amortization of the expensive
public key cryptography operations over multiple DTLS handshakes.

The SRTP keys used to protect packets originated by the client are
distinct from the SRTP keys used to protect packets originated by the
server.  All of the RTP sources originating on the client for the
same channel use the same SRTP keys, and similarly, all of the RTP
sources originating on the server for the same channel use the same
SRTP keys.  The SRTP implementation MUST ensure that all of the
synchronization source (SSRC) values for all of the RTP sources
originating from the same device over the same channel are distinct,
in order to avoid the "two-time pad" problem (as described in Section
9.1 of RFC 3711).  Note that this is not an issue for separate media
streams (on different host/port quartets) that use independent keying
material even if an SSRC collision occurs.