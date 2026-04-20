The use of multiple data protection framings negotiated in the same
handshake creates some complexities, which are discussed here.

## 7.1.  Security of Negotiation

One concern here is that attackers might be able to implement a bid-
down attack forcing the peers to use ordinary DTLS rather than SRTP.
However, because the negotiation of this extension is performed in
the DTLS handshake, it is protected by the Finished messages.
Therefore, any bid-down attack is automatically detected, which
reduces this to a denial-of-service attack -- which can be mounted by
any attacker who can control the channel.

## 7.2.  Framing Confusion

Because two different framing formats are used, there is concern that
an attacker could convince the receiver to treat an SRTP-framed RTP
packet as a DTLS record (e.g., a handshake message) or vice versa.
This attack is prevented by using different keys for Message
Authentication Code (MAC) verification for each type of data.
Therefore, this type of attack reduces to being able to forge a
packet with a valid MAC, which violates a basic security invariant of
both DTLS and SRTP.

As an additional defense against injection into the DTLS handshake
channel, the DTLS record type is included in the MAC.  Therefore, an
SRTP record would be treated as an unknown type and ignored.  (See
Section 6 of [RFC5246].)

## 7.3.  Sequence Number Interactions

As described in Section 5.1.1, the SRTP and DTLS sequence number
spaces are distinct.  This means that it is not possible to
unambiguously order a given DTLS control record with respect to an
SRTP packet.  In general, this is relevant in two situations: alerts
and rehandshake.

### 7.3.1.  Alerts

Because DTLS handshake and change_cipher_spec messages share the same
sequence number space as alerts, they can be ordered correctly.
Because DTLS alerts are inherently unreliable and SHOULD NOT be
generated as a response to data packets, reliable sequencing between
SRTP packets and DTLS alerts is not an important feature.  However,
implementations that wish to use DTLS alerts to signal problems with
the SRTP encoding SHOULD simply act on alerts as soon as they are
received and assume that they refer to the temporally contiguous
stream.  Such implementations MUST check for alert retransmission and
discard retransmitted alerts to avoid overreacting to replay attacks.

### 7.3.2.  Renegotiation

Because the rehandshake transition algorithm specified in Section 5.2
requires trying multiple sets of keys if no MKI is used, it slightly
weakens the authentication.  For instance, if an n-bit MAC is used
and k different sets of keys are present, then the MAC is weakened by
log_2(k) bits to n - log_2(k).  In practice, since the number of keys
used will be very small and the MACs in use are typically strong (the
default for SRTP is 80 bits), the decrease in security involved here
is minimal.

Another concern here is that this algorithm slightly increases the
work factor on the receiver because it needs to attempt multiple
validations.  However, again, the number of potential keys will be
very small (and the attacker cannot force it to be larger) and this
technique is already used for rollover counter management, so the
authors do not consider this to be a serious flaw.

## 7.4.  Decryption Cost

An attacker can impose computational costs on the receiver by sending
superficially valid SRTP packets that do not decrypt correctly.  In
general, encryption algorithms are so fast that this cost is
extremely small compared to the bandwidth consumed.  The SSRC-DTLS
mapping algorithm described in Section 5.1.2 gives the attacker a
slight advantage here because he can force the receiver to do more
then one decryption per packet.  However, this advantage is modest
because the number of decryptions that the receiver does is limited
by the number of associations he has corresponding to a given
destination host/port, which is typically quite small.  For
comparison, a single 1024-bit RSA private key operation (the typical
minimum cost to establish a DTLS-SRTP association) is hundreds of
times as expensive as decrypting an SRTP packet.

Implementations can detect this form of attack by keeping track of
the number of SRTP packets that are observed with unknown SSRCs and
that fail the authentication tag check.  If under such attack,
implementations SHOULD prioritize decryption and verification of
packets that either have known SSRCs or come from source addresses
that match those of peers with which it has DTLS-SRTP associations.

## 8.  Session Description for RTP/SAVP over DTLS

This specification defines new tokens to describe the protocol used
in SDP media descriptions ("m=" lines and their associated
parameters).  The new values defined for the proto field are:

o  When a RTP/SAVP or RTP/SAVPF [RFC5124] stream is transported over
    DTLS with the Datagram Congestion Control Protocol (DCCP), then
    the token SHALL be DCCP/TLS/RTP/SAVP or DCCP/TLS/RTP/SAVPF
    respectively.

o  When a RTP/SAVP or RTP/SAVPF stream is transported over DTLS with
    UDP, the token SHALL be UDP/TLS/RTP/SAVP or UDP/TLS/RTP/SAVPF
    respectively.

The "fmt" parameter SHALL be as defined for RTP/SAVP.

See [RFC5763] for how to use offer/answer with DTLS-SRTP.

This document does not specify how to protect RTP data transported
over TCP.  Potential approaches include carrying the RTP over TLS
over TCP (see [SRTP-NOT-MAND]) or using a mechanism similar to that
in this document over TCP, either via TLS or DTLS, with DTLS being
used for consistency between reliable and unreliable transports.  In the latter case, it would be necessary to profile DTLS so that
fragmentation and retransmissions no longer occurred.  In either
case, a new document would be required.

## Appendix A.  Overview of DTLS

This section provides a brief overview of Datagram TLS (DTLS) for
those who are not familiar with it.  DTLS is a channel security
protocol based on the well-known Transport Layer Security (TLS)
[RFC5246] protocol.  Where TLS depends on a reliable transport
channel (typically TCP), DTLS has been adapted to support unreliable
transports such as UDP.  Otherwise, DTLS is nearly identical to TLS
and generally supports the same cryptographic mechanisms.

Each DTLS association begins with a handshake exchange (shown below)
during which the peers authenticate each other and negotiate
algorithms, modes, and other parameters and establish shared keying
material, as shown below.  In order to support unreliable transport,
each side maintains retransmission timers to provide reliable
delivery of these messages.  Once the handshake is completed,
encrypted data may be sent.

         Client                                               Server

         ClientHello                  -------->
                                                         ServerHello
                                                        Certificate*
                                                  ServerKeyExchange*
                                                 CertificateRequest*
                                      <--------      ServerHelloDone
         Certificate*
         ClientKeyExchange
         CertificateVerify*
         [ChangeCipherSpec]
         Finished                     -------->
                                                  [ChangeCipherSpec]
                                      <--------             Finished
         Application Data             <------->     Application Data

               '*' indicates messages that are not always sent.

        Figure 5: Basic DTLS Handshake Exchange (after [RFC4347]).

Application data is protected by being sent as a series of DTLS
"records".  These records are independent and can be processed
correctly even in the face of loss or reordering.  In DTLS-SRTP, this
record protocol is replaced with SRTP [RFC3711]

## Appendix B.  Performance of Multiple DTLS Handshakes

Standard practice for security protocols such as TLS, DTLS, and SSH,
which do inline key management, is to create a separate security
association for each underlying network channel (TCP connection, UDP
host/port quartet, etc.).  This has dual advantages of simplicity and
independence of the security contexts for each channel.

Three concerns have been raised about the overhead of this strategy
in the context of RTP security.  The first concern is the additional
performance overhead of doing a separate public key operation for
each channel.  The conventional procedure here (used in TLS and DTLS)
is to establish a master context that can then be used to derive
fresh traffic keys for new associations.  In TLS/DTLS, this is called
"session resumption" and can be transparently negotiated between the
peers.

The second concern is network bandwidth overhead for the
establishment of subsequent connections and for rehandshake (for
rekeying) for existing connections.  In particular, there is a
concern that the channels will have very narrow capacity requirements
allocated entirely to media that will be overflowed by the
rehandshake.  Measurements of the size of the rehandshake (with
resumption) in TLS indicate that it is about 300-400 bytes if a full
selection of cipher suites is offered.  (The size of a full handshake
is approximately 1-2 kilobytes larger because of the certificate and
keying material exchange.)

The third concern is the additional round-trips associated with
establishing the second, third, ... channels.  In TLS/DTLS, these can
all be done in parallel, but in order to take advantage of session
resumption they should be done after the first channel is
established.  For two channels, this provides a ladder diagram
something like this (parenthetical numbers are media channel numbers)


   Alice                                   Bob
   -------------------------------------------
                      <-       ClientHello (1)
   ServerHello (1)    ->
   Certificate (1)
   ServerHelloDone (1)
                      <- ClientKeyExchange (1)
                          ChangeCipherSpec (1)
                                  Finished (1)
   ChangeCipherSpec (1)->
   Finished         (1)->
                                                <--- Channel 1 ready

                      <-       ClientHello (2)
   ServerHello (2)    ->
   ChangeCipherSpec(2)->
   Finished(2)        ->
                      <-  ChangeCipherSpec (2)
                                  Finished (2)
                                                <--- Channel 2 ready

                Figure 6: Parallel DTLS-SRTP negotiations.

So, there is an additional 1 RTT (round-trip time) after Channel 1 is
ready before Channel 2 is ready.  If the peers are potentially
willing to forego resumption, they can interlace the handshakes, like
so:

   Alice                                   Bob
   -------------------------------------------
                      <-       ClientHello (1)
   ServerHello (1)    ->
   Certificate (1)
   ServerHelloDone (1)
                      <- ClientKeyExchange (1)
                          ChangeCipherSpec (1)
                                  Finished (1)
                      <-       ClientHello (2)
   ChangeCipherSpec (1)->
   Finished         (1)->
                                                <--- Channel 1 ready
   ServerHello (2)    ->
   ChangeCipherSpec(2)->
   Finished(2)        ->
                      <-  ChangeCipherSpec (2)
                                  Finished (2)
                                                <--- Channel 2 ready

               Figure 7: Interlaced DTLS-SRTP negotiations.

In this case, the channels are ready contemporaneously, but if a
message in handshake (1) is lost, then handshake (2) requires either
a full rehandshake or that Alice be clever and queue the resumption
attempt until the first handshake completes.  Note that just dropping
the packet works as well, since Bob will retransmit.