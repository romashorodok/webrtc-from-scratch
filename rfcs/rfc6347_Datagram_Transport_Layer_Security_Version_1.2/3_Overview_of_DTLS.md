The basic design philosophy of DTLS is to construct "TLS over
datagram transport".  The reason that TLS cannot be used directly in
datagram environments is simply that packets may be lost or
reordered.  TLS has no internal facilities to handle this kind of
unreliability; therefore, TLS implementations break when rehosted on
datagram transport.  The purpose of DTLS is to make only the minimal
changes to TLS required to fix this problem.  To the greatest extent
possible, DTLS is identical to TLS.  Whenever we need to invent new
mechanisms, we attempt to do so in such a way that preserves the
style of TLS.

Unreliability creates problems for TLS at two levels:

    1. TLS does not allow independent decryption of individual
        records.  Because the integrity check depends on the sequence
        number, if record N is not received, then the integrity check
        on record N+1 will be based on the wrong sequence number and
        thus will fail.  (Note that prior to TLS 1.1, there was no
        explicit IV and so decryption would also fail.)

    2. The TLS handshake layer assumes that handshake messages are
        delivered reliably and breaks if those messages are lost.

The rest of this section describes the approach that DTLS uses to
solve these problems.

## 3.1.  Loss-Insensitive Messaging

In TLS's traffic encryption layer (called the TLS Record Layer),
records are not independent.  There are two kinds of inter-record
dependency:

    1. Cryptographic context (stream cipher key stream) is retained
        between records.

    2. Anti-replay and message reordering protection are provided by a
        MAC that includes a sequence number, but the sequence numbers
        are implicit in the records.

DTLS solves the first problem by banning stream ciphers.  DTLS solves
the second problem by adding explicit sequence numbers.

## 3.2.  Providing Reliability for Handshake

The TLS handshake is a lockstep cryptographic handshake.  Messages
must be transmitted and received in a defined order; any other order
is an error.  Clearly, this is incompatible with reordering and
message loss.  In addition, TLS handshake messages are potentially
larger than any given datagram, thus creating the problem of IP
fragmentation.  DTLS must provide fixes for both of these problems.

### 3.2.1.  Packet Loss

DTLS uses a simple retransmission timer to handle packet loss.  The
following figure demonstrates the basic concept, using the first
phase of the DTLS handshake:

        Client                                   Server
        ------                                   ------
        ClientHello           ------>

                                X<-- HelloVerifyRequest
                                                (lost)

        [Timer Expires]

        ClientHello           ------>
        (retransmit)

Once the client has transmitted the ClientHello message, it expects
to see a HelloVerifyRequest from the server.  However, if the
server's message is lost, the client knows that either the
ClientHello or the HelloVerifyRequest has been lost and retransmits.
When the server receives the retransmission, it knows to retransmit.

The server also maintains a retransmission timer and retransmits when
that timer expires.

Note that timeout and retransmission do not apply to the
HelloVerifyRequest, because this would require creating state on the
server.  The HelloVerifyRequest is designed to be small enough that
it will not itself be fragmented, thus avoiding concerns about
interleaving multiple HelloVerifyRequests.

### 3.2.2.  Reordering

In DTLS, each handshake message is assigned a specific sequence
number within that handshake.  When a peer receives a handshake
message, it can quickly determine whether that message is the next
message it expects.  If it is, then it processes it.  If not, it
queues it for future handling once all previous messages have been
received.

### 3.2.3.  Message Size

TLS and DTLS handshake messages can be quite large (in theory up to
2^24-1 bytes, in practice many kilobytes).  By contrast, UDP
datagrams are often limited to <1500 bytes if IP fragmentation is not
desired.  In order to compensate for this limitation, each DTLS
handshake message may be fragmented over several DTLS records, each
of which is intended to fit in a single IP datagram.  Each DTLS
handshake message contains both a fragment offset and a fragment
length.  Thus, a recipient in possession of all bytes of a handshake
message can reassemble the original unfragmented message.

### 3.3.  Replay Detection

DTLS optionally supports record replay detection.  The technique used
is the same as in IPsec AH/ESP, by maintaining a bitmap window of
received records.  Records that are too old to fit in the window and
records that have previously been received are silently discarded.
The replay detection feature is optional, since packet duplication is
not always malicious, but can also occur due to routing errors.
Applications may conceivably detect duplicate packets and accordingly
modify their data transmission strategy.

## 4.  Differences from TLS

As mentioned in Section 3, DTLS is intentionally very similar to TLS.
Therefore, instead of presenting DTLS as a new protocol, we present
it as a series of deltas from TLS 1.2 [TLS12].  Where we do not
explicitly call out differences, DTLS is the same as in [TLS12].

### 4.1.  Record Layer

The DTLS record layer is extremely similar to that of TLS 1.2.  The
only change is the inclusion of an explicit sequence number in the
record.  This sequence number allows the recipient to correctly
verify the TLS MAC.  The DTLS record format is shown below:

    struct {
        ContentType type;
        ProtocolVersion version;
        uint16 epoch;                                    // New field
        uint48 sequence_number;                          // New field
        uint16 length;
        opaque fragment[DTLSPlaintext.length];
        } DTLSPlaintext;

type
    Equivalent to the type field in a TLS 1.2 record.

version
    The version of the protocol being employed.  This document
    describes DTLS version 1.2, which uses the version { 254, 253 }.
    The version value of 254.253 is the 1's complement of DTLS version
    1.2.  This maximal spacing between TLS and DTLS version numbers
    ensures that records from the two protocols can be easily
    distinguished.  It should be noted that future on-the-wire version
    numbers of DTLS are decreasing in value (while the true version
    number is increasing in value.)

epoch
    A counter value that is incremented on every cipher state change.

sequence_number
    The sequence number for this record.

length
    Identical to the length field in a TLS 1.2 record.  As in TLS 1.2,
    the length should not exceed 2^14.

fragment
    Identical to the fragment field of a TLS 1.2 record.

DTLS uses an explicit sequence number, rather than an implicit one,
carried in the sequence_number field of the record.  Sequence numbers
are maintained separately for each epoch, with each sequence_number
initially being 0 for each epoch.  For instance, if a handshake
message from epoch 0 is retransmitted, it might have a sequence
number after a message from epoch 1, even if the message from epoch 1

