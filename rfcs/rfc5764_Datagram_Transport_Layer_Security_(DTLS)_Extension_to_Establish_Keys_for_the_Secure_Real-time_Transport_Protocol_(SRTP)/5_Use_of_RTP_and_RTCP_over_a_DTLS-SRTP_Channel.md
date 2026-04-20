## 5.1.  Data Protection

Once the DTLS handshake has completed, the peers can send RTP or RTCP
over the newly created channel.  We describe the transmission process
first followed by the reception process.

Within each RTP session, SRTP processing MUST NOT take place before
the DTLS handshake completes.

### 5.1.1.  Transmission

DTLS and TLS define a number of record content types.  In ordinary
TLS/DTLS, all data is protected using the same record encoding and
mechanisms.  When the mechanism described in this document is in
effect, this is modified so that data written by upper-level protocol
clients of DTLS is assumed to be RTP/RTP and is encrypted using SRTP
rather than the standard TLS record encoding.

When a user of DTLS wishes to send an RTP packet in SRTP mode, it
delivers it to the DTLS implementation as an ordinary application
data write (e.g., SSL_write()).  The DTLS implementation then invokes
the processing described in RFC 3711, Sections 3 and 4.  The
resulting SRTP packet is then sent directly on the wire as a single
datagram with no DTLS framing.  This provides an encapsulation of the
data that conforms to and interoperates with SRTP.  Note that the RTP
sequence number rather than the DTLS sequence number is used for
these packets.

### 5.1.2.  Reception

When DTLS-SRTP is used to protect an RTP session, the RTP receiver
needs to demultiplex packets that are arriving on the RTP port.
Arriving packets may be of types RTP, DTLS, or STUN [RFC5389].  If
these are the only types of packets present, the type of a packet can
be determined by looking at its first byte.

The process for demultiplexing a packet is as follows.  The receiver
looks at the first byte of the packet.  If the value of this byte is
0 or 1, then the packet is STUN.  If the value is in between 128 and
191 (inclusive), then the packet is RTP (or RTCP, if both RTCP and
RTP are being multiplexed over the same destination port).  If the
value is between 20 and 63 (inclusive), the packet is DTLS.  This
process is summarized in Figure 3.

                   +----------------+
                   | 127 < B < 192 -+--> forward to RTP
                   |                |
       packet -->  |  19 < B < 64  -+--> forward to DTLS
                   |                |
                   |       B < 2   -+--> forward to STUN
                   +----------------+

    Figure 3: The DTLS-SRTP receiver's packet demultiplexing algorithm.
         Here the field B denotes the leading byte of the packet.

If other packet types are to be multiplexed as well, implementors
and/or designers SHOULD ensure that they can be demultiplexed from
these three packet types.

In some cases, there will be multiple DTLS-SRTP associations for a
given SRTP endpoint.  For instance, if Alice makes a call that is SIP
forked to both Bob and Charlie, she will use the same local host/port
pair for both of them, as shown in Figure 4, where XXX and YYY
represent different DTLS-SRTP associations.  (The SSRCs shown are the
ones for data flowing to Alice.)

                                          Bob (192.0.2.1:6666)
                                         /
                                        /
                                       / SSRC=1
                                      /  DTLS-SRTP=XXX
                                     /
                                    v
               Alice (192.0.2.0:5555)
                                    ^
                                     \
                                      \  SSRC=2
                                       \ DTLS-SRTP=YYY
                                        \
                                         \
                                          Charlie (192.0.2.2:6666)

                 Figure 4: RTP sessions with SIP forking.

Because DTLS operates on the host/port quartet, the DTLS association
will still complete correctly, with the foreign host/port pair being
used, to distinguish the associations.  However, in RTP the source
host/port is not used and sessions are identified by the destination
host/port and the SSRC.  Thus, some mechanism is needed to determine
which SSRCs correspond to which DTLS associations.  The following
method SHOULD be used.

For each local host/port pair, the DTLS-SRTP implementation maintains
a table listing all the SSRCs it knows about and the DTLS-SRTP
associations they correspond to.  Initially, this table is empty.
When an SRTP packet is received for a given RTP endpoint (destination
IP/port pair), the following procedure is used:

1.  If the SSRC is already known for that endpoint, then the
    corresponding DTLS-SRTP association and its keying material is
    used to decrypt and verify the packet.
2.  If the SSRC is not known, then the receiver tries to decrypt it
    with the keying material corresponding to each DTLS-SRTP
    association for that endpoint.
3.  If the decryption and verification succeeds (the authentication
    tag verifies), then an entry is placed in the table mapping the
    SSRC to that association.
4.  If the decryption and verification fails, then the packet is
    silently discarded.
5.  When a DTLS-SRTP association is closed (for instance, because the
    fork is abandoned), its entries MUST be removed from the mapping
    table.

The average cost of this algorithm for a single SSRC is the
decryption and verification time of a single packet times the number
of valid DTLS-SRTP associations corresponding to a single receiving
port on the host.  In practice, this means the number of forks; so in
the case shown in Figure 4, that would be two.  This cost is only
incurred once for any given SSRC, since afterwards that SSRC is
placed in the map table and looked up immediately.  As with normal
RTP, this algorithm allows new SSRCs to be introduced by the source
at any time.  They will automatically be mapped to the correct DTLS
association.

Note that this algorithm explicitly allows multiple SSRCs to be sent
from the same address/port pair.  One way in which this can happen is
an RTP translator.  This algorithm will automatically assign the
SSRCs to the correct associations.  Note that because the SRTP
packets are cryptographically protected, such a translator must
either share keying material with one endpoint or refrain from
modifying the packets in a way which would cause the integrity check
to fail.  This is a general property of SRTP and is not specific to
DTLS-SRTP.

There are two error cases that should be considered.  First, if an
SSRC collision occurs, then only the packets from the first source
will be processed.  When the packets from the second source arrive,
the DTLS association with the first source will be used for
decryption and verification, which will fail, and the packet will be
discarded.  This is consistent with [RFC3550], which permits the

receiver to keep the packets from one source and discard those from
the other.  Of course the RFC 3550 SSRC collision detection and
handling procedures MUST also be followed.

Second, there may be cases where a malfunctioning source is sending
corrupt packets that cannot be decrypted and verified.  In this case,
the SSRC will never be entered into the mapping table because the
decryption and verification always fails.  Receivers MAY keep records
of unmapped SSRCs that consistently fail decryption and verification
and abandon attempts to process them once they reach some limit.
That limit MUST be large enough to account for the effects of
transmission errors.  Entries MUST be pruned from this table when the
relevant SRTP endpoint is deleted (e.g., the call ends) and SHOULD
time out faster than that (we do not offer a hard recommendation but
10 to 30 seconds seems appropriate) in order to allow for the
possibility that the peer implementation has been corrected.

## 5.2.  Rehandshake and Rekey

Rekeying in DTLS is accomplished by performing a new handshake over
the existing DTLS channel.  That is, the handshake messages are
protected by the existing DTLS cipher suite.  This handshake can be
performed in parallel with data transport, so no interruption of the
data flow is required.  Once the handshake is finished, the newly
derived set of keys is used to protect all outbound packets, both
DTLS and SRTP.

Because of packet reordering, packets protected by the previous set
of keys can appear on the wire after the handshake has completed.  To
compensate for this fact, receivers SHOULD maintain both sets of keys
for some time in order to be able to decrypt and verify older
packets.  The keys should be maintained for the duration of the
maximum segment lifetime (MSL).

If an MKI is used, then the receiver should use the corresponding set
of keys to process an incoming packet.  If no matching MKI is
present, the packet MUST be rejected.  Otherwise, when a packet
arrives after the handshake completed, a receiver SHOULD use the
newly derived set of keys to process that packet unless there is an
MKI.  (If the packet was protected with the older set of keys, this
fact will become apparent to the receiver as an authentication
failure will occur.)  If the authentication check on the packet fails
and no MKI is being used, then the receiver MAY process the packet
with the older set of keys.  If that authentication check indicates
that the packet is valid, the packet should be accepted; otherwise,
the packet MUST be discarded and rejected.

Receivers MAY use the SRTP packet sequence number to aid in the
selection of keys.  After a packet has been received and
authenticated with the new key set, any packets with sequence numbers
that are greater will also have been protected with the new key set.

## 6.  Multi-Party RTP Sessions

Since DTLS is a point-to-point protocol, DTLS-SRTP is intended only
to protect unicast RTP sessions.  This does not preclude its use with
RTP mixers.  For example, a conference bridge may use DTLS-SRTP to
secure the communication to and from each of the participants in a
conference.  However, because each flow between an endpoint and a
mixer has its own key, the mixer has to decrypt and then reencrypt
the traffic for each recipient.

A future specification may describe methods for sharing a single key
between multiple DTLS-SRTP associations thus allowing conferencing
systems to avoid the decrypt/reencrypt stage.  However, any system in
which the media is modified (e.g., for level balancing or
transcoding) will generally need to be performed on the plaintext and
will certainly break the authentication tag, and therefore will
require a decrypt/reencrypt stage.