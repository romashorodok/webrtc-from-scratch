# 9. Security

Lower layer protocols may eventually provide all the security
services that may be desired for applications of RTP, including
authentication, integrity, and confidentiality.  These services have
been specified for IP in [27].  Since the initial audio and video
applications using RTP needed a confidentiality service before such
services were available for the IP layer, the confidentiality service
described in the next section was defined for use with RTP and RTCP.
That description is included here to codify existing practice.  New
applications of RTP MAY implement this RTP-specific confidentiality
service for backward compatibility, and/or they MAY implement
alternative security services.  The overhead on the RTP protocol for
this confidentiality service is low, so the penalty will be minimal
if this service is obsoleted by other services in the future.

Alternatively, other services, other implementations of services and
other algorithms may be defined for RTP in the future.  In
particular, an RTP profile called Secure Real-time Transport Protocol
(SRTP) [28] is being developed to provide confidentiality of the RTP
payload while leaving the RTP header in the clear so that link-level
header compression algorithms can still operate.  It is expected that
SRTP will be the correct choice for many applications.  SRTP is based
on the Advanced Encryption Standard (AES) and provides stronger
security than the service described here.  No claim is made that the
methods presented here are appropriate for a particular security
need.  A profile may specify which services and algorithms should be
offered by applications, and may provide guidance as to their
appropriate use.

Key distribution and certificates are outside the scope of this
document.

## 9.1 Confidentiality

Confidentiality means that only the intended receiver(s) can decode
the received packets; for others, the packet contains no useful
information.  Confidentiality of the content is achieved by
encryption.

When it is desired to encrypt RTP or RTCP according to the method
specified in this section, all the octets that will be encapsulated
for transmission in a single lower-layer packet are encrypted as a
unit.  For RTCP, a 32-bit random number redrawn for each unit MUST be
prepended to the unit before encryption.  For RTP, no prefix is
prepended; instead, the sequence number and timestamp fields are
initialized with random offsets.  This is considered to be a weak

initialization vector (IV) because of poor randomness properties.  In
addition, if the subsequent field, the SSRC, can be manipulated by an
enemy, there is further weakness of the encryption method.

For RTCP, an implementation MAY segregate the individual RTCP packets
in a compound RTCP packet into two separate compound RTCP packets,
one to be encrypted and one to be sent in the clear.  For example,
SDES information might be encrypted while reception reports were sent
in the clear to accommodate third-party monitors that are not privy
to the encryption key.  In this example, depicted in Fig. 4, the SDES
information MUST be appended to an RR packet with no reports (and the
random number) to satisfy the requirement that all compound RTCP
packets begin with an SR or RR packet.  The SDES CNAME item is
required in either the encrypted or unencrypted packet, but not both.
The same SDES information SHOULD NOT be carried in both packets as
this may compromise the encryption.


             UDP packet                     UDP packet
   -----------------------------  ------------------------------
   [random][RR][SDES #CNAME ...]  [SR #senderinfo #site1 #site2]
   -----------------------------  ------------------------------
             encrypted                     not encrypted

   #: SSRC identifier

       Figure 4: Encrypted and non-encrypted RTCP packets

The presence of encryption and the use of the correct key are
confirmed by the receiver through header or payload validity checks.
Examples of such validity checks for RTP and RTCP headers are given
in Appendices A.1 and A.2.

To be consistent with existing implementations of the initial
specification of RTP in RFC 1889, the default encryption algorithm is
the Data Encryption Standard (DES) algorithm in cipher block chaining
(CBC) mode, as described in Section 1.1 of RFC 1423 [29], except that
padding to a multiple of 8 octets is indicated as described for the P
bit in Section 5.1.  The initialization vector is zero because random
values are supplied in the RTP header or by the random prefix for
compound RTCP packets.  For details on the use of CBC initialization
vectors, see [30].

Implementations that support the encryption method specified here
SHOULD always support the DES algorithm in CBC mode as the default
cipher for this method to maximize interoperability.  This method was
chosen because it has been demonstrated to be easy and practical to
use in experimental audio and video tools in operation on the
Internet.  However, DES has since been found to be too easily broken.

It is RECOMMENDED that stronger encryption algorithms such as
Triple-DES be used in place of the default algorithm.  Furthermore,
secure CBC mode requires that the first block of each packet be XORed
with a random, independent IV of the same size as the cipher's block
size.  For RTCP, this is (partially) achieved by prepending each
packet with a 32-bit random number, independently chosen for each
packet.  For RTP, the timestamp and sequence number start from random
values, but consecutive packets will not be independently randomized.
It should be noted that the randomness in both cases (RTP and RTCP)
is limited.  High-security applications SHOULD consider other, more
conventional, protection means.  Other encryption algorithms MAY be
specified dynamically for a session by non-RTP means.  In particular,
the SRTP profile [28] based on AES is being developed to take into
account known plaintext and CBC plaintext manipulation concerns, and
will be the correct choice in the future.

As an alternative to encryption at the IP level or at the RTP level
as described above, profiles MAY define additional payload types for
encrypted encodings.  Those encodings MUST specify how padding and
other aspects of the encryption are to be handled.  This method
allows encrypting only the data while leaving the headers in the
clear for applications where that is desired.  It may be particularly
useful for hardware devices that will handle both decryption and
decoding.  It is also valuable for applications where link-level
compression of RTP and lower-layer headers is desired and
confidentiality of the payload (but not addresses) is sufficient
since encryption of the headers precludes compression.

## 9.2 Authentication and Message Integrity

Authentication and message integrity services are not defined at the
RTP level since these services would not be directly feasible without
a key management infrastructure.  It is expected that authentication
and integrity services will be provided by lower layer protocols.
