## 3.  SRTP Framework

RTP is the Real-time Transport Protocol [RFC3550].  We define SRTP as
a profile of RTP.  This profile is an extension to the RTP
Audio/Video Profile [RFC3551].  Except where explicitly noted, all
aspects of that profile apply, with the addition of the SRTP security
features.  Conceptually, we consider SRTP to be a "bump in the stack"
implementation which resides between the RTP application and the
transport layer.  SRTP intercepts RTP packets and then forwards an
equivalent SRTP packet on the sending side, and intercepts SRTP
packets and passes an equivalent RTP packet up the stack on the
receiving side.

Secure RTCP (SRTCP) provides the same security services to RTCP as
SRTP does to RTP.  SRTCP message authentication is MANDATORY and
thereby protects the RTCP fields to keep track of membership, provide
feedback to RTP senders, or maintain packet sequence counters.  SRTCP
is described in Section 3.4.

### 3.1.  Secure RTP

The format of an SRTP packet is illustrated in Figure 1.

        0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
     |V=2|P|X|  CC   |M|     PT      |       sequence number         | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     |                           timestamp                           | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     |           synchronization source (SSRC) identifier            | |
     +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
     |            contributing source (CSRC) identifiers             | |
     |                               ....                            | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     |                   RTP extension (OPTIONAL)                    | |
   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | |                          payload  ...                         | |
   | |                               +-------------------------------+ |
   | |                               | RTP padding   | RTP pad count | |
   +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
   | ~                     SRTP MKI (OPTIONAL)                       ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | :                 authentication tag (RECOMMENDED)              : |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   |                                                                   |
   +- Encrypted Portion*                      Authenticated Portion ---+

   Figure 1.  The format of an SRTP packet.  *Encrypted Portion is the
   same size as the plaintext for the Section 4 pre-defined transforms.

The "Encrypted Portion" of an SRTP packet consists of the encryption
of the RTP payload (including RTP padding when present) of the
equivalent RTP packet.  The Encrypted Portion MAY be the exact size
of the plaintext or MAY be larger.  Figure 1 shows the RTP payload
including any possible padding for RTP [RFC3550].

None of the pre-defined encryption transforms uses any padding; for
these, the RTP and SRTP payload sizes match exactly.  New transforms
added to SRTP (following Section 6) may require padding, and may
hence produce larger payloads.  RTP provides its own padding format
(as seen in Fig. 1), which due to the padding indicator in the RTP
header has merits in terms of compactness relative to paddings using
prefix-free codes.  This RTP padding SHALL be the default method for
transforms requiring padding.  Transforms MAY specify other padding
methods, and MUST then specify the amount, format, and processing of
their padding.  It is important to note that encryption transforms

that use padding are vulnerable to subtle attacks, especially when
message authentication is not used [V02].  Each specification for a
new encryption transform needs to carefully consider and describe the
security implications of the padding that it uses.  Message
authentication codes define their own padding, so this default does
not apply to authentication transforms.

The OPTIONAL MKI and the RECOMMENDED authentication tag are the only
fields defined by SRTP that are not in RTP.  Only 8-bit alignment is
assumed.

    MKI (Master Key Identifier): configurable length, OPTIONAL.  The
            MKI is defined, signaled, and used by key management.  The
            MKI identifies the master key from which the session
            key(s) were derived that authenticate and/or encrypt the
            particular packet.  Note that the MKI SHALL NOT identify
            the SRTP cryptographic context, which is identified
            according to Section 3.2.3.  The MKI MAY be used by key
            management for the purposes of re-keying, identifying a
            particular master key within the cryptographic context
            (Section 3.2.1).

    Authentication tag: configurable length, RECOMMENDED.  The
            authentication tag is used to carry message authentication
            data.  The Authenticated Portion of an SRTP packet
            consists of the RTP header followed by the Encrypted
            Portion of the SRTP packet.  Thus, if both encryption and
            authentication are applied, encryption SHALL be applied
            before authentication on the sender side and conversely on
            the receiver side.  The authentication tag provides
            authentication of the RTP header and payload, and it
            indirectly provides replay protection by authenticating
            the sequence number.  Note that the MKI is not integrity
            protected as this does not provide any extra protection.

### 3.2.  SRTP Cryptographic Contexts

Each SRTP stream requires the sender and receiver to maintain
cryptographic state information.  This information is called the
"cryptographic context".

SRTP uses two types of keys: session keys and master keys.  By a
"session key", we mean a key which is used directly in a
cryptographic transform (e.g., encryption or message authentication),
and by a "master key", we mean a random bit string (given by the key
management protocol) from which session keys are derived in a

cryptographically secure way.  The master key(s) and other parameters
in the cryptographic context are provided by key management
mechanisms external to SRTP, see Section 8.

### 3.2.1.  Transform-independent parameters

Transform-independent parameters are present in the cryptographic
context independently of the particular encryption or authentication
transforms that are used.  The transform-independent parameters of
the cryptographic context for SRTP consist of:

*  a 32-bit unsigned rollover counter (ROC), which records how many
    times the 16-bit RTP sequence number has been reset to zero after
    passing through 65,535.  Unlike the sequence number (SEQ), which
    SRTP extracts from the RTP packet header, the ROC is maintained by
    SRTP as described in Section 3.3.1.

    We define the index of the SRTP packet corresponding to a given
    ROC and RTP sequence number to be the 48-bit quantity

        i = 2^16 * ROC + SEQ.

*  for the receiver only, a 16-bit sequence number s_l, which can be
    thought of as the highest received RTP sequence number (see
    Section 3.3.1 for its handling), which SHOULD be authenticated
    since message authentication is RECOMMENDED,

*  an identifier for the encryption algorithm, i.e., the cipher and
    its mode of operation,

*  an identifier for the message authentication algorithm,

*  a replay list, maintained by the receiver only (when
    authentication and replay protection are provided), containing
    indices of recently received and authenticated SRTP packets,

*  an MKI indicator (0/1) as to whether an MKI is present in SRTP and
    SRTCP packets,

*  if the MKI indicator is set to one, the length (in octets) of the
    MKI field, and (for the sender) the actual value of the currently
    active MKI (the value of the MKI indicator and length MUST be kept
    fixed for the lifetime of the context),

*  the master key(s), which MUST be random and kept secret,

*  for each master key, there is a counter of the number of SRTP
    packets that have been processed (sent) with that master key
    (essential for security, see Sections 3.3.1 and 9),

*  non-negative integers n_e, and n_a, determining the length of the
    session keys for encryption, and message authentication.

In addition, for each master key, an SRTP stream MAY use the
following associated values:

*  a master salt, to be used in the key derivation of session keys.
    This value, when used, MUST be random, but MAY be public.  Use of
    master salt is strongly RECOMMENDED, see Section 9.2.  A "NULL"
    salt is treated as 00...0.

*  an integer in the set {1,2,4,...,2^24}, the "key_derivation_rate",
    where an unspecified value is treated as zero.  The constraint to
    be a power of 2 simplifies the session-key derivation
    implementation, see Section 4.3.

*  an MKI value,

*  <From, To> values, specifying the lifetime for a master key,
    expressed in terms of the two 48-bit index values inside whose
    range (including the range end-points) the master key is valid.
    For the use of <From, To>, see Section 8.1.1.  <From, To> is an
    alternative to the MKI and assumes that a master key is in one-
    to-one correspondence with the SRTP session key on which the
    <From, To> range is defined.

SRTCP SHALL by default share the crypto context with SRTP, except:

*  no rollover counter and s_l-value need to be maintained as the
    RTCP index is explicitly carried in each SRTCP packet,

*  a separate replay list is maintained (when replay protection is
    provided),

*  SRTCP maintains a separate counter for its master key (even if the
    master key is the same as that for SRTP, see below), as a means to
    maintain a count of the number of SRTCP packets that have been
    processed with that key.

Note in particular that the master key(s) MAY be shared between SRTP
and the corresponding SRTCP, if the pre-defined transforms (including
the key derivation) are used but the session key(s) MUST NOT be so
shared.

In addition, there can be cases (see Sections 8 and 9.1) where
several SRTP streams within a given RTP session, identified by their
synchronization source (SSRCs, which is part of the RTP header),
share most of the crypto context parameters (including possibly
master and session keys).  In such cases, just as in the normal
SRTP/SRTCP parameter sharing above, separate replay lists and packet
counters for each stream (SSRC) MUST still be maintained.  Also,
separate SRTP indices MUST then be maintained.

A summary of parameters, pre-defined transforms, and default values
for the above parameters (and other SRTP parameters) can be found in
Sections 5 and 8.2.

### 3.2.3.  Mapping SRTP Packets to Cryptographic Contexts

Recall that an RTP session for each participant is defined [RFC3550]
by a pair of destination transport addresses (one network address
plus a port pair for RTP and RTCP), and that a multimedia session is
defined as a collection of RTP sessions.  For example, a particular
multimedia session could include an audio RTP session, a video RTP
session, and a text RTP session.

A cryptographic context SHALL be uniquely identified by the triplet
context identifier:

context id = <SSRC, destination network address, destination
transport port number>

where the destination network address and the destination transport
port are the ones in the SRTP packet.  It is assumed that, when
presented with this information, the key management returns a context
with the information as described in Section 3.2.

As noted above, SRTP and SRTCP by default share the bulk of the
parameters in the cryptographic context.  Thus, retrieving the crypto
context parameters for an SRTCP stream in practice may imply a
binding to the correspondent SRTP crypto context.  It is up to the
implementation to assure such binding, since the RTCP port may not be

directly deducible from the RTP port only.  Alternatively, the key
management may choose to provide separate SRTP- and SRTCP- contexts,
duplicating the common parameters (such as master key(s)).  The
latter approach then also enables SRTP and SRTCP to use, e.g.,
distinct transforms, if so desired.  Similar considerations arise
when multiple SRTP streams, forming part of one single RTP session,
share keys and other parameters.

If no valid context can be found for a packet corresponding to a
certain context identifier, that packet MUST be discarded.

## 3.3.  SRTP Packet Processing

The following applies to SRTP.  SRTCP is described in Section 3.4.

Assuming initialization of the cryptographic context(s) has taken
place via key management, the sender SHALL do the following to
construct an SRTP packet:

1. Determine which cryptographic context to use as described in
    Section 3.2.3.

2. Determine the index of the SRTP packet using the rollover counter,
    the highest sequence number in the cryptographic context, and the
    sequence number in the RTP packet, as described in Section 3.3.1.

3. Determine the master key and master salt.  This is done using the
    index determined in the previous step or the current MKI in the
    cryptographic context, according to Section 8.1.

4. Determine the session keys and session salt (if they are used by
    the transform) as described in Section 4.3, using master key,
    master salt, key_derivation_rate, and session key-lengths in the
    cryptographic context with the index, determined in Steps 2 and 3.

5. Encrypt the RTP payload to produce the Encrypted Portion of the
    packet (see Section 4.1, for the defined ciphers).  This step uses
    the encryption algorithm indicated in the cryptographic context,
    the session encryption key and the session salt (if used) found in
    Step 4 together with the index found in Step 2.

6. If the MKI indicator is set to one, append the MKI to the packet.

7. For message authentication, compute the authentication tag for the
    Authenticated Portion of the packet, as described in Section 4.2.
    This step uses the current rollover counter, the authentication
    algorithm indicated in the cryptographic context, and the session
    authentication key found in Step 4.  Append the authentication tag
    to the packet.

8. If necessary, update the ROC as in Section 3.3.1, using the packet
    index determined in Step 2.

To authenticate and decrypt an SRTP packet, the receiver SHALL do the
following:

1. Determine which cryptographic context to use as described in
    Section 3.2.3.

2. Run the algorithm in Section 3.3.1 to get the index of the SRTP
    packet.  The algorithm uses the rollover counter and highest
    sequence number in the cryptographic context with the sequence
    number in the SRTP packet, as described in Section 3.3.1.

3. Determine the master key and master salt.  If the MKI indicator in
    the context is set to one, use the MKI in the SRTP packet,
    otherwise use the index from the previous step, according to
    Section 8.1.

4. Determine the session keys, and session salt (if used by the
    transform) as described in Section 4.3, using master key, master
    salt, key_derivation_rate and session key-lengths in the
    cryptographic context with the index, determined in Steps 2 and 3.

5. For message authentication and replay protection, first check if
    the packet has been replayed (Section 3.3.2), using the Replay
    List and the index as determined in Step 2.  If the packet is
    judged to be replayed, then the packet MUST be discarded, and the
    event SHOULD be logged.

    Next, perform verification of the authentication tag, using the
    rollover counter from Step 2, the authentication algorithm
    indicated in the cryptographic context, and the session
    authentication key from Step 4.  If the result is "AUTHENTICATION
    FAILURE" (see Section 4.2), the packet MUST be discarded from
    further processing and the event SHOULD be logged.

6. Decrypt the Encrypted Portion of the packet (see Section 4.1, for
    the defined ciphers), using the decryption algorithm indicated in
    the cryptographic context, the session encryption key and salt (if
    used) found in Step 4 with the index from Step 2.

7. Update the rollover counter and highest sequence number, s_l, in
    the cryptographic context as in Section 3.3.1, using the packet
    index estimated in Step 2.  If replay protection is provided, also
    update the Replay List as described in Section 3.3.2.

8. When present, remove the MKI and authentication tag fields from
    the packet.

### 3.3.1.  Packet Index Determination, and ROC, s_l Update

SRTP implementations use an "implicit" packet index for sequencing,
i.e., not all of the index is explicitly carried in the SRTP packet.
For the pre-defined transforms, the index i is used in replay
protection (Section 3.3.2), encryption (Section 4.1), message
authentication (Section 4.2), and for the key derivation (Section
4.3).

When the session starts, the sender side MUST set the rollover
counter, ROC, to zero.  Each time the RTP sequence number, SEQ, wraps
modulo 2^16, the sender side MUST increment ROC by one, modulo 2^32
(see security aspects below).  The sender's packet index is then
defined as

    i = 2^16 * ROC + SEQ.

Receiver-side implementations use the RTP sequence number to
determine the correct index of a packet, which is the location of the
packet in the sequence of all SRTP packets.  A robust approach for
the proper use of a rollover counter requires its handling and use to
be well defined.  In particular, out-of-order RTP packets with
sequence numbers close to 2^16 or zero must be properly handled.

The index estimate is based on the receiver's locally maintained ROC
and s_l values.  At the setup of the session, the ROC MUST be set to
zero.  Receivers joining an on-going session MUST be given the
current ROC value using out-of-band signaling such as key-management
signaling.  Furthermore, the receiver SHALL initialize s_l to the RTP
sequence number (SEQ) of the first observed SRTP packet (unless the
initial value is provided by out of band signaling such as key
management).

On consecutive SRTP packets, the receiver SHOULD estimate the index
as
        i = 2^16 * v + SEQ,

where v is chosen from the set { ROC-1, ROC, ROC+1 } (modulo 2^32)
such that i is closest (in modulo 2^48 sense) to the value 2^16 * ROC
+ s_l (see Appendix A for pseudocode).

After the packet has been processed and authenticated (when enabled
for SRTP packets for the session), the receiver MUST use v to
conditionally update its s_l and ROC variables as follows.  If
v=(ROC-1) mod 2^32, then there is no update to s_l or ROC.  If v=ROC,
then s_l is set to SEQ if and only if SEQ is larger than the current
s_l; there is no change to ROC.  If v=(ROC+1) mod 2^32, then s_l is
set to SEQ and ROC is set to v.

After a re-keying occurs (changing to a new master key), the rollover
counter always maintains its sequence of values, i.e., it MUST NOT be
reset to zero.

As the rollover counter is 32 bits long and the sequence number is 16
bits long, the maximum number of packets belonging to a given SRTP
stream that can be secured with the same key is 2^48 using the pre-
defined transforms.  After that number of SRTP packets have been sent
with a given (master or session) key, the sender MUST NOT send any
more packets with that key.  (There exists a similar limit for SRTCP,
which in practice may be more restrictive, see Section 9.2.)  This
limitation enforces a security benefit by providing an upper bound on
the amount of traffic that can pass before cryptographic keys are
changed.  Re-keying (see Section 8.1) MUST be triggered, before this
amount of traffic, and MAY be triggered earlier, e.g., for increased
security and access control to media.  Recurring key derivation by
means of a non-zero key_derivation_rate (see Section 4.3), also gives
stronger security but does not change the above absolute maximum
value.

On the receiver side, there is a caveat to updating s_l and ROC: if
message authentication is not present, neither the initialization of
s_l, nor the ROC update can be made completely robust.  The
receiver's "implicit index" approach works for the pre-defined
transforms as long as the reorder and loss of the packets are not too
great and bit-errors do not occur in unfortunate ways.  In
particular, 2^15 packets would need to be lost, or a packet would
need to be 2^15 packets out of sequence before synchronization is
lost.  Such drastic loss or reorder is likely to disrupt the RTP
application itself.

The algorithm for the index estimate and ROC update is a matter of
implementation, and should take into consideration the environment
(e.g., packet loss rate) and the cases when synchronization is likely
to be lost, e.g., when the initial sequence number (randomly chosen
by RTP) is not known in advance (not sent in the key management
protocol) but may be near to wrap modulo 2^16.
A more elaborate and more robust scheme than the one given above is
the handling of RTP's own "rollover counter", see Appendix A.1 of
[RFC3550].

### 3.3.2.  Replay Protection

Secure replay protection is only possible when integrity protection
is present.  It is RECOMMENDED to use replay protection, both for RTP
and RTCP, as integrity protection alone cannot assure security
against replay attacks.

A packet is "replayed" when it is stored by an adversary, and then
re-injected into the network.  When message authentication is
provided, SRTP protects against such attacks through a Replay List.
Each SRTP receiver maintains a Replay List, which conceptually
contains the indices of all of the packets which have been received
and authenticated.  In practice, the list can use a "sliding window"
approach, so that a fixed amount of storage suffices for replay
protection.  Packet indices which lag behind the packet index in the
context by more than SRTP-WINDOW-SIZE can be assumed to have been
received, where SRTP-WINDOW-SIZE is a receiver-side, implementation-
dependent parameter and MUST be at least 64, but which MAY be set to
a higher value.

The receiver checks the index of an incoming packet against the
replay list and the window.  Only packets with index ahead of the
window, or, inside the window but not already received, SHALL be
accepted.

After the packet has been authenticated (if necessary the window is
first moved ahead), the replay list SHALL be updated with the new
index.

The Replay List can be efficiently implemented by using a bitmap to
represent which packets have been received, as described in the
Security Architecture for IP [RFC2401].

### 3.4.  Secure RTCP

Secure RTCP follows the definition of Secure RTP.  SRTCP adds three
mandatory new fields (the SRTCP index, an "encrypt-flag", and the
authentication tag) and one optional field (the MKI) to the RTCP
packet definition.  The three mandatory fields MUST be appended to an
RTCP packet in order to form an equivalent SRTCP packet.  The added
fields follow any other profile-specific extensions.

According to Section 6.1 of [RFC3550], there is a REQUIRED packet
format for compound packets.  SRTCP MUST be given packets according
to that requirement in the sense that the first part MUST be a sender
report or a receiver report.  However, the RTCP encryption prefix (a
random 32-bit quantity) specified in that Section MUST NOT be used
since, as is stated there, it is only applicable to the encryption
method specified in [RFC3550] and is not needed by the cryptographic
mechanisms used in SRTP.


      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
     |V=2|P|    RC   |   PT=SR or RR   |             length          | |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     |                         SSRC of sender                        | |
   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | ~                          sender info                          ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                         report block 1                        ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                         report block 2                        ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                              ...                              ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | |V=2|P|    SC   |  PT=SDES=202  |             length            | |
   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |                          SSRC/CSRC_1                          | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | ~                           SDES items                          ~ |
   | +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | ~                              ...                              ~ |
   +>+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ |
   | |E|                         SRTCP index                         | |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+
   | ~                     SRTCP MKI (OPTIONAL)                      ~ |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   | :                     authentication tag                        : |
   | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   |                                                                   |
   +-- Encrypted Portion                    Authenticated Portion -----+


   Figure 2.  An example of the format of a Secure RTCP packet,
   consisting of an underlying RTCP compound packet with a Sender Report
   and SDES packet.

The Encrypted Portion of an SRTCP packet consists of the encryption
(Section 4.1) of the RTCP payload of the equivalent compound RTCP
packet, from the first RTCP packet, i.e., from the ninth (9) octet to
the end of the compound packet.  The Authenticated Portion of an
SRTCP packet consists of the entire equivalent (eventually compound)
RTCP packet, the E flag, and the SRTCP index (after any encryption
has been applied to the payload).

The added fields are:

E-flag: 1 bit, REQUIRED
        The E-flag indicates if the current SRTCP packet is
        encrypted or unencrypted.  Section 9.1 of [RFC3550] allows
        the split of a compound RTCP packet into two lower-layer
        packets, one to be encrypted and one to be sent in the
        clear.  The E bit set to "1" indicates encrypted packet, and
        "0" indicates non-encrypted packet.

SRTCP index: 31 bits, REQUIRED
        The SRTCP index is a 31-bit counter for the SRTCP packet.
        The index is explicitly included in each packet, in contrast
        to the "implicit" index approach used for SRTP.  The SRTCP
        index MUST be set to zero before the first SRTCP packet is
        sent, and MUST be incremented by one, modulo 2^31, after
        each SRTCP packet is sent.  In particular, after a re-key,
        the SRTCP index MUST NOT be reset to zero again.

Authentication Tag: configurable length, REQUIRED
        The authentication tag is used to carry message
        authentication data.

MKI: configurable length, OPTIONAL
        The MKI is the Master Key Indicator, and functions according
        to the MKI definition in Section 3.

SRTCP uses the cryptographic context parameters and packet processing
of SRTP by default, with the following changes:

*  The receiver does not need to "estimate" the index, as it is
    explicitly signaled in the packet.

*  Pre-defined SRTCP encryption is as specified in Section 4.1, but
    using the definition of the SRTCP Encrypted Portion given in this
    section, and using the SRTCP index as the index i.  The encryption
    transform and related parameters SHALL by default be the same
    selected for the protection of the associated SRTP stream(s),
    while the NULL algorithm SHALL be applied to the RTCP packets not
    to be encrypted.  SRTCP may have a different encryption transform
    than the one used by the corresponding SRTP.  The expected use for
    this feature is when the former has NULL-encryption and the latter
    has a non NULL-encryption.

The E-flag is assigned a value by the sender depending on whether the
packet was encrypted or not.

*  SRTCP decryption is performed as in Section 4, but only if the E
    flag is equal to 1.  If so, the Encrypted Portion is decrypted,
    using the SRTCP index as the index i.  In case the E-flag is 0,
    the payload is simply left unmodified.

*  SRTCP replay protection is as defined in Section 3.3.2, but using
    the SRTCP index as the index i and a separate Replay List that is
    specific to SRTCP.

*  The pre-defined SRTCP authentication tag is specified as in
    Section 4.2, but with the Authenticated Portion of the SRTCP
    packet given in this section (which includes the index).  The
    authentication transform and related parameters (e.g., key size)
    SHALL by default be the same as selected for the protection of the
    associated SRTP stream(s).

*  In the last step of the processing, only the sender needs to
    update the value of the SRTCP index by incrementing it modulo 2^31
    and for security reasons the sender MUST also check the number of
    SRTCP packets processed, see Section 9.2.

Message authentication for RTCP is REQUIRED, as it is the control
protocol (e.g., it has a BYE packet) for RTP.

Precautions must be taken so that the packet expansion in SRTCP (due
to the added fields) does not cause SRTCP messages to use more than
their share of RTCP bandwidth.  To avoid this, the following two
measures MUST be taken:

1. When initializing the RTCP variable "avg_rtcp_size" defined in
    chapter 6.3 of [RFC3550], it MUST include the size of the fields
    that will be added by SRTCP (index, E-bit, authentication tag, and
    when present, the MKI).

2. When updating the "avg_rtcp_size" using the variable "packet_size"
    (section 6.3.3 of [RFC3550]), the value of "packet_size" MUST
    include the size of the additional fields added by SRTCP.

With these measures in place the SRTCP messages will not use more
than the allotted bandwidth.  The effect of the size of the added
fields on the SRTCP traffic will be that messages will be sent with
longer packet intervals.  The increase in the intervals will be
directly proportional to size of the added fields.  For the pre-
defined transforms, the size of the added fields will be at least 14
octets, and upper bounded depending on MKI and the authentication tag
sizes.