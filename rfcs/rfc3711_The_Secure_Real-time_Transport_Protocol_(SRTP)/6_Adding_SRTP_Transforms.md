
Section 4 provides examples of the level of detail needed for
defining transforms.  Whenever a new transform is to be added to
SRTP, a companion standard track RFC MUST be written to exactly
define how the new transform can be used with SRTP (and SRTCP).  Such
a companion RFC SHOULD avoid overlap with the SRTP protocol document.
Note however, that it MAY be necessary to extend the SRTP or SRTCP
cryptographic context definition with new parameters (including fixed
or default values), add steps to the packet processing, or even add
fields to the SRTP/SRTCP packets.  The companion RFC SHALL explain
any known issues regarding interactions between the transform and
other aspects of SRTP.

Each new transform document SHOULD specify its key attributes, e.g.,
size of keys (minimum, maximum, recommended), format of keys,
recommended/required processing of input keying material,
requirements/recommendations on key lifetime, re-keying and key
derivation, whether sharing of keys between SRTP and SRTCP is allowed
or not, etc.

An added message integrity transform SHOULD define a minimum acceptable key/tag size for SRTCP, equivalent in strength to the
minimum values as defined in Section 5.2.

# 7.  Rationale

This section explains the rationale behind several important features
of SRTP.

## 7.1.  Key derivation

Key derivation reduces the burden on the key establishment.  As many
as six different keys are needed per crypto context (SRTP and SRTCP
encryption keys and salts, SRTP and SRTCP authentication keys), but
these are derived from a single master key in a cryptographically
secure way.  Thus, the key management protocol needs to exchange only
one master key (plus master salt when required), and then SRTP itself
derives all the necessary session keys (via the first, mandatory
application of the key derivation function).

Multiple applications of the key derivation function are optional,
but will give security benefits when enabled.  They prevent an
attacker from obtaining large amounts of ciphertext produced by a
single fixed session key.  If the attacker was able to collect a
large amount of ciphertext for a certain session key, he might be
helped in mounting certain attacks.

Multiple applications of the key derivation function provide
backwards and forward security in the sense that a compromised
session key does not compromise other session keys derived from the
same master key.  This means that the attacker who is able to recover
a certain session key, is anyway not able to have access to messages
secured under previous and later session keys (derived from the same
master key).  (Note that, of course, a leaked master key reveals all
the session keys derived from it.)

Considerations arise with high-rate key refresh, especially in large
multicast settings, see Section 11.

## 7.2.  Salting key

The master salt guarantees security against off-line key-collision
attacks on the key derivation that might otherwise reduce the
effective key size [MF00].

The derived session salting key used in the encryption, has been
introduced to protect against some attacks on additive stream
ciphers, see Section 9.2.  The explicit inclusion method of the salt
in the IV has been selected for ease of hardware implementation.


## 7.3.  Message Integrity from Universal Hashing

The particular definition of the keystream given in Section 4.1 (the
keystream prefix) is to give provision for particular universal hash
functions, suitable for message authentication in the Wegman-Carter
paradigm [WC81].  Such functions are provably secure, simple, quick,
and especially appropriate for Digital Signal Processors and other
processors with a fast multiply operation.

No authentication transforms are currently provided in SRTP other
than HMAC-SHA1.  Future transforms, like the above mentioned
universal hash functions, MAY be added following the guidelines in
Section 6.

## 7.4.  Data Origin Authentication Considerations

Note that in pair-wise communications, integrity and data origin
authentication are provided together.  However, in group scenarios
where the keys are shared between members, the MAC tag only proves
that a member of the group sent the packet, but does not prevent
against a member impersonating another.  Data origin authentication
(DOA) for multicast and group RTP sessions is a hard problem that
needs a solution; while some promising proposals are being
investigated [PCST1] [PCST2], more work is needed to rigorously
specify these technologies.  Thus SRTP data origin authentication in
groups is for further study.

DOA can be done otherwise using signatures.  However, this has high
impact in terms of bandwidth and processing time, therefore we do not
offer this form of authentication in the pre-defined packet-integrity
transform.

The presence of mixers and translators does not allow data origin
authentication in case the RTP payload and/or the RTP header are
manipulated.  Note that these types of middle entities also disrupt
end-to-end confidentiality (as the IV formation depends e.g., on the
RTP header preservation).  A certain trust model may choose to trust
the mixers/translators to decrypt/re-encrypt the media (this would
imply breaking the end-to-end security, with related security
implications).

## 7.5.  Short and Zero-length Message Authentication

As shown in Figure 1, the authentication tag is RECOMMENDED in SRTP.
A full 80-bit authentication-tag SHOULD be used, but a shorter tag or
even a zero-length tag (i.e., no message authentication) MAY be used
under certain conditions to support either of the following two
application environments.

    1. Strong authentication can be impractical in environments where
        bandwidth preservation is imperative.  An important special
        case is wireless communication systems, in which bandwidth is a
        scarce and expensive resource.  Studies have shown that for
        certain applications and link technologies, additional bytes
        may result in a significant decrease in spectrum efficiency
        [SWO].  Considerable effort has been made to design IP header
        compression techniques to improve spectrum efficiency
        [RFC3095].  A typical voice application produces 20 byte
        samples, and the RTP, UDP and IP headers need to be jointly
        compressed to one or two bytes on average in order to obtain
        acceptable wireless bandwidth economy [RFC3095].  In this case,
        strong authentication would impose nearly fifty percent
        overhead.

    2. Authentication is impractical for applications that use data
        links with fixed-width fields that cannot accommodate the
        expansion due to the authentication tag.  This is the case for
        some important existing wireless channels.  For example, zero-
        byte header compression is used to adapt EVRC/SMV voice with
        the legacy IS-95 bearer channel in CDMA2000 VoIP services.  It
        was found that not a single additional octet could be added to
        the data, which motivated the creation of a zero-byte profile
        for ROHC [RFC3242].

A short tag is secure for a restricted set of applications.  Consider
a voice telephony application, for example, such as a G.729 audio
codec with a 20-millisecond packetization interval, protected by a
32-bit message authentication tag.  The likelihood of any given
packet being successfully forged is only one in 2^32.  Thus an
adversary can control no more than 20 milliseconds of audio output
during a 994-day period, on average.  In contrast, the effect of a
single forged packet can be much larger if the application is
stateful.  A codec that uses relative or predictive compression
across packets will propagate the maliciously generated state,
affecting a longer duration of output.


Certainly not all SRTP or telephony applications meet the criteria
for short or zero-length authentication tags.  Section 9.5.1
discusses the risks of weak or no message authentication, and section
9.5 describes the circumstances when it is acceptable and when it is
unacceptable.

# 8.  Key Management Considerations

There are emerging key management standards [MIKEY] [KEYMGT] [SDMS]
for establishing an SRTP cryptographic context (e.g., an SRTP master
key).  Both proprietary and open-standard key management methods are
likely to be used for telephony applications [MIKEY] [KINK] and
multicast applications [GDOI].  This section provides guidance for
key management systems that service SRTP session.

For initialization, an interoperable SRTP implementation SHOULD be
given the SSRC and MAY be given the initial RTP sequence number for
the RTP stream by key management (thus, key management has a
dependency on RTP operational parameters).  Sending the RTP sequence
number in the key management may be useful e.g., when the initial
sequence number is close to wrapping (to avoid synchronization
problems), and to communicate the current sequence number to a
joining endpoint (to properly initialize its replay list).

If the pre-defined transforms are used, SRTP allows sharing of the
same master key between SRTP/SRTCP streams belonging to the same RTP
session.

First, sharing between SRTP streams belonging to the same RTP session
is secure if the design of the synchronization mechanism, i.e., the
IV, avoids keystream re-use (the two-time pad, Section 9.1).  This is
taken care of by the fact that RTP provides for unique SSRCs for
streams belonging to the same RTP session.  See Section 9.1 for
further discussion.

Second, sharing between SRTP and the corresponding SRTCP is secure.
The fact that an SRTP stream and its associated SRTCP stream both
carry the same SSRC does not constitute a problem for the two-time
pad due to the key derivation.  Thus, SRTP and SRTCP corresponding to
one RTP session MAY share master keys (as they do by default).

Note that message authentication also has a dependency on SSRC
uniqueness that is unrelated to the problem of keystream reuse: SRTP
streams authenticated under the same key MUST have a distinct SSRC in
order to identify the sender of the message.  This requirement is
needed because the SSRC is the cryptographically authenticated field

used to distinguish between different SRTP streams.  Were two streams
to use identical SSRC values, then an adversary could substitute
messages from one stream into the other without detection.

SRTP/SRTCP MUST NOT share master keys under any other circumstances
than the ones given above, i.e., between SRTP and its corresponding
SRTCP, and, between streams belonging to the same RTP session.

### 8.1.  Re-keying

The recommended way for a particular key management system to provide
re-key within SRTP is by associating a master key in a crypto context
with an MKI.

This provides for easy master key retrieval (see Scenarios in Section
11), but has the disadvantage of adding extra bits to each packet.
As noted in Section 7.5, some wireless links do not cater for added
bits, therefore SRTP also defines a more economic way of triggering
re-keying, via use of <From, To>, which works in some specific,
simple scenarios (see Section 8.1.1).

SRTP senders SHALL count the amount of SRTP and SRTCP traffic being
used for a master key and invoke key management to re-key if needed
(Section 9.2).  These interactions are defined by the key management
interface to SRTP and are not defined by this protocol specification.

#### 8.1.1.  Use of the <From, To> for re-keying

In addition to the use of the MKI, SRTP defines another optional
mechanism for master key retrieval, the <From, To>.  The <From, To>
specifies the range of SRTP indices (a pair of sequence number and
ROC) within which a certain master key is valid, and is (when used)
part of the crypto context.  By looking at the 48-bit SRTP index of
the current SRTP packet, the corresponding master key can be found by
determining which From-To interval it belongs to.  For SRTCP, the
most recently observed/used SRTP index (which can be obtained from
the cryptographic context) is used for this purpose, even though
SRTCP has its own (31-bit) index (see caveat below).

This method, compared to the MKI, has the advantage of identifying
the master key and defining its lifetime without adding extra bits to
each packet.  This could be useful, as already noted, for some
wireless links that do not cater for added bits.  However, its use
SHOULD be limited to specific, very simple scenarios.  We recommend
to limit its use when the RTP session is a simple unidirectional or
bi-directional stream.  This is because in case of multiple streams,
it is difficult to trigger the re-key based on the <From, To> of a
single RTP stream. For example, if several streams share a master
key, there is no simple one-to-one correspondence between the index
sequence space of a certain stream, and the index sequence space on
which the <From, To> values are based.  Consequently, when a master
key is shared between streams, one of these streams MUST be
designated by key management as the one whose index space defines the
re-keying points.  Also, the re-key triggering on SRTCP is based on
the correspondent SRTP stream, i.e., when the SRTP stream changes the
master key, so does the correspondent SRTCP.  This becomes obviously
more and more complex with multiple streams.

The default values for the <From, To> are "from the first observed
packet" and "until further notice".  However, the maximum limit of
SRTP/SRTCP packets that are sent under each given master/session key
(Section 9.2) MUST NOT be exceeded.

In case the <From, To> is used as key retrieval, then the MKI is not
inserted in the packet (and its indicator in the crypto context is
zero).  However, using the MKI does not exclude using <From, To> key
lifetime simultaneously.  This can for instance be useful to signal
at the sender side at which point in time an MKI is to be made
active.

### 8.2.  Key Management parameters

The table below lists all SRTP parameters that key management can
supply.  For reference, it also provides a summary of the default and
mandatory-to-support values for an SRTP implementation as described
in Section 5.

   Parameter                     Mandatory-to-support    Default
   ---------                     --------------------    -------

   SRTP and SRTCP encr transf.       AES_CM, NULL         AES_CM
   (Other possible values: AES_f8)

   SRTP and SRTCP auth transf.       HMAC-SHA1           HMAC-SHA1

   SRTP and SRTCP auth params:
     n_tag (tag length)                 80                 80
     SRTP prefix_length                  0                  0

   Key derivation PRF                 AES_CM              AES_CM

   Key material params
   (for each master key):
     master key length                 128                128
     n_e (encr session key length)     128                128
     n_a (auth session key length)     160                160
     master salt key
     length of the master salt         112                112
     n_s (session salt key length)     112                112
     key derivation rate                 0                  0

     key lifetime
        SRTP-packets-max-lifetime      2^48               2^48
        SRTCP-packets-max-lifetime     2^31               2^31
        from-to-lifetime <From, To>
     MKI indicator                       0                 0
     length of the MKI                   0                 0
     value of the MKI

   Crypto context index params:
     SSRC value
     ROC
     SEQ
     SRTCP Index
     Transport address
     Port number

   Relation to other RTP profiles:
     sender's order between FEC and SRTP FEC-SRTP      FEC-SRTP
     (see Section 10)

# 9. Security Considerations

### 9.1.  SSRC collision and two-time pad

Any fixed keystream output, generated from the same key and index
MUST only be used to encrypt once.  Re-using such keystream (jokingly
called a "two-time pad" system by cryptographers), can seriously
compromise security.  The NSA's VENONA project [C99] provides a
historical example of such a compromise.  It is REQUIRED that
automatic key management be used for establishing and maintaining
SRTP and SRTCP keying material; this requirement is to avoid
keystream reuse, which is more likely to occur with manual key
management.  Furthermore, in SRTP, a "two-time pad" is avoided by
requiring the key, or some other parameter of cryptographic
significance, to be unique per RTP/RTCP stream and packet.  The pre-
defined SRTP transforms accomplish packet-uniqueness by including the
packet index and stream-uniqueness by inclusion of the SSRC.

The pre-defined transforms (AES-CM and AES-f8) allow master keys to
be shared across streams belonging to the same RTP session by the
inclusion of the SSRC in the IV.  A master key MUST NOT be shared
among different RTP sessions.

Thus, the SSRC MUST be unique between all the RTP streams within the
same RTP session that share the same master key.  RTP itself provides
an algorithm for detecting SSRC collisions within the same RTP
session.  Thus, temporary collisions could lead to temporary two-time
pad, in the unfortunate event that SSRCs collide at a point in time
when the streams also have identical sequence numbers (occurring with
probability roughly 2^(-48)).  Therefore, the key management SHOULD
take care of avoiding such SSRC collisions by including the SSRCs to
be used in the session as negotiation parameters, proactively
assuring their uniqueness.  This is a strong requirements in
scenarios where for example, there are multiple senders that can
start to transmit simultaneously, before SSRC collision are detected
at the RTP level.

Note also that even with distinct SSRCs, extensive use of the same
key might improve chances of probabilistic collision and time-
memory-tradeoff attacks succeeding.

As described, master keys MAY be shared between streams belonging to
the same RTP session, but it is RECOMMENDED that each SSRC have its
own master key.  When master keys are shared among SSRC participants
and SSRCs are managed by a key management module as recommended
above, the RECOMMENDED policy for an SSRC collision error is for the
participant to leave the SRTP session as it is a sign of malfunction.

### 9.2.  Key Usage

The effective key size is determined (upper bounded) by the size of
the master key and, for encryption, the size of the salting key.  Any
additive stream cipher is vulnerable to attacks that use statistical
knowledge about the plaintext source to enable key collision and
time-memory tradeoff attacks [MF00] [H80] [BS00].  These attacks take
advantage of commonalities among plaintexts, and provide a way for a
cryptanalyst to amortize the computational effort of decryption over
many keys, or over many bytes of output, thus reducing the effective
key size of the cipher.  A detailed analysis of these attacks and
their applicability to the encryption of Internet traffic is provided
in [MF00].  In summary, the effective key size of SRTP when used in a
security system in which m distinct keys are used, is equal to the
key size of the cipher less the logarithm (base two) of m.
Protection against such attacks can be provided simply by increasing
the size of the keys used, which here can be accomplished by the use
of the salting key.  Note that the salting key MUST be random but MAY
be public.  A salt size of (the suggested) size 112 bits protects
against attacks in scenarios where at most 2^112 keys are in use.
This is sufficient for all practical purposes.

Implementations SHOULD use keys that are as large as possible.
Please note that in many cases increasing the key size of a cipher
does not affect the throughput of that cipher.

The use of the SRTP and SRTCP indices in the pre-defined transforms
fixes the maximum number of packets that can be secured with the same
key.  This limit is fixed to 2^48 SRTP packets for an SRTP stream,
and 2^31 SRTCP packets, when SRTP and SRTCP are considered
independently.  Due to for example re-keying, reaching this limit may
or may not coincide with wrapping of the indices, and thus the sender
MUST keep packet counts.  However, when the session keys for related
SRTP and SRTCP streams are derived from the same master key (the
default behavior, Section 4.3), the upper bound that has to be
considered is in practice the minimum of the two quantities.  That
is, when 2^48 SRTP packets or 2^31 SRTCP packets have been secured
with the same key (whichever occurs before), the key management MUST
be called to provide new master key(s) (previously stored and used
keys MUST NOT be used again), or the session MUST be terminated.  If
a sender of RTCP discovers that the sender of SRTP (or SRTCP) has not
updated the master or session key prior to sending 2^48 SRTP (or 2^31
SRTCP) packets belonging to the same SRTP (SRTCP) stream, it is up to
the security policy of the RTCP sender how to behave, e.g., whether
an RTCP BYE-packet should be sent and/or if the event should be
logged.

Note: in most typical applications (assuming at least one RTCP packet
for every 128,000 RTP packets), it will be the SRTCP index that first
reaches the upper limit, although the time until this occurs is very
long: even at 200 SRTCP packets/sec, the 2^31 index space of SRTCP is
enough to secure approximately 4 months of communication.

Note that if the master key is to be shared between SRTP streams
within the same RTP session (Section 9.1), although the above bounds
are on a per stream (i.e., per SSRC) basis, the sender MUST base re-
key decision on the stream whose sequence number space is the first
to be exhausted.

Key derivation limits the amount of plaintext that is encrypted with
a fixed session key, and made available to an attacker for analysis,
but key derivation does not extend the master key's lifetime.  To see
this, simply consider our requirements to avoid two-time pad:  two
distinct packets MUST either be processed with distinct IVs, or with
distinct session keys, and both the distinctness of IV and of the
session keys are (for the pre-defined transforms) dependent on the
distinctness of the packet indices.

Note that with the key derivation, the effective key size is at most
that of the master key, even if the derived session key is
considerably longer.  With the pre-defined authentication transform,
the session authentication key is 160 bits, but the master key by
default is only 128 bits.  This design choice was made to comply with
certain recommendations in [RFC2104] so that an existing HMAC
implementation can be plugged into SRTP without problems.  Since the
default tag size is 80 bits, it is, for the applications in mind,
also considered acceptable from security point of view.  Users having
concerns about this are RECOMMENDED to instead use a 192 bit master
key in the key derivation.  It was, however, chosen not to mandate
192-bit keys since existing AES implementations to be used in the
key-derivation may not always support key-lengths other than 128
bits.  Since AES is not defined (or properly analyzed) for use with
160 bit keys it is NOT RECOMMENDED that ad-hoc key-padding schemes
are used to pad shorter keys to 192 or 256 bits.

### 9.3.  Confidentiality of the RTP Payload

SRTP's pre-defined ciphers are "seekable" stream ciphers, i.e.,
ciphers able to efficiently seek to arbitrary locations in their
keystream (so that the encryption or decryption of one packet does
not depend on preceding packets).  By using seekable stream ciphers,
SRTP avoids the denial of service attacks that are possible on stream
ciphers that lack this property.  It is important to be aware that,
as with any stream cipher, the exact length of the payload is
revealed by the encryption.  This means that it may be possible to
deduce certain "formatting bits" of the payload, as the length of the
codec output might vary due to certain parameter settings etc.  This,
in turn, implies that the corresponding bit of the keystream can be
deduced.  However, if the stream cipher is secure (counter mode and
f8 are provably secure under certain assumptions [BDJR] [KSYH] [IK]),
knowledge of a few bits of the keystream will not aid an attacker in
predicting subsequent keystream bits.  Thus, the payload length (and
information deducible from this) will leak, but nothing else.

As some RTP packet could contain highly predictable data, e.g., SID,
it is important to use a cipher designed to resist known plaintext
attacks (which is the current practice).

### 9.4.  Confidentiality of the RTP Header

In SRTP, RTP headers are sent in the clear to allow for header
compression.  This means that data such as payload type,
synchronization source identifier, and timestamp are available to an
eavesdropper.  Moreover, since RTP allows for future extensions of
headers, we cannot foresee what kind of possibly sensitive
information might also be "leaked".

SRTP is a low-cost method, which allows header compression to reduce
bandwidth.  It is up to the endpoints' policies to decide about the
security protocol to employ.  If one really needs to protect headers,
and is allowed to do so by the surrounding environment, then one
should also look at alternatives, e.g., IPsec [RFC2401].

### 9.5.  Integrity of the RTP payload and header

SRTP messages are subject to attacks on their integrity and source
identification, and these risks are discussed in Section 9.5.1.  To
protect against these attacks, each SRTP stream SHOULD be protected
by HMAC-SHA1 [RFC2104] with an 80-bit output tag and a 160-bit key,
or a message authentication code with equivalent strength.  Secure
RTP SHOULD NOT be used without message authentication, except under
the circumstances described in this section.  It is important to note
that encryption algorithms, including AES Counter Mode and f8, do not
provide message authentication.  SRTCP MUST NOT be used with weak (or
NULL) authentication.

SRTP MAY be used with weak authentication (e.g., a 32-bit
authentication tag), or with no authentication (the NULL
authentication algorithm).  These options allow SRTP to be used to
provide confidentiality in situations where

* weak or null authentication is an acceptable security risk, and
* it is impractical to provide strong message authentication.

These conditions are described below and in Section 7.5.  Note that
both conditions MUST hold in order for weak or null authentication to
be used.  The risks associated with exercising the weak or null
authentication options need to be considered by a security audit
prior to their use for a particular application or environment given
the risks, which are discussed in Section 9.5.1.

Weak authentication is acceptable when the RTP application is such
that the effect of a small fraction of successful forgeries is
negligible.  If the application is stateless, then the effect of a
single forged RTP packet is limited to the decoding of that
particular packet.  Under this condition, the size of the
authentication tag MUST ensure that only a negligible fraction of the
packets passed to the RTP application by the SRTP receiver can be
forgeries.  This fraction is negligible when an adversary, if given
control of the forged packets, is not able to make a significant
impact on the output of the RTP application (see the example of
Section 7.5).

Weak or null authentication MAY be acceptable when it is unlikely
that an adversary can modify ciphertext so that it decrypts to an
intelligible value.  One important case is when it is difficult for
an adversary to acquire the RTP plaintext data, since for many
codecs, an adversary that does not know the input signal cannot
manipulate the output signal in a controlled way.  In many cases it
may be difficult for the adversary to determine the actual value of
the plaintext.  For example, a hidden snooping device might be
required in order to know a live audio or video signal.  The
adversary's signal must have a quality equivalent to or greater than
that of the signal under attack, since otherwise the adversary would
not have enough information to encode that signal with the codec used
by the victim.  Plaintext prediction may also be especially difficult
for an interactive application such as a telephone call.

Weak or null authentication MUST NOT be used when the RTP application
makes data forwarding or access control decisions based on the RTP
data.  In such a case, an attacker may be able to subvert
confidentiality by causing the receiver to forward data to an
attacker.  See Section 3 of [B96] for a real-life example of such
attacks.

Null authentication MUST NOT be used when a replay attack, in which
an adversary stores packets then replays them later in the session,
could have a non-negligible impact on the receiver.  An example of a
successful replay attack is the storing of the output of a
surveillance camera for a period of time, later followed by the

injection of that output to the monitoring station to avoid
surveillance.  Encryption does not protect against this attack, and
non-null authentication is REQUIRED in order to defeat it.

If existential message forgery is an issue, i.e., when the accuracy
of the received data is of non-negligible importance, null
authentication MUST NOT be used.

#### 9.5.1.  Risks of Weak or Null Message Authentication

During a security audit considering the use of weak or null
authentication, it is important to keep in mind the following attacks
which are possible when no message authentication algorithm is used.

An attacker who cannot predict the plaintext is still always able to
modify the message sent between the sender and the receiver so that
it decrypts to a random plaintext value, or to send a stream of bogus
packets to the receiver that will decrypt to random plaintext values.
This attack is essentially a denial of service attack, though in the
absence of message authentication, the RTP application will have
inputs that are bit-wise correlated with the true value.  Some
multimedia codecs and common operating systems will crash when such
data are accepted as valid video data.  This denial of service attack
may be a much larger threat than that due to an attacker dropping,
delaying, or re-ordering packets.

An attacker who cannot predict the plaintext can still replay a
previous message with certainty that the receiver will accept it.
Applications with stateless codecs might be robust against this type
of attack, but for other, more complex applications these attacks may
be far more grave.

An attacker who can predict the plaintext can modify the ciphertext
so that it will decrypt to any value of her choosing.  With an
additive stream cipher, an attacker will always be able to change
individual bits.

An attacker may be able to subvert confidentiality due to the lack of
authentication when a data forwarding or access control decision is
made on decrypted but unauthenticated plaintext.  This is because the
receiver may be fooled into forwarding data to an attacker, leading
to an indirect breach of confidentiality (see Section 3 of [B96]).
This is because data-forwarding decisions are made on the decrypted
plaintext; information in the plaintext will determine to what subnet
(or process) the plaintext is forwarded in ESP [RFC2401] tunnel mode
(respectively, transport mode).  When Secure RTP is used without

message authentication, it should be verified that the application
does not make data forwarding or access control decisions based on
the decrypted plaintext.

Some cipher modes of operation that require padding, e.g., standard
cipher block chaining (CBC) are very sensitive to attacks on
confidentiality if certain padding types are used in the absence of
integrity.  The attack [V02] shows that this is indeed the case for
the standard RTP padding as discussed in reference to Figure 1, when
used together with CBC mode.  Later transform additions to SRTP MUST
therefore carefully consider the risk of using this padding without
proper integrity protection.

#### 9.5.2.  Implicit Header Authentication

The IV formation of the f8-mode gives implicit authentication (IHA)
of the RTP header, even when message authentication is not used.
When IHA is used, an attacker that modifies the value of the RTP
header will cause the decryption process at the receiver to produce
random plaintext values.  While this protection is not equivalent to
message authentication, it may be useful for some applications.

# 10.  Interaction with Forward Error Correction mechanisms

The default processing when using Forward Error Correction (e.g., RFC
2733) processing with SRTP SHALL be to perform FEC processing prior
to SRTP processing on the sender side and to perform SRTP processing
prior to FEC processing on the receiver side.  Any change to this
ordering (reversing it, or, placing FEC between SRTP encryption and
SRTP authentication) SHALL be signaled out of band.

# 11.  Scenarios

SRTP can be used as security protocol for the RTP/RTCP traffic in
many different scenarios.  SRTP has a number of configuration
options, in particular regarding key usage, and can have impact on
the total performance of the application according to the way it is
used.  Hence, the use of SRTP is dependent on the kind of scenario
and application it is used with.  In the following, we briefly
illustrate some use cases for SRTP, and give some guidelines for
recommended setting of its options.

## 11.1.  Unicast

A typical example would be a voice call or video-on-demand
application.

Consider one bi-directional RTP stream, as one RTP session.  It is
possible for the two parties to share the same master key in the two
directions according to the principles of Section 9.1.  The first
round of the key derivation splits the master key into any or all of
the following session keys (according to the provided security
functions):

SRTP_encr_key, SRTP_auth_key, SRTCP_encr_key, and SRTCP_auth key.

(For simplicity, we omit discussion of the salts, which are also
derived.)  In this scenario, it will in most cases suffice to have a
single master key with the default lifetime.  This guarantees
sufficiently long lifetime of the keys and a minimum set of keys in
place for most practical purposes.  Also, in this case RTCP
protection can be applied smoothly.  Under these assumptions, use of
the MKI can be omitted.  As the key-derivation in combination with
large difference in the packet rate in the respective directions may
require simultaneous storage of several session keys, if storage is
an issue, we recommended to use low-rate key derivation.

The same considerations can be extended to the unicast scenario with
multiple RTP sessions, where each session would have a distinct
master key.

## 11.2.  Multicast (one sender)

Just as with (unprotected) RTP, a scalability issue arises in big
groups due to the possibly very large amount of SRTCP Receiver
Reports that the sender might need to process.  In SRTP, the sender
may have to keep state (the cryptographic context) for each receiver,
or more precisely, for the SRTCP used to protect Receiver Reports.
The overhead increases proportionally to the size of the group.  In
particular, re-keying requires special concern, see below.

Consider first a small group of receivers.  There are a few possible
setups with the distribution of master keys among the receivers.
Given a single RTP session, one possibility is that the receivers
share the same master key as per Section 9.1 to secure all their
respective RTCP traffic.  This shared master key could then be the
same one used by the sender to protect its outbound SRTP traffic.
Alternatively, it could be a master key shared only among the
receivers and used solely for their SRTCP traffic.  Both alternatives
require the receivers to trust each other.

Considering SRTCP and key storage, it is recommended to use low-rate
(or zero) key_derivation (except the mandatory initial one), so that
the sender does not need to store too many session keys (each SRTCP
stream might otherwise have a different session key at a given point

in time, as the SRTCP sources send at different times).  Thus, in
case key derivation is wanted for SRTP, the cryptographic context for
SRTP can be kept separate from the SRTCP crypto context, so that it
is possible to have a key_derivation_rate of 0 for SRTCP and a non-
zero value for SRTP.

Use of the MKI for re-keying is RECOMMENDED for most applications
(see Section 8.1).

If there are more than one SRTP/SRTCP stream (within the same RTP
session) that share the master key, the upper limit of 2^48 SRTP
packets / 2^31 SRTCP packets means that, before one of the streams
reaches its maximum number of packets, re-keying MUST be triggered on
ALL streams sharing the master key.  (From strict security point of
view, only the stream reaching the maximum would need to be re-keyed,
but then the streams would no longer be sharing master key, which is
the intention.)  A local policy at the sender side should force
rekeying in a way that the maximum packet limit is not reached on any
of the streams.  Use of the MKI for re-keying is RECOMMENDED.

In large multicast with one sender, the same considerations as for
the small group multicast hold.  The biggest issue in this scenario
is the additional load placed at the sender side, due to the state
(cryptographic contexts) that has to be maintained for each receiver,
sending back RTCP Receiver Reports.  At minimum, a replay window
might need to be maintained for each RTCP source.

## 11.3.  Re-keying and access control

Re-keying may occur due to access control (e.g., when a member is
removed during a multicast RTP session), or for pure cryptographic
reasons (e.g., the key is at the end of its lifetime).  When using
SRTP default transforms, the master key MUST be replaced before any
of the index spaces are exhausted for any of the streams protected by
one and the same master key.

How key management re-keys SRTP implementations is out of scope, but
it is clear that there are straightforward ways to manage keys for a
multicast group.  In one-sender multicast, for example, it is
typically the responsibility of the sender to determine when a new
key is needed.  The sender is the one entity that can keep track of
when the maximum number of packets has been sent, as receivers may
join and leave the session at any time, there may be packet loss and
delay etc.  In scenarios other than one-sender multicast, other
methods can be used.  Here, one must take into consideration that key
exchange can be a costly operation, taking several seconds for a
single exchange.  Hence, some time before the master key is
exhausted/expires, out-of-band key management is initiated, resulting

in a new master key that is shared with the receiver(s).  In any
event, to maintain synchronization when switching to the new key,
group policy might choose between using the MKI and the <From, To>,
as described in Section 8.1.

For access control purposes, the <From, To> periods are set at the
desired granularity, dependent on the packet rate.  High rate re-
keying can be problematic for SRTCP in some large-group scenarios.
As mentioned, there are potential problems in using the SRTP index,
rather than the SRTCP index, for determining the master key.  In
particular, for short periods during switching of master keys, it may
be the case that SRTCP packets are not under the current master key
of the correspondent SRTP.  Therefore, using the MKI for re-keying in
such scenarios will produce better results.

## 11.4.  Summary of basic scenarios

The description of these scenarios highlights some recommendations on
the use of SRTP, mainly related to re-keying and large scale
multicast:

- Do not use fast re-keying with the <From, To> feature.  It may, in
    particular, give problems in retrieving the correct SRTCP key, if
    an SRTCP packet arrives close to the re-keying time.  The MKI
    SHOULD be used in this case.

- If multiple SRTP streams in the same RTP session share the same
    master key, also moderate rate re-keying MAY have the same
    problems, and the MKI SHOULD be used.

- Though offering increased security, a non-zero key_derivation_rate
    is NOT RECOMMENDED when trying to minimize the number of keys in
    use with multiple streams.


# 12.  IANA Considerations

The RTP specification establishes a registry of profile names for use
by higher-level control protocols, such as the Session Description
Protocol (SDP), to refer to transport methods.  This profile
registers the name "RTP/SAVP".

SRTP uses cryptographic transforms which a key management protocol
signals.  It is the task of each particular key management protocol
to register the cryptographic transforms or suites of transforms with
IANA.  The key management protocol conveys these protocol numbers,
not SRTP, and each key management protocol chooses the numbering
scheme and syntax that it requires.

Specification of a key management protocol for SRTP is out of scope
here.  Section 8.2, however, provides guidance on the parameters that
need to be defined for the default and mandatory transforms.

# Appendix A: Pseudocode for Index Determination

   The following is an example of pseudo-code for the algorithm to
   determine the index i of an SRTP packet with sequence number SEQ.  In
   the following, signed arithmetic is assumed.

         if (s_l < 32,768)
            if (SEQ - s_l > 32,768)
               set v to (ROC-1) mod 2^32
            else
               set v to ROC
            endif
         else
            if (s_l - 32,768 > SEQ)
               set v to (ROC+1) mod 2^32
            else
               set v to ROC
            endif
         endif
         return SEQ + v*65,536

# Appendix B: Test Vectors

   All values are in hexadecimal.

## B.1.  AES-f8 Test Vectors

   SRTP PREFIX LENGTH  :   0

   RTP packet header   :   806e5cba50681de55c621599

   RTP packet payload  :   70736575646f72616e646f6d6e657373
                           20697320746865206e65787420626573
                           74207468696e67

   ROC                 :   d462564a
   key                 :   234829008467be186c3de14aae72d62c
   salt key            :   32f2870d
   key-mask (m)        :   32f2870d555555555555555555555555
   key XOR key-mask    :   11baae0dd132eb4d3968b41ffb278379

   IV                  :   006e5cba50681de55c621599d462564a
   IV'                 :   595b699bbd3bc0df26062093c1ad8f73



   j = 0
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f73
   S(-1)               :   00000000000000000000000000000000
   IV' xor S(-1) xor j :   595b699bbd3bc0df26062093c1ad8f73
   S(0)                :   71ef82d70a172660240709c7fbb19d8e
   plaintext           :   70736575646f72616e646f6d6e657373
   ciphertext          :   019ce7a26e7854014a6366aa95d4eefd

   j = 1
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f72
   S(0)                :   71ef82d70a172660240709c7fbb19d8e
   IV' xor S(0) xor j  :   28b4eb4cb72ce6bf020129543a1c12fc
   S(1)                :   3abd640a60919fd43bd289a09649b5fc
   plaintext           :   20697320746865206e65787420626573
   ciphertext          :   1ad4172a14f9faf455b7f1d4b62bd08f

   j = 2
   IV' xor j           :   595b699bbd3bc0df26062093c1ad8f71
   S(1)                :   3abd640a60919fd43bd289a09649b5fc
   IV' xor S(1) xor j  :   63e60d91ddaa5f0b1dd4a93357e43a8d
   S(2)                :   220c7a8715266565b09ecc8a2a62b11b
   plaintext           :   74207468696e67
   ciphertext          :   562c0eef7c4802

## B.2.  AES-CM Test Vectors

    Keystream segment length: 1044512 octets (65282 AES blocks)
    Session Key:      2B7E151628AED2A6ABF7158809CF4F3C
    Rollover Counter: 00000000
    Sequence Number:  0000
    SSRC:             00000000
    Session Salt:     F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000 (already shifted)
    Offset:           F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000

    Counter                            Keystream

    F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000   E03EAD0935C95E80E166B16DD92B4EB4
    F0F1F2F3F4F5F6F7F8F9FAFBFCFD0001   D23513162B02D0F72A43A2FE4A5F97AB
    F0F1F2F3F4F5F6F7F8F9FAFBFCFD0002   41E95B3BB0A2E8DD477901E4FCA894C0
    ...                                ...
    F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF   EC8CDF7398607CB0F2D21675EA9EA1E4
    F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF00   362B7C3C6773516318A077D7FC5073AE
    F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF01   6A2CC3787889374FBEB4C81B17BA6C44

   Nota Bene: this test case is contrived so that the latter part of the
   keystream segment coincides with the test case in Section F.5.1 of
   [CTR].

## B.3.  Key Derivation Test Vectors

   This section provides test data for the default key derivation
   function, which uses AES-128 in Counter Mode.  In the following, we
   walk through the initial key derivation for the AES-128 Counter Mode
   cipher, which requires a 16 octet session encryption key and a 14
   octet session salt, and an authentication function which requires a
   94-octet session authentication key.  These values are called the
   cipher key, the cipher salt, and the auth key in the following.
   Since this is the initial key derivation and the key derivation rate
   is equal to zero, the value of (index DIV key_derivation_rate) is
   zero (actually, a six-octet string of zeros).  In the following, we
   shorten key_derivation_rate to kdr.

   The inputs to the key derivation function are the 16 octet master key
   and the 14 octet master salt:

      master key:  E1F97A0D3E018BE0D64FA32C06DE4139
      master salt: 0EC675AD498AFEEBB6960B3AABE6

   We first show how the cipher key is generated.  The input block for
   AES-CM is generated by exclusive-oring the master salt with the
   concatenation of the encryption key label 0x00 with (index DIV kdr),
   then padding on the right with two null octets (which implements the
   multiply-by-2^16 operation, see Section 4.3.3).  The resulting value
   is then AES-CM- encrypted using the master key to get the cipher key.

      index DIV kdr:                 000000000000
      label:                       00
      master salt:   0EC675AD498AFEEBB6960B3AABE6
      -----------------------------------------------
      xor:           0EC675AD498AFEEBB6960B3AABE6     (x, PRF input)

      x*2^16:        0EC675AD498AFEEBB6960B3AABE60000 (AES-CM input)

      cipher key:    C61E7A93744F39EE10734AFE3FF7A087 (AES-CM output)


   Next, we show how the cipher salt is generated.  The input block for
   AES-CM is generated by exclusive-oring the master salt with the
   concatenation of the encryption salt label.  That value is padded and
   encrypted as above.

      index DIV kdr:                 000000000000
      label:                       02
      master salt:   0EC675AD498AFEEBB6960B3AABE6

      ----------------------------------------------
      xor:           0EC675AD498AFEE9B6960B3AABE6     (x, PRF input)

      x*2^16:        0EC675AD498AFEE9B6960B3AABE60000 (AES-CM input)

                     30CBBC08863D8C85D49DB34A9AE17AC6 (AES-CM ouptut)

      cipher salt:   30CBBC08863D8C85D49DB34A9AE1

   We now show how the auth key is generated.  The input block for AES-
   CM is generated as above, but using the authentication key label.

      index DIV kdr:                   000000000000
      label:                         01
      master salt:     0EC675AD498AFEEBB6960B3AABE6
      -----------------------------------------------
      xor:             0EC675AD498AFEEAB6960B3AABE6     (x, PRF input)

      x*2^16:          0EC675AD498AFEEAB6960B3AABE60000 (AES-CM input)

   Below, the auth key is shown on the left, while the corresponding AES
   input blocks are shown on the right.

   auth key                           AES input blocks
   CEBE321F6FF7716B6FD4AB49AF256A15   0EC675AD498AFEEAB6960B3AABE60000
   6D38BAA48F0A0ACF3C34E2359E6CDBCE   0EC675AD498AFEEAB6960B3AABE60001
   E049646C43D9327AD175578EF7227098   0EC675AD498AFEEAB6960B3AABE60002
   6371C10C9A369AC2F94A8C5FBCDDDC25   0EC675AD498AFEEAB6960B3AABE60003
   6D6E919A48B610EF17C2041E47403576   0EC675AD498AFEEAB6960B3AABE60004
   6B68642C59BBFC2F34DB60DBDFB2       0EC675AD498AFEEAB6960B3AABE60005

