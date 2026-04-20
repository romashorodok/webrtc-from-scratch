# 4.  Pre-Defined Cryptographic Transforms

While there are numerous encryption and message authentication
algorithms that can be used in SRTP, below we define default
algorithms in order to avoid the complexity of specifying the
encodings for the signaling of algorithm and parameter identifiers.
The defined algorithms have been chosen as they fulfill the goals
listed in Section 2.  Recommendations on how to extend SRTP with new
transforms are given in Section 6.

## 4.1.  Encryption

The following parameters are common to both pre-defined, non-NULL,
encryption transforms specified in this section.

*  BLOCK_CIPHER-MODE indicates the block cipher used and its mode of
    operation
*  n_b is the bit-size of the block for the block cipher
*  k_e is the session encryption key
*  n_e is the bit-length of k_e
*  k_s is the session salting key
*  n_s is the bit-length of k_s
*  SRTP_PREFIX_LENGTH is the octet length of the keystream prefix, a
    non-negative integer, specified by the message authentication code
    in use.

The distinct session keys and salts for SRTP/SRTCP are by default
derived as specified in Section 4.3.

The encryption transforms defined in SRTP map the SRTP packet index
and secret key into a pseudo-random keystream segment.  Each
keystream segment encrypts a single RTP packet.  The process of
encrypting a packet consists of generating the keystream segment
corresponding to the packet, and then bitwise exclusive-oring that
keystream segment onto the payload of the RTP packet to produce the
Encrypted Portion of the SRTP packet.  In case the payload size is
not an integer multiple of n_b bits, the excess (least significant)
bits of the keystream are simply discarded.  Decryption is done the
same way, but swapping the roles of the plaintext and ciphertext.


   +----+   +------------------+---------------------------------+
   | KG |-->| Keystream Prefix |          Keystream Suffix       |---+
   +----+   +------------------+---------------------------------+   |
                                                                     |
                               +---------------------------------+   v
                               |     Payload of RTP Packet       |->(*)
                               +---------------------------------+   |
                                                                     |
                               +---------------------------------+   |
                               | Encrypted Portion of SRTP Packet|<--+
                               +---------------------------------+

   Figure 3: Default SRTP Encryption Processing.  Here KG denotes the
   keystream generator, and (*) denotes bitwise exclusive-or.

The definition of how the keystream is generated, given the index,
depends on the cipher and its mode of operation.  Below, two such
keystream generators are defined.  The NULL cipher is also defined,
to be used when encryption of RTP is not required.

The SRTP definition of the keystream is illustrated in Figure 3.  The
initial octets of each keystream segment MAY be reserved for use in a
message authentication code, in which case the keystream used for
encryption starts immediately after the last reserved octet.  The
initial reserved octets are called the "keystream prefix" (not to be
confused with the "encryption prefix" of [RFC3550, Section 6.1]), and
the remaining octets are called the "keystream suffix".  The
keystream prefix MUST NOT be used for encryption.  The process is
illustrated in Figure 3.

The number of octets in the keystream prefix is denoted as
SRTP_PREFIX_LENGTH.  The keystream prefix is indicated by a positive,
non-zero value of SRTP_PREFIX_LENGTH.  This means that, even if
confidentiality is not to be provided, the keystream generator output
may still need to be computed for packet authentication, in which
case the default keystream generator (mode) SHALL be used.

The default cipher is the Advanced Encryption Standard (AES) [AES],
and we define two modes of running AES, (1) Segmented Integer Counter
Mode AES and (2) AES in f8-mode.  In the remainder of this section,
let E(k,x) be AES applied to key k and input block x.

### 4.1.1.  AES in Counter Mode

Conceptually, counter mode [AES-CTR] consists of encrypting
successive integers.  The actual definition is somewhat more
complicated, in order to randomize the starting point of the integer
sequence.  Each packet is encrypted with a distinct keystream
segment, which SHALL be computed as follows.

A keystream segment SHALL be the concatenation of the 128-bit output
blocks of the AES cipher in the encrypt direction, using key k = k_e,
in which the block indices are in increasing order.  Symbolically,
each keystream segment looks like

    E(k, IV) || E(k, IV + 1 mod 2^128) || E(k, IV + 2 mod 2^128) ...

where the 128-bit integer value IV SHALL be defined by the SSRC, the
SRTP packet index i, and the SRTP session salting key k_s, as below.

    IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)

Each of the three terms in the XOR-sum above is padded with as many
leading zeros as needed to make the operation well-defined,
considered as a 128-bit value.

The inclusion of the SSRC allows the use of the same key to protect
distinct SRTP streams within the same RTP session, see the security
caveats in Section 9.1.

In the case of SRTCP, the SSRC of the first header of the compound
packet MUST be used, i SHALL be the 31-bit SRTCP index and k_e, k_s
SHALL be replaced by the SRTCP encryption session key and salt.

Note that the initial value, IV, is fixed for each packet and is
formed by "reserving" 16 zeros in the least significant bits for the
purpose of the counter.  The number of blocks of keystream generated
for any fixed value of IV MUST NOT exceed 2^16 to avoid keystream
re-use, see below.  The AES has a block size of 128 bits, so 2^16
output blocks are sufficient to generate the 2^23 bits of keystream
needed to encrypt the largest possible RTP packet (except for IPv6
"jumbograms" [RFC2675], which are not likely to be used for RTP-based
multimedia traffic).  This restriction on the maximum bit-size of the
packet that can be encrypted ensures the security of the encryption
method by limiting the effectiveness of probabilistic attacks [BDJR].

For a particular Counter Mode key, each IV value used as an input
MUST be distinct, in order to avoid the security exposure of a two-
time pad situation (Section 9.1).  To satisfy this constraint, an
implementation MUST ensure that the combination of the SRTP packet

index of ROC || SEQ, and the SSRC used in the construction of the IV
are distinct for any particular key.  The failure to ensure this
uniqueness could be catastrophic for Secure RTP.  This is in contrast
to the situation for RTP itself, which may be able to tolerate such
failures.  It is RECOMMENDED that, if a dedicated security module is
present, the RTP sequence numbers and SSRC either be generated or
checked by that module (i.e., sequence-number and SSRC processing in
an SRTP system needs to be protected as well as the key).

### 4.1.2.  AES in f8-mode

To encrypt UMTS (Universal Mobile Telecommunications System, as 3G
networks) data, a solution (see [f8-a] [f8-b]) known as the f8-
algorithm has been developed.  On a high level, the proposed scheme
is a variant of Output Feedback Mode (OFB) [HAC], with a more
elaborate initialization and feedback function.  As in normal OFB,
the core consists of a block cipher.  We also define here the use of
AES as a block cipher to be used in what we shall call "f8-mode of
operation" RTP encryption.  The AES f8-mode SHALL use the same
default sizes for session key and salt as AES counter mode.

Figure 4 shows the structure of block cipher, E, running in f8-mode.

                    IV
                    |
                    v
                +------+
                |      |
           +--->|  E   |
           |    +------+
           |        |
     m -> (*)       +-----------+-------------+--  ...     ------+
           |    IV' |           |             |                  |
           |        |   j=1 -> (*)    j=2 -> (*)   ...  j=L-1 ->(*)
           |        |           |             |                  |
           |        |      +-> (*)       +-> (*)   ...      +-> (*)
           |        |      |    |        |    |             |    |
           |        v      |    v        |    v             |    v
           |    +------+   | +------+    | +------+         | +------+
    k_e ---+--->|  E   |   | |  E   |    | |  E   |         | |  E   |
                |      |   | |      |    | |      |         | |      |
                +------+   | +------+    | +------+         | +------+
                    |      |    |        |    |             |    |
                    +------+    +--------+    +--  ...  ----+    |
                    |           |             |                  |
                    v           v             v                  v
                   S(0)        S(1)          S(2)  . . .       S(L-1)

   Figure 4.  f8-mode of operation (asterisk, (*), denotes bitwise XOR).
   The figure represents the KG in Figure 3, when AES-f8 is used.

#### 4.1.2.1.  f8 Keystream Generation

The Initialization Vector (IV) SHALL be determined as described in
Section 4.1.2.2 (and in Section 4.1.2.3 for SRTCP).

Let IV', S(j), and m denote n_b-bit blocks.  The keystream,
S(0) ||... || S(L-1), for an N-bit message SHALL be defined by
setting IV' = E(k_e XOR m, IV), and S(-1) = 00..0.  For
j = 0,1,..,L-1 where L = N/n_b (rounded up to nearest integer if it
is not already an integer) compute

        S(j) = E(k_e, IV' XOR j XOR S(j-1))

Notice that the IV is not used directly.  Instead it is fed through E
under another key to produce an internal, "masked" value (denoted
IV') to prevent an attacker from gaining known input/output pairs.

The role of the internal counter, j, is to prevent short keystream
cycles.  The value of the key mask m SHALL be

        m = k_s || 0x555..5,

i.e., the session salting key, appended by the binary pattern 0101..
to fill out the entire desired key size, n_e.

The sender SHOULD NOT generate more than 2^32 blocks, which is
sufficient to generate 2^39 bits of keystream.  Unlike counter mode,
there is no absolute threshold above (below) which f8 is guaranteed
to be insecure (secure).  The above bound has been chosen to limit,
with sufficient security margin, the probability of degenerative
behavior in the f8 keystream generation.

#### 4.1.2.2.  f8 SRTP IV Formation

The purpose of the following IV formation is to provide a feature
which we call implicit header authentication (IHA), see Section 9.5.

The SRTP IV for 128-bit block AES-f8 SHALL be formed in the following
way:

    IV = 0x00 || M || PT || SEQ || TS || SSRC || ROC

M, PT, SEQ, TS, SSRC SHALL be taken from the RTP header; ROC is from
the cryptographic context.

The presence of the SSRC as part of the IV allows AES-f8 to be used
when a master key is shared between multiple streams within the same
RTP session, see Section 9.1.

#### 4.1.2.3.  f8 SRTCP IV Formation

The SRTCP IV for 128-bit block AES-f8 SHALL be formed in the
following way:

IV= 0..0 || E || SRTCP index || V || P || RC || PT || length || SSRC

where V, P, RC, PT, length, SSRC SHALL be taken from the first header
in the RTCP compound packet.  E and SRTCP index are the 1-bit and
31-bit fields added to the packet.

### 4.1.3.  NULL Cipher

The NULL cipher is used when no confidentiality for RTP/RTCP is
requested.  The keystream can be thought of as "000..0", i.e., the
encryption SHALL simply copy the plaintext input into the ciphertext
output.

## 4.2.  Message Authentication and Integrity

Throughout this section, M will denote data to be integrity
protected.  In the case of SRTP, M SHALL consist of the Authenticated
Portion of the packet (as specified in Figure 1) concatenated with
the ROC, M = Authenticated Portion || ROC; in the case of SRTCP, M
SHALL consist of the Authenticated Portion (as specified in Figure 2)
only.

Common parameters:

*  AUTH_ALG is the authentication algorithm
*  k_a is the session message authentication key
*  n_a is the bit-length of the authentication key
*  n_tag is the bit-length of the output authentication tag
*  SRTP_PREFIX_LENGTH is the octet length of the keystream prefix as
    defined above, a parameter of AUTH_ALG

The distinct session authentication keys for SRTP/SRTCP are by
default derived as specified in Section 4.3.

The values of n_a, n_tag, and SRTP_PREFIX_LENGTH MUST be fixed for
any particular fixed value of the key.

We describe the process of computing authentication tags as follows.
The sender computes the tag of M and appends it to the packet.  The
SRTP receiver verifies a message/authentication tag pair by computing
a new authentication tag over M using the selected algorithm and key,
and then compares it to the tag associated with the received message.
If the two tags are equal, then the message/tag pair is valid;
otherwise, it is invalid and the error audit message "AUTHENTICATION
FAILURE" MUST be returned.

### 4.2.1.  HMAC-SHA1

The pre-defined authentication transform for SRTP is HMAC-SHA1
[RFC2104].  With HMAC-SHA1, the SRTP_PREFIX_LENGTH (Figure 3) SHALL
be 0.  For SRTP (respectively SRTCP), the HMAC SHALL be applied to
the session authentication key and M as specified above, i.e.,
HMAC(k_a, M).  The HMAC output SHALL then be truncated to the n_tag
left-most bits.

## 4.3.  Key Derivation

### 4.3.1.  Key Derivation Algorithm

Regardless of the encryption or message authentication transform that
is employed (it may be an SRTP pre-defined transform or newly
introduced according to Section 6), interoperable SRTP
implementations MUST use the SRTP key derivation to generate session
keys.  Once the key derivation rate is properly signaled at the start
of the session, there is no need for extra communication between the
parties that use SRTP key derivation.

                         packet index ---+
                                         |
                                         v
               +-----------+ master  +--------+ session encr_key
               | ext       | key     |        |---------->
               | key mgmt  |-------->|  key   | session auth_key
               | (optional |         | deriv  |---------->
               | rekey)    |-------->|        | session salt_key
               |           | master  |        |---------->
               +-----------+ salt    +--------+

   Figure 5: SRTP key derivation.

At least one initial key derivation SHALL be performed by SRTP, i.e.,
the first key derivation is REQUIRED.  Further applications of the
key derivation MAY be performed, according to the
"key_derivation_rate" value in the cryptographic context.  The key
derivation function SHALL initially be invoked before the first
packet and then, when r > 0, a key derivation is performed whenever
index mod r equals zero.  This can be thought of as "refreshing" the
session keys.  The value of "key_derivation_rate" MUST be kept fixed
for the lifetime of the associated master key.

Interoperable SRTP implementations MAY also derive session salting
keys for encryption transforms, as is done in both of the pre-
defined transforms.

Let m and n be positive integers.  A pseudo-random function family is
a set of keyed functions {PRF_n(k,x)} such that for the (secret)
random key k, given m-bit x, PRF_n(k,x) is an n-bit string,
computationally indistinguishable from random n-bit strings, see
[HAC].  For the purpose of key derivation in SRTP, a secure PRF with
m = 128 (or more) MUST be used, and a default PRF transform is
defined in Section 4.3.3.

Let "a DIV t" denote integer division of a by t, rounded down, and
with the convention that "a DIV 0 = 0" for all a.  We also make the
convention of treating "a DIV t" as a bit string of the same length
as a, and thus "a DIV t" will in general have leading zeros.

Key derivation SHALL be defined as follows in terms of <label>, an
8-bit constant (see below), master_salt and key_derivation_rate, as
determined in the cryptographic context, and index, the packet index
(i.e., the 48-bit ROC || SEQ for SRTP):

*  Let r = index DIV key_derivation_rate (with DIV as defined above).

*  Let key_id = <label> || r.

*  Let x = key_id XOR master_salt, where key_id and master_salt are
    aligned so that their least significant bits agree (right-
    alignment).

<label> MUST be unique for each type of key to be derived.  We
currently define <label> 0x00 to 0x05 (see below), and future
extensions MAY specify new values in the range 0x06 to 0xff for other
purposes.  The n-bit SRTP key (or salt) for this packet SHALL then be
derived from the master key, k_master as follows:

    PRF_n(k_master, x).

(The PRF may internally specify additional formatting and padding of
x, see e.g., Section 4.3.3 for the default PRF.)

The session keys and salt SHALL now be derived using:

- k_e (SRTP encryption): <label> = 0x00, n = n_e.

- k_a (SRTP message authentication): <label> = 0x01, n = n_a.

- k_s (SRTP salting key): <label> = 0x02, n = n_s.

where n_e, n_s, and n_a are from the cryptographic context.

The master key and master salt MUST be random, but the master salt
MAY be public.

Note that for a key_derivation_rate of 0, the application of the key
derivation SHALL take place exactly once.

The definition of DIV above is purely for notational convenience.
For a non-zero t among the set of allowed key derivation rates, "a
DIV t" can be implemented as a right-shift by the base-2 logarithm of t. 

The derivation operation is further facilitated if the rates are
chosen to be powers of 256, but that granularity was considered too
coarse to be a requirement of this specification.

The upper limit on the number of packets that can be secured using
the same master key (see Section 9.2) is independent of the key
derivation.

### 4.3.2.  SRTCP Key Derivation

SRTCP SHALL by default use the same master key (and master salt) as
SRTP.  To do this securely, the following changes SHALL be done to
the definitions in Section 4.3.1 when applying session key derivation
for SRTCP.

Replace the SRTP index by the 32-bit quantity: 0 || SRTCP index
(i.e., excluding the E-bit, replacing it with a fixed 0-bit), and use
<label> = 0x03 for the SRTCP encryption key, <label> = 0x04 for the
SRTCP authentication key, and, <label> = 0x05 for the SRTCP salting
key.

### 4.3.3.  AES-CM PRF

The currently defined PRF, keyed by 128, 192, or 256 bit master key,
has input block size m = 128 and can produce n-bit outputs for n up
to 2^23.  PRF_n(k_master,x) SHALL be AES in Counter Mode as described
in Section 4.1.1, applied to key k_master, and IV equal to (x*2^16),
and with the output keystream truncated to the n first (left-most)
bits.  (Requiring n/128, rounded up, applications of AES.)
