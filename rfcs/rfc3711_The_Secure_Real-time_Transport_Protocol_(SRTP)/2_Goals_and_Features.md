## 2.  Goals and Features

The security goals for SRTP are to ensure:

*  the confidentiality of the RTP and RTCP payloads, and

*  the integrity of the entire RTP and RTCP packets, together with
protection against replayed packets.

These security services are optional and independent from each other,
except that SRTCP integrity protection is mandatory (malicious or
erroneous alteration of RTCP messages could otherwise disrupt the
processing of the RTP stream).

Other, functional, goals for the protocol are:

*  a framework that permits upgrading with new cryptographic
transforms,

*  low bandwidth cost, i.e., a framework preserving RTP header
compression efficiency,

and, asserted by the pre-defined transforms:

*  a low computational cost,

*  a small footprint (i.e., small code size and data memory for
keying information and replay lists),

*  limited packet expansion to support the bandwidth economy goal,

*  independence from the underlying transport, network, and physical
layers used by RTP, in particular high tolerance to packet loss
and re-ordering.

These properties ensure that SRTP is a suitable protection scheme for
RTP/RTCP in both wired and wireless scenarios.

## 2.1.  Features

Besides the above mentioned direct goals, SRTP provides for some
additional features.  They have been introduced to lighten the burden
on key management and to further increase security.  They include:

*  A single "master key" can provide keying material for
    confidentiality and integrity protection, both for the SRTP stream
    and the corresponding SRTCP stream.  This is achieved with a key
    derivation function (see Section 4.3), providing "session keys"
    for the respective security primitive, securely derived from the
    master key.

*  In addition, the key derivation can be configured to periodically
    refresh the session keys, which limits the amount of ciphertext
    produced by a fixed key, available for an adversary to
    cryptanalyze.

*  "Salting keys" are used to protect against pre-computation and
    time-memory tradeoff attacks [MF00] [BS00].

Detailed rationale for these features can be found in Section 7.