## 4.1.  The use_srtp Extension

In order to negotiate the use of SRTP data protection, clients
include an extension of type "use_srtp" in the DTLS extended client
hello.  This extension MUST only be used when the data being
transported is RTP or RTCP [RFC3550].  The "extension_data" field of
this extension contains the list of acceptable SRTP protection
profiles, as indicated below.

Servers that receive an extended hello containing a "use_srtp"
extension can agree to use SRTP by including an extension of type
"use_srtp", with the chosen protection profile in the extended server
hello.  This process is shown below.

         Client                                               Server

         ClientHello + use_srtp       -------->
                                              ServerHello + use_srtp
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
         SRTP packets                 <------->      SRTP packets

        Client                                               Server

Note that '*' indicates messages that are not always sent in DTLS.
The CertificateRequest, client and server Certificates, and
CertificateVerify will be sent in DTLS-SRTP.

Once the "use_srtp" extension is negotiated, the RTP or RTCP
application data is protected solely using SRTP.  Application data is
never sent in DTLS record-layer "application_data" packets.  Rather,
complete RTP or RTCP packets are passed to the DTLS stack, which
passes them to the SRTP stack, which protects them appropriately.
Note that if RTP/RTCP multiplexing [RFC5761] is in use, this means
that RTP and RTCP packets may both be passed to the DTLS stack.
Because the DTLS layer does not process the packets, it does not need
to distinguish them.  The SRTP stack can use the procedures of
[RFC5761] to distinguish RTP from RTCP.

When the "use_srtp" extension is in effect, implementations must not
place more than one application data "record" per datagram.  (This is
only meaningful from the perspective of DTLS because SRTP is
inherently oriented towards one payload per packet, but this is
stated purely for clarification.)

Data other than RTP/RTCP (i.e., TLS control messages) MUST use
ordinary DTLS framing and MUST be placed in separate datagrams from
SRTP data.

A DTLS-SRTP handshake establishes one or more SRTP crypto contexts;
however, they all have the same SRTP Protection Profile and Master
Key Identifier (MKI), if any.  MKIs are used solely to distinguish
the keying material and protection profiles between distinct
handshakes, for instance, due to rekeying.  When an MKI is
established in a DTLS-SRTP session, it MUST apply for all of the
SSRCs within that session -- though a single endpoint may negotiate
multiple DTLS-SRTP sessions due, for instance, to forking.  (Note
that RFC 3711 allows packets within the same session but with
different SSRCs to use MKIs differently; in contrast, DTLS-SRTP
requires that MKIs and the keys that they are associated with have
the same meaning and are uniform across the entire SRTP session.)

### 4.1.1.  use_srtp Extension Definition

The client MUST fill the extension_data field of the "use_srtp"
extension with an UseSRTPData value (see Section 9 for the
registration):

uint8 SRTPProtectionProfile[2];

struct {
      SRTPProtectionProfiles SRTPProtectionProfiles;
      opaque srtp_mki<0..255>;
} UseSRTPData;

SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;

The SRTPProtectionProfiles list indicates the SRTP protection
profiles that the client is willing to support, listed in descending
order of preference.  The srtp_mki value contains the SRTP Master Key
Identifier (MKI) value (if any) that the client will use for his SRTP
packets.  If this field is of zero length, then no MKI will be used.

Note: for those unfamiliar with TLS syntax, "srtp_mki<0..255>"
indicates a variable-length value with a length between 0 and 255
(inclusive).  Thus, the MKI may be up to 255 bytes long.

If the server is willing to accept the use_srtp extension, it MUST
respond with its own "use_srtp" extension in the ExtendedServerHello.
The extension_data field MUST contain a UseSRTPData value with a
single SRTPProtectionProfile value that the server has chosen for use
with this connection.  The server MUST NOT select a value that the
client has not offered.  If there is no shared profile, the server
SHOULD NOT return the use_srtp extension at which point the
connection falls back to the negotiated DTLS cipher suite.  If that
is not acceptable, the server SHOULD return an appropriate DTLS
alert.

### 4.1.2.  SRTP Protection Profiles

A DTLS-SRTP SRTP Protection Profile defines the parameters and
options that are in effect for the SRTP processing.  This document
defines the following SRTP protection profiles.

SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_80 = {0x00, 0x01};
SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_32 = {0x00, 0x02};
SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_80      = {0x00, 0x05};
SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_32      = {0x00, 0x06};

The following list indicates the SRTP transform parameters for each
protection profile.  The parameters cipher_key_length,
cipher_salt_length, auth_key_length, and auth_tag_length express the
number of bits in the values to which they refer.  The
maximum_lifetime parameter indicates the maximum number of packets
that can be protected with each single set of keys when the parameter
profile is in use.  All of these parameters apply to both RTP and
RTCP, unless the RTCP parameters are separately specified.

All of the crypto algorithms in these profiles are from [RFC3711].

SRTP_AES128_CM_HMAC_SHA1_80
      cipher: AES_128_CM
      cipher_key_length: 128
      cipher_salt_length: 112
      maximum_lifetime: 2^31
      auth_function: HMAC-SHA1
      auth_key_length: 160
      auth_tag_length: 80
SRTP_AES128_CM_HMAC_SHA1_32
      cipher: AES_128_CM
      cipher_key_length: 128
      cipher_salt_length: 112
      maximum_lifetime: 2^31
      auth_function: HMAC-SHA1
      auth_key_length: 160
      auth_tag_length: 32
      RTCP auth_tag_length: 80
SRTP_NULL_HMAC_SHA1_80
      cipher: NULL
      cipher_key_length: 0
      cipher_salt_length: 0
      maximum_lifetime: 2^31
      auth_function: HMAC-SHA1
      auth_key_length: 160
      auth_tag_length: 80


SRTP_NULL_HMAC_SHA1_32
         cipher: NULL
         cipher_key_length: 0
         cipher_salt_length: 0
         maximum_lifetime: 2^31
         auth_function: HMAC-SHA1
         auth_key_length: 160
         auth_tag_length: 32
         RTCP auth_tag_length: 80

With all of these SRTP Parameter profiles, the following SRTP options
are in effect:

o  The TLS PseudoRandom Function (PRF) is used to generate keys to
feed into the SRTP Key Derivation Function (KDF).  When DTLS 1.2
[DTLS1.2] is in use, the PRF is the one associated with the cipher
suite.  Note that this specification is compatible with DTLS 1.0
or DTLS 1.2

o  The Key Derivation Rate (KDR) is equal to zero.  Thus, keys are
not re-derived based on the SRTP sequence number.

o  The key derivation procedures from Section 4.3 with the AES-CM PRF
from RFC 3711 are used.

o  For all other parameters (in particular, SRTP replay window size
and FEC order), the default values are used.

If values other than the defaults for these parameters are required,
they can be enabled by writing a separate specification specifying
SDP syntax to signal them.

Applications using DTLS-SRTP SHOULD coordinate the SRTP Protection
Profiles between the DTLS-SRTP session that protects an RTP flow and
the DTLS-SRTP session that protects the associated RTCP flow (in
those cases in which the RTP and RTCP are not multiplexed over a
common port).  In particular, identical ciphers SHOULD be used.

New SRTPProtectionProfile values must be defined according to the
"Specification Required" policy as defined by RFC 5226 [RFC5226].
See Section 9 for IANA Considerations.

### 4.1.3.  srtp_mki value

The srtp_mki value MAY be used to indicate the capability and desire
to use the SRTP Master Key Identifier (MKI) field in the SRTP and
SRTCP packets.  The MKI field indicates to an SRTP receiver which key
was used to protect the packet that contains that field.  The

srtp_mki field contains the value of the SRTP MKI which is associated
with the SRTP master keys derived from this handshake.  Each SRTP
session MUST have exactly one master key that is used to protect
packets at any given time.  The client MUST choose the MKI value so
that it is distinct from the last MKI value that was used, and it
SHOULD make these values unique for the duration of the TLS session.

Upon receipt of a "use_srtp" extension containing a "srtp_mki" field,
the server MUST either (assuming it accepts the extension at all):

1.  include a matching "srtp_mki" value in its "use_srtp" extension
      to indicate that it will make use of the MKI, or
2.  return an empty "srtp_mki" value to indicate that it cannot make
      use of the MKI.

If the client detects a nonzero-length MKI in the server's response
that is different than the one the client offered, then the client
MUST abort the handshake and SHOULD send an invalid_parameter alert.
If the client and server agree on an MKI, all SRTP packets protected
under the new security parameters MUST contain that MKI.

Note that any given DTLS-SRTP session only has a single active MKI
(if any).  Thus, at any given time, a set of endpoints will generally
only be using one MKI (the major exception is during rehandshakes).

## 4.2.  Key Derivation

When SRTP mode is in effect, different keys are used for ordinary
DTLS record protection and SRTP packet protection.  These keys are
generated using a TLS exporter [RFC5705] to generate

2 * (SRTPSecurityParams.master_key_len +
      SRTPSecurityParams.master_salt_len) bytes of data

which are assigned as shown below.  The per-association context value
is empty.

client_write_SRTP_master_key[SRTPSecurityParams.master_key_len];
server_write_SRTP_master_key[SRTPSecurityParams.master_key_len];
client_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len];
server_write_SRTP_master_salt[SRTPSecurityParams.master_salt_len];

The exporter label for this usage is "EXTRACTOR-dtls_srtp".  (The
"EXTRACTOR" prefix is for historical compatibility.)

The four keying material values (the master key and master salt for
each direction) are provided as inputs to the SRTP key derivation
mechanism, as shown in Figure 1 and detailed below.  By default, the

mechanism defined in Section 4.3 of [RFC3711] is used, unless another
key derivation mechanism is specified as part of an SRTP Protection
Profile.

The client_write_SRTP_master_key and client_write_SRTP_master_salt
are provided to one invocation of the SRTP key derivation function,
to generate the SRTP keys used to encrypt and authenticate packets
sent by the client.  The server MUST only use these keys to decrypt
and to check the authenticity of inbound packets.

The server_write_SRTP_master_key and server_write_SRTP_master_salt
are provided to one invocation of the SRTP key derivation function,
to generate the SRTP keys used to encrypt and authenticate packets
sent by the server.  The client MUST only use these keys to decrypt
and to check the authenticity of inbound packets.

   TLS master
     secret   label
      |         |
      v         v
   +---------------+
   | TLS extractor |
   +---------------+
          |                                         +------+   SRTP
          +-> client_write_SRTP_master_key ----+--->| SRTP |-> client
          |                                    | +->| KDF  |   write
          |                                    | |  +------+   keys
          |                                    | |
          +-> server_write_SRTP_master_key --  | |  +------+   SRTCP
          |                                  \ \--->|SRTCP |-> client
          |                                   \  +->| KDF  |   write
          |                                    | |  +------+   keys
          +-> client_write_SRTP_master_salt ---|-+
          |                                    |
          |                                    |    +------+   SRTP
          |                                    +--->| SRTP |-> server
          +-> server_write_SRTP_master_salt -+-|--->| KDF  |   write
                                             | |    +------+   keys
                                             | |
                                             | |    +------+   SRTCP
                                             | +--->|SRTCP |-> server
                                             +----->| KDF  |   write
                                                    +------+   keys

                Figure 1: The derivation of the SRTP keys.

When both RTCP and RTP use the same source and destination ports,
then both the SRTP and SRTCP keys are needed.  Otherwise, there are
two DTLS-SRTP sessions, one of which protects the RTP packets and one
of which protects the RTCP packets; each DTLS-SRTP session protects
the part of an SRTP session that passes over a single source/
destination transport address pair, as shown in Figure 2, independent
of which SSRCs are used on that pair.  When a DTLS-SRTP session is
protecting RTP, the SRTCP keys derived from the DTLS handshake are
not needed and are discarded.  When a DTLS-SRTP session is protecting
RTCP, the SRTP keys derived from the DTLS handshake are not needed
and are discarded.

Client            Server
(Sender)         (Receiver)
(1)   <----- DTLS ------>    src/dst = a/b and b/a
      ------ SRTP ------>    src/dst = a/b, uses client write keys

(2)   <----- DTLS ------>    src/dst = c/d and d/c
      ------ SRTCP ----->    src/dst = c/d, uses client write keys
      <----- SRTCP ------    src/dst = d/c, uses server write keys

Figure 2: A DTLS-SRTP session protecting RTP (1) and another one
protecting RTCP (2), showing the transport addresses and keys used.

## 4.3.  Key Scope

Because of the possibility of packet reordering, DTLS-SRTP
implementations SHOULD store multiple SRTP keys sets during a rekey
in order to avoid the need for receivers to drop packets for which
they lack a key.

## 4.4.  Key Usage Limitations

The maximum_lifetime parameter in the SRTP protection profile
indicates the maximum number of packets that can be protected with
each single encryption and authentication key.  (Note that, since RTP
and RTCP are protected with independent keys, those protocols are
counted separately for the purposes of determining when a key has
reached the end of its lifetime.)  Each profile defines its own
limit.  When this limit is reached, a new DTLS session SHOULD be used
to establish replacement keys, and SRTP implementations MUST NOT use
the existing keys for the processing of either outbound or inbound
traffic.