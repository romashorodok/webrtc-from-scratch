# 14.  STUN Attributes

After the STUN header are zero or more attributes.  Each attribute
MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
above, all fields in an attribute are transmitted most significant
bit first.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Type                  |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Value (variable)                ....
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 4: Format of STUN Attributes

The value in the Length field MUST contain the length of the Value
part of the attribute, prior to padding, measured in bytes.  Since
STUN aligns attributes on 32-bit boundaries, attributes whose content
is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
padding so that its value contains a multiple of 4 bytes.  The
padding bits MUST be set to zero on sending and MUST be ignored by
the receiver.

Any attribute type MAY appear more than once in a STUN message.
Unless specified otherwise, the order of appearance is significant:
only the first occurrence needs to be processed by a receiver, and
any duplicates MAY be ignored by a receiver.

To allow future revisions of this specification to add new attributes
if needed, the attribute space is divided into two ranges.
Attributes with type values between 0x0000 and 0x7FFF are

comprehension-required attributes, which means that the STUN agent
cannot successfully process the message unless it understands the
attribute.  Attributes with type values between 0x8000 and 0xFFFF are
comprehension-optional attributes, which means that those attributes
can be ignored by the STUN agent if it does not understand them.

The set of STUN attribute types is maintained by IANA.  The initial
set defined by this specification is found in Section 18.3.

The rest of this section describes the format of the various
attributes defined in this specification.

## 14.1.  MAPPED-ADDRESS

The MAPPED-ADDRESS attribute indicates a reflexive transport address
of the client.  It consists of an 8-bit address family and a 16-bit
port, followed by a fixed-length value representing the IP address.
If the address family is IPv4, the address MUST be 32 bits.  If the
address family is IPv6, the address MUST be 128 bits.  All fields
must be in network byte order.

The format of the MAPPED-ADDRESS attribute is:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |0 0 0 0 0 0 0 0|    Family     |           Port                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                 Address (32 bits or 128 bits)                 |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 5: Format of MAPPED-ADDRESS Attribute

The address family can take on the following values:

0x01:IPv4
0x02:IPv6

The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
ignored by receivers.  These bits are present for aligning parameters
on natural 32-bit boundaries.

This attribute is used only by servers for achieving backwards
compatibility with [RFC3489] clients.

## 14.2.  XOR-MAPPED-ADDRESS

The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS
attribute, except that the reflexive transport address is obfuscated
through the XOR function.

The format of the XOR-MAPPED-ADDRESS is:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |0 0 0 0 0 0 0 0|    Family     |         X-Port                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                X-Address (Variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 6: Format of XOR-MAPPED-ADDRESS Attribute

The Family field represents the IP address family and is encoded
identically to the Family field in MAPPED-ADDRESS.

X-Port is computed by XOR'ing the mapped port with the most
significant 16 bits of the magic cookie.  If the IP address family is
IPv4, X-Address is computed by XOR'ing the mapped IP address with the
magic cookie.  If the IP address family is IPv6, X-Address is
computed by XOR'ing the mapped IP address with the concatenation of
the magic cookie and the 96-bit transaction ID.  In all cases, the
XOR operation works on its inputs in network byte order (that is, the
order they will be encoded in the message).

The rules for encoding and processing the first 8 bits of the
attribute's value, the rules for handling multiple occurrences of the
attribute, and the rules for processing address families are the same
as for MAPPED-ADDRESS.

Note: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS differ only in their
encoding of the transport address.  The former encodes the transport
address by XOR'ing it with the magic cookie.  The latter encodes it
directly in binary.  RFC 3489 originally specified only MAPPED-
ADDRESS.  However, deployment experience found that some NATs rewrite
the 32-bit binary payloads containing the NAT's public IP address,
such as STUN's MAPPED-ADDRESS attribute, in the well-meaning but
misguided attempt to provide a generic Application Layer Gateway
(ALG) function.  Such behavior interferes with the operation of STUN
and also causes failure of STUN's message-integrity checking.

## 14.3.  USERNAME

The USERNAME attribute is used for message integrity.  It identifies
the username and password combination used in the message-integrity
check.

The value of USERNAME is a variable-length value containing the
authentication username.  It MUST contain a UTF-8-encoded [RFC3629]
sequence of fewer than 509 bytes and MUST have been processed using
the OpaqueString profile [RFC8265].  A compliant implementation MUST
be able to parse a UTF-8-encoded sequence of 763 or fewer octets to
be compatible with [RFC5389].

   Note: [RFC5389] mistakenly referenced the definition of UTF-8 in
   [RFC2279].  [RFC2279] assumed up to 6 octets per characters
   encoded.  [RFC2279] was replaced by [RFC3629], which allows only 4
   octets per character encoded, consistent with changes made in
   Unicode 2.0 and ISO/IEC 10646.

   Note: This specification uses the OpaqueString profile instead of
   the UsernameCasePreserved profile for username string processing
   in order to improve compatibility with deployed password stores.
   Many password databases used for HTTP and SIP Digest
   authentication store the MD5 hash of username:realm:password
   instead of storing a plain text password.  In [RFC3489], STUN
   authentication was designed to be compatible with these existing
   databases to the extent possible, which like SIP and HTTP
   performed no pre-processing of usernames and passwords other than
   prohibiting non-space ASCII control characters.  The next revision
   of the STUN specification, [RFC5389], used the SASLprep [RFC4013]
   stringprep [RFC3454] profile to pre-process usernames and
   passwords.  SASLprep uses Unicode Normalization Form KC
   (Compatibility Decomposition, followed by Canonical Composition)
   [UAX15] and prohibits various control, space, and non-text,
   deprecated, or inappropriate codepoints.  The PRECIS framework
   [RFC8264] obsoletes stringprep.  PRECIS handling of usernames and
   passwords [RFC8265] uses Unicode Normalization Form C (Canonical
   Decomposition, followed by Canonical Composition).  While there
   are specific cases where different username strings under HTTP
   Digest could be mapped to a single STUN username processed with
   OpaqueString, these cases are extremely unlikely and easy to
   detect and correct.  With a UsernameCasePreserved profile, it
   would be more likely that valid usernames under HTTP Digest would
   not match their processed forms (specifically usernames containing
   bidirectional text and compatibility forms).  Operators are free
   to further restrict the allowed codepoints in usernames to avoid
   problematic characters.

## 14.4.  USERHASH

The USERHASH attribute is used as a replacement for the USERNAME
attribute when username anonymity is supported.

The value of USERHASH has a fixed length of 32 bytes.  The username
MUST have been processed using the OpaqueString profile [RFC8265],
and the realm MUST have been processed using the OpaqueString profile
[RFC8265] before hashing.

The following is the operation that the client will perform to hash
the username:

userhash = SHA-256(OpaqueString(username) ":" OpaqueString(realm))

## 14.5.  MESSAGE-INTEGRITY

The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104] of
the STUN message.  The MESSAGE-INTEGRITY attribute can be present in
any STUN message type.  Since it uses the SHA-1 hash, the HMAC will
be 20 bytes.

The key for the HMAC depends on which credential mechanism is in use.
Section 9.1.1 defines the key for the short-term credential
mechanism, and Section 9.2.2 defines the key for the long-term
credential mechanism.  Other credential mechanisms MUST define the
key that is used for the HMAC.

The text used as input to HMAC is the STUN message, up to and
including the attribute preceding the MESSAGE-INTEGRITY attribute.
The Length field of the STUN message header is adjusted to point to
the end of the MESSAGE-INTEGRITY attribute.  The value of the
MESSAGE-INTEGRITY attribute is set to a dummy value.

Once the computation is performed, the value of the MESSAGE-INTEGRITY
attribute is filled in, and the value of the length in the STUN
header is set to its correct value -- the length of the entire
message.  Similarly, when validating the MESSAGE-INTEGRITY, the
Length field in the STUN header must be adjusted to point to the end
of the MESSAGE-INTEGRITY attribute prior to calculating the HMAC over
the STUN message, up to and including the attribute preceding the
MESSAGE-INTEGRITY attribute.  Such adjustment is necessary when
attributes, such as FINGERPRINT and MESSAGE-INTEGRITY-SHA256, appear
after MESSAGE-INTEGRITY.  See also [RFC5769] for examples of such
calculations.

## 14.6.  MESSAGE-INTEGRITY-SHA256

The MESSAGE-INTEGRITY-SHA256 attribute contains an HMAC-SHA256
[RFC2104] of the STUN message.  The MESSAGE-INTEGRITY-SHA256
attribute can be present in any STUN message type.  The MESSAGE-
INTEGRITY-SHA256 attribute contains an initial portion of the HMAC-
SHA-256 [RFC2104] of the STUN message.  The value will be at most 32
bytes, but it MUST be at least 16 bytes and MUST be a multiple of 4
bytes.  The value must be the full 32 bytes unless the STUN Usage
explicitly specifies that truncation is allowed.  STUN Usages may
specify a minimum length longer than 16 bytes.

The key for the HMAC depends on which credential mechanism is in use.
Section 9.1.1 defines the key for the short-term credential
mechanism, and Section 9.2.2 defines the key for the long-term
credential mechanism.  Other credential mechanism MUST define the key
that is used for the HMAC.

The text used as input to HMAC is the STUN message, up to and
including the attribute preceding the MESSAGE-INTEGRITY-SHA256
attribute.  The Length field of the STUN message header is adjusted
to point to the end of the MESSAGE-INTEGRITY-SHA256 attribute.  The
value of the MESSAGE-INTEGRITY-SHA256 attribute is set to a dummy
value.

Once the computation is performed, the value of the MESSAGE-
INTEGRITY-SHA256 attribute is filled in, and the value of the length
in the STUN header is set to its correct value -- the length of the
entire message.  Similarly, when validating the MESSAGE-INTEGRITY-
SHA256, the Length field in the STUN header must be adjusted to point
to the end of the MESSAGE-INTEGRITY-SHA256 attribute prior to
calculating the HMAC over the STUN message, up to and including the
attribute preceding the MESSAGE-INTEGRITY-SHA256 attribute.  Such
adjustment is necessary when attributes, such as FINGERPRINT, appear
after MESSAGE-INTEGRITY-SHA256.  See also Appendix B.1 for examples
of such calculations.

## 14.7.  FINGERPRINT

The FINGERPRINT attribute MAY be present in all STUN messages.

The value of the attribute is computed as the CRC-32 of the STUN
message up to (but excluding) the FINGERPRINT attribute itself,
XOR'ed with the 32-bit value 0x5354554e.  (The XOR operation ensures
that the FINGERPRINT test will not report a false positive on a
packet containing a CRC-32 generated by an application protocol.)
The 32-bit CRC is the one defined in ITU V.42 [ITU.V42.2002], which
has a generator polynomial of x^32 + x^26 + x^23 + x^22 + x^16 + x^12
+ x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.  See the sample
code for the CRC-32 in Section 8 of [RFC1952].

When present, the FINGERPRINT attribute MUST be the last attribute in
the message and thus will appear after MESSAGE-INTEGRITY and MESSAGE-
INTEGRITY-SHA256.

The FINGERPRINT attribute can aid in distinguishing STUN packets from
packets of other protocols.  See Section 7.

As with MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256, the CRC used
in the FINGERPRINT attribute covers the Length field from the STUN
message header.  Therefore, prior to computation of the CRC, this
value must be correct and include the CRC attribute as part of the
message length.  When using the FINGERPRINT attribute in a message,
the attribute is first placed into the message with a dummy value;
then, the CRC is computed, and the value of the attribute is updated.
If the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute is
also present, then it must be present with the correct message-
integrity value before the CRC is computed, since the CRC is done
over the value of the MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256
attributes as well.

## 14.8.  ERROR-CODE

The ERROR-CODE attribute is used in error response messages.  It
contains a numeric error code value in the range of 300 to 699 plus a
textual reason phrase encoded in UTF-8 [RFC3629]; it is also
consistent in its code assignments and semantics with SIP [RFC3261]
and HTTP [RFC7231].  The reason phrase is meant for diagnostic
purposes and can be anything appropriate for the error code.
Recommended reason phrases for the defined error codes are included
in the IANA registry for error codes.  The reason phrase MUST be a
UTF-8-encoded [RFC3629] sequence of fewer than 128 characters (which
can be as long as 509 bytes when encoding them or 763 bytes when
decoding them).

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           Reserved, should be 0         |Class|     Number    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Reason Phrase (variable)                                ..
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Figure 7: Format of ERROR-CODE Attribute


To facilitate processing, the class of the error code (the hundreds
digit) is encoded separately from the rest of the code, as shown in
Figure 7.

The Reserved bits SHOULD be 0 and are for alignment on 32-bit
boundaries.  Receivers MUST ignore these bits.  The Class represents
the hundreds digit of the error code.  The value MUST be between 3
and 6.  The Number represents the binary encoding of the error code
modulo 100, and its value MUST be between 0 and 99.

The following error codes, along with their recommended reason
phrases, are defined:

300  Try Alternate: The client should contact an alternate server for
      this request.  This error response MUST only be sent if the
      request included either a USERNAME or USERHASH attribute and a
      valid MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute;
      otherwise, it MUST NOT be sent and error code 400 (Bad Request)
      is suggested.  This error response MUST be protected with the
      MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, and
      receivers MUST validate the MESSAGE-INTEGRITY or MESSAGE-
      INTEGRITY-SHA256 of this response before redirecting themselves
      to an alternate server.

      Note: Failure to generate and validate message integrity for a
      300 response allows an on-path attacker to falsify a 300
      response thus causing subsequent STUN messages to be sent to a
      victim.

400  Bad Request: The request was malformed.  The client SHOULD NOT
      retry the request without modification from the previous
      attempt.  The server may not be able to generate a valid
      MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 for this error, so
      the client MUST NOT expect a valid MESSAGE-INTEGRITY or MESSAGE-
      INTEGRITY-SHA256 attribute on this response.

401  Unauthenticated: The request did not contain the correct
      credentials to proceed.  The client should retry the request
      with proper credentials.

420  Unknown Attribute: The server received a STUN packet containing
      a comprehension-required attribute that it did not understand.
      The server MUST put this unknown attribute in the UNKNOWN-
      ATTRIBUTE attribute of its error response.

438  Stale Nonce: The NONCE used by the client was no longer valid.
      The client should retry, using the NONCE provided in the
      response.
500  Server Error: The server has suffered a temporary error.  The
      client should try again.

## 14.9.  REALM

The REALM attribute may be present in requests and responses.  It
contains text that meets the grammar for "realm-value" as described
in [RFC3261] but without the double quotes and their surrounding
whitespace.  That is, it is an unquoted realm-value (and is therefore
a sequence of qdtext or quoted-pair).  It MUST be a UTF-8-encoded
[RFC3629] sequence of fewer than 128 characters (which can be as long
as 509 bytes when encoding them and as long as 763 bytes when
decoding them) and MUST have been processed using the OpaqueString
profile [RFC8265].

Presence of the REALM attribute in a request indicates that long-term
credentials are being used for authentication.  Presence in certain
error responses indicates that the server wishes the client to use a
long-term credential in that realm for authentication.

## 14.10.  NONCE

The NONCE attribute may be present in requests and responses.  It
contains a sequence of qdtext or quoted-pair, which are defined in
[RFC3261].  Note that this means that the NONCE attribute will not
contain the actual surrounding quote characters.  The NONCE attribute
MUST be fewer than 128 characters (which can be as long as 509 bytes
when encoding them and a long as 763 bytes when decoding them).  See
Section 5.4 of [RFC7616] for guidance on selection of nonce values in
a server.

## 14.11.  PASSWORD-ALGORITHMS

The PASSWORD-ALGORITHMS attribute may be present in requests and
responses.  It contains the list of algorithms that the server can
use to derive the long-term password.

The set of known algorithms is maintained by IANA.  The initial set
defined by this specification is found in Section 18.5.

The attribute contains a list of algorithm numbers and variable
length parameters.  The algorithm number is a 16-bit value as defined
in Section 18.5.  The parameters start with the length (prior to
padding) of the parameters as a 16-bit value, followed by the
parameters that are specific to each algorithm.  The parameters are
padded to a 32-bit boundary, in the same manner as an attribute.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Algorithm 1           | Algorithm 1 Parameters Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm 1 Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Algorithm 2           | Algorithm 2 Parameters Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm 2 Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                             ...

             Figure 8: Format of PASSWORD-ALGORITHMS Attribute

## 14.12.  PASSWORD-ALGORITHM

The PASSWORD-ALGORITHM attribute is present only in requests.  It
contains the algorithm that the server must use to derive a key from
the long-term password.

The set of known algorithms is maintained by IANA.  The initial set
defined by this specification is found in Section 18.5.

The attribute contains an algorithm number and variable length
parameters.  The algorithm number is a 16-bit value as defined in
Section 18.5.  The parameters starts with the length (prior to
padding) of the parameters as a 16-bit value, followed by the
parameters that are specific to the algorithm.  The parameters are
padded to a 32-bit boundary, in the same manner as an attribute.
Similarly, the padding bits MUST be set to zero on sending and MUST
be ignored by the receiver.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Algorithm           |  Algorithm Parameters Length   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Algorithm Parameters (variable)
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 9: Format of PASSWORD-ALGORITHM Attribute

## 14.13.  UNKNOWN-ATTRIBUTES

The UNKNOWN-ATTRIBUTES attribute is present only in an error response
when the response code in the ERROR-CODE attribute is 420 (Unknown
Attribute).

The attribute contains a list of 16-bit values, each of which
represents an attribute type that was not understood by the server.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Attribute 1 Type         |       Attribute 2 Type        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Attribute 3 Type         |       Attribute 4 Type    ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 10: Format of UNKNOWN-ATTRIBUTES Attribute

   Note: In [RFC3489], this field was padded to 32 by duplicating the
   last attribute.  In this version of the specification, the normal
   padding rules for attributes are used instead.

## 14.14.  SOFTWARE

The SOFTWARE attribute contains a textual description of the software
being used by the agent sending the message.  It is used by clients
and servers.  Its value SHOULD include manufacturer and version
number.  The attribute has no impact on operation of the protocol and
serves only as a tool for diagnostic and debugging purposes.  The
value of SOFTWARE is variable length.  It MUST be a UTF-8-encoded
[RFC3629] sequence of fewer than 128 characters (which can be as long
as 509 when encoding them and as long as 763 bytes when decoding
them).

## 14.15.  ALTERNATE-SERVER

The alternate server represents an alternate transport address
identifying a different STUN server that the STUN client should try.

It is encoded in the same way as MAPPED-ADDRESS and thus refers to a
single server by IP address.

## 14.16.  ALTERNATE-DOMAIN

The alternate domain represents the domain name that is used to
verify the IP address in the ALTERNATE-SERVER attribute when the
transport protocol uses TLS or DTLS.

The value of ALTERNATE-DOMAIN is variable length.  It MUST be a valid
DNS name [RFC1123] (including A-labels [RFC5890]) of 255 or fewer
ASCII characters.

# 15.  Operational Considerations

STUN MAY be used with anycast addresses, but only with UDP and in
STUN Usages where authentication is not used.
