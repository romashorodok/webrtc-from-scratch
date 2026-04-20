# 18.  IANA Considerations

## 18.1.  STUN Security Features Registry

A STUN Security Feature set defines 24 bits as flags.

IANA has created a new registry containing the STUN Security Features
that are protected by the bid-down attack prevention mechanism
described in Section 9.2.1.

The initial STUN Security Features are:

Bit 0: Password algorithms
Bit 1: Username anonymity
Bit 2-23: Unassigned

Bits are assigned starting from the most significant side of the bit
set, so Bit 0 is the leftmost bit and Bit 23 is the rightmost bit.

New Security Features are assigned by Standards Action [RFC8126].

## 18.2.  STUN Methods Registry

A STUN method is a hex number in the range 0x000-0x0FF.  The encoding
of a STUN method into a STUN message is described in Section 5.

STUN methods in the range 0x000-0x07F are assigned by IETF Review
[RFC8126].  STUN methods in the range 0x080-0x0FF are assigned by
Expert Review [RFC8126].  The responsibility of the expert is to
verify that the selected codepoint(s) is not in use and that the
request is not for an abnormally large number of codepoints.
Technical review of the extension itself is outside the scope of the
designated expert responsibility.

IANA has updated the name for method 0x002 as described below as well
as updated the reference from RFC 5389 to RFC 8489 for the following
STUN methods:

0x000: Reserved
0x001: Binding
0x002: Reserved; was SharedSecret prior to [RFC5389]

## 18.3.  STUN Attributes Registry

A STUN attribute type is a hex number in the range 0x0000-0xFFFF.
STUN attribute types in the range 0x0000-0x7FFF are considered
comprehension-required; STUN attribute types in the range
0x8000-0xFFFF are considered comprehension-optional.  A STUN agent
handles unknown comprehension-required and comprehension-optional
attributes differently.

STUN attribute types in the first half of the comprehension-required
range (0x0000-0x3FFF) and in the first half of the comprehension-
optional range (0x8000-0xBFFF) are assigned by IETF Review [RFC8126].
STUN attribute types in the second half of the comprehension-required
range (0x4000-0x7FFF) and in the second half of the comprehension-
optional range (0xC000-0xFFFF) are assigned by Expert Review
[RFC8126].  The responsibility of the expert is to verify that the
selected codepoint(s) are not in use and that the request is not for
an abnormally large number of codepoints.  Technical review of the
extension itself is outside the scope of the designated expert
responsibility.

### 18.3.1.  Updated Attributes

IANA has updated the names for attributes 0x0002, 0x0004, 0x0005,
0x0007, and 0x000B as well as updated the reference from RFC 5389 to
RFC 8489 for each the following STUN methods.

In addition, [RFC5389] introduced a mistake in the name of attribute
0x0003; [RFC5389] called it CHANGE-ADDRESS when it was actually
previously called CHANGE-REQUEST.  Thus, IANA has updated the
description for 0x0003 to read "Reserved; was CHANGE-REQUEST prior to
[RFC5389]".

Comprehension-required range (0x0000-0x7FFF):
0x0000: Reserved
0x0001: MAPPED-ADDRESS
0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
0x0006: USERNAME
0x0007: Reserved; was PASSWORD prior to [RFC5389]
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
0x0014: REALM
0x0015: NONCE
0x0020: XOR-MAPPED-ADDRESS

Comprehension-optional range (0x8000-0xFFFF)
0x8022: SOFTWARE
0x8023: ALTERNATE-SERVER
0x8028: FINGERPRINT

### 18.3.2.  New Attributes

IANA has added the following attribute to the "STUN Attributes"
registry:

Comprehension-required range (0x0000-0x7FFF):
0x001C: MESSAGE-INTEGRITY-SHA256
0x001D: PASSWORD-ALGORITHM
0x001E: USERHASH

Comprehension-optional range (0x8000-0xFFFF)
0x8002: PASSWORD-ALGORITHMS
0x8003: ALTERNATE-DOMAIN

## 18.4.  STUN Error Codes Registry

A STUN error code is a number in the range 0-699.  STUN error codes
are accompanied by a textual reason phrase in UTF-8 [RFC3629] that is
intended only for human consumption and can be anything appropriate;
this document proposes only suggested values.

STUN error codes are consistent in codepoint assignments and
semantics with SIP [RFC3261] and HTTP [RFC7231].

New STUN error codes are assigned based on IETF Review [RFC8126].
The specification must carefully consider how clients that do not
understand this error code will process it before granting the
request.  See the rules in Section 6.3.4.

IANA has updated the reference from RFC 5389 to RFC 8489 for the
error codes defined in Section 14.8.

IANA has changed the name of the 401 error code from "Unauthorized"
to "Unauthenticated".

## 18.5.  STUN Password Algorithms Registry

IANA has created a new registry titled "STUN Password Algorithms".

A password algorithm is a hex number in the range 0x0000-0xFFFF.

The initial contents of the "Password Algorithm" registry are as
follows:

0x0000: Reserved
0x0001: MD5
0x0002: SHA-256
0x0003-0xFFFF: Unassigned

Password algorithms in the first half of the range (0x0000-0x7FFF)
are assigned by IETF Review [RFC8126].  Password algorithms in the
second half of the range (0x8000-0xFFFF) are assigned by Expert
Review [RFC8126].

### 18.5.1.  Password Algorithms

#### 18.5.1.1.  MD5

This password algorithm is taken from [RFC1321].

The key length is 16 bytes, and the parameters value is empty.

    Note: This algorithm MUST only be used for compatibility with
    legacy systems.

            key = MD5(username ":" OpaqueString(realm)
                ":" OpaqueString(password))

#### 18.5.1.2.  SHA-256

This password algorithm is taken from [RFC7616].

The key length is 32 bytes, and the parameters value is empty.

            key = SHA-256(username ":" OpaqueString(realm)
            ":" OpaqueString(password))

## 18.6.  STUN UDP and TCP Port Numbers

IANA has updated the reference from RFC 5389 to RFC 8489 for the
following ports in the "Service Name and Transport Protocol Port
Number Registry".

stun   3478/tcp   Session Traversal Utilities for NAT (STUN) port
stun   3478/udp   Session Traversal Utilities for NAT (STUN) port
stuns  5349/tcp   Session Traversal Utilities for NAT (STUN) port
