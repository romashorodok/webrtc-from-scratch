# 10.  ICE Option

This section defines a new ICE option, 'ice2'.  When an ICE agent
includes 'ice2' in a candidate exchange, the ICE option indicates
that it is compliant to this specification.  For example, the agent
will not use the aggressive nomination procedure defined in RFC 5245.
In addition, it will ensure that a peer compliant with RFC 5245 does
not use aggressive nomination either, as required by Section 14 of
RFC 5245 for peers that receive unknown ICE options.

An agent compliant to this specification MUST inform the peer about
the compliance using the 'ice2' option.

NOTE: The encoding of the 'ice2' option, and the message(s) used to
carry it to the peer, are protocol specific.  The encoding for SDP
[RFC4566] is defined in [ICE-SIP-SDP].
