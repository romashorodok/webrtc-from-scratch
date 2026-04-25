## 8.  Session Description for RTP/SAVP over DTLS

This specification defines new tokens to describe the protocol used
in SDP media descriptions ("m=" lines and their associated
parameters).  The new values defined for the proto field are:

o  When a RTP/SAVP or RTP/SAVPF [RFC5124] stream is transported over
    DTLS with the Datagram Congestion Control Protocol (DCCP), then
    the token SHALL be DCCP/TLS/RTP/SAVP or DCCP/TLS/RTP/SAVPF
    respectively.

o  When a RTP/SAVP or RTP/SAVPF stream is transported over DTLS with
    UDP, the token SHALL be UDP/TLS/RTP/SAVP or UDP/TLS/RTP/SAVPF
    respectively.

The "fmt" parameter SHALL be as defined for RTP/SAVP.

See [RFC5763] for how to use offer/answer with DTLS-SRTP.

This document does not specify how to protect RTP data transported
over TCP.  Potential approaches include carrying the RTP over TLS
over TCP (see [SRTP-NOT-MAND]) or using a mechanism similar to that
in this document over TCP, either via TLS or DTLS, with DTLS being
used for consistency between reliable and unreliable transports.  In the latter case, it would be necessary to profile DTLS so that
fragmentation and retransmissions no longer occurred.  In either
case, a new document would be required.

