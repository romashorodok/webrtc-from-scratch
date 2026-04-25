## 3.  ICE Usage

This document specifies generic use of ICE with protocols that
provide means to exchange candidate information between ICE agents.
The specific details (i.e., how to encode candidate information and
the actual candidate exchange process) for different protocols using
ICE (referred to as "using protocol") are described in separate usage
documents.

One mechanism that allows agents to exchange candidate information is
the utilization of Offer/Answer semantics (which are based on
[RFC3264]) as part of the SIP protocol [RFC3261] [ICE-SIP-SDP].

[RFC7825] defines an ICE usage for the Real-Time Streaming Protocol
(RTSP).  Note, however, that the ICE usage is based on RFC 5245.

