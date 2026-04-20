# 1. Introduction

# 1.1. Background
When the SDP offer/answer mechanism [RFC3264] is used to negotiate the establishment of multimedia communication sessions, if separate transports (5-tuples) are negotiated for each individual media stream, each transport consumes additional resources (especially when Interactive Connectivity Establishment (ICE) [RFC8445] is used). For this reason, it is attractive to use a single transport for multiple media streams.

# 1.2. BUNDLE Mechanism
This specification defines a way to use a single transport (BUNDLE transport) for sending and receiving media (bundled media) described by multiple SDP media descriptions ("m=" sections). The address:port combination used by an endpoint for sending and receiving bundled media is referred to as the "BUNDLE address:port". The set of SDP attributes that are applied to each "m=" section within a BUNDLE group is referred to as "BUNDLE attributes". The same BUNDLE transport is used for sending and receiving bundled media, which means that the symmetric Real-time Transport Protocol (RTP) mechanism [RFC4961] is always used for RTP-based bundled media.

This specification defines a new SDP Grouping Framework [RFC5888] extension called 'BUNDLE'. The extension can be used with the Session Description Protocol (SDP) offer/answer mechanism [RFC3264] to negotiate which "m=" sections will become part of a BUNDLE group. In addition, the offerer and answerer [RFC3264] use the BUNDLE extension to negotiate the BUNDLE addresses:ports (offerer BUNDLE address:port and answerer BUNDLE address:port) and the set of BUNDLE attributes (offerer BUNDLE attributes and answerer BUNDLE attributes) that will be applied to each "m=" section within the BUNDLE group.

The use of a BUNDLE transport allows the usage of a single set of ICE candidates [RFC8445] for the whole BUNDLE group.

A given BUNDLE address:port MUST only be associated with a single BUNDLE group. If an SDP offer or SDP answer (hereafter referred to as "offer" and "answer") contains multiple BUNDLE groups, the procedures in this specification apply to each group independently. All RTP-based bundled media associated with a given BUNDLE group belong to a single RTP session [RFC3550].

The BUNDLE extension is backward compatible. Endpoints that do not support the extension are expected to generate offers and answers without an SDP 'group:BUNDLE' attribute and assign a unique address:port to each "m=" section within an offer and answer, according to the procedures in [RFC3264] and [RFC4566].

# 1.3. Protocol Extensions
In addition to defining the new SDP Grouping Framework extension, this specification defines the following protocol extensions and makes the following updates to RFCs. This specification:

defines a new SDP attribute, 'bundle-only', which can be used to request that a specific "m=" section (and the associated media) be used only if kept within a BUNDLE group.
updates RFC 3264 [RFC3264] to also allow assigning a zero port value to an "m=" section in cases where the media described by the "m=" section is not disabled or rejected.
defines a new RTCP [RFC3550] SDES item, Media Identification ('MID'), and a new RTP SDES header extension that can be used to associate RTP streams with "m=" sections.
updates [RFC7941] by adding an exception, for the MID RTP header extension, to the requirement regarding protection of an SDES RTP header extension carrying an SDES item for the MID RTP header extension.
updates [RFC5888] by allowing an SDP 'group' attribute to contain an identification-tag that identifies an "m=" section with the port value set to zero.
1.4. Changes from RFC 8843
When [RFC8843] and [RFC8829] were published, an inconsistency between the specifications was identified. The procedures regarding assigning the port value to a bundled "m=" section in an answer (initial or subsequent) and a subsequent offer were inconsistent. This specification removes the inconsistency by aligning the port value assignment procedure with the procedure in [RFC8829].

In addition, this document implements changes from the following errata reports: [Err6431], [Err6437].

