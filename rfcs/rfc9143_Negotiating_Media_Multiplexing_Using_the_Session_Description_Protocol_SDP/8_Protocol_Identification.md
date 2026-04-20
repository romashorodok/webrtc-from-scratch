8. Protocol Identification
Each "m=" section within a BUNDLE group MUST use the same transport- layer protocol. If bundled "m=" sections use different upper-layer protocols on top of the transport-layer protocol, there MUST exist a publicly available specification that describes how a mechanism associates received data with the correct protocol for this particular protocol combination.

In addition, if received data can be associated with more than one bundled "m=" section, there MUST exist a publicly available specification that describes a mechanism for associating the received data with the correct "m=" section.

This document describes a mechanism to identify the protocol of received data among the Session Traversal Utilities for NAT (STUN), Datagram Transport Layer Security (DTLS), and the Secure Real-time Transport Protocol (SRTP) (in any combination) when UDP is used as a transport-layer protocol, but it does not describe how to identify different protocols transported on DTLS. While the mechanism is generally applicable to other protocols and transport-layer protocols, any such use requires further specification that encompasses how to multiplex multiple protocols on a given transport-layer protocol and how to associate received data with the correct protocols.

8.1. STUN, DTLS, and SRTP
Section 5.1.2 of [RFC5764] describes a mechanism to identify the protocol of a received packet among the STUN, DTLS, and SRTP protocols (in any combination). If an offer or answer includes a bundled "m=" section that represents these protocols, the offerer or answerer MUST support the mechanism described in [RFC5764], and no explicit negotiation is required in order to indicate support and usage of the mechanism.

[RFC5764] does not describe how to identify different protocols transported on DTLS, only how to identify the DTLS protocol itself. If multiple protocols are transported on DTLS, there MUST exist a specification describing a mechanism for identifying each individual protocol. In addition, if a received DTLS packet can be associated with more than one "m=" section, there MUST exist a specification that describes a mechanism for associating the received DTLS packets with the correct "m=" section.

Section 9.2 describes how to associate the packets in a received SRTP stream with the correct "m=" section.

9. RTP Considerations
9.1. Single RTP Session
All RTP-based media within a single BUNDLE group belong to a single RTP session [RFC3550].

Since a single BUNDLE transport is used for sending and receiving bundled media, the symmetric RTP mechanism [RFC4961] MUST be used for RTP-based bundled media.

Since a single RTP session is used for each BUNDLE group, all "m=" sections representing RTP-based media within a BUNDLE group will share a single synchronization source (SSRC) numbering space [RFC3550].

The following rules and restrictions apply for a single RTP session:

A specific payload type value can be used in multiple bundled "m=" sections only if each codec associated with the payload type number shares an identical codec configuration (Section 9.1.1).
The proto value in each bundled RTP-based "m=" section MUST be identical (e.g., RTP/AVPF).
The RTP MID header extension MUST be enabled by including an SDP 'extmap' attribute [RFC8285], with a 'urn:ietf:params:rtp- hdrext:sdes:mid' URI value defined in this specification in each bundled RTP-based "m=" section in every offer and answer.
A given SSRC MUST NOT transmit RTP packets using payload types that originate from different bundled "m=" sections.
NOTE: The last bullet above is to avoid sending multiple media types from the same SSRC. If transmission of multiple media types is done with time overlap, RTP and RTCP fail to function. Even if done in the proper sequence, this causes RTP timestamp rate switching issues [RFC7160]. However, once an SSRC has left the RTP session (by sending an RTCP BYE packet), that SSRC can be reused by another source (possibly associated with a different bundled "m=" section) after a delay of 5 RTCP reporting intervals (the delay is to ensure the SSRC has timed out in case the RTCP BYE packet was lost [RFC3550]).

[RFC7657] defines Differentiated Services (Diffserv) considerations for RTP-based bundled media sent using a mixture of Diffserv Codepoints.

9.1.1. Payload Type (PT) Value Reuse
Multiple bundled "m=" sections might describe RTP-based media. As all RTP-based media associated with a BUNDLE group belong to the same RTP session, in order for a given payload type value to be used inside more than one bundled "m=" section, all codecs associated with the payload type number MUST share an identical codec configuration. This means that the codecs MUST share the same media type, encoding name, clock rate, and any parameter that can affect the codec configuration and packetization. [RFC8859] lists SDP attributes whose attribute values are required to be identical for all codecs that use the same payload type value.

9.2. Associating RTP/RTCP Streams with the Correct SDP Media Description
As described in [RFC3550], RTP packets are associated with RTP streams [RFC7656]. Each RTP stream is identified by an SSRC value, and each RTP packet includes an SSRC field that is used to associate the packet with the correct RTP stream. RTCP packets also use SSRCs to identify which RTP streams the packet relates to. However, an RTCP packet can contain multiple SSRC fields in the course of providing feedback or reports on different RTP streams; therefore, they can be associated with multiple such streams.

In order to be able to process received RTP/RTCP packets correctly, it MUST be possible to associate an RTP stream with the correct "m=" section, as the "m=" section and SDP attributes associated with the "m=" section contain information needed to process the packets.

As all RTP streams associated with a BUNDLE group use the same transport for sending and receiving RTP/RTCP packets, the local address:port combination part of the transport cannot be used to associate an RTP stream with the correct "m=" section. In addition, multiple RTP streams might be associated with the same "m=" section.

An offerer and answerer can inform each other which SSRC values they will use for an RTP stream by using the SDP 'ssrc' attribute [RFC5576]. However, an offerer will not know which SSRC values the answerer will use until the offerer has received the answer providing that information. Due to this, before the offerer has received the answer, the offerer will not be able to associate an RTP stream with the correct "m=" section using the SSRC value associated with the RTP stream. In addition, the offerer and answerer may start using new SSRC values mid-session, without informing each other about using the SDP 'ssrc' attribute.

In order for an offerer and answerer to always be able to associate an RTP stream with the correct "m=" section, the offerer and answerer using the BUNDLE extension MUST support the mechanism defined in Section 15, where the offerer and answerer insert the identification-tag associated with an "m=" section (provided by the remote peer) into RTP and RTCP packets associated with a BUNDLE group.

When using this mechanism, the mapping from an SSRC to an identification-tag is carried in RTP header extensions or RTCP SDES packets, as specified in Section 15. Since a compound RTCP packet can contain multiple RTCP SDES packets and each RTCP SDES packet can contain multiple chunks, a single RTCP packet can contain several mappings of SSRC to identification-tag. The offerer and answerer maintain tables used for routing that are updated each time an RTP/RTCP packet contains new information that affects how packets are to be routed.

However, some legacy implementations may not include this identification-tag in their RTP and RTCP traffic when using the BUNDLE mechanism and instead use a mechanism based on the payload type to associate RTP streams with SDP "m=" sections. In this situation, each "m=" section needs to use unique payload type values in order for the payload type to be a reliable indicator of the relevant "m=" section for the RTP stream. If an implementation fails to ensure unique payload type values, it will be impossible to associate the RTP stream using that payload type value to a particular "m=" section. Note that when using the payload type to associate RTP streams with "m=" sections, an RTP stream, identified by its SSRC, will be mapped to an "m=" section when the first packet of that RTP stream is received, and the mapping will not be changed even if the payload type used by that RTP stream changes. In other words, the SSRC cannot "move" to a different "m=" section simply by changing the payload type.

Applications can implement RTP stacks in different ways. The algorithm below details one way that RTP streams can be associated with "m=" sections, but it is not meant to be prescriptive about exactly how an RTP stack needs to be implemented. Applications MAY use any algorithm that achieves equivalent results to those described in the algorithm below.

To prepare to associate RTP streams with the correct "m=" section, the following steps MUST be followed for each BUNDLE group:

Construct a table mapping a MID to an "m=" section for each "m=" section in this BUNDLE group. Note that an "m=" section may only have one MID.
Construct a table mapping SSRCs of incoming RTP streams to an "m=" section for each "m=" section in this BUNDLE group and for each SSRC configured for receiving in that "m=" section.
Construct a table mapping the SSRC of each outgoing RTP stream to an "m=" section for each "m=" section in this BUNDLE group and for each SSRC configured for sending in that "m=" section.
Construct a table mapping a payload type to an "m=" section for each "m=" section in the BUNDLE group and for each payload type configured for receiving in that "m=" section. If any payload type is configured for receiving in more than one "m=" section in the BUNDLE group, do not include it in the table, as it cannot be used to uniquely identify an "m=" section.
Note that for each of these tables, there can only be one mapping for any given key (MID, SSRC, or PT). In other words, the tables are not multimaps.
As "m=" sections are added or removed from the BUNDLE groups or their configurations are changed, the tables above MUST also be updated.

When an RTP packet is received, it MUST be delivered to the RTP stream corresponding to its SSRC. That RTP stream MUST then be associated with the correct "m=" section within a BUNDLE group for additional processing, according to the following steps:

If the MID associated with the RTP stream is not in the table mapping a MID to an "m=" section, then the RTP stream is not decoded, and the payload data is discarded.
If the packet has a MID and the packet's extended sequence number is greater than that of the last MID update, as discussed in [RFC7941], Section 4.2.6, update the MID associated with the RTP stream to match the MID carried in the RTP packet and then update the mapping tables to include an entry that maps the SSRC of that RTP stream to the "m=" section for that MID.
If the SSRC of the RTP stream is in the incoming SSRC mapping table, check that the payload type used by the RTP stream matches a payload type included in the matching "m=" section. If so, associate the RTP stream with that "m=" section. Otherwise, the RTP stream is not decoded, and the payload data is discarded.
If the payload type used by the RTP stream is in the payload type table, update the incoming SSRC mapping table to include an entry that maps the RTP stream's SSRC to the "m=" section for that payload type. Associate the RTP stream with the corresponding "m=" section.
Otherwise, mark the RTP stream as "not for decoding" and discard the payload.
If the RTP packet contains one or more contributing source (CSRC) identifiers, then each CSRC is looked up in the incoming SSRC table, and a copy of the RTP packet is associated with the corresponding "m=" section for additional processing.

For each RTCP packet received (including each RTCP packet that is part of a compound RTCP packet), the packet is processed as usual by the RTP layer, then associated with the appropriate "m=" sections and processed for the RTP streams represented by those "m=" sections. This routing is type dependent, as each kind of RTCP packet has its own mechanism for associating it with the relevant RTP streams.

RTCP packets that cannot be associated with an appropriate "m=" section MUST still be processed as usual by the RTP layer, which updates the metadata associated with the corresponding RTP streams. This situation can occur with certain multiparty RTP topologies or when RTCP packets are sent containing a subset of the SDES information.

Additional rules for processing various types of RTCP packets are explained below.

If the RTCP packet is of type SDES, for each chunk in the packet whose SSRC is found in the incoming SSRC table, deliver a copy of the SDES packet to the "m=" section associated with that SSRC. In addition, for any SDES MID items contained in these chunks, if the MID is found in the table mapping a MID to an "m=" section, update the incoming SSRC table to include an entry that maps the RTP stream associated with the chunk's SSRC to the "m=" section associated with that MID, unless the packet is older than the packet that most recently updated the mapping for this SSRC, as discussed in [RFC7941], Section 4.2.6.
Note that if an SDES packet is received as part of a compound RTCP packet, the SSRC to "m=" section mapping might not exist until the SDES packet is handled (e.g., in the case where RTCP for a source is received before any RTP packets). Therefore, it can be beneficial for an implementation to delay RTCP packet routing, such that it either prioritizes processing of the SDES item to generate or update the mapping or buffers the RTCP information that needs to be routed until the SDES item(s) has been processed. If the implementation is unable to follow this recommendation, the consequence could be that some RTCP information from this particular RTCP compound packet is not provided to higher layers. The impact from this is likely minor when this information relates to a future incoming RTP stream.
If the RTCP packet is of type BYE, it indicates that the RTP streams referenced in the packet are ending. Therefore, for each SSRC indicated in the packet that is found in the incoming SSRC table, first deliver a copy of the BYE packet to the "m=" section associated with that SSRC, and then remove the entry for that SSRC from the incoming SSRC table after an appropriate delay to account for "straggler packets", as specified in [RFC3550], Section 6.2.1.
If the RTCP packet is of type sender report (SR) or receiver report (RR), for each report block in the report whose "SSRC of source" is found in the outgoing SSRC table, deliver a copy of the SR or RR packet to the "m=" section associated with that SSRC. In addition, if the packet is of type SR and the sender SSRC for the packet is found in the incoming SSRC table, deliver a copy of the SR packet to the "m=" section associated with that SSRC.
If the implementation supports the RTCP Extended Report (XR) and the packet is of type XR, as defined in [RFC3611], for each report block in the report whose "SSRC of source" is found in the outgoing SSRC table, deliver a copy of the XR packet to the "m=" section associated with that SSRC. In addition, if the sender SSRC for the packet is found in the incoming SSRC table, deliver a copy of the XR packet to the "m=" section associated with that SSRC.
If the RTCP packet is a feedback message of type RTPFB (transport-layer FB message) or PSFB (payload-specific FB message), as defined in [RFC4585], it will contain a media source SSRC, and this SSRC is used for routing certain subtypes of feedback messages. However, several subtypes of PSFB and RTPFB messages include a target SSRC(s) in a section called Feedback Control Information (FCI). For these messages, the target SSRC(s) is used for routing.
If the RTCP packet is a feedback packet that does not include target SSRCs in its FCI section, and the media source SSRC is found in the outgoing SSRC table, deliver the feedback packet to the "m=" section associated with that SSRC. RTPFB and PSFB types that are handled in this way include:

Generic NACK:
(PT=RTPFB, FMT=1) [RFC4585]
Picture Loss Indication (PLI):
(PT=PSFB, FMT=1) [RFC4585]
Slice Loss Indication (SLI):
(PT=PSFB, FMT=2) [RFC4585]
Reference Picture Selection Indication (RPSI):
(PT=PSFB, FMT=3) [RFC4585]
If the RTCP packet is a feedback message that does include a target SSRC(s) in its FCI section, it can either be a request or a notification. Requests reference an RTP stream that is being sent by the message recipient, whereas notifications are responses to an earlier request and therefore reference an RTP stream that is being received by the message recipient.
If the RTCP packet is a feedback request that includes a target SSRC(s), for each target SSRC that is found in the outgoing SSRC table, deliver a copy of the RTCP packet to the "m=" section associated with that SSRC. PSFB and RTPFB types that are handled in this way include:

Full Intra Request (FIR):
(PT=PSFB, FMT=4) [RFC5104]
Temporal-Spatial Trade-off Request (TSTR):
(PT=PSFB, FMT=5) [RFC5104]
H.271 Video Back Channel Message (VBCM):
(PT=PSFB, FMT=7) [RFC5104]
Temporary Maximum Media Stream Bit Rate Request (TMMBR):
(PT=RTPFB, FMT=3) [RFC5104]
Layer Refresh Request (LRR):
(PT=PSFB, FMT=10) [LLR-RTCP].
If the RTCP packet is a feedback notification that includes a target SSRC(s), for each target SSRC that is found in the incoming SSRC table, deliver a copy of the RTCP packet to the "m=" section associated with the RTP stream with a matching SSRC. PSFB and RTPFB types that are handled in this way include:

Temporal-Spatial Trade-off Notification (TSTN):
(PT=PSFB, FMT=6) [RFC5104]. This message is a notification in response to a prior TSTR.
Temporary Maximum Media Stream Bit Rate Notification (TMMBN):
(PT=RTPFB, FMT=4) [RFC5104]. This message is a notification in response to a prior TMMBR, but it can also be sent unsolicited.
If the RTCP packet is of type APP, then it is handled in an application-specific manner. If the application does not recognize the APP packet, then it MUST be discarded.
9.3. RTP/RTCP Multiplexing
Within a BUNDLE group, the offerer and answerer MUST enable RTP/RTCP multiplexing [RFC5761] for the RTP-based bundled media (i.e., the same transport will be used for both RTP packets and RTCP packets). In addition, the offerer and answerer MUST support the SDP 'rtcp-mux-only' attribute [RFC8858].

9.3.1. SDP Offer/Answer Procedures
This section describes how an offerer and answerer use the SDP 'rtcp-mux' [RFC5761] and SDP 'rtcp-mux-only' attributes [RFC8858] to negotiate usage of RTP/RTCP multiplexing for RTP-based bundled media.

RTP/RTCP multiplexing only applies to RTP-based media. However, as described in Section 7.1.3, within an offer or answer, the SDP 'rtcp-mux' and SDP 'rtcp-mux-only' attributes might be included in a bundled "m=" section for non-RTP-based media (if such an "m=" section is the offerer-tagged "m=" section or answerer-tagged "m=" section).

9.3.1.1. Generating the Initial BUNDLE Offer
When an offerer generates an initial BUNDLE offer, if the offer contains one or more bundled "m=" sections for RTP-based media (or if there is a chance that "m=" sections for RTP-based media will later be added to the BUNDLE group), the offerer MUST include an SDP 'rtcp-mux' attribute [RFC5761] in each bundled "m=" section (excluding any bundle-only "m=" sections). In addition, the offerer MAY include an SDP 'rtcp-mux-only' attribute [RFC8858] in one or more bundled "m=" sections for RTP-based media.

NOTE: Whether the offerer includes the SDP 'rtcp-mux-only' attribute depends on whether the offerer supports fallback to usage of a separate port for RTCP in case the answerer moves one or more "m=" sections for RTP-based media out of the BUNDLE group in the answer.

NOTE: If the offerer includes an SDP 'rtcp-mux' attribute in the bundled "m=" sections but does not include an SDP 'rtcp-mux-only' attribute, the offerer can also include an SDP 'rtcp' attribute [RFC3605] in one or more RTP-based bundled "m=" sections in order to provide a fallback port for RTCP, as described in [RFC5761]. However, the fallback port will only be applied to "m=" sections for RTP-based media that are moved out of the BUNDLE group by the answerer.

In the initial BUNDLE offer, the address:port combination for RTCP MUST be unique in each bundled "m=" section for RTP-based media (excluding a bundle-only "m=" section), similar to RTP.

9.3.1.2. Generating the SDP Answer
When an answerer generates an answer, if the answerer supports RTP-based media and if a bundled "m=" section in the corresponding offer contained an SDP 'rtcp-mux' attribute, the answerer MUST enable usage of RTP/RTCP multiplexing, even if there currently are no bundled "m=" sections for RTP-based media within the BUNDLE group. The answerer MUST include an SDP 'rtcp-mux' attribute in the answerer-tagged "m=" section, following the procedures for BUNDLE attributes (Section 7.1.3). In addition, if the "m=" section that is selected as the offerer-tagged "m=" section contained an SDP 'rtcp-mux-only' attribute, the answerer MUST include an SDP 'rtcp-mux-only' attribute in the answerer-tagged "m=" section.

In an initial BUNDLE offer, if the suggested offerer-tagged "m=" section contained an SDP 'rtcp-mux-only' attribute, the "m=" section was for RTP-based media. If the answerer does not accept the "m=" section in the created BUNDLE group and moves the "m=" section out of the BUNDLE group (Section 7.3.2), the answerer MUST include the attribute in the moved "m=" section and enable RTP/RTCP multiplexing for the media associated with the "m=" section. If the answerer rejects the "m=" section (Section 7.3.3), the answerer MUST NOT include the attribute.

The answerer MUST NOT include an SDP 'rtcp' attribute in any bundled "m=" section in the answer. The answerer will use the port value of the offerer-tagged "m=" section sending RTP and RTCP packets associated with RTP-based bundled media towards the offerer.

If the usage of RTP/RTCP multiplexing within a BUNDLE group has been negotiated in a previous offer/answer exchange, the answerer MUST include an SDP 'rtcp-mux' attribute in the answerer-tagged "m=" section. It is not possible to disable RTP/RTCP multiplexing within a BUNDLE group.

9.3.1.3. Offerer Processing of the SDP Answer
When an offerer receives an answer, if the answerer has accepted the usage of RTP/RTCP multiplexing (Section 9.3.1.2), the answerer follows the procedures for RTP/RTCP multiplexing defined in [RFC5761]. The offerer will use the port value of the answerer-tagged "m=" section for sending RTP and RTCP packets associated with RTP-based bundled media towards the answerer.

NOTE: It is considered a protocol error if the answerer has not accepted the usage of RTP/RTCP multiplexing for RTP-based "m=" sections that the answerer included in the BUNDLE group.

9.3.1.4. Modifying the Session
When an offerer generates a subsequent offer, the offerer MUST include an SDP 'rtcp-mux' attribute in the offerer-tagged "m=" section, following the procedures for IDENTICAL multiplexing category attributes in Section 7.1.3.

