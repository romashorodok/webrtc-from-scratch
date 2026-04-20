10. ICE Considerations
This section describes how to use the BUNDLE grouping extension together with the ICE mechanism [RFC8445].

The generic procedures for negotiating the usage of ICE using SDP, defined in [RFC8839], also apply to the usage of ICE with BUNDLE, with the following exceptions:

When the BUNDLE transport has been established, ICE connectivity checks and keepalives only need to be performed for the BUNDLE transport, instead of per individual bundled "m=" section within the BUNDLE group.
The generic SDP attribute offer/answer considerations (Section 7.1.3) also apply to ICE-related attributes. Therefore, when an offerer sends an initial BUNDLE offer (in order to negotiate a BUNDLE group), the offerer includes ICE-related media-level attributes in each bundled "m=" section (excluding any bundle-only "m=" sections), and each "m=" section MUST contain unique ICE properties. When an answerer generates an answer (initial BUNDLE answer or subsequent) that contains a BUNDLE group and when an offerer sends a subsequent offer that contains a BUNDLE group, ICE-related media-level attributes are only included in the tagged "m=" section (suggested offerer-tagged "m=" section or answerer-tagged "m=" section), and the ICE properties are applied to each bundled "m=" section within the BUNDLE group.
NOTE: Most ICE-related media-level SDP attributes belong to the TRANSPORT multiplexing category [RFC8859], and the generic SDP attribute offer/answer considerations for the TRANSPORT multiplexing category apply to the attributes. However, in the case of ICE-related attributes, the same considerations also apply to ICE-related media-level attributes that belong to other multiplexing categories.

NOTE: The following ICE-related media-level SDP attributes are defined in [RFC8839]: 'candidate', 'remote-candidates', 'ice-mismatch', 'ice-ufrag', 'ice-pwd', and 'ice-pacing'.

Initially, before ICE has produced selected candidate pairs that will be used for media, there might be multiple transports established (if multiple candidate pairs are tested). Once ICE has selected candidate pairs, they form the BUNDLE transport.

Support and usage of the ICE mechanism together with the BUNDLE extension is OPTIONAL, and the procedures in this section only apply when the ICE mechanism is used. Note that applications might mandate usage of the ICE mechanism even if the BUNDLE extension is not used.

NOTE: If the Trickle ICE mechanism [RFC8840] is used, an offerer and answerer might assign a port value of '9' and an IPv4 address of '0.0.0.0' (or, the IPv6 equivalent '::') to multiple bundled "m=" sections in the initial BUNDLE offer. The offerer and answerer will follow the normal procedures for generating the offers and answers, including picking a bundled "m=" section as the suggested offerer-tagged "m=" section, selecting the tagged "m=" sections, etc. The only difference is that media cannot be sent until one or more candidates have been provided. Once a BUNDLE group has been negotiated, trickled candidates associated with a bundled "m=" section will be applied to all bundled "m=" sections within the BUNDLE group.

11. DTLS Considerations
One or more media streams within a BUNDLE group might use the DTLS protocol [RFC6347] in order to encrypt the data or negotiate encryption keys if another encryption mechanism is used to encrypt media.

When DTLS is used within a BUNDLE group, the following rules apply:

There can only be one DTLS association [RFC6347] associated with the BUNDLE group;
Each usage of the DTLS association within the BUNDLE group MUST use the same mechanism for determining which endpoints (the offerer or answerer) become DTLS client and DTLS server;
Each usage of the DTLS association within the BUNDLE group MUST use the same mechanism for determining whether an offer or answer will trigger the establishment of a new DTLS association or if an existing DTLS association will be used instead; and
If the DTLS client supports DTLS-SRTP, it MUST include the 'use_srtp' extension in the DTLS ClientHello message [RFC5764]. The client MUST include the extension even if the usage of DTLS-SRTP is not negotiated as part of the multimedia session (e.g., the SIP session [RFC3261]).
NOTE: The inclusion of the 'use_srtp' extension during the initial DTLS handshake ensures that a DTLS renegotiation will not be required in order to include the extension in case DTLS-SRTP encrypted media is added to the BUNDLE group later during the multimedia session.

12. RTP Header Extensions Consideration
When RTP header extensions [RFC8285] are used in the context of this specification, the identifier used for a given extension MUST identify the same extension across all the bundled media descriptions.

13. Updates to RFC 3264
This section updates [RFC3264] in order to allow extensions to define the usage of a zero port value in offers and answers for purposes other than removing or disabling media streams. The following sections are being updated:

"Unicast Streams"; see Section 5.1 of [RFC3264].
"Putting a Unicast Media Stream on Hold"; see Section 8.4 of [RFC3264].
13.1. Original Text from RFC 3264, Section 5.1, Paragraph 2
For recvonly and sendrecv streams, the port number and address in the offer indicate where the offerer would like to receive the media stream. For sendonly RTP streams, the address and port number indirectly indicate where the offerer wants to receive RTCP reports. Unless there is an explicit indication otherwise, reports are sent to the port number one higher than the number indicated. The IP address and port present in the offer indicate nothing about the source IP address and source port of RTP and RTCP packets that will be sent by the offerer. A port number of zero in the offer indicates that the stream is offered but MUST NOT be used. This has no useful semantics in an initial offer, but is allowed for reasons of completeness, since the answer can contain a zero port indicating a rejected stream (Section 6). Furthermore, existing streams can be terminated by setting the port to zero (Section 8). In general, a port number of zero indicates that the media stream is not wanted.
13.2. New Text Replacing RFC 3264, Section 5.1, Paragraph 2
For recvonly and sendrecv streams, the port number and address in the offer indicate where the offerer would like to receive the media stream. For sendonly RTP streams, the address and port number indirectly indicate where the offerer wants to receive RTCP reports. Unless there is an explicit indication otherwise, reports are sent to the port number one higher than the number indicated. The IP address and port present in the offer indicate nothing about the source IP address and source port of the RTP and RTCP packets that will be sent by the offerer. By default, a port number of zero in the offer indicates that the stream is offered but MUST NOT be used, but an extension mechanism might specify different semantics for the usage of a zero port value. Furthermore, existing streams can be terminated by setting the port to zero (Section 8). In general, a port number of zero by default indicates that the media stream is not wanted.

13.3. Original Text from RFC 3264, Section 8.4, Paragraph 6
RFC 2543 [10] specified that placing a user on hold was accomplished by setting the connection address to 0.0.0.0. Its usage for putting a call on hold is no longer recommended, since it doesn't allow for RTCP to be used with held streams, doesn't work with IPv6, and breaks with connection oriented media. However, it can be useful in an initial offer when the offerer knows it wants to use a particular set of media streams and formats, but doesn't know the addresses and ports at the time of the offer. Of course, when used, the port number MUST NOT be zero, which would specify that the stream has been disabled. An agent MUST be capable of receiving SDP with a connection address of 0.0.0.0, in which case it means that neither RTP nor RTCP should be sent to the peer.
13.4. New Text Replacing RFC 3264, Section 8.4, Paragraph 6
RFC 2543 [RFC2543] specifies that placing a user on hold was accomplished by setting the connection address to 0.0.0.0. Its usage for putting a call on hold is no longer recommended, since it doesn't allow for RTCP to be used with held streams, doesn't work with IPv6, and breaks with connection oriented media. However, it can be useful in an initial offer when the offerer knows it wants to use a particular set of media streams and formats, but doesn't know the addresses and ports at the time of the offer. Of course, when used, the port number MUST NOT be zero, if it would specify that the stream has been disabled. However, an extension mechanism might specify different semantics of the zero port number usage. An agent MUST be capable of receiving SDP with a connection address of 0.0.0.0, in which case it means that neither RTP nor RTCP is to be sent to the peer.

14. Update to RFC 5888
This section updates RFC 5888 [RFC5888] in order for extensions to allow an SDP 'group' attribute containing an identification-tag that identifies an "m=" section with the port set to zero. "Group Value in Answers" (Section 9.2 of [RFC5888]) is updated.

14.1. Original Text from RFC 5888, Section 9.2, Paragraph 3
SIP entities refuse media streams by setting the port to zero in the corresponding "m" line. "a=group" lines MUST NOT contain identification-tags that correspond to "m" lines with the port set to zero.
14.2. New Text Replacing RFC 5888, Section 9.2, Paragraph 3
SIP entities refuse media streams by setting the port to zero in the corresponding "m" line. "a=group" lines MUST NOT contain identification-tags that correspond to "m" lines with the port set to zero, but an extension mechanism might specify different semantics for including identification-tags that correspond to such "m=" lines.

15. RTP/RTCP Extensions for identification-tag Transport
Offerers and answerers [RFC3264] can associate identification-tags with "m=" sections within offers and answers using the procedures in [RFC5888]. Each identification-tag uniquely represents an "m=" section.

This section defines a new RTCP SDES item [RFC3550], 'MID', which is used to carry identification-tags within RTCP SDES packets. This section also defines a new RTP SDES header extension [RFC7941], which is used to carry the 'MID' RTCP SDES item in RTP packets.

The SDES item and RTP SDES header extension make it possible for a receiver to associate each RTP stream with a specific "m=" section with which the receiver has associated an identification-tag, even if those "m=" sections are part of the same RTP session. The RTP SDES header extension also ensures that the media recipient gets the identification-tag upon receipt of the first decodable media and is able to associate the media with the correct application.

A media recipient informs the media sender about the identification-tag associated with an "m=" section through the use of a 'mid' attribute [RFC5888]. The media sender then inserts the identification-tag in RTCP and RTP packets sent to the media recipient.

NOTE: The text above defines how identification-tags are carried in offers and answers. The usage of other signaling protocols for carrying identification-tags is not prevented, but the usage of such protocols is outside the scope of this document.

[RFC3550] defines general procedures regarding the RTCP transmission interval. The RTCP MID SDES item SHOULD be sent in the first few RTCP packets after joining the session and SHOULD be sent regularly thereafter. The exact number of RTCP packets in which this SDES item is sent is intentionally not specified here, as it will depend on the expected packet-loss rate, the RTCP reporting interval, and the allowable overhead.

The RTP SDES header extension for carrying the 'MID' RTCP SDES SHOULD be included in some RTP packets at the start of the session and whenever the SSRC changes. It might also be useful to include the header extension in RTP packets that comprise access points in the media (e.g., with video I-frames). The exact number of RTP packets in which this header extension is sent is intentionally not specified here, as it will depend on expected packet-loss rate and loss patterns, the overhead the application can tolerate, and the importance of immediate receipt of the identification-tag.

For robustness, endpoints need to be prepared for situations where the reception of the identification-tag is delayed and SHOULD NOT terminate sessions in such cases, as the identification-tag is likely to arrive soon.

15.1. RTCP MID SDES Item
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      MID=15   |     length    | identification-tag          ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
The identification-tag payload is UTF-8 encoded [RFC3629], as in SDP.

The identification-tag is not zero terminated.

15.2. RTP SDES Header Extension for MID
The payload, containing the identification-tag, of the RTP SDES header extension element can be encoded using either the 1-byte or the 2-byte header [RFC7941]. The identification-tag payload is UTF-8 encoded, as in SDP.

The identification-tag is not zero terminated. Note that the set of header extensions included in the packet needs to be padded to the next 32-bit boundary using zero bytes [RFC8285].

As the identification-tag is included in an RTCP SDES item, an RTP SDES header extension, or both, there needs to be some consideration about the packet expansion caused by the identification-tag. To avoid Maximum Transmission Unit (MTU) issues for the RTP packets, the header extension's size needs to be taken into account when encoding the media.

It is recommended that the identification-tag be kept short. Due to the properties of the RTP header extension mechanism, when using the 1-byte header, a tag that is 1-3 bytes will result in a minimal number of 32-bit words used for the RTP SDES header extension, in case no other header extensions are included at the same time. Note: do take into account that some single characters when UTF-8 encoded will result in multiple octets. The identification-tag MUST NOT contain any user information, and applications SHALL avoid generating the identification-tag using a pattern that enables user or application identification.

16. IANA Considerations
NOTE: Apart from the references, the IANA considerations in this section are identical to those in [RFC8843].

16.1. SDES Item
This document updates the MID SDES entry in the "RTP SDES Item Types" registry as follows:

Value:
15
Abbrev.:
MID
Name:
Media Identification
Reference:
RFC 9143
16.2. RTP SDES Header Extension URI
This document updates the extension URI in the "RTP SDES Compact Header Extensions" subregistry of the "RTP Compact Header Extensions" sub-registry, according to the following data:

Extension URI:
urn:ietf:params:rtp-hdrext:sdes:mid
Description:
Media identification
Contact:
IESG (iesg@ietf.org)
Reference:
RFC 9143
The SDES item does not reveal privacy information about the users. It is simply used to associate RTP-based media with the correct SDP media description ("m=" section) in the SDP used to negotiate the media.

The purpose of the extension is for the offerer to be able to associate received multiplexed RTP-based media before the offerer receives the associated answer.

16.3. SDP Attribute
This document updates the SDP media-level attribute, 'bundle-only', in the "attribute-name (formerly 'att-field')" subregistry of the "Session Description Protocol (SDP) Parameters" registry according to the following data:

Attribute name:
bundle-only
Type of attribute:
media
Subject to charset:
No
Purpose:
Request a media description to be accepted in the answer only if kept within a BUNDLE group by the answerer.
Appropriate values:
N/A
Contact name:
IESG
Contact e-mail:
iesg@ietf.org
Reference:
RFC 9143
Mux category:
NORMAL
16.4. SDP Group Semantics
This document updates the following semantics in the "Semantics for the 'group' SDP Attribute" subregistry (under the "Session Description Protocol (SDP) Parameters" registry):

Table 1: Update to SDP Group Semantics
Semantics	Token	Mux Category	Reference
Media bundling	BUNDLE	NORMAL	RFC 9143
17. Security Considerations
The security considerations defined in [RFC3264] and [RFC5888] apply to the BUNDLE extension. BUNDLE does not change which information, e.g., RTP streams, flows over the network, except for the usage of the MID SDES item as discussed below. Primarily, it changes which addresses and ports, and thus in which (RTP) sessions, the information flows to. This affects the security contexts being used and can cause previously separated information flows to share the same security context. This has very little impact on the performance of the security mechanism of the RTP sessions. In cases where one would have applied different security policies on the different RTP streams being bundled or where the parties having access to the security contexts would have differed between the RTP streams, additional analysis of the implications is needed before selecting to apply BUNDLE.

The identification-tag, independent of transport, RTCP SDES packet, or RTP header extension, can expose the value to parties beyond the signaling chain. Therefore, the identification-tag values MUST be generated in a fashion that does not leak user information, e.g., randomly or using a per-bundle group counter, and SHOULD be 3 bytes or fewer to allow them to efficiently fit into the MID RTP header extension. Note that if implementations use different methods for generating identification-tags, this could enable fingerprinting of the implementation, making it vulnerable to targeted attacks. The identification-tag is exposed on the RTP stream level when included in the RTP header extensions; however, what it reveals of the RTP media stream structure of the endpoint and application was already possible to deduce from the RTP streams without the MID SDES header extensions. As the identification-tag is also used to route the media stream to the right application functionality, it is important that the value received is the one intended by the sender; thus, integrity and the authenticity of the source are important to prevent denial of service on the application. Existing SRTP configurations and other security mechanisms protecting the whole RTP/RTCP packets will provide the necessary protection.

When the BUNDLE extension is used, the set of configurations of the security mechanism used in all the bundled media descriptions will need to be compatible so that they can be used simultaneously, at least per direction or endpoint. When using SRTP, this will be the case, at least for the IETF-defined key-management solutions due to their SDP attributes ("a=crypto", "a=fingerprint", "a=mikey") and their classification in [RFC8859].

The security considerations of "RTP Header Extension for the RTP Control Protocol (RTCP) Source Description Items" [RFC7941] require that when RTCP is confidentiality protected, any SDES RTP header extension carrying an SDES item, such as the MID RTP header extension, is also protected using commensurate strength algorithms. However, assuming the above requirements and recommendations are followed, there are no known significant security risks with leaving the MID RTP header extension without confidentiality protection. Therefore, this specification updates [RFC7941] by adding the exception that this requirement MAY be ignored for the MID RTP header extension. Security mechanisms for RTP/RTCP are discussed in "Options for Securing RTP Sessions" [RFC7201]; for example, SRTP [RFC3711] can provide the necessary security functions of ensuring the integrity and source authenticity.

18. Examples
18.1. Example: Tagged "m=" Section Selections
The example below shows:

An initial BUNDLE offer, in which the offerer wants to negotiate a BUNDLE group and indicates the audio "m=" section as the suggested offerer-tagged "m=" section.
An initial BUNDLE answer, in which the answerer accepts the creation of the BUNDLE group, selects the audio "m=" section in the offer as the offerer-tagged "m=" section, selects the audio "m=" section in the answer as the answerer-tagged "m=" section, and assigns the answerer BUNDLE address:port to that "m=" section.
SDP Offer (1)

    v=0
    o=alice 2890844526 2890844526 IN IP6 2001:db8::3
    s=
    c=IN IP6 2001:db8::3
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 10000 RTP/AVP 0 8 97
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:97 iLBC/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10002 RTP/AVP 31 32
    b=AS:1000
    a=mid:bar
    a=rtcp-mux
    a=rtpmap:31 H261/90000
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
SDP Answer (2)

    v=0
    o=bob 2808844564 2808844564 IN IP6 2001:db8::1
    s=
    c=IN IP6 2001:db8::1
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 20000 RTP/AVP 0
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 20000 RTP/AVP 32
    b=AS:1000
    a=mid:bar
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
18.2. Example: BUNDLE Group Rejected
The example below shows:

An initial BUNDLE offer, in which the offerer wants to negotiate a BUNDLE group and indicates the audio "m=" section as the suggested offerer-tagged "m=" section.
An initial BUNDLE answer, in which the answerer rejects the creation of the BUNDLE group, generates a normal answer, and assigns a unique address:port to each "m=" section in the answer.
SDP Offer (1)

    v=0
    o=alice 2890844526 2890844526 IN IP6 2001:db8::3
    s=
    c=IN IP6 2001:db8::3
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 10000 RTP/AVP 0 8 97
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:97 iLBC/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10002 RTP/AVP 31 32
    b=AS:1000
    a=mid:bar
    a=rtcp-mux
    a=rtpmap:31 H261/90000
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
SDP Answer (2)

    v=0
    o=bob 2808844564 2808844564 IN IP6 2001:db8::1
    s=
    c=IN IP6 2001:db8::1
    t=0 0

    m=audio 20000 RTP/AVP 0
    b=AS:200
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000

    m=video 30000 RTP/AVP 32
    b=AS:1000
    a=rtcp-mux
    a=rtpmap:32 MPV/90000
18.3. Example: Offerer Adds a Media Description to a BUNDLE Group
The example below shows:

A subsequent offer, in which the offerer adds a new bundled "m=" section (video), indicated by the "zen" identification-tag, to a previously negotiated BUNDLE group; indicates the new "m=" section as the offerer-tagged "m=" section; and assigns the offerer BUNDLE address:port to that "m=" section.
A subsequent answer, in which the answerer indicates the new video "m=" section in the answer as the answerer-tagged "m=" section and assigns the answerer BUNDLE address:port to that "m=" section.
SDP Offer (1)

    v=0
    o=alice 2890844526 2890844526 IN IP6 2001:db8::3
    s=
    c=IN IP6 2001:db8::3
    t=0 0
    a=group:BUNDLE zen foo bar

    m=audio 10000 RTP/AVP 0 8 97
    b=AS:200
    a=mid:foo
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:97 iLBC/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10000 RTP/AVP 31 32
    b=AS:1000
    a=mid:bar
    a=rtpmap:31 H261/90000
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10000 RTP/AVP 66
    b=AS:1000
    a=mid:zen
    a=rtcp-mux
    a=rtpmap:66 H261/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
SDP Answer (2)

    v=0
    o=bob 2808844564 2808844564 IN IP6 2001:db8::1
    s=
    c=IN IP6 2001:db8::1
    t=0 0
    a=group:BUNDLE zen foo bar

    m=audio 20000 RTP/AVP 0
    b=AS:200
    a=mid:foo
    a=rtpmap:0 PCMU/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 20000 RTP/AVP 32
    b=AS:1000
    a=mid:bar
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 20000 RTP/AVP 66
    b=AS:1000
    a=mid:zen
    a=rtcp-mux
    a=rtpmap:66 H261/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
18.4. Example: Offerer Moves a Media Description Out of a BUNDLE Group
The example below shows:

A subsequent offer, in which the offerer removes an "m=" section (video), indicated by the "zen" identification-tag, from a previously negotiated BUNDLE group; indicates one of the bundled "m=" sections (audio) remaining in the BUNDLE group as the offerer-tagged "m=" section; and assigns the offerer BUNDLE address:port to that "m=" section.
A subsequent answer, in which the answerer removes the "m=" section from the BUNDLE group, indicates the audio "m=" section in the answer as the answerer-tagged "m=" section, and assigns the answerer BUNDLE address:port to that "m=" section.
SDP Offer (1)

    v=0
    o=alice 2890844526 2890844526 IN IP6 2001:db8::3
    s=
    c=IN IP6 2001:db8::3
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 10000 RTP/AVP 0 8 97
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:97 iLBC/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10000 RTP/AVP 31 32
    b=AS:1000
    a=mid:bar
    a=rtpmap:31 H261/90000
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 50000 RTP/AVP 66
    b=AS:1000
    a=mid:zen
    a=rtcp-mux
    a=rtpmap:66 H261/90000
SDP Answer (2)

    v=0
    o=bob 2808844564 2808844564 IN IP6 2001:db8::1
    s=
    c=IN IP6 2001:db8::1
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 20000 RTP/AVP 0
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 20000 RTP/AVP 32
    b=AS:1000
    a=mid:bar
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 60000 RTP/AVP 66
    b=AS:1000
    a=mid:zen
    a=rtcp-mux
    a=rtpmap:66 H261/90000
18.5. Example: Offerer Disables a Media Description within a BUNDLE Group
The example below shows:

A subsequent offer, in which the offerer disables (by assigning a zero port value) an "m=" section (video), indicated by the "zen" identification-tag, from a previously negotiated BUNDLE group; indicates one of the bundled "m=" sections (audio) remaining active in the BUNDLE group as the offerer-tagged "m=" section; and assigns the offerer BUNDLE address:port to that "m=" section.
A subsequent answer, in which the answerer disables the "m=" section, indicates the audio "m=" section in the answer as the answerer-tagged "m=" section, and assigns the answerer BUNDLE address:port to that "m=" section.
SDP Offer (1)

    v=0
    o=alice 2890844526 2890844526 IN IP6 2001:db8::3
    s=
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 10000 RTP/AVP 0 8 97
    c=IN IP6 2001:db8::3
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=rtpmap:8 PCMA/8000
    a=rtpmap:97 iLBC/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 10000 RTP/AVP 31 32
    c=IN IP6 2001:db8::3
    b=AS:1000
    a=mid:bar
    a=rtpmap:31 H261/90000
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 0 RTP/AVP 66
    a=mid:zen
    a=rtpmap:66 H261/90000
SDP Answer (2)

    v=0
    o=bob 2808844564 2808844564 IN IP6 2001:db8::1
    s=
    t=0 0
    a=group:BUNDLE foo bar

    m=audio 20000 RTP/AVP 0
    c=IN IP6 2001:db8::1
    b=AS:200
    a=mid:foo
    a=rtcp-mux
    a=rtpmap:0 PCMU/8000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 20000 RTP/AVP 32
    c=IN IP6 2001:db8::1
    b=AS:1000
    a=mid:bar
    a=rtpmap:32 MPV/90000
    a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid

    m=video 0 RTP/AVP 66
    a=mid:zen
    a=rtpmap:66 H261/90000