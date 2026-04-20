# 5. SDP Grouping Framework BUNDLE Extension
This section defines a new SDP Grouping Framework [RFC5888] extension, 'BUNDLE'. The BUNDLE extension can be used with the SDP offer/answer mechanism to negotiate a set of "m=" sections that will become part of a BUNDLE group. Within a BUNDLE group, each "m=" section uses a BUNDLE transport for sending and receiving bundled media. Each endpoint uses a single address:port combination for sending and receiving the bundled media.

The BUNDLE extension is indicated using an SDP 'group' attribute with a semantics value [RFC5888] of "BUNDLE". An identification-tag is assigned to each bundled "m=" section, and each identification-tag is listed in the SDP 'group:BUNDLE' attribute identification-tag list. Each "m=" section whose identification-tag is listed in the identification-tag list is associated with a given BUNDLE group.

SDP bodies can contain multiple BUNDLE groups. Any given bundled "m=" section MUST NOT be associated with more than one BUNDLE group at any given time.

NOTE: The order of the "m=" sections listed in the SDP 'group:BUNDLE' attribute identification-tag list does not have to be the same as the order in which the "m=" sections occur in the SDP.

The multiplexing category [RFC8859] for the 'group:BUNDLE' attribute is 'NORMAL'.

Section 7 defines the detailed SDP offer/answer procedures for the BUNDLE extension.

# 6. SDP 'bundle-only' Attribute
This section defines a new SDP media-level attribute [RFC4566], 'bundle-only'. 'bundle-only' is a property attribute [RFC4566]; hence, it has no value.

In order to ensure that an answerer that does not support the BUNDLE extension always rejects a bundled "m=" section in an offer, the offerer can assign a zero port value to the "m=" section. According to [RFC3264], an answerer will reject such an "m=" section. By including an SDP 'bundle-only' attribute in a bundled "m=" section, the offerer can request that the answerer accept the "m=" section only if the answerer supports the BUNDLE extension and if the answerer keeps the "m=" section within the associated BUNDLE group.

Name:
bundle-only
Value:
N/A
Usage Level:
media
Charset Dependent:
no
Example:
a=bundle-only
The usage of the 'bundle-only' attribute is only defined for a bundled "m=" section with a zero port value. Other usage is unspecified. If an offerer or answerer receives a 'bundle-only' attribute in a non-bundled "m=" section, the offerer or answerer MUST discard the attribute.

Section 7 defines the detailed SDP offer/answer procedures for the 'bundle-only' attribute.

# 7. SDP Offer/Answer Procedures
This section describes the SDP offer/answer [RFC3264] procedures for:

Negotiating a BUNDLE group;
Suggesting and selecting the tagged "m=" sections (offerer-tagged "m=" section and answerer-tagged "m=" section);
Adding an "m=" section to a BUNDLE group;
Moving an "m=" section out of a BUNDLE group; and
Disabling an "m=" section within a BUNDLE group.
The generic rules and procedures defined in [RFC3264] and [RFC5888] also apply to the BUNDLE extension. For example, if an offer is rejected by the answerer, the previously negotiated addresses:ports, SDP parameters, and characteristics (including those associated with a BUNDLE group) apply. Hence, if an offerer generates an offer in order to negotiate a BUNDLE group and the answerer rejects the offer, the BUNDLE group is not created.

The procedures in this section are independent of the media type or "m=" line proto value assigned to a bundled "m=" section. Section 6 defines additional considerations for the usage of the SDP 'bundle-only' attribute. Section 9 defines additional considerations for RTP-based media. Section 10 defines additional considerations for the usage of the ICE mechanism [RFC8445].

Offers and answers can contain multiple BUNDLE groups. The procedures in this section apply independently to a given BUNDLE group.

7.1. Generic SDP Considerations
This section describes generic restrictions associated with the usage of SDP parameters within a BUNDLE group. It also describes how to calculate a value for the whole BUNDLE group, when parameter and attribute values have been assigned to each bundled "m=" section.

7.1.1. Connection Data ("c=")
The "c=" line nettype value [RFC4566] associated with a bundled "m=" section MUST be 'IN'.

The "c=" line addrtype value [RFC4566] associated with a bundled "m=" section MUST be 'IP4' or 'IP6'. The same value MUST be associated with each "m=" section.

NOTE: Extensions to this specification can specify usage of the BUNDLE mechanism for other nettype and addrtype values than the ones listed above.

7.1.2. Bandwidth ("b=")
An offerer and answerer MUST use the rules and restrictions defined in [RFC8859] for associating the SDP bandwidth ("b=") line with bundled "m=" sections.

7.1.3. Attributes ("a=")
An offerer and answerer MUST include SDP attributes in every bundled "m=" section where applicable, following the normal offer/answer procedures for each attribute, with the following exceptions:

In the initial BUNDLE offer, the offerer MUST NOT include IDENTICAL and TRANSPORT multiplexing category SDP attributes (BUNDLE attributes) in bundle-only "m=" sections. The offerer MUST include such attributes in all other bundled "m=" sections. In the initial BUNDLE offer, each bundled "m=" line can contain a different set of BUNDLE attributes and attribute values. Once the offerer-tagged "m=" section has been selected, the BUNDLE attributes contained in the offerer-tagged "m=" section will apply to each bundled "m=" section within the BUNDLE group.
In a subsequent offer or in an answer (initial or subsequent), the offerer and answerer MUST include IDENTICAL and TRANSPORT multiplexing category SDP attributes (BUNDLE attributes) only in the tagged "m=" section (offerer-tagged "m=" section or answerer-tagged "m=" section). The offerer and answerer MUST NOT include such attributes in any other bundled "m=" section. The BUNDLE attributes contained in the tagged "m=" section will apply to each bundled "m=" section within the BUNDLE group.
In an offer (initial BUNDLE offer or subsequent) or in an answer (initial BUNDLE answer or subsequent), the offerer and answerer MUST include SDP attributes from categories other than IDENTICAL and TRANSPORT in each bundled "m=" section that a given attribute applies to. Each bundled "m=" line can contain a different set of such attributes and attribute values, as such attributes only apply to the given bundled "m=" section in which they are included.
NOTE: A consequence of the rules above is that media-specific IDENTICAL and TRANSPORT multiplexing category SDP attributes that are applicable only to some of the bundled "m=" sections within the BUNDLE group might appear in the tagged "m=" section for which they are not applicable. For instance, the tagged "m=" section might contain an SDP 'rtcp-mux' attribute even if the tagged "m=" section does not describe RTP-based media (but another bundled "m=" section within the BUNDLE group does describe RTP-based media).

7.2. Generating the Initial BUNDLE Offer
The procedures in this section apply to the first offer within an SDP session (e.g., a SIP dialog when SIP [RFC3261] is used to carry SDP) in which the offerer indicates that it wants to negotiate a given BUNDLE group. This could occur in the initial offer, or in a subsequent offer, of the SDP session.

When an offerer generates an initial BUNDLE offer, in order to negotiate a BUNDLE group, it MUST:

Assign a unique address:port to each bundled "m=" section following the procedures in [RFC3264], excluding any bundle-only "m=" sections (see below);
Pick a bundled "m=" section as the suggested offerer-tagged "m=" (Section 7.2.1);
Include SDP attributes in the bundled "m=" sections following the rules in Section 7.1.3;
Include an SDP 'group:BUNDLE' attribute in the offer; and
Place the identification-tag of each bundled "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list. The offerer BUNDLE-tag indicates the suggested offerer-tagged "m=" section.
NOTE: When the offerer assigns unique addresses:ports to multiple bundled "m=" sections, the offerer needs to be prepared to receive bundled media on each unique address:port until it receives the associated answer and finds out which bundled "m=" section (and associated address:port combination) the answerer has selected as the offerer-tagged "m=" section.

If the offerer wants to request that the answerer accept a given bundled "m=" section only if the answerer keeps the "m=" section within the negotiated BUNDLE group, the offerer MUST:

Include an SDP 'bundle-only' attribute (Section 7.2.1) in the "m=" section, and
Assign a zero port value to the "m=" section.
NOTE: If the offerer assigns a zero port value to a bundled "m=" section but does not include an SDP 'bundle-only' attribute in the "m=" section, it is an indication that the offerer wants to disable the "m=" section (Section 7.5.3).

Sections 7.2.2 and 18.1 show an example of an initial BUNDLE offer.

7.2.1. Suggesting the Offerer-Tagged "m=" Section
In the initial BUNDLE offer, the bundled "m=" section indicated by the offerer BUNDLE-tag is the suggested offerer-tagged "m=" section. The address:port combination associated with the "m=" section will be used by the offerer for sending and receiving bundled media if the answerer selects the "m=" section as the offerer-tagged "m=" section (Section 7.3.1). In addition, if the answerer selects the "m=" section as the offerer-tagged "m=" section, the BUNDLE attributes included in the "m=" section will be applied to each "m=" section within the negotiated BUNDLE group.

The offerer MUST NOT suggest a bundle-only "m=" section as the offerer-tagged "m=" section.

It is RECOMMENDED that the suggested offerer-tagged "m=" section be a bundled "m=" section which the offerer believes is unlikely to be rejected or moved out of the BUNDLE group by the answerer. How such an assumption is made is outside the scope of this document.

7.2.2. Example: Initial BUNDLE Offer
The following example shows an initial BUNDLE offer. The offer includes two "m=" sections in the offer and suggests that both "m=" sections be included in a BUNDLE group. The audio "m=" section is the suggested offerer-tagged "m=" section, indicated by placing the identification-tag associated with the "m=" section (offerer BUNDLE-tag) first in the SDP 'group:BUNDLE' attribute identification-id list.

SDP Offer

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
The following example shows an initial BUNDLE offer. The offer includes two "m=" sections in the offer and suggests that both "m=" sections are included in a BUNDLE group. The offerer includes an SDP 'bundle-only' attribute in the video "m=" section to request that the answerer accept the "m=" section only if the answerer supports the BUNDLE extension and if the answerer keeps the "m=" section within the associated BUNDLE group. The audio "m=" section is the suggested offerer-tagged "m=" section, indicated by placing the identification-tag associated with the "m=" section (offerer BUNDLE-tag) first in the SDP 'group:BUNDLE' attribute identification-id list.

SDP Offer

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

  m=video 0 RTP/AVP 31 32
  b=AS:1000
  a=mid:bar
  a=bundle-only
  a=rtpmap:31 H261/90000
  a=rtpmap:32 MPV/90000
  a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
7.3. Generating the SDP Answer
When an answerer generates an answer (initial BUNDLE answer or subsequent) that contains a BUNDLE group, the following general SDP Grouping Framework restrictions, defined in [RFC5888], also apply to the BUNDLE group:

The answerer is only allowed to include a BUNDLE group in an initial BUNDLE answer if the offerer requested the BUNDLE group to be created in the corresponding initial BUNDLE offer;
The answerer is only allowed to include a BUNDLE group in a subsequent answer if the corresponding subsequent offer contains a previously negotiated BUNDLE group;
The answerer is only allowed to include a bundled "m=" section in an answer if the "m=" section was indicated as bundled in the corresponding offer; and
The answerer is only allowed to include a bundled "m=" section in the same BUNDLE group as the bundled "m=" line in the corresponding offer.
In addition, when an answerer generates an answer (initial BUNDLE answer or subsequent) that contains a BUNDLE group, the answerer MUST:

In case of an initial BUNDLE answer, select the offerer-tagged "m=" section using the procedures in Section 7.3.1. In case of a subsequent answer, the offerer-tagged "m=" section is indicated in the corresponding subsequent offer and MUST NOT be changed by the answerer;
Select the answerer-tagged "m=" section (Section 7.3.1);
Assign the answerer BUNDLE address:port to the answerer-tagged "m=" section and to every other bundled "m=" section within the BUNDLE group;
Include SDP attributes in the bundled "m=" sections following the rules in Section 7.1.3;
Include an SDP 'group:BUNDLE' attribute in the answer; and
Place the identification-tag of each bundled "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list. The answerer BUNDLE-tag indicates the answerer-tagged "m=" section (Section 7.3.1).
If the answerer does not want to keep an "m=" section within a BUNDLE group, it MUST:

Move the "m=" section out of the BUNDLE group (Section 7.3.2); or
Reject the "m=" section (Section 7.3.3).
The answerer can modify the answerer BUNDLE address:port, add and remove SDP attributes, or modify SDP attribute values in a subsequent answer. Changes to the answerer BUNDLE address:port and the answerer BUNDLE attributes will be applied to each bundled "m=" section within the BUNDLE group.

NOTE: If a bundled "m=" section in an offer contains a zero port value, but the "m=" section does not contain an SDP 'bundle-only' attribute, it is an indication that the offerer wants to disable the "m=" section (Section 7.5.3).

7.3.1. Answerer Selection of Tagged "m=" Sections
When selecting the offerer-tagged "m=" section, the answerer MUST first check whether the "m=" section fulfills the following criteria (Section 7.2.1):

The answerer will not move the "m=" section out of the BUNDLE group (Section 7.3.2);
The answerer will not reject the "m=" section (Section 7.3.3); and
The "m=" section does not contain a zero port value.
If all of the criteria above are fulfilled, the answerer MUST select the "m=" section as the offerer-tagged "m=" section and MUST also mark the corresponding "m=" section in the answer as the answerer-tagged "m=" section. In the answer, the answerer BUNDLE-tag indicates the answerer-tagged "m=" section.

If one or more of the criteria are not fulfilled, the answerer MUST pick the next identification-tag in the identification-tag list in the offer and perform the same criteria check for the "m=" section indicated by that identification-tag. If there are no more identification-tags in the identification-tag list, the answerer MUST NOT create the BUNDLE group. In addition, unless the answerer rejects the whole offer, the answerer MUST apply the answerer procedures for moving an "m=" section out of a BUNDLE group (Section 7.3.2) or rejecting an "m=" section within a BUNDLE group (Section 7.3.3) to every bundled "m=" section in the offer when creating the answer.

Section 18.1 shows an example of an offerer BUNDLE address:port selection.

Sections 7.3.4 and 18.1 show an example of an answerer-tagged "m=" section selection.

7.3.2. Moving a Media Description Out of a BUNDLE Group
When an answerer generates the answer, the answerer MUST first check the following criteria if it wants to move a bundled "m=" section out of the negotiated BUNDLE group:

In the corresponding offer, the "m=" section is within a previously negotiated BUNDLE group, and
In the corresponding offer, the "m=" section contains an SDP 'bundle-only' attribute.
If either criterion above is fulfilled, the answerer cannot move the "m=" section out of the BUNDLE group in the answer. The answerer can reject the whole offer, reject each bundled "m=" section within the BUNDLE group (Section 7.3.3), or keep the "m=" section within the BUNDLE group in the answer and later create an offer where the "m=" section is moved out of the BUNDLE group (Section 7.5.2).

NOTE: One consequence of the rules above is that, once a BUNDLE group has been negotiated, a bundled "m=" section cannot be moved out of the BUNDLE group in an answer. Instead, an offer is needed.

When the answerer generates an answer in which it moves a bundled "m=" section out of a BUNDLE group, the answerer:

MUST assign a unique address:port to the "m=" section;
MUST include any applicable SDP attribute in the "m=" section using the normal offer/answer procedures for each attribute;
MUST NOT place the identification-tag associated with the "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list associated with the BUNDLE group; and
MUST NOT include an SDP 'bundle-only' attribute to the "m=" section.
Because an answerer is not allowed to move an "m=" section from one BUNDLE group to another within an answer (Section 7.3), if the answerer wants to move an "m=" section from one BUNDLE group to another, it MUST first move the "m=" section out of the current BUNDLE group and then generate an offer where the "m=" section is added to another BUNDLE group (Section 7.5.1).

7.3.3. Rejecting a Media Description in a BUNDLE Group
When an answerer wants to reject a bundled "m=" section in an answer, it MUST first check the following criterion:

In the corresponding offer (subsequent), the "m=" section is the offerer-tagged "m=" section.
If the criterion above is fulfilled, the answerer cannot reject the "m=" section in the answer. The answerer can reject the whole offer, reject each bundled "m=" section within the BUNDLE group, or keep the "m=" section within the BUNDLE group in the answer and later create an offer where the "m=" section is disabled within the BUNDLE group (Section 7.5.3).

When an answerer generates an answer in which it rejects a bundled "m=" section, the answerer:

MUST assign a zero port value to the "m=" section, according to the procedures in [RFC3264];
MUST NOT place the identification-tag associated with the "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list associated with the BUNDLE group; and
MUST NOT include an SDP 'bundle-only' attribute in the "m=" section.
7.3.4. Example: SDP Answer
The example below shows an answer based on the corresponding offer in Section 7.2.2. The answerer accepts both bundled "m=" sections within the created BUNDLE group. The audio "m=" section is the answerer-tagged "m=" section, indicated by placing the identification-tag associated with the "m=" section (answerer BUNDLE-tag) first in the SDP 'group:BUNDLE' attribute identification-id list.

SDP Answer

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
7.3.5. RFC 8843 Considerations
In [RFC8843], instead of assigning the offerer BUNDLE address:port to each "m=" section within the BUNDLE group when modifying the session (Section 7.5), the offerer only assigned the offerer BUNDLE address:port to the offerer-tagged "m=" section. For every other "m=" section within the BUNDLE group, the offerer included an SDP 'bundle-only' attribute in, and assigned a zero port value to, the "m=" section. The way an answerer compliant with this specification processes such offer is considered an implementation issue (e.g., based on whether the answerer needs to be backward compatible with offerers compliant with [RFC8843]) and is outside the scope of this specification. The example below shows such an SDP Offer:

SDP Offer

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

  m=video 0 RTP/AVP 31 32
  b=AS:1000
  a=mid:bar
  a=bundle-only
  a=rtpmap:31 H261/90000
  a=rtpmap:32 MPV/90000
  a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
7.4. Offerer Processing of the SDP Answer
When an offerer receives an answer, if the answer contains a BUNDLE group, the offerer MUST check that any bundled "m=" section in the answer was indicated as bundled in the corresponding offer (for the same BUNDLE group). If there is no mismatch, the offerer MUST apply the properties (BUNDLE address:port, BUNDLE attributes, etc.) of the offerer-tagged "m=" section (selected by the answerer; see Section 7.3.1) to each bundled "m=" section within the BUNDLE group.

NOTE: As the answerer might reject one or more bundled "m=" sections in an initial BUNDLE offer or move a bundled "m=" section out of a BUNDLE group, a given bundled "m=" section in the offer might not be indicated as bundled in the corresponding answer.

If the answer does not contain a BUNDLE group, the offerer MUST process the answer as a normal answer.

7.4.1. RFC 8843 Considerations
In [RFC8843], instead of assigning the answerer BUNDLE address:port to each "m=" section within the BUNDLE group when generating the SDP Answer (Section 7.3), the answerer only assigned the answerer BUNDLE address:port to the answerer-tagged "m=" section. For every other "m=" section within the BUNDLE group, the answerer included an SDP 'bundle-only' attribute in, and assigned a zero port value to, the "m=" section. The way an offerer compliant with this specification processes such an SDP Answer is considered an implementation issue (e.g., based on whether the answerer needs to be backward compatible with offerers compliant with [RFC8843]) and is outside the scope of this specification. The example below shows such an SDP Answer:

SDP Answer

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

  m=video 0 RTP/AVP 32
  b=AS:1000
  a=mid:bar
  a=bundle-only
  a=rtpmap:32 MPV/90000
  a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
7.5. Modifying the Session
When a BUNDLE group has been previously negotiated and an offerer generates a subsequent offer, the offerer MUST:

Pick one bundled "m=" section as the offerer-tagged "m=" section. The offerer can pick either the "m=" section that was previously selected by the answerer as the offerer-tagged "m=" section or another bundled "m=" section within the BUNDLE group;
Assign a BUNDLE address:port (previously negotiated or newly suggested) to the offerer-tagged "m=" section and to every other bundled "m=" section within the BUNDLE group;
Include SDP attributes in the bundled "m=" sections following the rules in Section 7.1.3;
Include an SDP 'group:BUNDLE' attribute in the offer; and
Place the identification-tag of each bundled "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list. The offerer BUNDLE-tag indicates the offerer-tagged "m=" section.
The offerer MUST NOT pick a given bundled "m=" section as the offerer-tagged "m=" section if:

The offerer wants to move the "m=" section out of the BUNDLE group (Section 7.5.2), or
The offerer wants to disable the "m=" section (Section 7.5.3).
The offerer can modify the offerer BUNDLE address:port, add and remove SDP attributes, or modify SDP attribute values in the subsequent offer. Changes to the offerer BUNDLE address:port and the offerer BUNDLE attributes will (if the offer is accepted by the answerer) be applied to each bundled "m=" section within the BUNDLE group.

7.5.1. Adding a Media Description to a BUNDLE Group
When an offerer generates a subsequent offer in which it wants to add a bundled "m=" section to a previously negotiated BUNDLE group, the offerer follows the procedures in Section 7.5. The offerer picks either the added "m=" section or an "m=" section previously added to the BUNDLE group as the offerer-tagged "m=" section.

NOTE: As described in Section 7.3.2, the answerer cannot move the added "m=" section out of the BUNDLE group in its answer. If the answerer wants to move the "m=" section out of the BUNDLE group, it will have to first accept it into the BUNDLE group in the answer and then send a subsequent offer where the "m=" section is moved out of the BUNDLE group (Section 7.5.2).

7.5.2. Moving a Media Description Out of a BUNDLE Group
When an offerer generates a subsequent offer in which it wants to remove a bundled "m=" section from a BUNDLE group, the offerer:

MUST assign a unique address:port to the "m=" section;
MUST include SDP attributes in the "m=" section following the normal offer/answer rules for each attribute;
MUST NOT place the identification-tag associated with the "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list associated with the BUNDLE group; and
MUST NOT assign an SDP 'bundle-only' attribute to the "m=" section.
For the other bundled "m=" sections within the BUNDLE group, the offerer follows the procedures in Section 7.5.

An offerer MUST NOT move an "m=" section from one BUNDLE group to another within a single offer. If the offerer wants to move an "m=" section from one BUNDLE group to another, it MUST first move the BUNDLE group out of the current BUNDLE group and then generate a second offer where the "m=" section is added to another BUNDLE group (Section 7.5.1).

Section 18.4 shows an example of an offer for moving an "m=" section out of a BUNDLE group.

7.5.3. Disabling a Media Description in a BUNDLE Group
When an offerer generates a subsequent offer in which it wants to disable a bundled "m=" section from a BUNDLE group, the offerer:

MUST assign a zero port value to the "m=" section, following the procedures in [RFC4566];
MUST NOT place the identification-tag associated with the "m=" section in the SDP 'group:BUNDLE' attribute identification-tag list associated with the BUNDLE group; and
MUST NOT assign an SDP 'bundle-only' attribute to the "m=" section.
For the other bundled "m=" sections within the BUNDLE group, the offerer follows the procedures in Section 7.5.

Section 18.5 shows an example of an offer and answer for disabling an "m=" section within a BUNDLE group.

7.6. 3PCC Considerations
In some third-party call control (3PCC) scenarios, a new session will be established between an endpoint that is currently part of an ongoing session and an endpoint that is not currently part of an ongoing session. In this situation, the endpoint that is not part of a session, while expecting an initial offer, can receive an SDP offer created as a subsequent offer. The text below describes how this can occur with the Session Initiation Protocol (SIP) [RFC3261].

SIP [RFC3261] allows a User Agent Client (UAC) to send a re-INVITE request without an SDP body (sometimes referred to as an "empty re-INVITE"). In such cases, the User Agent Server (UAS) will include an SDP Offer in the associated 200 (OK) response; when the UAS is a part of an ongoing SIP session, this offer will be a subsequent offer. This offer will be received by the 3PCC controller (UAC) and then forwarded to another User Agent (UA). When that UA is not part of an ongoing SIP session, as noted above, it will process the offer as an initial SDP offer.

When the BUNDLE mechanism is used, an initial BUNDLE offer is constructed using different rules than subsequent BUNDLE offers, and it cannot be assumed that a UA is able to correctly process a subsequent BUNDLE offer as an initial BUNDLE offer. Therefore, the 3PCC controller SHOULD take action to mitigate this problem, e.g., rewrite the subsequent BUNDLE offer into a valid initial BUNDLE offer (Section 7.2), before it forwards the BUNDLE offer to a UA.

