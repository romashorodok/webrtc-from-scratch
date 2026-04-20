7. Security Considerations
SDP is frequently used with the Session Initiation Protocol [RFC3261] using the offer/answer model [RFC3264] to agree on parameters for unicast sessions. When used in this manner, the security considerations of those protocols apply.

SDP is a session description format that describes multimedia sessions. Entities receiving and acting upon an SDP message SHOULD be aware that a session description cannot be trusted unless it has been obtained by an authenticated and integrity-protected transport protocol from a known and trusted source. Many different transport protocols may be used to distribute session descriptions, and the nature of the authentication and integrity protection will differ from transport to transport. For some transports, security features are often not deployed. In case a session description has not been obtained in a trusted manner, the endpoint SHOULD exercise care because, among other attacks, the media sessions received may not be the intended ones, the destination to where the media is sent may not be the expected one, any of the parameters of the session may be incorrect, or the media security may be compromised. It is up to the endpoint to make a sensible decision, taking into account the security risks of the application and the user preferences - the endpoint may decide to ask the user whether or not to accept the session.

On receiving a session description over an unauthenticated transport mechanism or from an untrusted party, software parsing the session description should take a few precautions. Similar concerns apply if integrity protection is not in place. Session descriptions contain information required to start software on the receiver's system. Software that parses a session description MUST NOT be able to start other software except that which is specifically configured as appropriate software to participate in multimedia sessions. It is normally considered inappropriate for software parsing a session description to start, on a user's system, software that is appropriate to participate in multimedia sessions, without the user first being informed that such software will be started and giving the user's consent. Thus, a session description arriving by session announcement, email, session invitation, or WWW page MUST NOT deliver the user into an interactive multimedia session unless the user has explicitly pre-authorized such action. As it is not always simple to tell whether or not a session is interactive, applications that are unsure should assume sessions are interactive. Software processing URLs contained in session descriptions should also heed the security considerations identified in [RFC3986].

In this specification, there are no attributes that would allow the recipient of a session description to be informed to start multimedia tools in a mode where they default to transmitting. Under some circumstances it might be appropriate to define such attributes. If this is done, an application parsing a session description containing such attributes SHOULD either ignore them or inform the user that joining this session will result in the automatic transmission of multimedia data. The default behavior for an unknown attribute is to ignore it.

In certain environments, it has become common for intermediary systems to intercept and analyze session descriptions contained within other signaling protocols. This is done for a range of purposes, including but not limited to opening holes in firewalls to allow media streams to pass, or to mark, prioritize, or block traffic selectively. In some cases, such intermediary systems may modify the session description, for example, to have the contents of the session description match NAT bindings dynamically created. These behaviors are NOT RECOMMENDED unless the session description is conveyed in such a manner that allows the intermediary system to conduct proper checks to establish the authenticity of the session description, and the authority of its source to establish such communication sessions. SDP by itself does not include sufficient information to enable these checks: they depend on the encapsulating protocol (e.g., SIP or RTSP). The use of some procedures and SDP extensions (e.g., Interactive Connectivity Establishment (ICE) [RFC8445] and ICE-SIP-SDP [RFC8839]) may avoid the need for intermediaries to modify SDP.

SDP MUST NOT be used to convey keying material (e.g., using the "a=crypto:" attribute [RFC4568]) unless it can be guaranteed that the channel over which the SDP is delivered is both private and authenticated.

8. IANA Considerations
8.1. The "application/sdp" Media Type
One media type registration from [RFC4566] has been updated, as defined below.

Type name:
application
Subtype name:
sdp
Required parameters:
None.
Optional parameters:
None.
Encoding considerations:
8-bit text. SDP files are primarily UTF-8 format text. The "a=charset:" attribute may be used to signal the presence of other character sets in certain parts of an SDP file (see Section 6 of RFC 8866). Arbitrary binary content cannot be directly represented in SDP.
Security considerations:
See Section 7 of RFC 8866.
Interoperability considerations:
See RFC 8866.
Published specification:
See RFC 8866.
Applications which use this media type:

Voice over IP, video teleconferencing, streaming media, instant messaging, among others. See also Section 3 of RFC 8866.

Fragment identifier considerations:
None
Additional information:


Deprecated alias names for this type:
N/A
Magic number(s):
None.
File extension(s):
The extension ".sdp" is commonly used.
Macintosh File Type Code(s):
"sdp"
Person & email address to contact for further information:

IETF MMUSIC working group
<mmusic@ietf.org>
Intended usage:
COMMON
Restrictions on usage:
None
Author/Change controller:

Authors of RFC 8866
IETF MMUSIC working group delegated from the IESG
8.2. Registration of SDP Parameters with IANA
This document specifies IANA parameter registries for six named SDP subfields. Using the terminology in the SDP specification Augmented Backus-Naur Form (ABNF), they are <media>, <proto>, <attribute-name>, <bwtype>, <nettype>, and <addrtype>.

This document also replaces and updates the definitions of all those parameters previously defined by [RFC4566].

IANA has changed all references to RFC 4566 in these registries to instead refer to this document.

The contact name and email address for all parameters registered in this document is:

The IETF MMUSIC working group <mmusic@ietf.org> or its successor as designated by the IESG.

All of these registries have a common format:

Table 3: Common Format for SDP Registries
Type	SDP Name	[other fields]	Reference
8.2.1. Registration Procedure
A specification document that defines values for SDP <media>, <proto>, <attribute-name>, <bwtype>, <nettype>, and <addrtype> parameters MUST include the following information:

Contact name
Contact email address
Name being defined (as it will appear in SDP)
Type of name (<media>, <proto>, <attribute-name>, <bwtype>, <nettype>, or <addrtype>)
A description of the purpose of the defined name
A stable reference to the document containing this information and the definition of the value. (This will typically be an RFC number.)
The subsections below specify what other information (if any) must be specified for particular parameters, and what other fields are to be included in the registry.

8.2.2. Media Types (<media>)
The set of media types is intended to be small and SHOULD NOT be extended except under rare circumstances. The same rules should apply for media names as well as for top-level media types, and where possible the same name should be registered for SDP as for MIME. For media other than existing top-level media types, a Standards Track RFC MUST be produced for a new top-level media type to be registered, and the registration MUST provide good justification why no existing media name is appropriate (the "Standards Action" policy of [RFC8126]).

This memo registers the media types "audio", "video", "text", "application", and "message".

Note: The media types "control" and "data" were listed as valid in an early version of this specification [RFC2327]; however, their semantics were never fully specified, and they are not widely used. These media types have been removed in this specification, although they still remain valid media type capabilities for a SIP user agent as defined in [RFC3840]. If these media types are considered useful in the future, a Standards Track RFC MUST be produced to document their use. Until that is done, applications SHOULD NOT use these types and SHOULD NOT declare support for them in SIP capabilities declarations (even though they exist in the registry created by [RFC3840]). Also note that [RFC6466] defined the "image" media type.

8.2.3. Transport Protocols (<proto>)
The <proto> subfield describes the transport protocol used. The registration procedure for this registry is "RFC Required".

This document registers two values:

"RTP/AVP" is a reference to [RFC3550] used under the RTP Profile for Audio and Video Conferences with Minimal Control [RFC3551] running over UDP/IP.
"udp" indicates direct use of UDP.
New transport protocols MAY be defined, and MUST be registered with IANA. Registrations MUST reference an RFC describing the protocol. Such an RFC MAY be Experimental or Informational, although it is preferable that it be Standards Track. The RFC defining a new protocol MUST define the rules by which the <fmt> (see below) namespace is managed.

<proto> names starting with "RTP/" MUST only be used for defining transport protocols that are profiles of RTP. For example, a profile whose short name is "XYZ" would be denoted by a <proto> subfield of "RTP/XYZ".

Each transport protocol, defined by the <proto> subfield, has an associated <fmt> namespace that describes the media formats that may be conveyed by that protocol. Formats cover all the possible encodings that could be transported in a multimedia session.

RTP payload formats under the "RTP/AVP" and other "RTP/*" profiles MUST use the payload type number as their <fmt> value. If the payload type number is dynamically assigned by this session description, an additional "a=rtpmap:" attribute MUST be included to specify the format name and parameters as defined by the media type registration for the payload format. It is RECOMMENDED that other RTP profiles that are registered (in combination with RTP) as SDP transport protocols specify the same rules for the <fmt> namespace.

For the "udp" protocol, the allowed <fmt> values are media subtypes from the IANA Media Types registry. The media type and subtype combination <media>/<fmt> specifies the format of the body of UDP packets. Use of an existing media subtype for the format is encouraged. If no suitable media subtype exists, it is RECOMMENDED that a new one be registered through the IETF process [RFC6838] by production of, or reference to, a Standards Track RFC that defines the format.

For other protocols, formats MAY be registered according to the rules of the associated <proto> specification.

Registrations of new formats MUST specify which transport protocols they apply to.

8.2.4. Attribute Names (<attribute-name>)
Attribute-field names (<attribute-name>) MUST be registered with IANA and documented to avoid any issues due to conflicting attribute definitions under the same name. (While unknown attributes in SDP are simply ignored, conflicting ones that fragment the protocol are a serious problem.)

The format of the <attribute-name> registry is:

Table 4: Format of the <attribute-name> Registry
Type	SDP Name	Usage Level	Mux Category	Reference
For example, the attribute "a=lang:", which is defined for both session and media level, will be listed in the new registry as follows:

Table 5: <attribute-name> Registry Example
Type	SDP Name	Usage Level	Mux Category	Reference
attribute	lang	session, media	TRANSPORT	[RFC8866] [RFC8859]
This one <attribute-name> registry combines all of the previous usage-level-specific "att-field" registries, including updates made by [RFC8859], and renames the "att-field" registry to the "attribute-name (formerly "att-field")" registry. IANA has completed the necessary reformatting.

Section 6 of this document replaces the initial set of attribute definitions made by [RFC4566]. IANA has updated the registry accordingly.

Documents can define new attributes and can also extend the definitions of previously defined attributes.

8.2.4.1. New Attributes
New attribute registrations are accepted according to the "Specification Required" policy of [RFC8126], provided that the specification includes the following information:

Contact name
Contact email address
Attribute name: the name of the attribute that will appear in SDP. This MUST conform to the definition of <attribute-name>.
Attribute syntax: for a value attribute (see Section 5.13), an ABNF definition of the attribute value <attribute-value> syntax (see Section 9) MUST be provided. The syntax MUST follow the rule form per Section 2.2 of [RFC5234] and [RFC7405]. This SHALL define the allowable values that the attribute might take. It MAY also define an extension method for the addition of future values. For a property attribute, the ABNF definition is omitted as the property attribute takes no values.
Attribute semantics: for a value attribute, a semantic description of the values that the attribute might take MUST be provided. The usage of a property attribute is described under Purpose below.
Attribute value: the name of an ABNF syntax rule defining the syntax of the value. Absence of a rule name indicates that the attribute takes no values. Enclosing the rule name in "[" and "]" indicates that a value is optional.
Usage level: the usage level(s) of the attribute. This MUST be one or more of the following: session, media, source, dcsa, and dcsa(subprotocol). For a definition of source-level attributes, see [RFC5576]. For a definition of dcsa attributes see [RFC8864].
Charset dependent: this MUST be "Yes" or "No" depending on whether the attribute value is subject to the "a=charset:" attribute.
Purpose: an explanation of the purpose and usage of the attribute.
O/A procedures: offer/answer procedures as explained in [RFC3264].
Mux Category: this MUST indicate one of the following categories: NORMAL, NOT RECOMMENDED, IDENTICAL, SUM, TRANSPORT, INHERIT, IDENTICAL-PER-PT, SPECIAL, or TBD as defined by [RFC8859].
Reference: a reference to the specification defining the attribute.
The above is the minimum that IANA will accept. Attributes that are expected to see widespread use and interoperability SHOULD be documented with a Standards Track RFC that specifies the attribute more precisely.

Submitters of registrations should ensure that the specification is in the spirit of SDP attributes, most notably that the attribute is platform independent in the sense that it makes no implicit assumptions about operating systems and does not name specific pieces of software in a manner that might inhibit interoperability.

Submitters of registrations should also carefully choose the attribute usage level. They should not choose only "session" when the attribute can have different values when media is disaggregated, i.e., when each "m=" section has its own IP address on a different endpoint. In that case, the attribute type chosen should be "session, media" or "media" (depending on desired semantics). The default rule is that for all new SDP attributes that can occur both in session and media level, the media level overrides the session level. When this is not the case for a new SDP attribute, it MUST be explicitly stated.

IANA has registered the initial set of attribute names (<attribute-name> values) with definitions as in Section 6 of this memo (these definitions replace those in [RFC4566]).

8.2.4.2. Updates to Existing Attributes
Updated attribute registrations are accepted according to the "Specification Required" policy of [RFC8126].

The Designated Expert reviewing the update is requested to evaluate whether the update is compatible with the prior intent and use of the attribute, and whether the new document is of sufficient maturity and authority in relation to the prior document.

The specification updating the attribute (for example, by adding a new value) MUST update registration information items from Section 8.2.4.1 according to the following constraints:

Contact name: a name for an entity responsible for the update MUST be provided.
Contact email address: an email address for an entity responsible for the update MUST be provided.
Attribute name: MUST be provided and MUST NOT be changed. Otherwise it is a new attribute.
Attribute syntax: the existing rule syntax with the syntax extensions MUST be provided if there is a change to the syntax. A revision to an existing attribute usage MAY extend the syntax of an attribute, but MUST be backward compatible.
Attribute semantics: a semantic description of new additional attribute values or a semantic extension of existing values. Existing attribute values semantics MUST only be extended in a backward compatible manner.
Usage level: updates MAY only add additional levels.
Charset dependent: MUST NOT be changed.
Purpose: MAY be extended according to the updated usage.
O/A procedures: MAY be updated in a backward compatible manner and/or it applies to a new usage level only.
Mux Category: no change unless from "TBD" to another value (see [RFC8859]. It MAY also change if media level is being added to the definition of an attribute that previously did not include it.
Reference: a new (additional or replacement) reference MUST be provided.
Items SHOULD be omitted if there is no impact to them as a result of the attribute update.

8.2.5. Bandwidth Specifiers (<bwtype>)
A proliferation of bandwidth specifiers is strongly discouraged.

New bandwidth specifiers (<bwtype> subfield values) MUST be registered with IANA. The submission MUST reference a Standards Track RFC specifying the semantics of the bandwidth specifier precisely, and indicating when it should be used, and why the existing registered bandwidth specifiers do not suffice.

The RFC MUST specify the Mux Category for this value as defined by [RFC8859].

The format of the <bwtype> registry is:

Table 6: Format of the <bwtype> Registry
Type	SDP Name	Mux Category	Reference
IANA has updated the <bwtype> registry entries for the bandwidth specifiers "CT" and "AS" with the definitions in Section 5.8 of this memo (these definitions replace those in [RFC4566]).

8.2.6. Network Types (<nettype>)
Network type "IN", representing the Internet, is defined in Section 5.2 and Section 5.7 of this memo (this definition replaces that in [RFC4566]).

To enable SDP to reference a new non-Internet environment, a new network type (<nettype> subfield value) MUST be registered with IANA. The registration is subject to the "RFC Required" policy of [RFC8126]. Although non-Internet environments are not normally the preserve of IANA, there may be circumstances when an Internet application needs to interoperate with a non-Internet application, such as when gatewaying an Internet telephone call into the Public Switched Telephone Network (PSTN). The number of network types should be small and should be rarely extended. A new network type registration MUST reference an RFC that gives details of the network type and the address type(s) that may be used with it.

The format of the <nettype> registry is:

Table 7: Format of the <nettype> Registry
Type	SDP Name	Usable addrtype Values	Reference
IANA has updated the <nettype> registry to this new format. The following is the updated content of the registry:

Table 8: Content of the <nettype> registry
Type	SDP Name	Usable addrtype Values	Reference
nettype	IN	IP4, IP6	[RFC8866]
nettype	TN	RFC2543	[RFC2848]
nettype	ATM	NSAP, GWID, E164	[RFC3108]
nettype	PSTN	E164	[RFC7195]
Note that both [RFC7195] and [RFC3108] registered "E164" as an address type, although [RFC7195] mentions that the "E164" address type has a different context for ATM and PSTN networks.

8.2.7. Address Types (<addrtype>)
New address types (<addrtype>) MUST be registered with IANA. The registration is subject to the "RFC Required" policy of [RFC8126]. A new address type registration MUST reference an RFC, giving details of the syntax of the address type. Address types are not expected to be registered frequently.

Section 5.7 of this document gives new definitions of address types "IP4" and "IP6".

8.3. Encryption Key Access Methods (OBSOLETE)
The IANA previously maintained a table of SDP encryption key access method ("enckey") names. This table is obsolete, since the "k=" line is not extensible. New registrations MUST NOT be accepted.

