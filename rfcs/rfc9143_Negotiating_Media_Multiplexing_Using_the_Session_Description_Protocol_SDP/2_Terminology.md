# 2. Terminology

"m=" section:
SDP bodies contain one or more media descriptions, referred to as "m=" sections. Each "m=" section is represented by an SDP "m=" line and zero or more SDP attributes associated with the "m=" line. A local address:port combination is assigned to each "m=" section.
5-tuple:
A collection of the following values: source address, source port, destination address, destination port, and transport-layer protocol.
Unique address:port:
An address:port combination that is assigned to only one "m=" section in an offer or answer.
Offerer BUNDLE-tag:
The first identification-tag in a given SDP 'group:BUNDLE' attribute identification-tag list in an offer.
Answerer BUNDLE-tag:
The first identification-tag in a given SDP 'group:BUNDLE' attribute identification-tag list in an answer.
Suggested offerer-tagged "m=" section:
The bundled "m=" section identified by the offerer BUNDLE-tag in an initial BUNDLE offer, before a BUNDLE group has been negotiated.
Offerer-tagged "m=" section:
The bundled "m=" section identified by the offerer BUNDLE-tag in a subsequent offer. The "m=" section contains characteristics (offerer BUNDLE address:port and offerer BUNDLE attributes) that are applied to each "m=" section within the BUNDLE group.
Answerer-tagged "m=" section:
The bundled "m=" section identified by the answerer BUNDLE-tag in an answer (initial BUNDLE answer or subsequent). The "m=" section contains characteristics (answerer BUNDLE address:port and answerer BUNDLE attributes) that are applied to each "m=" section within the BUNDLE group.
BUNDLE address:port:
An address:port combination that an endpoint uses for sending and receiving bundled media.
Offerer BUNDLE address:port:
The address:port combination used by the offerer for sending and receiving media.
Answerer BUNDLE address:port:
The address:port combination used by the answerer for sending and receiving media.
BUNDLE attributes:
IDENTICAL and TRANSPORT multiplexing category SDP attributes. Once a BUNDLE group has been created, the attribute values apply to each bundled "m=" section within the BUNDLE group.
Offerer BUNDLE attributes:
IDENTICAL and TRANSPORT multiplexing category SDP attributes included in the offerer-tagged "m=" section.
Answerer BUNDLE attributes:
IDENTICAL and TRANSPORT multiplexing category SDP attributes included in the answerer-tagged "m=" section.
BUNDLE transport:
The transport (5-tuple) used by all media described by the "m=" sections within a BUNDLE group.
BUNDLE group:
A set of bundled "m=" sections, created using an SDP offer/answer exchange, that uses a single BUNDLE transport and a single set of BUNDLE attributes for sending and receiving all media (bundled media) described by the set of "m=" sections. The same BUNDLE transport is used for sending and receiving bundled media.
Bundled "m=" section:
An "m=" section, whose identification-tag is placed in an SDP 'group:BUNDLE' attribute identification-tag list in an offer or answer.
Bundle-only "m=" section:
A bundled "m=" section that contains an SDP 'bundle-only' attribute.
Bundled media:
All media associated with a given BUNDLE group.
Initial BUNDLE offer:
The first offer, within an SDP session (e.g., a SIP dialog when SIP [RFC3261] is used to carry SDP), in which the offerer indicates that it wants to negotiate a given BUNDLE group.
Initial BUNDLE answer:
The answer to an initial BUNDLE offer in which the offerer indicates that it wants to negotiate a BUNDLE group, and the answerer accepts the creation of the BUNDLE group. The BUNDLE group is created once the answerer sends the initial BUNDLE answer.
Subsequent offer:
An offer that contains a BUNDLE group that has been created as part of a previous offer/answer exchange.
Subsequent answer:
An answer to a subsequent offer.
Identification-tag:
A unique token value that is used to identify an "m=" section. The SDP 'mid' attribute [RFC5888] in an "m=" section carries the unique identification-tag assigned to that "m=" section. The session-level SDP 'group' attribute [RFC5888] carries a list of identification-tags, identifying the "m=" sections associated with that particular 'group' attribute.
