# 13.  RTP Profiles and Payload Format Specifications

A complete specification of RTP for a particular application will
require one or more companion documents of two types described here:
profiles, and payload format specifications.

RTP may be used for a variety of applications with somewhat differing
requirements.  The flexibility to adapt to those requirements is
provided by allowing multiple choices in the main protocol
specification, then selecting the appropriate choices or defining
extensions for a particular environment and class of applications in
a separate profile document.  Typically an application will operate
under only one profile in a particular RTP session, so there is no
explicit indication within the RTP protocol itself as to which
profile is in use.  A profile for audio and video applications may be
found in the companion RFC 3551.  Profiles are typically titled "RTP
Profile for ...".

The second type of companion document is a payload format
specification, which defines how a particular kind of payload data,
such as H.261 encoded video, should be carried in RTP.  These
documents are typically titled "RTP Payload Format for XYZ
Audio/Video Encoding".  Payload formats may be useful under multiple
profiles and may therefore be defined independently of any particular
profile.  The profile documents are then responsible for assigning a
default mapping of that format to a payload type value if needed.

Within this specification, the following items have been identified
for possible definition within a profile, but this list is not meant
to be exhaustive:

RTP data header: The octet in the RTP data header that contains
    the marker bit and payload type field MAY be redefined by a
    profile to suit different requirements, for example with more or
    fewer marker bits (Section 5.3, p. 18).

Payload types: Assuming that a payload type field is included,
    the profile will usually define a set of payload formats (e.g.,
    media encodings) and a default static mapping of those formats to
    payload type values.  Some of the payload formats may be defined
    by reference to separate payload format specifications.  For each
    payload type defined, the profile MUST specify the RTP timestamp
    clock rate to be used (Section 5.1, p. 14).

RTP data header additions: Additional fields MAY be appended to
    the fixed RTP data header if some additional functionality is
    required across the profile's class of applications independent of
    payload type (Section 5.3, p. 18).

RTP data header extensions: The contents of the first 16 bits of
    the RTP data header extension structure MUST be defined if use of
    that mechanism is to be allowed under the profile for
    implementation-specific extensions (Section 5.3.1, p. 18).

RTCP packet types: New application-class-specific RTCP packet
    types MAY be defined and registered with IANA.

RTCP report interval: A profile SHOULD specify that the values
    suggested in Section 6.2 for the constants employed in the
    calculation of the RTCP report interval will be used.  Those are
    the RTCP fraction of session bandwidth, the minimum report
    interval, and the bandwidth split between senders and receivers.
    A profile MAY specify alternate values if they have been
    demonstrated to work in a scalable manner.

SR/RR extension: An extension section MAY be defined for the
    RTCP SR and RR packets if there is additional information that
    should be reported regularly about the sender or receivers
    (Section 6.4.3, p. 42 and 43).

SDES use: The profile MAY specify the relative priorities for
    RTCP SDES items to be transmitted or excluded entirely (Section
    6.3.9); an alternate syntax or semantics for the CNAME item
    (Section 6.5.1); the format of the LOC item (Section 6.5.5); the
    semantics and use of the NOTE item (Section 6.5.7); or new SDES
    item types to be registered with IANA.

Security: A profile MAY specify which security services and
    algorithms should be offered by applications, and MAY provide
    guidance as to their appropriate use (Section 9, p. 65).

String-to-key mapping: A profile MAY specify how a user-provided
    password or pass phrase is mapped into an encryption key.

Congestion: A profile SHOULD specify the congestion control
    behavior appropriate for that profile.

Underlying protocol: Use of a particular underlying network or
    transport layer protocol to carry RTP packets MAY be required.

Transport mapping: A mapping of RTP and RTCP to transport-level
    addresses, e.g., UDP ports, other than the standard mapping
    defined in Section 11, p. 68 may be specified.

Encapsulation: An encapsulation of RTP packets may be defined to
    allow multiple RTP data packets to be carried in one lower-layer
    packet or to provide framing over underlying protocols that do not
    already do so (Section 11, p. 69).

It is not expected that a new profile will be required for every
application.  Within one application class, it would be better to
extend an existing profile rather than make a new one in order to
facilitate interoperation among the applications since each will
typically run under only one profile.  Simple extensions such as the
definition of additional payload type values or RTCP packet types may
be accomplished by registering them through IANA and publishing their
descriptions in an addendum to the profile or in a payload format
specification.
