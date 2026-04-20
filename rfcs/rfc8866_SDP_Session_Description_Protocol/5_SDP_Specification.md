5. SDP Specification
An SDP description is denoted by the media type "application/sdp" (See Section 8).

An SDP description is entirely textual. SDP field names and attribute names use only the US-ASCII subset of UTF-8 [RFC3629], but textual fields and attribute values MAY use the full ISO 10646 character set in UTF-8 encoding, or some other character set defined by the "a=charset:" attribute (Section 6.10). Field and attribute values that use the full UTF-8 character set are never directly compared, hence there is no requirement for UTF-8 normalization. The textual form, as opposed to a binary encoding such as ASN.1 or XDR, was chosen to enhance portability, to enable a variety of transports to be used, and to allow flexible, text-based toolkits to be used to generate and process session descriptions. However, since SDP may be used in environments where the maximum permissible size of a session description is limited, the encoding is deliberately compact. Also, since descriptions may be transported via very unreliable means or damaged by an intermediate caching server, the encoding was designed with strict order and formatting rules so that most errors would result in malformed session descriptions that could be detected easily and discarded.

An SDP description consists of a number of lines of text of the form:

   <type>=<value>
where <type> is exactly one case-significant character and <value> is structured text whose format depends on <type>. In general, <value> is either a number of subfields delimited by a single space character or a free format string, and is case-significant unless a specific field defines otherwise. Whitespace separators are not used on either side of the "=" sign, however, the value can contain a leading whitespace as part of its syntax, i.e., that whitespace is part of the value.

An SDP description MUST conform to the syntax defined in Section 9. The following is an overview of the syntax.

An SDP description consists of a session-level section followed by zero or more media descriptions. The session-level section starts with a "v=" line and continues to the first media description (or the end of the whole description, whichever comes first). Each media description starts with an "m=" line and continues to the next media description or the end of the whole session description, whichever comes first. In general, session-level values are the default for all media unless overridden by an equivalent media-level value.

Some lines in each description are required and some are optional, but when present, they must appear in exactly the order given here. (The fixed order greatly enhances error detection and allows for a simple parser). In the following overview, optional items are marked with a "*".

   Session description
      v=  (protocol version)
      o=  (originator and session identifier)
      s=  (session name)
      i=* (session information)
      u=* (URI of description)
      e=* (email address)
      p=* (phone number)
      c=* (connection information -- not required if included in
           all media descriptions)
      b=* (zero or more bandwidth information lines)
      One or more time descriptions:
        ("t=", "r=" and "z=" lines; see below)
      k=* (obsolete)
      a=* (zero or more session attribute lines)
      Zero or more media descriptions

   Time description
      t=  (time the session is active)
      r=* (zero or more repeat times)
      z=* (optional time zone offset line)

   Media description, if present
      m=  (media name and transport address)
      i=* (media title)
      c=* (connection information -- optional if included at
           session level)
      b=* (zero or more bandwidth information lines)
      k=* (obsolete)
      a=* (zero or more media attribute lines)
The set of type letters is deliberately small and not intended to be extensible -- an SDP parser MUST completely ignore or reject any session description that contains a type letter that it does not understand. The attribute mechanism ("a=", described in Section 5.13) is the primary means for extending SDP and tailoring it to particular applications or media. Some attributes (the ones listed in Section 6) have a defined meaning, but others may be added on a media- or session-specific basis. (Attribute scopes in addition to media-specific and session-specific scopes may also be defined in extensions to this document, e.g., [RFC5576] and [RFC8864].) An SDP parser MUST ignore any attribute it doesn't understand.

An SDP description may contain URIs that reference external content in the "u=", "k=", and "a=" lines. These URIs may be dereferenced in some cases, making the session description non-self-contained.

The connection ("c=") information in the session-level section applies to all the media descriptions of that session unless overridden by connection information in the media description. For instance, in the example below, each audio media description behaves as if it were given a "c=IN IP4 198.51.100.1".

An example SDP description is:

      v=0
      o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
      s=Call to John Smith
      i=SDP Offer #1
      u=http://www.jdoe.example.com/home.html
      e=Jane Doe <jane@jdoe.example.com>
      p=+1 617 555-6011
      c=IN IP4 198.51.100.1
      t=0 0
      m=audio 49170 RTP/AVP 0
      m=audio 49180 RTP/AVP 0
      m=video 51372 RTP/AVP 99
      c=IN IP6 2001:db8::2
      a=rtpmap:99 h263-1998/90000
Text-containing fields such as the session-name-field and information-field are octet strings that may contain any octet with the exceptions of 0x00 (Nul), 0x0a (ASCII newline), and 0x0d (ASCII carriage return). The sequence CRLF (0x0d0a) is used to end a line, although parsers SHOULD be tolerant and also accept lines terminated with a single newline character. If the "a=charset:" attribute is not present, these octet strings MUST be interpreted as containing ISO-10646 characters in UTF-8 encoding. When the "a=charset:" attribute is present the session-name-field, information-field, and some attribute fields are interpreted according to the selected character set.

A session description can contain domain names in the "o=", "u=", "e=", "c=", and "a=" lines. Any domain name used in SDP MUST comply with [RFC1034] and [RFC1035]. Internationalized domain names (IDNs) MUST be represented using the ASCII Compatible Encoding (ACE) form defined in [RFC5890] and MUST NOT be directly represented in UTF-8 or any other encoding (this requirement is for compatibility with [RFC2327] and other early SDP-related standards, which predate the development of internationalized domain names).

5.1. Protocol Version ("v=")
      v=0
The "v=" line (version-field) gives the version of the Session Description Protocol. This memo defines version 0. There is no minor version number.

5.2. Origin ("o=")
     o=<username> <sess-id> <sess-version> <nettype> <addrtype>
     <unicast-address>
The "o=" line (origin-field) gives the originator of the session (her username and the address of the user's host) plus a session identifier and version number:

<username>
is the user's login on the originating host, or it is "-" if the originating host does not support the concept of user IDs. The <username> MUST NOT contain spaces.
<sess-id>
is a numeric string such that the tuple of <username>, <sess-id>, <nettype>, <addrtype>, and <unicast-address> forms a globally unique identifier for the session. The method of <sess-id> allocation is up to the creating tool, but a timestamp, in seconds since January 1, 1900 UTC, is recommended to ensure uniqueness.
<sess-version>
is a version number for this session description. Its usage is up to the creating tool, so long as <sess-version> is increased when a modification is made to the session description. Again, as with <sess-id> it is RECOMMENDED that a timestamp be used.
<nettype>
is a text string giving the type of network. Initially, "IN" is defined to have the meaning "Internet", but other values MAY be registered in the future (see Section 8).
<addrtype>
is a text string giving the type of the address that follows. Initially, "IP4" and "IP6" are defined, but other values MAY be registered in the future (see Section 8).
<unicast-address>
is an address of the machine from which the session was created. For an address type of "IP4", this is either a fully qualified domain name of the machine or the dotted-decimal representation of an IP version 4 address of the machine. For an address type of "IP6", this is either a fully qualified domain name of the machine or the address of the machine represented as specified in Section 4 of [RFC5952]. For both "IP4" and "IP6", the fully qualified domain name is the form that SHOULD be given unless this is unavailable, in which case a globally unique address MAY be substituted.
In general, the "o=" line serves as a globally unique identifier for this version of the session description, and the subfields excepting the version, taken together identify the session irrespective of any modifications.

For privacy reasons, it is sometimes desirable to obfuscate the username and IP address of the session originator. If this is a concern, an arbitrary <username> and private <unicast-address> MAY be chosen to populate the "o=" line, provided that these are selected in a manner that does not affect the global uniqueness of the field.

5.3. Session Name ("s=")
   s=<session name>
The "s=" line (session-name-field) is the textual session name. There MUST be one and only one "s=" line per session description. The "s=" line MUST NOT be empty. If a session has no meaningful name, then "s= " or "s=-" (i.e., a single space or dash as the session name) is RECOMMENDED. If a session-level "a=charset:" attribute is present, it specifies the character set used in the "s=" field. If a session-level "a=charset:" attribute is not present, the "s=" field MUST contain ISO 10646 characters in UTF-8 encoding.

5.4. Session Information ("i=")
   i=<session information>
The "i=" line (information-field) provides textual information about the session. There can be at most one session-level "i=" line per session description, and at most one "i=" line in each media description. Unless a media-level "i=" line is provided, the session-level "i=" line applies to that media description. If the "a=charset:" attribute is present, it specifies the character set used in the "i=" line. If the "a=charset:" attribute is not present, the "i=" line MUST contain ISO 10646 characters in UTF-8 encoding.

At most one "i=" line can be used for each media description. In media definitions, "i=" lines are primarily intended for labeling media streams. As such, they are most likely to be useful when a single session has more than one distinct media stream of the same media type. An example would be two different whiteboards, one for slides and one for feedback and questions.

The "i=" line is intended to provide a free-form human-readable description of the session or the purpose of a media stream. It is not suitable for parsing by automata.

5.5. URI ("u=")
   u=<uri>
The "u=" line (uri-field) provides a URI (Uniform Resource Identifier) [RFC3986]. The URI should be a pointer to additional human readable information about the session. This line is OPTIONAL. No more than one "u=" line is allowed per session description.

5.6. Email Address and Phone Number ("e=" and "p=")
   e=<email-address>
   p=<phone-number>
The "e=" line (email-field) and "p=" line (phone-field) specify contact information for the person responsible for the session. This is not necessarily the same person that created the session description.

Inclusion of an email address or phone number is OPTIONAL.

If an email address or phone number is present, it MUST be specified before the first media description. More than one email or phone line can be given for a session description.

Phone numbers SHOULD be given in the form of an international public telecommunication number (see ITU-T Recommendation E.164 [E164]) preceded by a "+". Spaces and hyphens may be used to split up a phone-field to aid readability if desired. For example:

   p=+1 617 555-6011
Both email addresses and phone numbers can have an OPTIONAL free text string associated with them, normally giving the name of the person who may be contacted. This MUST be enclosed in parentheses if it is present. For example:

   e=j.doe@example.com (Jane Doe)
The alternative [RFC5322] name quoting convention is also allowed for both email addresses and phone numbers. For example:

   e=Jane Doe <j.doe@example.com>
The free text string SHOULD be in the ISO-10646 character set with UTF-8 encoding, or alternatively in ISO-8859-1 or other encodings if the appropriate session-level "a=charset:" attribute is set.

5.7. Connection Information ("c=")
   c=<nettype> <addrtype> <connection-address>
The "c=" line (connection-field) contains information necessary to establish a network connection.

A session description MUST contain either at least one "c=" line in each media description or a single "c=" line at the session level. It MAY contain a single session-level "c=" line and additional media-level "c=" line(s) per-media-description, in which case the media-level values override the session-level settings for the respective media.

The first subfield (<nettype>) is the network type, which is a text string giving the type of network. Initially, "IN" is defined to have the meaning "Internet", but other values MAY be registered in the future (see Section 8).

The second subfield (<addrtype>) is the address type. This allows SDP to be used for sessions that are not IP based. This memo only defines "IP4" and "IP6", but other values MAY be registered in the future (see Section 8).

The third subfield (<connection-address>) is the connection address. Additional subfields MAY be added after the connection address depending on the value of the <addrtype> subfield.

When the <addrtype> is "IP4" or "IP6", the connection address is defined as follows:

If the session is multicast, the connection address will be an IP multicast group address. If the session is not multicast, then the connection address contains the unicast IP address of the expected data source, data relay, or data sink as determined by additional attribute-fields (Section 5.13). It is not expected that unicast addresses will be given in a session description that is communicated by a multicast announcement, though this is not prohibited.
Sessions using an "IP4" multicast connection address MUST also have a time to live (TTL) value present in addition to the multicast address. The TTL and the address together define the scope with which multicast packets sent in this session will be sent. TTL values MUST be in the range 0-255. Although the TTL MUST be specified, its use to scope multicast traffic is deprecated; applications SHOULD use an administratively scoped address instead.
The TTL for the session is appended to the address using a slash as a separator. An example is:

   c=IN IP4 233.252.0.1/127
"IP6" multicast does not use TTL scoping, and hence the TTL value MUST NOT be present for "IP6" multicast. It is expected that IPv6 scoped addresses will be used to limit the scope of multimedia conferences.

Hierarchical or layered encoding schemes are data streams where the encoding from a single media source is split into a number of layers. The receiver can choose the desired quality (and hence bandwidth) by only subscribing to a subset of these layers. Such layered encodings are normally transmitted in multiple multicast groups to allow multicast pruning. This technique keeps unwanted traffic from sites only requiring certain levels of the hierarchy. For applications requiring multiple multicast groups, we allow the following notation to be used for the connection address:

   <base multicast address>[/<ttl>]/<number of addresses>
If the number of addresses is not given, it is assumed to be one. Multicast addresses so assigned are contiguously allocated above the base address, so that, for example:

   c=IN IP4 233.252.0.1/127/3
would state that addresses 233.252.0.1, 233.252.0.2, and 233.252.0.3 are to be used with a TTL of 127. This is semantically identical to including multiple "c=" lines in a media description:

   c=IN IP4 233.252.0.1/127
   c=IN IP4 233.252.0.2/127
   c=IN IP4 233.252.0.3/127
Similarly, an IPv6 example would be:

   c=IN IP6 ff00::db8:0:101/3
which is semantically equivalent to:

   c=IN IP6 ff00::db8:0:101
   c=IN IP6 ff00::db8:0:102
   c=IN IP6 ff00::db8:0:103
(remember that the TTL subfield is not present in "IP6" multicast).

Multiple addresses or "c=" lines MAY be specified on a per media description basis only if they provide multicast addresses for different layers in a hierarchical or layered encoding scheme. Multiple addresses or "c=" lines MUST NOT be specified at session level.

The slash notation for multiple addresses described above MUST NOT be used for IP unicast addresses.

5.8. Bandwidth Information ("b=")
   b=<bwtype>:<bandwidth>
The OPTIONAL "b=" line (bandwidth-field) denotes the proposed bandwidth to be used by the session or media description. The <bwtype> is an alphanumeric modifier that provides the meaning of the <bandwidth> number. Two values are defined in this specification, but other values MAY be registered in the future (see Section 8 and [RFC3556], [RFC3890]):

CT
If the bandwidth of a session is different from the bandwidth implicit from the scope, a "b=CT:" line SHOULD be supplied for the session giving the proposed upper limit to the bandwidth used (the "conference total" bandwidth). Similarly, if the bandwidth of bundled media streams [RFC8843] in an "m=" line is different from the implicit value from the scope, a "b=CT:" line SHOULD be supplied in the media level. The primary purpose of this is to give an approximate idea as to whether two or more sessions (or bundled media streams) can coexist simultaneously. Note that a "b=CT:" line gives a total bandwidth figure for all the media at all endpoints.

The Mux Category for "b=CT:" is NORMAL. This is discussed in [RFC8859].

AS
The bandwidth is interpreted to be application specific (it will be the application's concept of maximum bandwidth). Normally, this will coincide with what is set on the application's "maximum bandwidth" control if applicable. For RTP-based applications, the "b=AS:" line gives the RTP "session bandwidth" as defined in Section 6.2 of [RFC3550]. Note that a "b=AS:" line gives a bandwidth figure for a single media at a single endpoint, although there may be many endpoints sending simultaneously.

The Mux Category for "b=AS:" is SUM. This is discussed in [RFC8859].

[RFC4566] defined an "X-" prefix for <bwtype> names. This was intended for experimental purposes only. For example:

   b=X-YZ:128
Use of the "X-" prefix is NOT RECOMMENDED. Instead new (non "X-" prefix) <bwtype> names SHOULD be defined, and then MUST be registered with IANA in the standard namespace. SDP parsers MUST ignore bandwidth-fields with unknown <bwtype> names. The <bwtype> names MUST be alphanumeric and, although no length limit is given, it is recommended that they be short.

The <bandwidth> is interpreted as kilobits per second by default (including the transport and network-layer, but not the link-layer, overhead). The definition of a new <bwtype> modifier MAY specify that the bandwidth is to be interpreted in some alternative unit (the "CT" and "AS" modifiers defined in this memo use the default units).

5.9. Time Active ("t=")
   t=<start-time> <stop-time>
A "t=" line (time-field) begins a time description that specifies the start and stop times for a session. Multiple time descriptions MAY be used if a session is active at multiple irregularly spaced times; each additional time description specifies additional periods of time for which the session will be active. If the session is active at regular repeat times, a repeat description, begun by an "r=" line (see Section 5.10) can be included following the time-field -- in which case the time-field specifies the start and stop times of the entire repeat sequence.

The following example specifies two active intervals:

   t=3724394400 3724398000 ; Mon 8-Jan-2018 10:00-11:00 UTC
   t=3724484400 3724488000 ; Tue 9-Jan-2018 11:00-12:00 UTC
The first and second subfields of the time-field give the start and stop times, respectively, for the session. These are the decimal representation of time values in seconds since January 1, 1900 UTC. To convert these values to Unix time (UTC), subtract decimal 2208988800.

Some time representations will wrap in the year 2036. Because SDP uses an arbitrary length decimal representation, it does not have this issue. Implementations of SDP need to be prepared to handle these larger values.

If the <stop-time> is set to zero, then the session is not bounded, though it will not become active until after the <start-time>. If the <start-time> is also zero, the session is regarded as permanent.

User interfaces SHOULD strongly discourage the creation of unbounded and permanent sessions as they give no information about when the session is actually going to terminate, and so make scheduling difficult.

The general assumption may be made, when displaying unbounded sessions that have not timed out to the user, that an unbounded session will only be active until half an hour from the current time or the session start time, whichever is the later. If behavior other than this is required, a <stop-time> SHOULD be given and modified as appropriate when new information becomes available about when the session should really end.

Permanent sessions may be shown to the user as never being active unless there are associated repeat times that state precisely when the session will be active.

5.10. Repeat Times ("r=")
   r=<repeat interval> <active duration> <offsets from start-time>
An"r=" line (repeat-field) specifies repeat times for a session. If needed to express complex schedules, multiple repeat-fields may be included. For example, if a session is active at 10am on Monday and 11am on Tuesday for one hour each week for three months, then the <start-time> in the corresponding "t=" line would be the representation of 10am on the first Monday, the <repeat interval> would be 1 week, the <active duration> would be 1 hour, and the offsets would be zero and 25 hours. The corresponding "t=" line stop time would be the representation of the end of the last session three months later. By default, all subfields are in seconds, so the "r=" and "t=" lines might be the following:

   t=3724394400 3730536000 ; Mon 8-Jan-2018 10:00-11:00 UTC
                           ; Tues 20-Mar-2018 12:00 UTC
   r=604800 3600 0 90000   ; 1 week, 1 hour, zero, 25 hours
To make the description more compact, times may also be given in units of days, hours, or minutes. The syntax for these is a number immediately followed by a single case-sensitive character. Fractional units are not allowed -- a smaller unit should be used instead. The following unit specification characters are allowed:

Table 1: Time Unit Specification Characters
d	days (86400 seconds)
h	hours (3600 seconds)
m	minutes (60 seconds)
s	seconds (allowed for completeness)
Thus, the above repeat-field could also have been written:

   r=7d 1h 0 25h
Monthly and yearly repeats cannot be directly specified with a single SDP repeat time; instead, separate time-descriptions should be used to explicitly list the session times.

5.11. Time Zone Adjustment ("z=")
   z=<adjustment time> <offset> <adjustment time> <offset> ....
A "z=" line (zone-field) is an optional modifier to the repeat-fields it immediately follows. It does not apply to any other fields.

To schedule a repeated session that spans a change from daylight saving time to standard time or vice versa, it is necessary to specify offsets from the base time. This is required because different time zones change time at different times of day, different countries change to or from daylight saving time on different dates, and some countries do not have daylight saving time at all.

Thus, in order to schedule a session that is at the same time winter and summer, it must be possible to specify unambiguously by whose time zone a session is scheduled. To simplify this task for receivers, we allow the sender to specify the time (represented as seconds since January 1, 1900 UTC) that a time zone adjustment happens and the offset from the time when the session was first scheduled. The "z=" line allows the sender to specify a list of these adjustment times and offsets from the base time.

An example might be the following:

   t=3724394400 3754123200       ; Mon 8-Jan-2018 10:00 UTC
                                 ; Tues 18-Dec-2018 12:00 UTC
   r=604800 3600 0 90000         ; 1 week, 1 hour, zero, 25 hours
   z=3730928400 -1h 3749680800 0 ; Sun 25-Mar-2018 1:00 UTC,
                                 ; offset 1 hour,
                                 ; Sun 28-Oct-2018 2:00 UTC,
                                 ; no offset
This specifies that at time 3730928400 (Sun 25-Mar-2018 1:00 UTC, the onset of British Summer Time) the time base by which the session's repeat times are calculated is shifted back by 1 hour, and that at time 3749680800 (Sun 28-Oct-2018 2:00 UTC, the end of British Summer Time) the session's original time base is restored. Adjustments are always relative to the specified start time -- they are not cumulative.

If a session is likely to last several years, it is expected that the session description will be modified periodically rather than transmit several years' worth of adjustments in one session description.

5.12. Encryption Keys ("k=")
   k=<method>
   k=<method>:<encryption key>
The "k=" line (key-field) is obsolete and MUST NOT be used. It is included in this document for legacy reasons. One MUST NOT include a "k=" line in an SDP, and MUST discard it if it is received in an SDP.

5.13. Attributes ("a=")
   a=<attribute-name>
   a=<attribute-name>:<attribute-value>
Attributes are the primary means for extending SDP. Attributes may be defined to be used as session-level attributes, media-level attributes, or both. (Attribute scopes in addition to media-level and session-level scopes may also be defined in extensions to this document, e.g., [RFC5576] and [RFC8864].)

A media description may contain any number of "a=" lines (attribute-fields) that are media description specific. These are referred to as media-level attributes and add information about the media description. Attribute-fields can also be added before the first media description; these session-level attributes convey additional information that applies to the session as a whole rather than to individual media descriptions.

Attribute-fields may be of two forms:

A property attribute is simply of the form "a=<attribute-name>". These are binary attributes, and the presence of the attribute conveys that the attribute is a property of the session. An example might be "a=recvonly".
A value attribute is of the form "a=<attribute-name>:<attribute-value>". For example, a whiteboard could have the value attribute "a=orient:landscape".
Attribute interpretation depends on the media tool being invoked. Thus receivers of session descriptions should be configurable in their interpretation of session descriptions in general and of attributes in particular.

Attribute names MUST use the US-ASCII subset of ISO-10646/UTF-8.

Attribute values are octet strings, and MAY use any octet value except 0x00 (Nul), 0x0A (LF), and 0x0D (CR). By default, attribute values are to be interpreted as in ISO-10646 character set with UTF-8 encoding. Unlike other text fields, attribute values are NOT normally affected by the "a=charset:" attribute as this would make comparisons against known values problematic. However, when an attribute is defined, it can be defined to be charset dependent, in which case its value should be interpreted in the session charset rather than in ISO-10646.

Attributes MUST be registered with IANA (see Section 8). If an attribute is received that is not understood, it MUST be ignored by the receiver.

5.14. Media Descriptions ("m=")
   m=<media> <port> <proto> <fmt> ...
A session description may contain a number of media descriptions. Each media description starts with an "m=" line (media-field) and is terminated by either the next "m=" line or by the end of the session description. A media-field has several subfields:

<media>
is the media type. This document defines the values "audio", "video", "text", "application", and "message". This list is extended by other memos and may be further extended by additional memos registering media types in the future (see Section 8). For example, [RFC6466] defined the "image" media type.
<port>
is the transport port to which the media stream is sent. The meaning of the transport port depends on the network being used as specified in the relevant "c=" line, and on the transport protocol defined in the <proto> subfield of the media-field. Other ports used by the media application (such as the RTP Control Protocol (RTCP) port [RFC3550]) MAY be derived algorithmically from the base media port or MAY be specified in a separate attribute (for example, the "a=rtcp:" attribute as defined in [RFC3605]).

If noncontiguous ports are used or if they don't follow the parity rule of even RTP ports and odd RTCP ports, the "a=rtcp:" attribute MUST be used. Applications that are requested to send media to a <port> that is odd and where the "a=rtcp:" attribute is present MUST NOT subtract 1 from the RTP port: that is, they MUST send the RTP to the port indicated in <port> and send the RTCP to the port indicated in the "a=rtcp:" attribute.

For applications where hierarchically encoded streams are being sent to a unicast address, it may be necessary to specify multiple transport ports. This is done using a similar notation to that used for IP multicast addresses in the "c=" line:

    m=<media> <port>/<number of ports> <proto> <fmt> ...
In such a case, the ports used depend on the transport protocol. For RTP, the default is that only the even-numbered ports are used for data with the corresponding one-higher odd ports used for the RTCP belonging to the RTP session, and the <number of ports> denoting the number of RTP sessions. For example:

       m=video 49170/2 RTP/AVP 31
would specify that ports 49170 and 49171 form one RTP/RTCP pair, and 49172 and 49173 form the second RTP/RTCP pair. RTP/AVP is the transport protocol, and 31 is the format (see the description of <fmt> below).

This document does not include a mechanism for declaring hierarchically encoded streams using noncontiguous ports. (There is currently no attribute defined that can accomplish this. The "a=rtcp:" attribute defined in [RFC3605] does not handle hierarchical encoding.) If a need arises to declare noncontiguous ports then it will be necessary to define a new attribute to do so.

If multiple addresses are specified in the "c=" line and multiple ports are specified in the "m=" line, a one-to-one mapping from port to the corresponding address is implied. For example:

       m=video 49170/2 RTP/AVP 31
       c=IN IP4 233.252.0.1/127/2
would imply that address 233.252.0.1 is used with ports 49170 and 49171, and address 233.252.0.2 is used with ports 49172 and 49173.

The mapping is similar if multiple addresses are specified using multiple "c=" lines. For example:

       m=video 49170/2 RTP/AVP 31
       c=IN IP6 ff00::db8:0:101
       c=IN IP6 ff00::db8:0:102
would imply that address ff00::db8:0:101 is used with ports 49170 and 49171, and address ff00::db8:0:102 is used with ports 49172 and 49173.

This document gives no meaning to assigning the same media address to multiple media descriptions. Doing so does not implicitly group those media descriptions in any way. An explicit grouping framework (for example, [RFC5888]) should instead be used to express the intended semantics. For instance, see [RFC8843].

<proto>
is the transport protocol. The meaning of the transport protocol is dependent on the address type subfield in the relevant "c=" line. Thus a "c=" line with an address type of "IP4" indicates that the transport protocol runs over IPv4. The following transport protocols are defined, but may be extended through registration of new protocols with IANA (see Section 8):

udp: denotes that the data is transported directly in UDP with no additional framing.
RTP/AVP: denotes RTP [RFC3550] used under the RTP Profile for Audio and Video Conferences with Minimal Control [RFC3551] running over UDP.
RTP/SAVP: denotes the Secure Real-time Transport Protocol [RFC3711] running over UDP.
RTP/SAVPF: denotes SRTP with the Extended SRTP Profile for RTCP-Based Feedback [RFC5124] running over UDP.
The main reason to specify the transport protocol in addition to the media format is that the same standard media formats may be carried over different transport protocols even when the network protocol is the same -- a historical example is vat (MBone's popular multimedia audio tool) Pulse Code Modulation (PCM) audio and RTP PCM audio; another might be TCP/RTP PCM audio. In addition, relays and monitoring tools that are transport-protocol-specific but format-independent are possible.

<fmt>
is a media format description. The fourth and any subsequent subfields describe the format of the media. The interpretation of the media format depends on the value of the <proto> subfield.

If the <proto> subfield is "RTP/AVP" or "RTP/SAVP", the <fmt> subfields contain RTP payload type numbers. When a list of payload type numbers is given, this implies that all of these payload formats MAY be used in the session, and these payload formats are listed in order of preference, with the first format listed being preferred. When multiple payload formats are listed, the first acceptable payload format from the beginning of the list SHOULD be used for the session. For dynamic payload type assignments, the "a=rtpmap:" attribute (see Section 6.6) SHOULD be used to map from an RTP payload type number to a media encoding name that identifies the payload format. The "a=fmtp:" attribute MAY be used to specify format parameters (see Section 6.15).

If the <proto> subfield is "udp", the <fmt> subfields MUST reference a media type describing the format under the "audio", "video", "text", "application", or "message" top-level media types. The media type registration SHOULD define the packet format for use with UDP transport.

For media using other transport protocols, the <fmt> subfield is protocol specific. Rules for interpretation of the <fmt> subfield MUST be defined when registering new protocols (see Section 8.2.2).

Section 3 of [RFC4855] states that the payload format (encoding) names defined in the RTP profile are commonly shown in upper case, while media subtype names are commonly shown in lower case. It also states that both of these names are case-insensitive in both places, similar to parameter names which are case-insensitive both in media type strings and in the default mapping to the SDP "a=fmtp:" attribute.

