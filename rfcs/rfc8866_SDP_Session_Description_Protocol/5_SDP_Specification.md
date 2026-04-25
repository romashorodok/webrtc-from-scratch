# 5. SDP Specification
An SDP description is denoted by the media type "application/sdp" (See Section 8).

An SDP description is entirely textual. SDP field names and attribute names use only the US-ASCII subset of UTF-8 [RFC3629], but textual fields and attribute values MAY use the full ISO 10646 character set in UTF-8 encoding, or some other character set defined by the "a=charset:" attribute (Section 6.10). Field and attribute values that use the full UTF-8 character set are never directly compared, hence there is no requirement for UTF-8 normalization. The textual form, as opposed to a binary encoding such as ASN.1 or XDR, was chosen to enhance portability, to enable a variety of transports to be used, and to allow flexible, text-based toolkits to be used to generate and process session descriptions. However, since SDP may be used in environments where the maximum permissible size of a session description is limited, the encoding is deliberately compact. Also, since descriptions may be transported via very unreliable means or damaged by an intermediate caching server, the encoding was designed with strict order and formatting rules so that most errors would result in malformed session descriptions that could be detected easily and discarded.

An SDP description consists of a number of lines of text of the form:

   <type>=<value>
where <type> is exactly one case-significant character and <value> is structured text whose format depends on <type>. In general, <value> is either a number of subfields delimited by a single space character or a free format string, and is case-significant unless a specific field defines otherwise. Whitespace separators are not used on either side of the "=" sign, however, the value can contain a leading whitespace as part of its syntax, i.e., that whitespace is part of the value.

An SDP description MUST conform to the syntax defined in Section 9. The following is an overview of the syntax.

An SDP description consists of a session-level section followed by zero or more media descriptions. The session-level section starts with a "v=" line and continues to the first media description (or the end of the whole description, whichever comes first). Each media description starts with an "m=" line and continues to the next media description or the end of the whole session description, whichever comes first. In general, session-level values are the default for all media unless overridden by an equivalent media-level value.

Some lines in each description are required and some are optional, but when present, they must appear in exactly the order given here. (The fixed order greatly enhances error detection and allows for a simple parser). In the following overview, optional items are marked with "*".

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
