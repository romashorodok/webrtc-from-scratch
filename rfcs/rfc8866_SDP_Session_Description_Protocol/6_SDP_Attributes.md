6. SDP Attributes
The following attributes are defined. Since application writers may add new attributes as they are required, this list is not exhaustive. Registration procedures for new attributes are defined in Section 8.2.4. Syntax is provided using ABNF [RFC7405] with some of the rules defined further in Section 9.

6.1. cat (Category)
Name:
cat
Value:
cat-value
Usage Level:
session
Charset Dependent:
no
Syntax:

      cat-value = category
      category = non-ws-string
Example:

      a=cat:foo.bar
This attribute gives the dot-separated hierarchical category of the session. This is to enable a receiver to filter unwanted sessions by category. There is no central registry of categories. This attribute is obsolete and SHOULD NOT be used. It SHOULD be ignored if received.

6.2. keywds (Keywords)
Name:
keywds
Value:
keywds-value
Usage Level:
session
Charset Dependent:
yes
Syntax:

      keywds-value = keywords
      keywords = text
Example:

      a=keywds:SDP session description protocol
Like the "a=cat:" attribute, this was intended to assist identifying wanted sessions at the receiver, and to allow a receiver to select interesting sessions based on keywords describing the purpose of the session; however, there is no central registry of keywords. Its value should be interpreted in the charset specified for the session description if one is specified, or by default in ISO 10646/UTF-8. This attribute is obsolete and SHOULD NOT be used. It SHOULD be ignored if received.

6.3. tool
Name:
tool
Value:
tool-value
Usage Level:
session
Charset Dependent:
no
Syntax:

      tool-value = tool-name-and-version
      tool-name-and-version = text
Example:

      a=tool:foobar V3.2
This gives the name and version number of the tool used to create the session description.

6.4. ptime (Packet Time)
Name:
ptime
Value:
ptime-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      ptime-value = non-zero-int-or-real
Example:

      a=ptime:20
This gives the length of time in milliseconds represented by the media in a packet. This is probably only meaningful for audio data, but may be used with other media types if it makes sense. It should not be necessary to know "a=ptime:" to decode RTP or vat audio, and it is intended as a recommendation for the encoding/packetization of audio.

6.5. maxptime (Maximum Packet Time)
Name:
maxptime
Value:
maxptime-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      maxptime-value = non-zero-int-or-real
Example:

      a=maxptime:20
This gives the maximum amount of media that can be encapsulated in each packet, expressed as time in milliseconds. The time SHALL be calculated as the sum of the time the media present in the packet represents. For frame-based codecs, the time SHOULD be an integer multiple of the frame size. This attribute is probably only meaningful for audio data, but may be used with other media types if it makes sense. Note that this attribute was introduced after [RFC2327], and implementations that have not been updated will ignore this attribute.

6.6. rtpmap
Name:
rtpmap
Value:
rtpmap-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      rtpmap-value = payload-type SP encoding-name
        "/" clock-rate [ "/" encoding-params ]
      payload-type = zero-based-integer
      encoding-name = token
      clock-rate = integer
      encoding-params = channels
      channels = integer
This attribute maps from an RTP payload type number (as used in an "m=" line) to an encoding name denoting the payload format to be used. It also provides information on the clock rate and encoding parameters. Note that the payload type number is indicated in a 7-bit field, limiting the values to inclusively between 0 and 127.

Although an RTP profile can make static assignments of payload type numbers to payload formats, it is more common for that assignment to be done dynamically using "a=rtpmap:" attributes. As an example of a static payload type, consider u-law PCM encoded single-channel audio sampled at 8 kHz. This is completely defined in the RTP audio/video profile as payload type 0, so there is no need for an "a=rtpmap:" attribute, and the media for such a stream sent to UDP port 49232 can be specified as:

          m=audio 49232 RTP/AVP 0
An example of a dynamic payload type is 16-bit linear encoded stereo audio sampled at 16 kHz. If we wish to use the dynamic RTP/AVP payload type 98 for this stream, additional information is required to decode it:

          m=audio 49232 RTP/AVP 98
          a=rtpmap:98 L16/16000/2
Up to one "a=rtpmap:" attribute can be defined for each media format specified. Thus, we might have the following:

          m=audio 49230 RTP/AVP 96 97 98
          a=rtpmap:96 L8/8000
          a=rtpmap:97 L16/8000
          a=rtpmap:98 L16/11025/2
RTP profiles that specify the use of dynamic payload types MUST define the set of valid encoding names and/or a means to register encoding names if that profile is to be used with SDP. The "RTP/AVP" and "RTP/SAVP" profiles use media subtypes for encoding names, under the top-level media type denoted in the "m=" line. In the example above, the media types are "audio/L8" and "audio/L16".

For audio streams, encoding-params indicates the number of audio channels. This parameter is OPTIONAL and may be omitted if the number of channels is one, provided that no additional parameters are needed.

For video streams, no encoding parameters are currently specified.

Additional encoding parameters MAY be defined in the future, but codec-specific parameters SHOULD NOT be added. Parameters added to an "a=rtpmap:" attribute SHOULD only be those required for a session directory to make the choice of appropriate media to participate in a session. Codec-specific parameters should be added in other attributes (for example, "a=fmtp:").

Note: RTP audio formats typically do not include information about the number of samples per packet. If a non-default (as defined in the RTP Audio/Video Profile [RFC3551]) packetization is required, the "a=ptime:" attribute is used as given in Section 6.4.

6.7. Media Direction Attributes
At most one occurrence of "a=recvonly", "a=sendrecv", "a=sendonly", or "a=inactive" MAY appear at session level, and at most one MAY appear in each media description.

If any one of these appears in a media description, then it applies for that media description. If none appears in a media description, then the one from session level, if any, applies to that media description.

If none of the media direction attributes is present at either session level or media level, "a=sendrecv" SHOULD be assumed as the default.

Within the following SDP example, the "a=sendrecv" attribute applies to the first audio media and the "a=inactive" attribute applies to the others.

      v=0
      o=jdoe 3724395000 3724395001 IN IP6 2001:db8::1
      s=-
      c=IN IP6 2001:db8::1
      t=0 0
      a=inactive
      m=audio 49170 RTP/AVP 0
      a=sendrecv
      m=audio 49180 RTP/AVP 0
      m=video 51372 RTP/AVP 99
      a=rtpmap:99 h263-1998/90000
6.7.1. recvonly (Receive-Only)
Name:
recvonly
Value:
Usage Level:
session, media
Charset Dependent:
no
Example:

      a=recvonly
This specifies that the tools should be started in receive-only mode where applicable. Note that receive-only mode applies to the media only, not to any associated control protocol. An RTP-based system in receive-only mode MUST still send RTCP packets as described in [RFC3550], Section 6.

6.7.2. sendrecv (Send-Receive)
Name:
sendrecv
Value:
Usage Level:
session, media
Charset Dependent:
no
Example:

      a=sendrecv
This specifies that the tools should be started in send and receive mode. This is necessary for interactive multimedia conferences with tools that default to receive-only mode.

6.7.3. sendonly (Send-Only)
Name:
sendonly
Value:
Usage Level:
session, media
Charset Dependent:
no
Example:

      a=sendonly
This specifies that the tools should be started in send-only mode. An example may be where a different unicast address is to be used for a traffic destination than for a traffic source. In such a case, two media descriptions may be used, one in send-only mode and one in receive-vonly mode. Note that send-only mode applies only to the media, and any associated control protocol (e.g., RTCP) SHOULD still be received and processed as normal.

6.7.4. inactive
Name:
inactive
Value:
Usage Level:
session, media
Charset Dependent:
no
Example:

      a=inactive
This specifies that the tools should be started in inactive mode. This is necessary for interactive multimedia conferences where users can put other users on hold. No media is sent over an inactive media stream. Note that an RTP-based system MUST still send RTCP (if RTCP is used), even if started in inactive mode.

6.8. orient (Orientation)
Name:
orient
Value:
orient-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      orient-value = portrait / landscape / seascape
      portrait  = %s"portrait"
      landscape = %s"landscape"
      seascape  = %s"seascape"
         ; NOTE: These names are case-sensitive.
Example:

      a=orient:portrait
Normally this is only used for a whiteboard or presentation tool. It specifies the orientation of the workspace on the screen. Permitted values are "portrait", "landscape", and "seascape" (upside-down landscape).

6.9. type (Conference Type)
Name:
type
Value:
type-value
Usage Level:
session
Charset Dependent:
no
Syntax:

      type-value = conference-type
      conference-type = broadcast / meeting / moderated / test /
                        H332
      broadcast = %s"broadcast"
      meeting   = %s"meeting"
      moderated = %s"moderated"
      test      = %s"test"
      H332      = %s"H332"
         ; NOTE: These names are case-sensitive.
Example:

      a=type:moderated
This specifies the type of the multimedia conference. Allowed values are "broadcast", "meeting", "moderated", "test", and "H332". These values have implications for other options that are likely to be appropriate:

When "a=type:broadcast" is specified, "a=recvonly" is probably appropriate for those connecting.
When "a=type:meeting" is specified, "a=sendrecv" is likely to be appropriate.
"a=type:moderated" suggests the use of a floor control tool and that the media tools be started so as to mute new sites joining the multimedia conference.
Specifying "a=type:H332" indicates that this loosely coupled session is part of an H.332 session as defined in the ITU H.332 specification [ITU.H332.1998]. Media tools should be started using "a=recvonly".
Specifying "a=type:test" is suggested as a hint that, unless explicitly requested otherwise, receivers can safely avoid displaying this session description to users.
6.10. charset (Character Set)
Name:
charset
Value:
charset-value
Usage Level:
session
Charset Dependent:
no
Syntax:

      charset-value = <defined in [RFC2978]>
This specifies the character set to be used to display the session name and information data. By default, the ISO-10646 character set in UTF-8 encoding is used. If a more compact representation is required, other character sets may be used. For example, the ISO 8859-1 is specified with the following SDP attribute:

      a=charset:ISO-8859-1
The charset specified MUST be one of those registered in the IANA Character Sets registry (http://www.iana.org/assignments/character-sets), such as ISO-8859-1. The character set identifier is a string that MUST be compared against identifiers from the "Name" or "Preferred MIME Name" field of the registry using a case-insensitive comparison. If the identifier is not recognized or not supported, all strings that are affected by it SHOULD be regarded as octet strings.

Charset-dependent fields MUST contain only sequences of bytes that are valid according to the definition of the selected character set. Furthermore, charset-dependent fields MUST NOT contain the bytes 0x00 (Nul), 0x0A (LF), and 0x0d (CR).

6.11. sdplang (SDP Language)
Name:
sdplang
Value:
sdplang-value
Usage Level:
session, media
Charset Dependent:
no
Syntax:

      sdplang-value = Language-Tag
      ; Language-Tag defined in RFC 5646
Example:

      a=sdplang:fr
Multiple "a=sdplang:" attributes can be provided either at session or media level if the session description or media use multiple languages.

As a session-level attribute, it specifies the language for the session description (not the language of the media). As a media-level attribute, it specifies the language for any media-level SDP information-field associated with that media (again not the language of the media), overriding any "a=sdplang:" attributes specified at session level.

In general, sending session descriptions consisting of multiple languages is discouraged. Instead, multiple session descriptions SHOULD be sent describing the session, one in each language. However, this is not possible with all transport mechanisms, and so multiple "a=sdplang:" attributes are allowed although NOT RECOMMENDED.

The "a=sdplang:" attribute value must be a single language tag [RFC5646]. An "a=sdplang:" attribute SHOULD be specified when a session is distributed with sufficient scope to cross geographic boundaries, where the language of recipients cannot be assumed, or where the session is in a different language from the locally assumed norm.

6.12. lang (Language)
Name:
lang
Value:
lang-value
Usage Level:
session, media
Charset Dependent:
no
Syntax:

      lang-value = Language-Tag
      ; Language-Tag defined in RFC 5646
Example:

      a=lang:de
Multiple "a=lang:" attributes can be provided either at session or media level if the session or media has capabilities in more than one language, in which case the order of the attributes indicates the order of preference of the various languages in the session or media, from most preferred to least preferred.

As a session-level attribute, "a=lang:" specifies a language capability for the session being described. As a media-level attribute, it specifies a language capability for that media, overriding any session-level language(s) specified.

The "a=lang:" attribute value must be a single [RFC5646] language tag. An "a=lang:" attribute SHOULD be specified when a session is of sufficient scope to cross geographic boundaries where the language of participants cannot be assumed, or where the session has capabilities in languages different from the locally assumed norm.

The "a=lang:" attribute is supposed to be used for setting the initial language(s) used in the session. Events during the session may influence which language(s) are used, and the participants are not strictly bound to only use the declared languages.

Most real-time use cases start with just one language used, while other cases involve a range of languages, e.g., an interpreted or subtitled session. When more than one "a=lang:" attribute is specified, the "a=lang:" attribute itself does not provide any information about multiple languages being intended to be used during the session, or if the intention is to only select one of the languages. If needed, a new attribute can be defined and used to indicate such intentions. Without such semantics, it is assumed that for a negotiated session one of the declared languages will be selected and used.

6.13. framerate (Frame Rate)
Name:
framerate
Value:
framerate-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      framerate-value = non-zero-int-or-real
Example:

      a=framerate:60
This gives the maximum video frame rate in frames/sec. It is intended as a recommendation for the encoding of video data. Decimal representations of fractional values are allowed. It is defined only for video media.

6.14. quality
Name:
quality
Value:
quality-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      quality-value = zero-based-integer
Example:

      a=quality:10
This gives a suggestion for the quality of the encoding as an integer value. The intention of the quality attribute for video is to specify a non-default trade-off between frame-rate and still-image quality. For video, the value is in the range 0 to 10, with the following suggested meaning:

Table 2: Encoding Quality Values
10	the best still-image quality the compression scheme can give.
5	the default behavior given no quality suggestion.
0	the worst still-image quality the codec designer thinks is still usable.
6.15. fmtp (Format Parameters)
Name:
fmtp
Value:
fmtp-value
Usage Level:
media
Charset Dependent:
no
Syntax:

      fmtp-value = fmt SP format-specific-params
      format-specific-params = byte-string
        ; Notes:
        ; - The format parameters are media type parameters and
        ;   need to reflect their syntax.
Example:

      a=fmtp:96 profile-level-id=42e016;max-mbps=108000;max-fs=3600
This attribute allows parameters that are specific to a particular format to be conveyed in a way that SDP does not have to understand them. The format must be one of the formats specified for the media. Format-specific parameters, semicolon separated, may be any set of parameters required to be conveyed by SDP and given unchanged to the media tool that will use this format. At most one instance of this attribute is allowed for each format.

The "a=fmtp:" attribute may be used to specify parameters for any protocol and format that defines use of such parameters.

