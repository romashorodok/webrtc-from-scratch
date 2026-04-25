# RFC 3264: An Offer Answer Model with the Session Description Protocol SDP

Source: `../rfc3264_An_Offer_Answer_Model_with_the_Session_Description_Protocol_SDP.md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `5.1_Unicast_Streams.md` | sec `5.1` | intent `Unicast Streams` | use `If the offerer wishes to only send media on a stream to its peer, it MUST mark the stream as…` | ref `5_Generating_the_Initial_Offer.md`
- `5.2_Multicast_Streams.md` | sec `5.2` | intent `Multicast Streams` | use `If a session description contains a multicast media stream which is listed as receive (send)…` | ref `5_Generating_the_Initial_Offer.md`
- `6.1_Unicast_Streams.md` | sec `6.1` | intent `Unicast Streams` | use `If a stream is offered with a unicast address, the answer for that stream MUST contain a…` | ref `6_Generating_the_Answer.md`
- `6.2_Multicast_Streams.md` | sec `6.2` | intent `Multicast Streams` | use `Unlike unicast, where there is a two-sided view of the stream, there is only a single view of…` | ref `6_Generating_the_Answer.md`
- `8.1_Adding_a_Media_Stream.md` | sec `8.1` | intent `Adding a Media Stream` | use `New media streams are created by new additional media descriptions below the existing ones, or…` | ref `8_Modifying_the_Session.md`
- `8.2_Removing_a_Media_Stream.md` | sec `8.2` | intent `Removing a Media Stream` | use `Existing media streams are removed by creating a new SDP with the port number for that stream…` | ref `8_Modifying_the_Session.md`
- `8.3_Modifying_a_Media_Stream.md` | sec `8.3` | intent `Modifying a Media Stream` | use `Nearly all characteristics of a media stream can be modified.` | ref `8_Modifying_the_Session.md`
- `8.3.1_Modifying_Address_Port_or_Transport.md` | sec `8.3.1` | intent `Modifying Address, Port or Transport` | use `The port number for a stream MAY be changed. To do this, the offerer creates a new media…` | ref `8_Modifying_the_Session.md`
- `8.3.2_Changing_the_Set_of_Media_Formats.md` | sec `8.3.2` | intent `Changing the Set of Media Formats` | use `The list of media formats used in the session MAY be changed. To do this, the offerer creates a…` | ref `8_Modifying_the_Session.md`
- `8.3.3_Changing_Media_Types.md` | sec `8.3.3` | intent `Changing Media Types` | use `The media type (audio, video, etc.) for a stream MAY be changed. It is RECOMMENDED that the…` | ref `8_Modifying_the_Session.md`
- `8.3.4_Changing_Attributes.md` | sec `8.3.4` | intent `Changing Attributes` | use `Any other attributes in a media description MAY be updated in an offer or answer. Generally, an…` | ref `8_Modifying_the_Session.md`
- `8.4_Putting_a_Unicast_Media_Stream_on_Hold.md` | sec `8.4` | intent `Putting a Unicast Media Stream on Hold` | use `If a party in a call wants to put the other party "on hold", i.e., request that it temporarily…` | ref `8_Modifying_the_Session.md`
