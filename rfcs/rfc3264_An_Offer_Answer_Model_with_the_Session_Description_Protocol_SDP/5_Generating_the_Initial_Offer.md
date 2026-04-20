# 5 Generating the Initial Offer

The offer (and answer) MUST be a valid SDP message, as defined by RFC
2327 [1], with one exception.  RFC 2327 mandates that either an e or
a p line is present in the SDP message.  This specification relaxes
that constraint; an SDP formulated for an offer/answer application
MAY omit both the e and p lines.  The numeric value of the session id
and version in the o line MUST be representable with a 64 bit signed
integer.  The initial value of the version MUST be less than
(2**62)-1, to avoid rollovers.  Although the SDP specification allows
for multiple session descriptions to be concatenated together into a
large SDP message, an SDP message used in the offer/answer model MUST
contain exactly one session description.

The SDP "s=" line conveys the subject of the session, which is
reasonably defined for multicast, but ill defined for unicast.  For
unicast sessions, it is RECOMMENDED that it consist of a single space
character (0x20) or a dash (-).

    Unfortunately, SDP does not allow the "s=" line to be empty.

The SDP "t=" line conveys the time of the session.  Generally,
streams for unicast sessions are created and destroyed through
external signaling means, such as SIP.  In that case, the "t=" line
SHOULD have a value of "0 0".

The offer will contain zero or more media streams (each media stream
is described by an "m=" line and its associated attributes).  Zero
media streams implies that the offerer wishes to communicate, but
that the streams for the session will be added at a later time
through a modified offer.  The streams MAY be for a mix of unicast
and multicast; the latter obviously implies a multicast address in
the relevant "c=" line(s).

Construction of each offered stream depends on whether the stream is
multicast or unicast.

## 5.1 Unicast Streams

If the offerer wishes to only send media on a stream to its peer, it
MUST mark the stream as sendonly with the "a=sendonly" attribute.  We
refer to a stream as being marked with a certain direction if a
direction attribute was present as either a media stream attribute or

a session attribute.  If the offerer wishes to only receive media
from its peer, it MUST mark the stream as recvonly.  If the offerer
wishes to communicate, but wishes to neither send nor receive media
at this time, it MUST mark the stream with an "a=inactive" attribute.
The inactive direction attribute is specified in RFC 3108 [3].  Note
that in the case of the Real Time Transport Protocol (RTP) [4], RTCP
is still sent and received for sendonly, recvonly, and inactive
streams.  That is, the directionality of the media stream has no
impact on the RTCP usage.  If the offerer wishes to both send and
receive media with its peer, it MAY include an "a=sendrecv"
attribute, or it MAY omit it, since sendrecv is the default.

For recvonly and sendrecv streams, the port number and address in the
offer indicate where the offerer would like to receive the media
stream.  For sendonly RTP streams, the address and port number
indirectly indicate where the offerer wants to receive RTCP reports.
Unless there is an explicit indication otherwise, reports are sent to
the port number one higher than the number indicated.  The IP address
and port present in the offer indicate nothing about the source IP
address and source port of RTP and RTCP packets that will be sent by
the offerer.  A port number of zero in the offer indicates that the
stream is offered but MUST NOT be used.  This has no useful semantics
in an initial offer, but is allowed for reasons of completeness,
since the answer can contain a zero port indicating a rejected stream
(Section 6).  Furthermore, existing streams can be terminated by
setting the port to zero (Section 8).  In general, a port number of
zero indicates that the media stream is not wanted.

The list of media formats for each media stream conveys two pieces of
information, namely the set of formats (codecs and any parameters
associated with the codec, in the case of RTP) that the offerer is
capable of sending and/or receiving (depending on the direction
attributes), and, in the case of RTP, the RTP payload type numbers
used to identify those formats.  If multiple formats are listed, it
means that the offerer is capable of making use of any of those
formats during the session.  In other words, the answerer MAY change
formats in the middle of the session, making use of any of the
formats listed, without sending a new offer.  For a sendonly stream,
the offer SHOULD indicate those formats the offerer is willing to
send for this stream.  For a recvonly stream, the offer SHOULD
indicate those formats the offerer is willing to receive for this
stream.  For a sendrecv stream, the offer SHOULD indicate those
codecs that the offerer is willing to send and receive with.

For recvonly RTP streams, the payload type numbers indicate the value
of the payload type field in RTP packets the offerer is expecting to
receive for that codec.  For sendonly RTP streams, the payload type
numbers indicate the value of the payload type field in RTP packets

the offerer is planning to send for that codec.  For sendrecv RTP
streams, the payload type numbers indicate the value of the payload
type field the offerer expects to receive, and would prefer to send.
However, for sendonly and sendrecv streams, the answer might indicate
different payload type numbers for the same codecs, in which case,
the offerer MUST send with the payload type numbers from the answer.

    Different payload type numbers may be needed in each direction
    because of interoperability concerns with H.323.

As per RFC 2327, fmtp parameters MAY be present to provide additional
parameters of the media format.

In the case of RTP streams, all media descriptions SHOULD contain
"a=rtpmap" mappings from RTP payload types to encodings.  If there is
no "a=rtpmap", the default payload type mapping, as defined by the
current profile in use (for example, RFC 1890 [5]) is to be used.

    This allows easier migration away from static payload types.

In all cases, the formats in the "m=" line MUST be listed in order of
preference, with the first format listed being preferred.  In this
case, preferred means that the recipient of the offer SHOULD use the
format with the highest preference that is acceptable to it.

If the ptime attribute is present for a stream, it indicates the
desired packetization interval that the offerer would like to
receive.  The ptime attribute MUST be greater than zero.

If the bandwidth attribute is present for a stream, it indicates the
desired bandwidth that the offerer would like to receive.  A value of
zero is allowed, but discouraged.  It indicates that no media should
be sent.  In the case of RTP, it would also disable all RTCP.

If multiple media streams of different types are present, it means
that the offerer wishes to use those streams at the same time.  A
typical case is an audio and a video stream as part of a
videoconference.

If multiple media streams of the same type are present in an offer,
it means that the offerer wishes to send (and/or receive) multiple
streams of that type at the same time.  When sending multiple streams
of the same type, it is a matter of local policy as to how each media
source of that type (for example, a video camera and VCR in the case
of video) is mapped to each stream.  When a user has a single source
for a particular media type, only one policy makes sense: the source
is sent to each stream of the same type.  Each stream MAY use
different encodings.  When receiving multiple streams of the same

type, it is a matter of local policy as to how each stream is mapped
to the various media sinks for that particular type (for example,
speakers or a recording device in the case of audio).  There are a
few constraints on the policies, however.  First, when receiving
multiple streams of the same type, each stream MUST be mapped to at
least one sink for the purpose of presentation to the user.  In other
words, the intent of receiving multiple streams of the same type is
that they should all be presented in parallel, rather than choosing
just one.  Another constraint is that when multiple streams are
received and sent to the same sink, they MUST be combined in some
media specific way.  For example, in the case of two audio streams,
the received media from each might be mapped to the speakers.  In
that case, the combining operation would be to mix them.  In the case
of multiple instant messaging streams, where the sink is the screen,
the combining operation would be to present all of them to the user
interface.  The third constraint is that if multiple sources are
mapped to the same stream, those sources MUST be combined in some
media specific way before they are sent on the stream.  Although
policies beyond these constraints are flexible, an agent won't
generally want a policy that will copy media from its sinks to its
sources unless it is a conference server (i.e., don't copy received
media on one stream to another stream).

A typical usage example for multiple media streams of the same type
is a pre-paid calling card application, where the user can press and
hold the pound ("#") key at any time during a call to hangup and make
a new call on the same card.  This requires media from the user to
two destinations - the remote gateway, and the DTMF processing
application which looks for the pound.  This could be accomplished
with two media streams, one sendrecv to the gateway, and the other
sendonly (from the perspective of the user) to the DTMF application.

Once the offerer has sent the offer, it MUST be prepared to receive
media for any recvonly streams described by that offer.  It MUST be
prepared to send and receive media for any sendrecv streams in the
offer, and send media for any sendonly streams in the offer (of
course, it cannot actually send until the peer provides an answer
with the needed address and port information).  In the case of RTP,
even though it may receive media before the answer arrives, it will
not be able to send RTCP receiver reports until the answer arrives.

## 5.2 Multicast Streams

If a session description contains a multicast media stream which is
listed as receive (send) only, it means that the participants,
including the offerer and answerer, can only receive (send) on that
stream.  This differs from the unicast view, where the directionality
refers to the flow of media between offerer and answerer.

Beyond that clarification, the semantics of an offered multicast
stream are exactly as described in RFC 2327 [1].