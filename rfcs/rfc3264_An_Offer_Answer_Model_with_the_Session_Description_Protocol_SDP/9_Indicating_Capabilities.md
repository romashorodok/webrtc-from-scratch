9 Indicating Capabilities

   Before an agent sends an offer, it is helpful to know if the media
   formats in that offer would be acceptable to the answerer.  Certain
   protocols, like SIP, provide a means to query for such capabilities.
   SDP can be used in responses to such queries to indicate
   capabilities.  This section describes how such an SDP message is
   formatted.  Since SDP has no way to indicate that the message is for
   the purpose of capability indication, this is determined from the
   context of the higher layer protocol.  The ability of baseline SDP to
   indicate capabilities is very limited.  It cannot express allowed
   parameter ranges or values, and can not be done in parallel with an
   offer/answer itself.  Extensions might address such limitations in
   the future.

   An SDP constructed to indicate media capabilities is structured as
   follows.  It MUST be a valid SDP, except that it MAY omit both "e="
   and "p=" lines.  The "t=" line MUST be equal to "0 0".  For each
   media type supported by the agent, there MUST be a corresponding
   media description of that type.  The session ID in the origin field
   MUST be unique for each SDP constructed to indicate media
   capabilities.  The port MUST be set to zero, but the connection
   address is arbitrary.  The usage of port zero makes sure that an SDP
   formatted for capabilities does not cause media streams to be
   established if it is interpreted as an offer or answer.

   The transport component of the "m=" line indicates the transport for
   that media type.  For each media format of that type supported by the
   agent, there SHOULD be a media format listed in the "m=" line.  In
   the case of RTP, if dynamic payload types are used, an rtpmap

  attribute MUST be present to bind the type to a specific format.
   There is no way to indicate constraints, such as how many
   simultaneous streams can be supported for a particular codec, and so
   on.

   v=0
   o=carol 28908764872 28908764872 IN IP4 100.3.6.6
   s=-
   t=0 0
   c=IN IP4 192.0.2.4
   m=audio 0 RTP/AVP 0 1 3
   a=rtpmap:0 PCMU/8000
   a=rtpmap:1 1016/8000
   a=rtpmap:3 GSM/8000
   m=video 0 RTP/AVP 31 34
   a=rtpmap:31 H261/90000
   a=rtpmap:34 H263/90000

   Figure 1: SDP Indicating Capabilities

   The SDP of Figure 1 indicates that the agent can support three audio
   codecs (PCMU, 1016, and GSM) and two video codecs (H.261 and H.263).

10 Example Offer/Answer Exchanges

   This section provides example offer/answer exchanges.

10.1 Basic Exchange

   Assume that the caller, Alice, has included the following description
   in her offer.  It includes a bidirectional audio stream and two
   bidirectional video streams, using H.261 (payload type 31) and MPEG
   (payload type 32).  The offered SDP is:

   v=0
   o=alice 2890844526 2890844526 IN IP4 host.anywhere.com
   s=
   c=IN IP4 host.anywhere.com
   t=0 0
   m=audio 49170 RTP/AVP 0
   a=rtpmap:0 PCMU/8000
   m=video 51372 RTP/AVP 31
   a=rtpmap:31 H261/90000
   m=video 53000 RTP/AVP 32
   a=rtpmap:32 MPV/90000

  The callee, Bob, does not want to receive or send the first video
   stream, so he returns the SDP below as the answer:

   v=0
   o=bob 2890844730 2890844730 IN IP4 host.example.com
   s=
   c=IN IP4 host.example.com
   t=0 0
   m=audio 49920 RTP/AVP 0
   a=rtpmap:0 PCMU/8000
   m=video 0 RTP/AVP 31
   m=video 53000 RTP/AVP 32
   a=rtpmap:32 MPV/90000

   At some point later, Bob decides to change the port where he will
   receive the audio stream (from 49920 to 65422), and at the same time,
   add an additional audio stream as receive only, using the RTP payload
   format for events [9].  Bob offers the following SDP in the offer:

   v=0
   o=bob 2890844730 2890844731 IN IP4 host.example.com
   s=
   c=IN IP4 host.example.com
   t=0 0
   m=audio 65422 RTP/AVP 0
   a=rtpmap:0 PCMU/8000
   m=video 0 RTP/AVP 31
   m=video 53000 RTP/AVP 32
   a=rtpmap:32 MPV/90000
   m=audio 51434 RTP/AVP 110
   a=rtpmap:110 telephone-events/8000
   a=recvonly



   Alice accepts the additional media stream, and so generates the
   following answer:

   v=0
   o=alice 2890844526 2890844527 IN IP4 host.anywhere.com
   s=
   c=IN IP4 host.anywhere.com
   t=0 0
   m=audio 49170 RTP/AVP 0
   a=rtpmap:0 PCMU/8000
   m=video 0 RTP/AVP 31
   a=rtpmap:31 H261/90000
   m=video 53000 RTP/AVP 32
   a=rtpmap:32 MPV/90000
   m=audio 53122 RTP/AVP 110
   a=rtpmap:110 telephone-events/8000
   a=sendonly

10.2 One of N Codec Selection

   A common occurrence in embedded phones is that the Digital Signal
   Processor (DSP) used for compression can support multiple codecs at a
   time, but once that codec is selected, it cannot be readily changed
   on the fly.  This example shows how a session can be set up using an
   initial offer/answer exchange, followed immediately by a second one
   to lock down the set of codecs.

   The initial offer from Alice to Bob indicates a single audio stream
   with the three audio codecs that are available in the DSP.  The
   stream is marked as inactive, since media cannot be received until a
   codec is locked down:

   v=0
   o=alice 2890844526 2890844526 IN IP4 host.anywhere.com
   s=
   c=IN IP4 host.anywhere.com
   t=0 0
   m=audio 62986 RTP/AVP 0 4 18
   a=rtpmap:0 PCMU/8000
   a=rtpmap:4 G723/8000
   a=rtpmap:18 G729/8000
   a=inactive

   Bob can support dynamic switching between PCMU and G.723.  So, he
   sends the following answer:

   v=0
   o=bob 2890844730 2890844731 IN IP4 host.example.com
   s=
   c=IN IP4 host.example.com
   t=0 0
   m=audio 54344 RTP/AVP 0 4
   a=rtpmap:0 PCMU/8000
   a=rtpmap:4 G723/8000
   a=inactive

   Alice can then select any one of these two codecs.  So, she sends an
   updated offer with a sendrecv stream:

   v=0
   o=alice 2890844526 2890844527 IN IP4 host.anywhere.com
   s=
   c=IN IP4 host.anywhere.com
   t=0 0
   m=audio 62986 RTP/AVP 4
   a=rtpmap:4 G723/8000
   a=sendrecv

   Bob accepts the single codec:

   v=0
   o=bob 2890844730 2890844732 IN IP4 host.example.com
   s=
   c=IN IP4 host.example.com
   t=0 0
   m=audio 54344 RTP/AVP 4
   a=rtpmap:4 G723/8000
   a=sendrecv

   If the answerer (Bob), was only capable of supporting one-of-N
   codecs, Bob would select one of the codecs from the offer, and place
   that in his answer. In this case, Alice would do a re-INVITE to
   activate that stream with that codec.

   As an alternative to using "a=inactive" in the first exchange, Alice
   can list all codecs, and as soon as she receives media from Bob,
   generate an updated offer locking down the codec to the one just
   received. Of course, if Bob only supports one-of-N codecs, there
   would only be one codec in his answer, and in this case, there is no
   need for a re-INVITE to lock down to a single codec.
