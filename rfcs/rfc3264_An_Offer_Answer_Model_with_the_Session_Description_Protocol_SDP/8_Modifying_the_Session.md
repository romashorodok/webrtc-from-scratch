# 8 Modifying the Session

At any point during the session, either participant MAY issue a new
offer to modify characteristics of the session.  It is fundamental to
the operation of the offer/answer model that the exact same
offer/answer procedure defined above is used for modifying parameters
of an existing session.

The offer MAY be identical to the last SDP provided to the other
party (which may have been provided in an offer or an answer), or it
MAY be different.  We refer to the last SDP provided as the "previous
SDP".  If the offer is the same, the answer MAY be the same as the
previous SDP from the answerer, or it MAY be different.  If the
offered SDP is different from the previous SDP, some constraints are
placed on its construction, discussed below.

Nearly all aspects of the session can be modified.  New streams can
be added, existing streams can be deleted, and parameters of existing
streams can change.  When issuing an offer that modifies the session,
the "o=" line of the new SDP MUST be identical to that in the
previous SDP, except that the version in the origin field MUST
increment by one from the previous SDP.  If the version in the origin
line does not increment, the SDP MUST be identical to the SDP with
that version number.  The answerer MUST be prepared to receive an
offer that contains SDP with a version that has not changed; this is
effectively a no-op.  However, the answerer MUST generate a valid
answer (which MAY be the same as the previous SDP from the answerer,
or MAY be different), according to the procedures defined in Section
6.

If an SDP is offered, which is different from the previous SDP, the
new SDP MUST have a matching media stream for each media stream in
the previous SDP.  In other words, if the previous SDP had N "m="
lines, the new SDP MUST have at least N "m=" lines.  The i-th media
stream in the previous SDP, counting from the top, matches the i-th
media stream in the new SDP, counting from the top.  This matching is
necessary in order for the answerer to determine which stream in the
new SDP corresponds to a stream in the previous SDP.  Because of
these requirements, the number of "m=" lines in a stream never
decreases, but either stays the same or increases.  Deleted media
streams from a previous SDP MUST NOT be removed in a new SDP;
however, attributes for these streams need not be present.

## 8.1 Adding a Media Stream

New media streams are created by new additional media descriptions
below the existing ones, or by reusing the "slot" used by an old
media stream which had been disabled by setting its port to zero.
Reusing its slot means that the new media description replaces the
old one, but retains its positioning relative to other media
descriptions in  the SDP.  New media descriptions MUST appear below
any existing media sections.  The rules for formatting these media
descriptions are identical to those described in Section 5.

When the answerer receives an SDP with more media descriptions than
the previous SDP from the offerer, or it receives an SDP with a media
stream in a slot where the port was previously zero, the answerer
knows that new media streams are being added.  These can be rejected
or accepted by placing an appropriately structured media description
in the answer.  The procedures for constructing the new media
description in the answer are described in Section 6.

## 8.2 Removing a Media Stream

Existing media streams are removed by creating a new SDP with the
port number for that stream set to zero.  The stream description MAY
omit all attributes present previously, and MAY list just a single
media format.

A stream that is offered with a port of zero MUST be marked with port
zero in the answer.  Like the offer, the answer MAY omit all
attributes present previously, and MAY list just a single media
format from amongst those in the offer.

Removal of a media stream implies that media is no longer sent for
that stream, and any media that is received is discarded.  In the
case of RTP, RTCP transmission also ceases, as does processing of any
received RTCP packets.  Any resources associated with it can be
released.  The user interface might indicate that the stream has
terminated, by closing the associated window on a PC, for example.

## 8.3 Modifying a Media Stream

Nearly all characteristics of a media stream can be modified.

### 8.3.1 Modifying Address, Port or Transport

The port number for a stream MAY be changed.  To do this, the offerer
creates a new media description, with the port number in the m line
different from the corresponding stream in the previous SDP.  If only
the port number is to be changed, the rest of the media stream
description SHOULD remain unchanged.  The offerer MUST be prepared to
receive media on both the old and new ports as soon as the offer is
sent.  The offerer SHOULD NOT cease listening for media on the old
port until the answer is received and media arrives on the new port.
Doing so could result in loss of media during the transition.

Received, in this case, means that the media is passed to a media
sink.  This means that if there is a playout buffer, the agent would
continue to listen on the old port until the media on the new port
reached the top of the playout buffer.  At that time, it MAY cease
listening for media on the old port.

The corresponding media stream in the answer MAY be the same as the
stream in the previous SDP from the answerer, or it MAY be different.
If the updated stream is accepted by the answerer, the answerer
SHOULD begin sending traffic for that stream to the new port
immediately.  If the answerer changes the port from the previous SDP,
it MUST be prepared to receive media on both the old and new ports as
soon as the answer is sent.  The answerer MUST NOT cease listening
for media on the old port until media arrives on the new port.  At
that time, it MAY cease listening for media on the old port.  The
same is true for an offerer that sends an updated offer with a new
port; it MUST NOT cease listening for media on the old port until
media arrives on the new port.

Of course, if the offered stream is rejected, the offerer can cease
being prepared to receive using the new port as soon as the rejection
is received.

To change the IP address where media is sent to, the same procedure
is followed for changing the port number.  The only difference is
that the connection line is updated, not the port number.

The transport for a stream MAY be changed.  The process for doing
this is identical to changing the port, except the transport is
updated, not the port.

### 8.3.2 Changing the Set of Media Formats

The list of media formats used in the session MAY be changed.  To do
this, the offerer creates a new media description, with the list of
media formats in the "m=" line different from the corresponding media
stream in the previous SDP.  This list MAY include new formats, and
MAY remove formats present from the previous SDP.  However, in the
case of RTP, the mapping from a particular dynamic payload type
number to a particular codec within that media stream MUST NOT change
for the duration of a session.  For example, if A generates an offer
with G.711 assigned to dynamic payload type number 46, payload type
number 46 MUST refer to G.711 from that point forward in any offers
or answers for that media stream within the session.  However, it is
acceptable for multiple payload type numbers to be mapped to the same
codec, so that an updated offer could also use payload type number 72
for G.711.


    The mappings need to remain fixed for the duration of the session
    because of the loose synchronization between signaling exchanges
    of SDP and the media stream.

The corresponding media stream in the answer is formulated as
described in Section 6, and may result in a change in media formats
as well.  Similarly, as described in Section 6, as soon as it sends
its answer, the answerer MUST begin sending media using any formats
in the offer that were also present in the answer, and SHOULD use the
most preferred format in the offer that was also listed in the answer
(assuming the stream allows for sending), and MUST NOT send using any
formats that are not in the offer, even if they were present in a
previous SDP from the peer.  Similarly, when the offerer receives the
answer, it MUST begin sending media using any formats in the answer,
and SHOULD use the most preferred one (assuming the stream allows for
sending), and MUST NOT send using any formats that are not in the
answer, even if they were present in a previous SDP from the peer.

When an agent ceases using a media format (by not listing that format
in an offer or answer, even though it was in a previous SDP) the
agent will still need to be prepared to receive media with that
format for a brief time.  How does it know when it can be prepared to
stop receiving with that format? If it needs to know, there are three
techniques that can be applied.  First, the agent can change ports in
addition to changing formats.  When media arrives on the new port, it
knows that the peer has ceased sending with the old format, and it
can cease being prepared to receive with it.  This approach has the
benefit of being media format independent.  However, changes in ports
may require changes in resource reservation or rekeying of security
protocols.  The second approach is to use a totally new set of
dynamic payload types for all codecs when one is discarded.  When
media is received with one of the new payload types, the agent knows
that the peer has ceased sending with the old format.  This approach
doesn't affect reservations or security contexts, but it is RTP
specific and wasteful of a very small payload type space.  A third
approach is to use a timer.  When the SDP from the peer is received,
the timer is set.  When it fires, the agent can cease being prepared
to receive with the old format.  A value of one minute would
typically be more than sufficient.  In some cases, an agent may not
care, and thus continually be prepared to receive with the old
formats.  Nothing need be done in this case.

Of course, if the offered stream is rejected, the offer can cease
being prepared to receive using any new formats as soon as the
rejection is received.

### 8.3.3 Changing Media Types

The media type (audio, video, etc.) for a stream MAY be changed.  It
is RECOMMENDED that the media type be changed (as opposed to adding a
new stream), when the same logical data is being conveyed, but just
in a different media format.  This is particularly useful for
changing between voiceband fax and fax in a single stream, which are
both separate media types.  To do this, the offerer creates a new
media description, with a new media type, in place of the description
in the previous SDP which is to be changed.

The corresponding media stream in the answer is formulated as
described in Section 6.  Assuming the stream is acceptable, the
answerer SHOULD begin sending with the new media type and formats as
soon as it receives the offer. The offerer MUST be prepared to
receive media with both the old and new types until the answer is
received, and media with the new type is received and reaches the top
of the playout buffer.

### 8.3.4 Changing Attributes

Any other attributes in a media description MAY be updated in an
offer or answer.  Generally, an agent MUST send media (if the
directionality of the stream allows) using the new parameters once
the SDP with the change is received.

## 8.4 Putting a Unicast Media Stream on Hold

If a party in a call wants to put the other party "on hold", i.e.,
request that it temporarily stops sending one or more unicast media
streams, a party offers the other an updated SDP.

If the stream to be placed on hold was previously a sendrecv media
stream, it is placed on hold by marking it as sendonly.  If the
stream to be placed on hold was previously a recvonly media stream,
it is placed on hold by marking it inactive.

This means that a stream is placed "on hold" separately in each
direction.  Each stream is placed "on hold" independently.  The
recipient of an offer for a stream on-hold SHOULD NOT automatically
return an answer with the corresponding stream on hold.  An SDP with
all streams "on hold" is referred to as held SDP.

    Certain third party call control scenarios do not work when an
    answerer responds to held SDP with held SDP.

Typically, when a user "presses" hold, the agent will generate an
offer with all streams in the SDP indicating a direction of sendonly,
and it will also locally mute, so that no media is sent to the far
end, and no media is played out.

RFC 2543 [10] specified that placing a user on hold was accomplished
by setting the connection address to 0.0.0.0.  Its usage for putting
a call on hold is no longer recommended, since it doesn't allow for
RTCP to be used with held streams, doesn't work with IPv6, and breaks
with connection oriented media.  However, it can be useful in an
initial offer when the offerer knows it wants to use a particular set
of media streams and formats, but doesn't know the addresses and
ports at the time of the offer.  Of course, when used, the port
number MUST NOT be zero, which would specify that the stream has been
disabled.  An agent MUST be capable of receiving SDP with a
connection address of 0.0.0.0, in which case it means that neither
RTP nor RTCP should be sent to the peer.