# 11. RTP over Network and Transport Protocols

This section describes issues specific to carrying RTP packets within
particular network and transport protocols.  The following rules
apply unless superseded by protocol-specific definitions outside this
specification.

RTP relies on the underlying protocol(s) to provide demultiplexing of
RTP data and RTCP control streams.  For UDP and similar protocols,
RTP SHOULD use an even destination port number and the corresponding
RTCP stream SHOULD use the next higher (odd) destination port number.
For applications that take a single port number as a parameter and
derive the RTP and RTCP port pair from that number, if an odd number
is supplied then the application SHOULD replace that number with the
next lower (even) number to use as the base of the port pair.  For
applications in which the RTP and RTCP destination port numbers are
specified via explicit, separate parameters (using a signaling
protocol or other means), the application MAY disregard the
restrictions that the port numbers be even/odd and consecutive
although the use of an even/odd port pair is still encouraged.  The
RTP and RTCP port numbers MUST NOT be the same since RTP relies on
the port numbers to demultiplex the RTP data and RTCP control
streams.

In a unicast session, both participants need to identify a port pair
for receiving RTP and RTCP packets.  Both participants MAY use the
same port pair.  A participant MUST NOT assume that the source port
of the incoming RTP or RTCP packet can be used as the destination
port for outgoing RTP or RTCP packets.  When RTP data packets are
being sent in both directions, each participant's RTCP SR packets
MUST be sent to the port that the other participant has specified for
reception of RTCP.  The RTCP SR packets combine sender information
for the outgoing data plus reception report information for the
incoming data.  If a side is not actively sending data (see Section
6.4), an RTCP RR packet is sent instead.

It is RECOMMENDED that layered encoding applications (see Section
2.4) use a set of contiguous port numbers.  The port numbers MUST be
distinct because of a widespread deficiency in existing operating

systems that prevents use of the same port with multiple multicast
addresses, and for unicast, there is only one permissible address.
Thus for layer n, the data port is P + 2n, and the control port is P
+ 2n + 1.  When IP multicast is used, the addresses MUST also be
distinct because multicast routing and group membership are managed
on an address granularity.  However, allocation of contiguous IP
multicast addresses cannot be assumed because some groups may require
different scopes and may therefore be allocated from different
address ranges.

The previous paragraph conflicts with the SDP specification, RFC 2327
[15], which says that it is illegal for both multiple addresses and
multiple ports to be specified in the same session description
because the association of addresses with ports could be ambiguous.
It is intended that this restriction will be relaxed in a revision of
RFC 2327 to allow an equal number of addresses and ports to be
specified with a one-to-one mapping implied.

RTP data packets contain no length field or other delineation,
therefore RTP relies on the underlying protocol(s) to provide a
length indication.  The maximum length of RTP packets is limited only
by the underlying protocols.

If RTP packets are to be carried in an underlying protocol that
provides the abstraction of a continuous octet stream rather than
messages (packets), an encapsulation of the RTP packets MUST be
defined to provide a framing mechanism.  Framing is also needed if
the underlying protocol may contain padding so that the extent of the
RTP payload cannot be determined.  The framing mechanism is not
defined here.

A profile MAY specify a framing method to be used even when RTP is
carried in protocols that do provide framing in order to allow
carrying several RTP packets in one lower-layer protocol data unit,
such as a UDP packet.  Carrying several RTP packets in one network or
transport packet reduces header overhead and may simplify
synchronization between different streams.
