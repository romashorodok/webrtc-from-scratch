# 3. Definitions

RTP payload: The data transported by RTP in a packet, for
   example audio samples or compressed video data.  The payload
   format and interpretation are beyond the scope of this document.

RTP packet: A data packet consisting of the fixed RTP header, a
   possibly empty list of contributing sources (see below), and the
   payload data.  Some underlying protocols may require an
   encapsulation of the RTP packet to be defined.  Typically one
   packet of the underlying protocol contains a single RTP packet,
   but several RTP packets MAY be contained if permitted by the
   encapsulation method (see Section 11).


RTCP packet: A control packet consisting of a fixed header part
   similar to that of RTP data packets, followed by structured
   elements that vary depending upon the RTCP packet type.  The
   formats are defined in Section 6.  Typically, multiple RTCP
   packets are sent together as a compound RTCP packet in a single
   packet of the underlying protocol; this is enabled by the length
   field in the fixed header of each RTCP packet.

Port: The "abstraction that transport protocols use to
   distinguish among multiple destinations within a given host
   computer.  TCP/IP protocols identify ports using small positive
   integers." [12] The transport selectors (TSEL) used by the OSI
   transport layer are equivalent to ports.  RTP depends upon the
   lower-layer protocol to provide some mechanism such as ports to
   multiplex the RTP and RTCP packets of a session.

Transport address: The combination of a network address and port
   that identifies a transport-level endpoint, for example an IP
   address and a UDP port.  Packets are transmitted from a source
   transport address to a destination transport address.

RTP media type: An RTP media type is the collection of payload
   types which can be carried within a single RTP session.  The RTP
   Profile assigns RTP media types to RTP payload types.

Multimedia session: A set of concurrent RTP sessions among a
   common group of participants.  For example, a videoconference
   (which is a multimedia session) may contain an audio RTP session
   and a video RTP session.

RTP session: An association among a set of participants
   communicating with RTP.  A participant may be involved in multiple
   RTP sessions at the same time.  In a multimedia session, each
   medium is typically carried in a separate RTP session with its own
   RTCP packets unless the the encoding itself multiplexes multiple
   media into a single data stream.  A participant distinguishes
   multiple RTP sessions by reception of different sessions using
   different pairs of destination transport addresses, where a pair
   of transport addresses comprises one network address plus a pair
   of ports for RTP and RTCP.  All participants in an RTP session may
   share a common destination transport address pair, as in the case
   of IP multicast, or the pairs may be different for each
   participant, as in the case of individual unicast network
   addresses and port pairs.  In the unicast case, a participant may
   receive from all other participants in the session using the same
   pair of ports, or may use a distinct pair of ports for each.


   The distinguishing feature of an RTP session is that each
   maintains a full, separate space of SSRC identifiers (defined
   next).  The set of participants included in one RTP session
   consists of those that can receive an SSRC identifier transmitted
   by any one of the participants either in RTP as the SSRC or a CSRC
   (also defined below) or in RTCP.  For example, consider a three-
   party conference implemented using unicast UDP with each
   participant receiving from the other two on separate port pairs.
   If each participant sends RTCP feedback about data received from
   one other participant only back to that participant, then the
   conference is composed of three separate point-to-point RTP
   sessions.  If each participant provides RTCP feedback about its
   reception of one other participant to both of the other
   participants, then the conference is composed of one multi-party
   RTP session.  The latter case simulates the behavior that would
   occur with IP multicast communication among the three
   participants.

   The RTP framework allows the variations defined here, but a
   particular control protocol or application design will usually
   impose constraints on these variations.

Synchronization source (SSRC): The source of a stream of RTP
   packets, identified by a 32-bit numeric SSRC identifier carried in
   the RTP header so as not to be dependent upon the network address.
   All packets from a synchronization source form part of the same
   timing and sequence number space, so a receiver groups packets by
   synchronization source for playback.  Examples of synchronization
   sources include the sender of a stream of packets derived from a
   signal source such as a microphone or a camera, or an RTP mixer
   (see below).  A synchronization source may change its data format,
   e.g., audio encoding, over time.  The SSRC identifier is a
   randomly chosen value meant to be globally unique within a
   particular RTP session (see Section 8).  A participant need not
   use the same SSRC identifier for all the RTP sessions in a
   multimedia session; the binding of the SSRC identifiers is
   provided through RTCP (see Section 6.5.1).  If a participant
   generates multiple streams in one RTP session, for example from
   separate video cameras, each MUST be identified as a different
   SSRC.

Contributing source (CSRC): A source of a stream of RTP packets
   that has contributed to the combined stream produced by an RTP
   mixer (see below).  The mixer inserts a list of the SSRC
   identifiers of the sources that contributed to the generation of a
   particular packet into the RTP header of that packet.  This list
   is called the CSRC list.  An example application is audio
   conferencing where a mixer indicates all the talkers whose speech
   was combined to produce the outgoing packet, allowing the receiver
   to indicate the current talker, even though all the audio packets
   contain the same SSRC identifier (that of the mixer).


End system: An application that generates the content to be sent
   in RTP packets and/or consumes the content of received RTP
   packets.  An end system can act as one or more synchronization
   sources in a particular RTP session, but typically only one.

Mixer: An intermediate system that receives RTP packets from one
   or more sources, possibly changes the data format, combines the
   packets in some manner and then forwards a new RTP packet.  Since
   the timing among multiple input sources will not generally be
   synchronized, the mixer will make timing adjustments among the
   streams and generate its own timing for the combined stream.
   Thus, all data packets originating from a mixer will be identified
   as having the mixer as their synchronization source.

Translator: An intermediate system that forwards RTP packets
   with their synchronization source identifier intact.  Examples of
   translators include devices that convert encodings without mixing,
   replicators from multicast to unicast, and application-level
   filters in firewalls.

Monitor: An application that receives RTCP packets sent by
   participants in an RTP session, in particular the reception
   reports, and estimates the current quality of service for
   distribution monitoring, fault diagnosis and long-term statistics.
   The monitor function is likely to be built into the application(s)
   participating in the session, but may also be a separate
   application that does not otherwise participate and does not send
   or receive the RTP data packets (since they are on a separate
   port).  These are called third-party monitors.  It is also
   acceptable for a third-party monitor to receive the RTP data
   packets but not send RTCP packets or otherwise be counted in the
   session.

Non-RTP means: Protocols and mechanisms that may be needed in
   addition to RTP to provide a usable service.  In particular, for
   multimedia conferences, a control protocol may distribute
   multicast addresses and keys for encryption, negotiate the
   encryption algorithm to be used, and define dynamic mappings
   between RTP payload type values and the payload formats they
   represent for formats that do not have a predefined payload type
   value.  Examples of such protocols include the Session Initiation
   Protocol (SIP) (RFC 3261 [13]), ITU Recommendation H.323 [14] and
   applications using SDP (RFC 2327 [15]), such as RTSP (RFC 2326
   [16]).  For simple
   applications, electronic mail or a conference database may also be
   used.  The specification of such protocols and mechanisms is
   outside the scope of this document.
