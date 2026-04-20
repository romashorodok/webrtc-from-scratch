# 7. RTP Translators and Mixers

In addition to end systems, RTP supports the notion of "translators"
and "mixers", which could be considered as "intermediate systems" at
the RTP level.  Although this support adds some complexity to the
protocol, the need for these functions has been clearly established
by experiments with multicast audio and video applications in the
Internet.  Example uses of translators and mixers given in Section
2.3 stem from the presence of firewalls and low bandwidth
connections, both of which are likely to remain

## 7.1 General Description

An RTP translator/mixer connects two or more transport-level
"clouds".  Typically, each cloud is defined by a common network and
transport protocol (e.g., IP/UDP) plus a multicast address and
transport level destination port or a pair of unicast addresses and
ports.  (Network-level protocol translators, such as IP version 4 to
IP version 6, may be present within a cloud invisibly to RTP.)  One
system may serve as a translator or mixer for a number of RTP
sessions, but each is considered a logically separate entity.

In order to avoid creating a loop when a translator or mixer is
installed, the following rules MUST be observed:

o  Each of the clouds connected by translators and mixers
    participating in one RTP session either MUST be distinct from all
    the others in at least one of these parameters (protocol, address,
    port), or MUST be isolated at the network level from the others.


o  A derivative of the first rule is that there MUST NOT be multiple
    translators or mixers connected in parallel unless by some
    arrangement they partition the set of sources to be forwarded.

Similarly, all RTP end systems that can communicate through one or
more RTP translators or mixers share the same SSRC space, that is,
the SSRC identifiers MUST be unique among all these end systems.
Section 8.2 describes the collision resolution algorithm by which
SSRC identifiers are kept unique and loops are detected.

There may be many varieties of translators and mixers designed for
different purposes and applications.  Some examples are to add or
remove encryption, change the encoding of the data or the underlying
protocols, or replicate between a multicast address and one or more
unicast addresses.  The distinction between translators and mixers is
that a translator passes through the data streams from different
sources separately, whereas a mixer combines them to form one new
stream:

Translator: Forwards RTP packets with their SSRC identifier
    intact; this makes it possible for receivers to identify
    individual sources even though packets from all the sources pass
    through the same translator and carry the translator's network
    source address.  Some kinds of translators will pass through the
    data untouched, but others MAY change the encoding of the data and
    thus the RTP data payload type and timestamp.  If multiple data
    packets are re-encoded into one, or vice versa, a translator MUST
    assign new sequence numbers to the outgoing packets.  Losses in
    the incoming packet stream may induce corresponding gaps in the
    outgoing sequence numbers.  Receivers cannot detect the presence
    of a translator unless they know by some other means what payload
    type or transport address was used by the original source.

Mixer: Receives streams of RTP data packets from one or more
    sources, possibly changes the data format, combines the streams in
    some manner and then forwards the combined stream.  Since the
    timing among multiple input sources will not generally be
    synchronized, the mixer will make timing adjustments among the
    streams and generate its own timing for the combined stream, so it
    is the synchronization source.  Thus, all data packets forwarded
    by a mixer MUST be marked with the mixer's own SSRC identifier.
    In order to preserve the identity of the original sources
    contributing to the mixed packet, the mixer SHOULD insert their
    SSRC identifiers into the CSRC identifier list following the fixed
    RTP header of the packet.  A mixer that is also itself a
    contributing source for some packet SHOULD explicitly include its
    own SSRC identifier in the CSRC list for that packet.


    For some applications, it MAY be acceptable for a mixer not to
    identify sources in the CSRC list.  However, this introduces the
    danger that loops involving those sources could not be detected.

The advantage of a mixer over a translator for applications like
audio is that the output bandwidth is limited to that of one source
even when multiple sources are active on the input side.  This may be
important for low-bandwidth links.  The disadvantage is that
receivers on the output side don't have any control over which
sources are passed through or muted, unless some mechanism is
implemented for remote control of the mixer.  The regeneration of
synchronization information by mixers also means that receivers can't
do inter-media synchronization of the original streams.  A multi-
media mixer could do it.


         [E1]                                    [E6]
          |                                       |
    E1:17 |                                 E6:15 |
          |                                       |   E6:15
          V  M1:48 (1,17)         M1:48 (1,17)    V   M1:48 (1,17)
         (M1)-------------><T1>-----------------><T2>-------------->[E7]
          ^                 ^     E4:47           ^   E4:47
     E2:1 |           E4:47 |                     |   M3:89 (64,45)
          |                 |                     |
         [E2]              [E4]     M3:89 (64,45) |
                                                  |        legend:
   [E3] --------->(M2)----------->(M3)------------|        [End system]
          E3:64        M2:12 (64)  ^                       (Mixer)
                                   | E5:45                 <Translator>
                                   |
                                  [E5]          source: SSRC (CSRCs)
                                                ------------------->

   Figure 3: Sample RTP network with end systems, mixers and translators

A collection of mixers and translators is shown in Fig. 3 to
illustrate their effect on SSRC and CSRC identifiers.  In the figure,
end systems are shown as rectangles (named E), translators as
triangles (named T) and mixers as ovals (named M).  The notation "M1:
48(1,17)" designates a packet originating a mixer M1, identified by
M1's (random) SSRC value of 48 and two CSRC identifiers, 1 and 17,
copied from the SSRC identifiers of packets from E1 and E2.

## 7.2 RTCP Processing in Translators

In addition to forwarding data packets, perhaps modified, translators
and mixers MUST also process RTCP packets.  In many cases, they will
take apart the compound RTCP packets received from end systems to



aggregate SDES information and to modify the SR or RR packets.
Retransmission of this information may be triggered by the packet
arrival or by the RTCP interval timer of the translator or mixer
itself.

A translator that does not modify the data packets, for example one
that just replicates between a multicast address and a unicast
address, MAY simply forward RTCP packets unmodified as well.  A
translator that transforms the payload in some way MUST make
corresponding transformations in the SR and RR information so that it
still reflects the characteristics of the data and the reception
quality.  These translators MUST NOT simply forward RTCP packets.  In
general, a translator SHOULD NOT aggregate SR and RR packets from
different sources into one packet since that would reduce the
accuracy of the propagation delay measurements based on the LSR and
DLSR fields.

SR sender information:  A translator does not generate its own
    sender information, but forwards the SR packets received from one
    cloud to the others.  The SSRC is left intact but the sender
    information MUST be modified if required by the translation.  If a
    translator changes the data encoding, it MUST change the "sender's
    byte count" field.  If it also combines several data packets into
    one output packet, it MUST change the "sender's packet count"
    field.  If it changes the timestamp frequency, it MUST change the
    "RTP timestamp" field in the SR packet.

SR/RR reception report blocks:  A translator forwards reception
    reports received from one cloud to the others.  Note that these
    flow in the direction opposite to the data.  The SSRC is left
    intact.  If a translator combines several data packets into one
    output packet, and therefore changes the sequence numbers, it MUST
    make the inverse manipulation for the packet loss fields and the
    "extended last sequence number" field.  This may be complex.  In
    the extreme case, there may be no meaningful way to translate the
    reception reports, so the translator MAY pass on no reception
    report at all or a synthetic report based on its own reception.
    The general rule is to do what makes sense for a particular
    translation.

    A translator does not require an SSRC identifier of its own, but
    MAY choose to allocate one for the purpose of sending reports
    about what it has received.  These would be sent to all the
    connected clouds, each corresponding to the translation of the
    data stream as sent to that cloud, since reception reports are
    normally multicast to all participants.


SDES:  Translators typically forward without change the SDES
    information they receive from one cloud to the others, but MAY,
    for example, decide to filter non-CNAME SDES information if
    bandwidth is limited.  The CNAMEs MUST be forwarded to allow SSRC
    identifier collision detection to work.  A translator that
    generates its own RR packets MUST send SDES CNAME information
    about itself to the same clouds that it sends those RR packets.

BYE:  Translators forward BYE packets unchanged.  A translator
    that is about to cease forwarding packets SHOULD send a BYE packet
    to each connected cloud containing all the SSRC identifiers that
    were previously being forwarded to that cloud, including the
    translator's own SSRC identifier if it sent reports of its own.

APP:  Translators forward APP packets unchanged.

## 7.3 RTCP Processing in Mixers

Since a mixer generates a new data stream of its own, it does not
pass through SR or RR packets at all and instead generates new
information for both sides.

SR sender information:  A mixer does not pass through sender
    information from the sources it mixes because the characteristics
    of the source streams are lost in the mix.  As a synchronization
    source, the mixer SHOULD generate its own SR packets with sender
    information about the mixed data stream and send them in the same
    direction as the mixed stream.

SR/RR reception report blocks:  A mixer generates its own
    reception reports for sources in each cloud and sends them out
    only to the same cloud.  It MUST NOT send these reception reports
    to the other clouds and MUST NOT forward reception reports from
    one cloud to the others because the sources would not be SSRCs
    there (only CSRCs).

SDES:  Mixers typically forward without change the SDES
    information they receive from one cloud to the others, but MAY,
    for example, decide to filter non-CNAME SDES information if
    bandwidth is limited.  The CNAMEs MUST be forwarded to allow SSRC
    identifier collision detection to work.  (An identifier in a CSRC
    list generated by a mixer might collide with an SSRC identifier
    generated by an end system.)  A mixer MUST send SDES CNAME
    information about itself to the same clouds that it sends SR or RR
    packets.


    Since mixers do not forward SR or RR packets, they will typically
    be extracting SDES packets from a compound RTCP packet.  To
    minimize overhead, chunks from the SDES packets MAY be aggregated
    into a single SDES packet which is then stacked on an SR or RR
    packet originating from the mixer.  A mixer which aggregates SDES
    packets will use more RTCP bandwidth than an individual source
    because the compound packets will be longer, but that is
    appropriate since the mixer represents multiple sources.
    Similarly, a mixer which passes through SDES packets as they are
    received will be transmitting RTCP packets at higher than the
    single source rate, but again that is correct since the packets
    come from multiple sources.  The RTCP packet rate may be different
    on each side of the mixer.

    A mixer that does not insert CSRC identifiers MAY also refrain
    from forwarding SDES CNAMEs.  In this case, the SSRC identifier
    spaces in the two clouds are independent.  As mentioned earlier,
    this mode of operation creates a danger that loops can't be
    detected.

BYE:  Mixers MUST forward BYE packets.  A mixer that is about to
    cease forwarding packets SHOULD send a BYE packet to each
    connected cloud containing all the SSRC identifiers that were
    previously being forwarded to that cloud, including the mixer's
    own SSRC identifier if it sent reports of its own.

APP:  The treatment of APP packets by mixers is application-specific.

## 7.4 Cascaded Mixers

An RTP session may involve a collection of mixers and translators as
shown in Fig. 3.  If two mixers are cascaded, such as M2 and M3 in
the figure, packets received by a mixer may already have been mixed
and may include a CSRC list with multiple identifiers.  The second
mixer SHOULD build the CSRC list for the outgoing packet using the
CSRC identifiers from already-mixed input packets and the SSRC
identifiers from unmixed input packets.  This is shown in the output
arc from mixer M3 labeled M3:89(64,45) in the figure.  As in the case
of mixers that are not cascaded, if the resulting CSRC list has more
than 15 identifiers, the remainder cannot be included.
