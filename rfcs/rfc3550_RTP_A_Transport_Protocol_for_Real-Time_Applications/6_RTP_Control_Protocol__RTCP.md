# 6. RTP Control Protocol -- RTCP

The RTP control protocol (RTCP) is based on the periodic transmission
of control packets to all participants in the session, using the same
distribution mechanism as the data packets.  The underlying protocol
MUST provide multiplexing of the data and control packets, for
example using separate port numbers with UDP.  RTCP performs four
functions:

1. The primary function is to provide feedback on the quality of the
    data distribution.  This is an integral part of the RTP's role as
    a transport protocol and is related to the flow and congestion
    control functions of other transport protocols (see Section 10 on
    the requirement for congestion control).  The feedback may be
    directly useful for control of adaptive encodings [18,19], but
    experiments with IP multicasting have shown that it is also


    critical to get feedback from the receivers to diagnose faults in
    the distribution.  Sending reception feedback reports to all
    participants allows one who is observing problems to evaluate
    whether those problems are local or global.  With a distribution
    mechanism like IP multicast, it is also possible for an entity
    such as a network service provider who is not otherwise involved
    in the session to receive the feedback information and act as a
    third-party monitor to diagnose network problems.  This feedback
    function is performed by the RTCP sender and receiver reports,
    described below in Section 6.4.

2. RTCP carries a persistent transport-level identifier for an RTP
    source called the canonical name or CNAME, Section 6.5.1.  Since
    the SSRC identifier may change if a conflict is discovered or a
    program is restarted, receivers require the CNAME to keep track of
    each participant.  Receivers may also require the CNAME to
    associate multiple data streams from a given participant in a set
    of related RTP sessions, for example to synchronize audio and
    video.  Inter-media synchronization also requires the NTP and RTP
    timestamps included in RTCP packets by data senders.

3. The first two functions require that all participants send RTCP
    packets, therefore the rate must be controlled in order for RTP to
    scale up to a large number of participants.  By having each
    participant send its control packets to all the others, each can
    independently observe the number of participants.  This number is
    used to calculate the rate at which the packets are sent, as
    explained in Section 6.2.

4. A fourth, OPTIONAL function is to convey minimal session control
    information, for example participant identification to be
    displayed in the user interface.  This is most likely to be useful
    in "loosely controlled" sessions where participants enter and
    leave without membership control or parameter negotiation.  RTCP
    serves as a convenient channel to reach all the participants, but
    it is not necessarily expected to support all the control
    communication requirements of an application.  A higher-level
    session control protocol, which is beyond the scope of this
    document, may be needed.

Functions 1-3 SHOULD be used in all environments, but particularly in
the IP multicast environment.  RTP application designers SHOULD avoid
mechanisms that can only work in unicast mode and will not scale to
larger numbers.  Transmission of RTCP MAY be controlled separately
for senders and receivers, as described in Section 6.2, for cases
such as unidirectional links where feedback from receivers is not
possible.

Non-normative note:  In the multicast routing approach
    called Source-Specific Multicast (SSM), there is only one sender
    per "channel" (a source address, group address pair), and
    receivers (except for the channel source) cannot use multicast to
    communicate directly with other channel members.  The
    recommendations here accommodate SSM only through Section 6.2's
    option of turning off receivers' RTCP entirely.  Future work will
    specify adaptation of RTCP for SSM so that feedback from receivers
    can be maintained.


## 6.1 RTCP Packet Format

This specification defines several RTCP packet types to carry a
variety of control information:

SR:   Sender report, for transmission and reception statistics from
        participants that are active senders

RR:   Receiver report, for reception statistics from participants
        that are not active senders and in combination with SR for
        active senders reporting on more than 31 sources

SDES: Source description items, including CNAME

BYE:  Indicates end of participation

APP:  Application-specific functions

Each RTCP packet begins with a fixed part similar to that of RTP data
packets, followed by structured elements that MAY be of variable
length according to the packet type but MUST end on a 32-bit
boundary.  The alignment requirement and a length field in the fixed
part of each packet are included to make RTCP packets "stackable".
Multiple RTCP packets can be concatenated without any intervening
separators to form a compound RTCP packet that is sent in a single
packet of the lower layer protocol, for example UDP.  There is no
explicit count of individual RTCP packets in the compound packet
since the lower layer protocols are expected to provide an overall
length to determine the end of the compound packet.

Each individual RTCP packet in the compound packet may be processed
independently with no requirements upon the order or combination of
packets.  However, in order to perform the functions of the protocol,
the following constraints are imposed:



o  Reception statistics (in SR or RR) should be sent as often as
    bandwidth constraints will allow to maximize the resolution of the
    statistics, therefore each periodically transmitted compound RTCP
    packet MUST include a report packet.

o  New receivers need to receive the CNAME for a source as soon as
    possible to identify the source and to begin associating media for
    purposes such as lip-sync, so each compound RTCP packet MUST also
    include the SDES CNAME except when the compound RTCP packet is
    split for partial encryption as described in Section 9.1.

o  The number of packet types that may appear first in the compound
    packet needs to be limited to increase the number of constant bits
    in the first word and the probability of successfully validating
    RTCP packets against misaddressed RTP data packets or other
    unrelated packets.

Thus, all RTCP packets MUST be sent in a compound packet of at least
two individual packets, with the following format:

Encryption prefix:  If and only if the compound packet is to be
    encrypted according to the method in Section 9.1, it MUST be
    prefixed by a random 32-bit quantity redrawn for every compound
    packet transmitted.  If padding is required for the encryption, it
    MUST be added to the last packet of the compound packet.

SR or RR:  The first RTCP packet in the compound packet MUST
    always be a report packet to facilitate header validation as
    described in Appendix A.2.  This is true even if no data has been
    sent or received, in which case an empty RR MUST be sent, and even
    if the only other RTCP packet in the compound packet is a BYE.

Additional RRs:  If the number of sources for which reception
    statistics are being reported exceeds 31, the number that will fit
    into one SR or RR packet, then additional RR packets SHOULD follow
    the initial report packet.

SDES:  An SDES packet containing a CNAME item MUST be included
    in each compound RTCP packet, except as noted in Section 9.1.
    Other source description items MAY optionally be included if
    required by a particular application, subject to bandwidth
    constraints (see Section 6.3.9).

BYE or APP:  Other RTCP packet types, including those yet to be
    defined, MAY follow in any order, except that BYE SHOULD be the
    last packet sent with a given SSRC/CSRC.  Packet types MAY appear
    more than once.


An individual RTP participant SHOULD send only one compound RTCP
packet per report interval in order for the RTCP bandwidth per
participant to be estimated correctly (see Section 6.2), except when
the compound RTCP packet is split for partial encryption as described
in Section 9.1.  If there are too many sources to fit all the
necessary RR packets into one compound RTCP packet without exceeding
the maximum transmission unit (MTU) of the network path, then only
the subset that will fit into one MTU SHOULD be included in each
interval.  The subsets SHOULD be selected round-robin across multiple
intervals so that all sources are reported.

It is RECOMMENDED that translators and mixers combine individual RTCP
packets from the multiple sources they are forwarding into one
compound packet whenever feasible in order to amortize the packet
overhead (see Section 7).  An example RTCP compound packet as might
be produced by a mixer is shown in Fig. 1.  If the overall length of
a compound packet would exceed the MTU of the network path, it SHOULD
be segmented into multiple shorter compound packets to be transmitted
in separate packets of the underlying protocol.  This does not impair
the RTCP bandwidth estimation because each compound packet represents
at least one distinct participant.  Note that each of the compound
packets MUST begin with an SR or RR packet.

An implementation SHOULD ignore incoming RTCP packets with types
unknown to it.  Additional RTCP packet types may be registered with
the Internet Assigned Numbers Authority (IANA) as described in
Section 15.

   if encrypted: random 32-bit integer
   |
   |[--------- packet --------][---------- packet ----------][-packet-]
   |
   |                receiver            chunk        chunk
   V                reports           item  item   item  item
   --------------------------------------------------------------------
   R[SR #sendinfo #site1#site2][SDES #CNAME PHONE #CNAME LOC][BYE##why]
   --------------------------------------------------------------------
   |                                                                  |
   |<-----------------------  compound packet ----------------------->|
   |<--------------------------  UDP packet ------------------------->|

   #: SSRC/CSRC identifier

              Figure 1: Example of an RTCP compound packet


## 6.2 RTCP Transmission Interval

RTP is designed to allow an application to scale automatically over
session sizes ranging from a few participants to thousands.  For
example, in an audio conference the data traffic is inherently self-
limiting because only one or two people will speak at a time, so with
multicast distribution the data rate on any given link remains
relatively constant independent of the number of participants.
However, the control traffic is not self-limiting.  If the reception
reports from each participant were sent at a constant rate, the
control traffic would grow linearly with the number of participants.
Therefore, the rate must be scaled down by dynamically calculating
the interval between RTCP packet transmissions.

For each session, it is assumed that the data traffic is subject to
an aggregate limit called the "session bandwidth" to be divided among
the participants.  This bandwidth might be reserved and the limit
enforced by the network.  If there is no reservation, there may be
other constraints, depending on the environment, that establish the
"reasonable" maximum for the session to use, and that would be the
session bandwidth.  The session bandwidth may be chosen based on some
cost or a priori knowledge of the available network bandwidth for the
session.  It is somewhat independent of the media encoding, but the
encoding choice may be limited by the session bandwidth.  Often, the
session bandwidth is the sum of the nominal bandwidths of the senders
expected to be concurrently active.  For teleconference audio, this
number would typically be one sender's bandwidth.  For layered
encodings, each layer is a separate RTP session with its own session
bandwidth parameter.

The session bandwidth parameter is expected to be supplied by a
session management application when it invokes a media application,
but media applications MAY set a default based on the single-sender
data bandwidth for the encoding selected for the session.  The
application MAY also enforce bandwidth limits based on multicast
scope rules or other criteria.  All participants MUST use the same
value for the session bandwidth so that the same RTCP interval will
be calculated.

Bandwidth calculations for control and data traffic include lower-
layer transport and network protocols (e.g., UDP and IP) since that
is what the resource reservation system would need to know.  The
application can also be expected to know which of these protocols are
in use.  Link level headers are not included in the calculation since
the packet will be encapsulated with different link level headers as
it travels.

The control traffic should be limited to a small and known fraction
of the session bandwidth: small so that the primary function of the
transport protocol to carry data is not impaired; known so that the
control traffic can be included in the bandwidth specification given
to a resource reservation protocol, and so that each participant can
independently calculate its share.  The control traffic bandwidth is
in addition to the session bandwidth for the data traffic.  It is
RECOMMENDED that the fraction of the session bandwidth added for RTCP
be fixed at 5%.  It is also RECOMMENDED that 1/4 of the RTCP
bandwidth be dedicated to participants that are sending data so that
in sessions with a large number of receivers but a small number of
senders, newly joining participants will more quickly receive the
CNAME for the sending sites.  When the proportion of senders is
greater than 1/4 of the participants, the senders get their
proportion of the full RTCP bandwidth.  While the values of these and
other constants in the interval calculation are not critical, all
participants in the session MUST use the same values so the same
interval will be calculated.  Therefore, these constants SHOULD be
fixed for a particular profile.

A profile MAY specify that the control traffic bandwidth may be a
separate parameter of the session rather than a strict percentage of
the session bandwidth.  Using a separate parameter allows rate-
adaptive applications to set an RTCP bandwidth consistent with a
"typical" data bandwidth that is lower than the maximum bandwidth
specified by the session bandwidth parameter.

The profile MAY further specify that the control traffic bandwidth
may be divided into two separate session parameters for those
participants which are active data senders and those which are not;
let us call the parameters S and R.  Following the recommendation
that 1/4 of the RTCP bandwidth be dedicated to data senders, the
RECOMMENDED default values for these two parameters would be 1.25%
and 3.75%, respectively.  When the proportion of senders is greater
than S/(S+R) of the participants, the senders get their proportion of
the sum of these parameters.  Using two parameters allows RTCP
reception reports to be turned off entirely for a particular session
by setting the RTCP bandwidth for non-data-senders to zero while
keeping the RTCP bandwidth for data senders non-zero so that sender
reports can still be sent for inter-media synchronization.  Turning
off RTCP reception reports is NOT RECOMMENDED because they are needed
for the functions listed at the beginning of Section 6, particularly
reception quality feedback and congestion control.  However, doing so
may be appropriate for systems operating on unidirectional links or
for sessions that don't require feedback on the quality of reception
or liveness of receivers and that have other means to avoid
congestion.

The calculated interval between transmissions of compound RTCP
packets SHOULD also have a lower bound to avoid having bursts of
packets exceed the allowed bandwidth when the number of participants
is small and the traffic isn't smoothed according to the law of large
numbers.  It also keeps the report interval from becoming too small
during transient outages like a network partition such that
adaptation is delayed when the partition heals.  At application
startup, a delay SHOULD be imposed before the first compound RTCP
packet is sent to allow time for RTCP packets to be received from
other participants so the report interval will converge to the
correct value more quickly.  This delay MAY be set to half the
minimum interval to allow quicker notification that the new
participant is present.  The RECOMMENDED value for a fixed minimum
interval is 5 seconds.

An implementation MAY scale the minimum RTCP interval to a smaller
value inversely proportional to the session bandwidth parameter with
the following limitations:

o  For multicast sessions, only active data senders MAY use the
    reduced minimum value to calculate the interval for transmission
    of compound RTCP packets.

o  For unicast sessions, the reduced value MAY be used by
    participants that are not active data senders as well, and the
    delay before sending the initial compound RTCP packet MAY be zero.

o  For all sessions, the fixed minimum SHOULD be used when
    calculating the participant timeout interval (see Section 6.3.5)
    so that implementations which do not use the reduced value for
    transmitting RTCP packets are not timed out by other participants
    prematurely.

o  The RECOMMENDED value for the reduced minimum in seconds is 360
    divided by the session bandwidth in kilobits/second.  This minimum
    is smaller than 5 seconds for bandwidths greater than 72 kb/s.

The algorithm described in Section 6.3 and Appendix A.7 was designed
to meet the goals outlined in this section.  It calculates the
interval between sending compound RTCP packets to divide the allowed
control traffic bandwidth among the participants.  This allows an
application to provide fast response for small sessions where, for
example, identification of all participants is important, yet
automatically adapt to large sessions.  The algorithm incorporates
the following characteristics:

o  The calculated interval between RTCP packets scales linearly with
    the number of members in the group.  It is this linear factor
    which allows for a constant amount of control traffic when summed
    across all members.

o  The interval between RTCP packets is varied randomly over the
    range [0.5,1.5] times the calculated interval to avoid unintended
    synchronization of all participants [20].  The first RTCP packet
    sent after joining a session is also delayed by a random variation
    of half the minimum RTCP interval.

o  A dynamic estimate of the average compound RTCP packet size is
    calculated, including all those packets received and sent, to
    automatically adapt to changes in the amount of control
    information carried.

o  Since the calculated interval is dependent on the number of
    observed group members, there may be undesirable startup effects
    when a new user joins an existing session, or many users
    simultaneously join a new session.  These new users will initially
    have incorrect estimates of the group membership, and thus their
    RTCP transmission interval will be too short.  This problem can be
    significant if many users join the session simultaneously.  To
    deal with this, an algorithm called "timer reconsideration" is
    employed.  This algorithm implements a simple back-off mechanism
    which causes users to hold back RTCP packet transmission if the
    group sizes are increasing.

o  When users leave a session, either with a BYE or by timeout, the
    group membership decreases, and thus the calculated interval
    should decrease.  A "reverse reconsideration" algorithm is used to
    allow members to more quickly reduce their intervals in response
    to group membership decreases.

o  BYE packets are given different treatment than other RTCP packets.
    When a user leaves a group, and wishes to send a BYE packet, it
    may do so before its next scheduled RTCP packet.  However,
    transmission of BYEs follows a back-off algorithm which avoids
    floods of BYE packets should a large number of members
    simultaneously leave the session.

This algorithm may be used for sessions in which all participants are
allowed to send.  In that case, the session bandwidth parameter is
the product of the individual sender's bandwidth times the number of
participants, and the RTCP bandwidth is 5% of that.

Details of the algorithm's operation are given in the sections that
follow.  Appendix A.7 gives an example implementation.

### 6.2.1 Maintaining the Number of Session Members

Calculation of the RTCP packet interval depends upon an estimate of
the number of sites participating in the session.  New sites are
added to the count when they are heard, and an entry for each SHOULD
be created in a table indexed by the SSRC or CSRC identifier (see
Section 8.2) to keep track of them.  New entries MAY be considered
not valid until multiple packets carrying the new SSRC have been
received (see Appendix A.1), or until an SDES RTCP packet containing
a CNAME for that SSRC has been received.  Entries MAY be deleted from
the table when an RTCP BYE packet with the corresponding SSRC
identifier is received, except that some straggler data packets might
arrive after the BYE and cause the entry to be recreated.  Instead,
the entry SHOULD be marked as having received a BYE and then deleted
after an appropriate delay.

A participant MAY mark another site inactive, or delete it if not yet
valid, if no RTP or RTCP packet has been received for a small number
of RTCP report intervals (5 is RECOMMENDED).  This provides some
robustness against packet loss.  All sites must have the same value
for this multiplier and must calculate roughly the same value for the
RTCP report interval in order for this timeout to work properly.
Therefore, this multiplier SHOULD be fixed for a particular profile.

For sessions with a very large number of participants, it may be
impractical to maintain a table to store the SSRC identifier and
state information for all of them.  An implementation MAY use SSRC
sampling, as described in [21], to reduce the storage requirements.
An implementation MAY use any other algorithm with similar
performance.  A key requirement is that any algorithm considered
SHOULD NOT substantially underestimate the group size, although it
MAY overestimate.

## 6.3 RTCP Packet Send and Receive Rules

The rules for how to send, and what to do when receiving an RTCP
packet are outlined here.  An implementation that allows operation in
a multicast environment or a multipoint unicast environment MUST meet
the requirements in Section 6.2.  Such an implementation MAY use the
algorithm defined in this section to meet those requirements, or MAY
use some other algorithm so long as it provides equivalent or better
performance.  An implementation which is constrained to two-party
unicast operation SHOULD still use randomization of the RTCP
transmission interval to avoid unintended synchronization of multiple
instances operating in the same environment, but MAY omit the "timer
reconsideration" and "reverse reconsideration" algorithms in Sections
6.3.3, 6.3.6 and 6.3.7.

To execute these rules, a session participant must maintain several
pieces of state:

tp: the last time an RTCP packet was transmitted;

tc: the current time;

tn: the next scheduled transmission time of an RTCP packet;

pmembers: the estimated number of session members at the time tn
    was last recomputed;

members: the most current estimate for the number of session
    members;

senders: the most current estimate for the number of senders in
    the session;

rtcp_bw: The target RTCP bandwidth, i.e., the total bandwidth
    that will be used for RTCP packets by all members of this session,
    in octets per second.  This will be a specified fraction of the
    "session bandwidth" parameter supplied to the application at
    startup.

we_sent: Flag that is true if the application has sent data
    since the 2nd previous RTCP report was transmitted.

avg_rtcp_size: The average compound RTCP packet size, in octets,
    over all RTCP packets sent and received by this participant.  The
    size includes lower-layer transport and network protocol headers
    (e.g., UDP and IP) as explained in Section 6.2.

initial: Flag that is true if the application has not yet sent
    an RTCP packet.

Many of these rules make use of the "calculated interval" between
packet transmissions.  This interval is described in the following
section.

## 6.3.1 Computing the RTCP Transmission Interval

To maintain scalability, the average interval between packets from a
session participant should scale with the group size.  This interval
is called the calculated interval.  It is obtained by combining a
number of the pieces of state described above.  The calculated
interval T is then determined as follows:

1. If the number of senders is less than or equal to 25% of the
    membership (members), the interval depends on whether the
    participant is a sender or not (based on the value of we_sent).
    If the participant is a sender (we_sent true), the constant C is
    set to the average RTCP packet size (avg_rtcp_size) divided by 25%
    of the RTCP bandwidth (rtcp_bw), and the constant n is set to the
    number of senders.  If we_sent is not true, the constant C is set
    to the average RTCP packet size divided by 75% of the RTCP
    bandwidth.  The constant n is set to the number of receivers
    (members - senders).  If the number of senders is greater than
    25%, senders and receivers are treated together.  The constant C
    is set to the average RTCP packet size divided by the total RTCP
    bandwidth and n is set to the total number of members.  As stated
    in Section 6.2, an RTP profile MAY specify that the RTCP bandwidth
    may be explicitly defined by two separate parameters (call them S
    and R) for those participants which are senders and those which
    are not.  In that case, the 25% fraction becomes S/(S+R) and the
    75% fraction becomes R/(S+R).  Note that if R is zero, the
    percentage of senders is never greater than S/(S+R), and the
    implementation must avoid division by zero.

2. If the participant has not yet sent an RTCP packet (the variable
    initial is true), the constant Tmin is set to 2.5 seconds, else it
    is set to 5 seconds.

3. The deterministic calculated interval Td is set to max(Tmin, n*C).

4. The calculated interval T is set to a number uniformly distributed
    between 0.5 and 1.5 times the deterministic calculated interval.

5. The resulting value of T is divided by e-3/2=1.21828 to compensate
    for the fact that the timer reconsideration algorithm converges to
    a value of the RTCP bandwidth below the intended average.

This procedure results in an interval which is random, but which, on
average, gives at least 25% of the RTCP bandwidth to senders and the
rest to receivers.  If the senders constitute more than one quarter
of the membership, this procedure splits the bandwidth equally among
all participants, on average.

### 6.3.2 Initialization

Upon joining the session, the participant initializes tp to 0, tc to
0, senders to 0, pmembers to 1, members to 1, we_sent to false,
rtcp_bw to the specified fraction of the session bandwidth, initial
to true, and avg_rtcp_size to the probable size of the first RTCP
packet that the application will later construct.  The calculated
interval T is then computed, and the first packet is scheduled for


time tn = T.  This means that a transmission timer is set which
expires at time T.  Note that an application MAY use any desired
approach for implementing this timer.

The participant adds its own SSRC to the member table.

### 6.3.3 Receiving an RTP or Non-BYE RTCP Packet

When an RTP or RTCP packet is received from a participant whose SSRC
is not in the member table, the SSRC is added to the table, and the
value for members is updated once the participant has been validated
as described in Section 6.2.1.  The same processing occurs for each
CSRC in a validated RTP packet.

When an RTP packet is received from a participant whose SSRC is not
in the sender table, the SSRC is added to the table, and the value
for senders is updated.

For each compound RTCP packet received, the value of avg_rtcp_size is
updated:

    avg_rtcp_size = (1/16) * packet_size + (15/16) * avg_rtcp_size

where packet_size is the size of the RTCP packet just received.

### 6.3.4 Receiving an RTCP BYE Packet

Except as described in Section 6.3.7 for the case when an RTCP BYE is
to be transmitted, if the received packet is an RTCP BYE packet, the
SSRC is checked against the member table.  If present, the entry is
removed from the table, and the value for members is updated.  The
SSRC is then checked against the sender table.  If present, the entry
is removed from the table, and the value for senders is updated.

Furthermore, to make the transmission rate of RTCP packets more
adaptive to changes in group membership, the following "reverse
reconsideration" algorithm SHOULD be executed when a BYE packet is
received that reduces members to a value less than pmembers:

o  The value for tn is updated according to the following formula:

        tn = tc + (members/pmembers) * (tn - tc)

o  The value for tp is updated according the following formula:

        tp = tc - (members/pmembers) * (tc - tp).

o  The next RTCP packet is rescheduled for transmission at time tn,
    which is now earlier.

o  The value of pmembers is set equal to members.

This algorithm does not prevent the group size estimate from
incorrectly dropping to zero for a short time due to premature
timeouts when most participants of a large session leave at once but
some remain.  The algorithm does make the estimate return to the
correct value more rapidly.  This situation is unusual enough and the
consequences are sufficiently harmless that this problem is deemed
only a secondary concern.

### 6.3.5 Timing Out an SSRC

At occasional intervals, the participant MUST check to see if any of
the other participants time out.  To do this, the participant
computes the deterministic (without the randomization factor)
calculated interval Td for a receiver, that is, with we_sent false.
Any other session member who has not sent an RTP or RTCP packet since
time tc - MTd (M is the timeout multiplier, and defaults to 5) is
timed out.  This means that its SSRC is removed from the member list,
and members is updated.  A similar check is performed on the sender
list.  Any member on the sender list who has not sent an RTP packet
since time tc - 2T (within the last two RTCP report intervals) is
removed from the sender list, and senders is updated.

If any members time out, the reverse reconsideration algorithm
described in Section 6.3.4 SHOULD be performed.

The participant MUST perform this check at least once per RTCP
transmission interval.

### 6.3.6 Expiration of Transmission Timer

When the packet transmission timer expires, the participant performs
the following operations:

o  The transmission interval T is computed as described in Section
    6.3.1, including the randomization factor.

o  If tp + T is less than or equal to tc, an RTCP packet is
    transmitted.  tp is set to tc, then another value for T is
    calculated as in the previous step and tn is set to tc + T.  The
    transmission timer is set to expire again at time tn.  If tp + T
    is greater than tc, tn is set to tp + T.  No RTCP packet is
    transmitted.  The transmission timer is set to expire at time tn.

o  pmembers is set to members.

If an RTCP packet is transmitted, the value of initial is set to
FALSE.  Furthermore, the value of avg_rtcp_size is updated:

    avg_rtcp_size = (1/16) * packet_size + (15/16) * avg_rtcp_size

where packet_size is the size of the RTCP packet just transmitted.

### 6.3.7 Transmitting a BYE Packet

When a participant wishes to leave a session, a BYE packet is
transmitted to inform the other participants of the event.  In order
to avoid a flood of BYE packets when many participants leave the
system, a participant MUST execute the following algorithm if the
number of members is more than 50 when the participant chooses to
leave.  This algorithm usurps the normal role of the members variable
to count BYE packets instead:

o  When the participant decides to leave the system, tp is reset to
    tc, the current time, members and pmembers are initialized to 1,
    initial is set to 1, we_sent is set to false, senders is set to 0,
    and avg_rtcp_size is set to the size of the compound BYE packet.
    The calculated interval T is computed.  The BYE packet is then
    scheduled for time tn = tc + T.

o  Every time a BYE packet from another participant is received,
    members is incremented by 1 regardless of whether that participant
    exists in the member table or not, and when SSRC sampling is in
    use, regardless of whether or not the BYE SSRC would be included
    in the sample.  members is NOT incremented when other RTCP packets
    or RTP packets are received, but only for BYE packets.  Similarly,
    avg_rtcp_size is updated only for received BYE packets.  senders
    is NOT updated when RTP packets arrive; it remains 0.

o  Transmission of the BYE packet then follows the rules for
    transmitting a regular RTCP packet, as above.

This allows BYE packets to be sent right away, yet controls their
total bandwidth usage.  In the worst case, this could cause RTCP
control packets to use twice the bandwidth as normal (10%) -- 5% for
non-BYE RTCP packets and 5% for BYE.

A participant that does not want to wait for the above mechanism to
allow transmission of a BYE packet MAY leave the group without
sending a BYE at all.  That participant will eventually be timed out
by the other group members.

If the group size estimate members is less than 50 when the
participant decides to leave, the participant MAY send a BYE packet
immediately.  Alternatively, the participant MAY choose to execute
the above BYE backoff algorithm.

In either case, a participant which never sent an RTP or RTCP packet
MUST NOT send a BYE packet when they leave the group.

### 6.3.8 Updating we_sent

The variable we_sent contains true if the participant has sent an RTP
packet recently, false otherwise.  This determination is made by
using the same mechanisms as for managing the set of other
participants listed in the senders table.  If the participant sends
an RTP packet when we_sent is false, it adds itself to the sender
table and sets we_sent to true.  The reverse reconsideration
algorithm described in Section 6.3.4 SHOULD be performed to possibly
reduce the delay before sending an SR packet.  Every time another RTP
packet is sent, the time of transmission of that packet is maintained
in the table.  The normal sender timeout algorithm is then applied to
the participant -- if an RTP packet has not been transmitted since
time tc - 2T, the participant removes itself from the sender table,
decrements the sender count, and sets we_sent to false.

### 6.3.9 Allocation of Source Description Bandwidth

This specification defines several source description (SDES) items in
addition to the mandatory CNAME item, such as NAME (personal name)
and EMAIL (email address).  It also provides a means to define new
application-specific RTCP packet types.  Applications should exercise
caution in allocating control bandwidth to this additional
information because it will slow down the rate at which reception
reports and CNAME are sent, thus impairing the performance of the
protocol.  It is RECOMMENDED that no more than 20% of the RTCP
bandwidth allocated to a single participant be used to carry the
additional information.  Furthermore, it is not intended that all
SDES items will be included in every application.  Those that are
included SHOULD be assigned a fraction of the bandwidth according to
their utility.  Rather than estimate these fractions dynamically, it
is recommended that the percentages be translated statically into
report interval counts based on the typical length of an item.

For example, an application may be designed to send only CNAME, NAME
and EMAIL and not any others.  NAME might be given much higher
priority than EMAIL because the NAME would be displayed continuously
in the application's user interface, whereas EMAIL would be displayed
only when requested.  At every RTCP interval, an RR packet and an
SDES packet with the CNAME item would be sent.  For a small session
operating at the minimum interval, that would be every 5 seconds on
the average.  Every third interval (15 seconds), one extra item would
be included in the SDES packet.  Seven out of eight times this would
be the NAME item, and every eighth time (2 minutes) it would be the
EMAIL item.

When multiple applications operate in concert using cross-application
binding through a common CNAME for each participant, for example in a
multimedia conference composed of an RTP session for each medium, the
additional SDES information MAY be sent in only one RTP session.  The
other sessions would carry only the CNAME item.  In particular, this
approach should be applied to the multiple sessions of a layered
encoding scheme (see Section 2.4).

## 6.4 Sender and Receiver Reports

RTP receivers provide reception quality feedback using RTCP report
packets which may take one of two forms depending upon whether or not
the receiver is also a sender.  The only difference between the
sender report (SR) and receiver report (RR) forms, besides the packet
type code, is that the sender report includes a 20-byte sender
information section for use by active senders.  The SR is issued if a
site has sent any data packets during the interval since issuing the
last report or the previous one, otherwise the RR is issued.

Both the SR and RR forms include zero or more reception report
blocks, one for each of the synchronization sources from which this
receiver has received RTP data packets since the last report.
Reports are not issued for contributing sources listed in the CSRC
list.  Each reception report block provides statistics about the data
received from the particular source indicated in that block.  Since a
maximum of 31 reception report blocks will fit in an SR or RR packet,
additional RR packets SHOULD be stacked after the initial SR or RR
packet as needed to contain the reception reports for all sources
heard during the interval since the last report.  If there are too
many sources to fit all the necessary RR packets into one compound
RTCP packet without exceeding the MTU of the network path, then only
the subset that will fit into one MTU SHOULD be included in each
interval.  The subsets SHOULD be selected round-robin across multiple
intervals so that all sources are reported.

The next sections define the formats of the two reports, how they may
be extended in a profile-specific manner if an application requires
additional feedback information, and how the reports may be used.
Details of reception reporting by translators and mixers is given in
Section 7.

### 6.4.1 SR: Sender Report RTCP Packet


        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=SR=200   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
sender |              NTP timestamp, most significant word             |
info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             NTP timestamp, least significant word             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         RTP timestamp                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     sender's packet count                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      sender's octet count                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The sender report packet consists of three sections, possibly
followed by a fourth profile-specific extension section if defined.
The first section, the header, is 8 octets long.  The fields have the
following meaning:

version (V): 2 bits
    Identifies the version of RTP, which is the same in RTCP packets
    as in RTP data packets.  The version defined by this specification
    is two (2).


padding (P): 1 bit
    If the padding bit is set, this individual RTCP packet contains
    some additional padding octets at the end which are not part of
    the control information but are included in the length field.  The
    last octet of the padding is a count of how many padding octets
    should be ignored, including itself (it will be a multiple of
    four).  Padding may be needed by some encryption algorithms with
    fixed block sizes.  In a compound RTCP packet, padding is only
    required on one individual packet because the compound packet is
    encrypted as a whole for the method in Section 9.1.  Thus, padding
    MUST only be added to the last individual packet, and if padding
    is added to that packet, the padding bit MUST be set only on that
    packet.  This convention aids the header validity checks described
    in Appendix A.2 and allows detection of packets from some early
    implementations that incorrectly set the padding bit on the first
    individual packet and add padding to the last individual packet.

reception report count (RC): 5 bits
    The number of reception report blocks contained in this packet.  A
    value of zero is valid.

packet type (PT): 8 bits
    Contains the constant 200 to identify this as an RTCP SR packet.

length: 16 bits
    The length of this RTCP packet in 32-bit words minus one,
    including the header and any padding.  (The offset of one makes
    zero a valid length and avoids a possible infinite loop in
    scanning a compound RTCP packet, while counting 32-bit words
    avoids a validity check for a multiple of 4.)

SSRC: 32 bits
    The synchronization source identifier for the originator of this
    SR packet.

The second section, the sender information, is 20 octets long and is
present in every sender report packet.  It summarizes the data
transmissions from this sender.  The fields have the following
meaning:

NTP timestamp: 64 bits
    Indicates the wallclock time (see Section 4) when this report was
    sent so that it may be used in combination with timestamps
    returned in reception reports from other receivers to measure
    round-trip propagation to those receivers.  Receivers should
    expect that the measurement accuracy of the timestamp may be
    limited to far less than the resolution of the NTP timestamp.  The
    measurement uncertainty of the timestamp is not indicated as it


    may not be known.  On a system that has no notion of wallclock
    time but does have some system-specific clock such as "system
    uptime", a sender MAY use that clock as a reference to calculate
    relative NTP timestamps.  It is important to choose a commonly
    used clock so that if separate implementations are used to produce
    the individual streams of a multimedia session, all
    implementations will use the same clock.  Until the year 2036,
    relative and absolute timestamps will differ in the high bit so
    (invalid) comparisons will show a large difference; by then one
    hopes relative timestamps will no longer be needed.  A sender that
    has no notion of wallclock or elapsed time MAY set the NTP
    timestamp to zero.

RTP timestamp: 32 bits
    Corresponds to the same time as the NTP timestamp (above), but in
    the same units and with the same random offset as the RTP
    timestamps in data packets.  This correspondence may be used for
    intra- and inter-media synchronization for sources whose NTP
    timestamps are synchronized, and may be used by media-independent
    receivers to estimate the nominal RTP clock frequency.  Note that
    in most cases this timestamp will not be equal to the RTP
    timestamp in any adjacent data packet.  Rather, it MUST be
    calculated from the corresponding NTP timestamp using the
    relationship between the RTP timestamp counter and real time as
    maintained by periodically checking the wallclock time at a
    sampling instant.

sender's packet count: 32 bits
    The total number of RTP data packets transmitted by the sender
    since starting transmission up until the time this SR packet was
    generated.  The count SHOULD be reset if the sender changes its
    SSRC identifier.

sender's octet count: 32 bits
    The total number of payload octets (i.e., not including header or
    padding) transmitted in RTP data packets by the sender since
    starting transmission up until the time this SR packet was
    generated.  The count SHOULD be reset if the sender changes its
    SSRC identifier.  This field can be used to estimate the average
    payload data rate.

The third section contains zero or more reception report blocks
depending on the number of other sources heard by this sender since
the last report.  Each reception report block conveys statistics on
the reception of RTP packets from a single synchronization source.
Receivers SHOULD NOT carry over statistics when a source changes its
SSRC identifier due to a collision.  These statistics are:


SSRC_n (source identifier): 32 bits
    The SSRC identifier of the source to which the information in this
    reception report block pertains.

fraction lost: 8 bits
    The fraction of RTP data packets from source SSRC_n lost since the
    previous SR or RR packet was sent, expressed as a fixed point
    number with the binary point at the left edge of the field.  (That
    is equivalent to taking the integer part after multiplying the
    loss fraction by 256.)  This fraction is defined to be the number
    of packets lost divided by the number of packets expected, as
    defined in the next paragraph.  An implementation is shown in
    Appendix A.3.  If the loss is negative due to duplicates, the
    fraction lost is set to zero.  Note that a receiver cannot tell
    whether any packets were lost after the last one received, and
    that there will be no reception report block issued for a source
    if all packets from that source sent during the last reporting
    interval have been lost.

cumulative number of packets lost: 24 bits
    The total number of RTP data packets from source SSRC_n that have
    been lost since the beginning of reception.  This number is
    defined to be the number of packets expected less the number of
    packets actually received, where the number of packets received
    includes any which are late or duplicates.  Thus, packets that
    arrive late are not counted as lost, and the loss may be negative
    if there are duplicates.  The number of packets expected is
    defined to be the extended last sequence number received, as
    defined next, less the initial sequence number received.  This may
    be calculated as shown in Appendix A.3.

extended highest sequence number received: 32 bits
    The low 16 bits contain the highest sequence number received in an
    RTP data packet from source SSRC_n, and the most significant 16
    bits extend that sequence number with the corresponding count of
    sequence number cycles, which may be maintained according to the
    algorithm in Appendix A.1.  Note that different receivers within
    the same session will generate different extensions to the
    sequence number if their start times differ significantly.

interarrival jitter: 32 bits
    An estimate of the statistical variance of the RTP data packet
    interarrival time, measured in timestamp units and expressed as an
    unsigned integer.  The interarrival jitter J is defined to be the
    mean deviation (smoothed absolute value) of the difference D in
    packet spacing at the receiver compared to the sender for a pair
    of packets.  As shown in the equation below, this is equivalent to
    the difference in the "relative transit time" for the two packets;


    the relative transit time is the difference between a packet's RTP
    timestamp and the receiver's clock at the time of arrival,
    measured in the same units.

    If Si is the RTP timestamp from packet i, and Ri is the time of
    arrival in RTP timestamp units for packet i, then for two packets
    i and j, D may be expressed as

        D(i,j) = (Rj - Ri) - (Sj - Si) = (Rj - Sj) - (Ri - Si)

    The interarrival jitter SHOULD be calculated continuously as each
    data packet i is received from source SSRC_n, using this
    difference D for that packet and the previous packet i-1 in order
    of arrival (not necessarily in sequence), according to the formula

        J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16

    Whenever a reception report is issued, the current value of J is
    sampled.

    The jitter calculation MUST conform to the formula specified here
    in order to allow profile-independent monitors to make valid
    interpretations of reports coming from different implementations.
    This algorithm is the optimal first-order estimator and the gain
    parameter 1/16 gives a good noise reduction ratio while
    maintaining a reasonable rate of convergence [22].  A sample
    implementation is shown in Appendix A.8.  See Section 6.4.4 for a
    discussion of the effects of varying packet duration and delay
    before transmission.

last SR timestamp (LSR): 32 bits
    The middle 32 bits out of 64 in the NTP timestamp (as explained in
    Section 4) received as part of the most recent RTCP sender report
    (SR) packet from source SSRC_n.  If no SR has been received yet,
    the field is set to zero.

delay since last SR (DLSR): 32 bits
    The delay, expressed in units of 1/65536 seconds, between
    receiving the last SR packet from source SSRC_n and sending this
    reception report block.  If no SR packet has been received yet
    from SSRC_n, the DLSR field is set to zero.

    Let SSRC_r denote the receiver issuing this receiver report.
    Source SSRC_n can compute the round-trip propagation delay to
    SSRC_r by recording the time A when this reception report block is
    received.  It calculates the total round-trip time A-LSR using the
    last SR timestamp (LSR) field, and then subtracting this field to
    leave the round-trip propagation delay as (A - LSR - DLSR).  This


    is illustrated in Fig. 2.  Times are shown in both a hexadecimal
    representation of the 32-bit fields and the equivalent floating-
    point decimal representation.  Colons indicate a 32-bit field
    divided into a 16-bit integer part and 16-bit fraction part.

    This may be used as an approximate measure of distance to cluster
    receivers, although some links have very asymmetric delays.

   [10 Nov 1995 11:33:25.125 UTC]       [10 Nov 1995 11:33:36.5 UTC]
   n                 SR(n)              A=b710:8000 (46864.500 s)
   ---------------------------------------------------------------->
                      v                 ^
   ntp_sec =0xb44db705 v               ^ dlsr=0x0005:4000 (    5.250s)
   ntp_frac=0x20000000  v             ^  lsr =0xb705:2000 (46853.125s)
     (3024992005.125 s)  v           ^
   r                      v         ^ RR(n)
   ---------------------------------------------------------------->
                          |<-DLSR->|
                           (5.250 s)

   A     0xb710:8000 (46864.500 s)
   DLSR -0x0005:4000 (    5.250 s)
   LSR  -0xb705:2000 (46853.125 s)
   -------------------------------
   delay 0x0006:2000 (    6.125 s)

           Figure 2: Example for round-trip time computation

### 6.4.2 RR: Receiver Report RTCP Packet

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=RR=201   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     SSRC of packet sender                     |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_1 (SSRC of first source)                 |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  1    | fraction lost |       cumulative number of packets lost       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           extended highest sequence number received           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      interarrival jitter                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         last SR (LSR)                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   delay since last SR (DLSR)                  |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report |                 SSRC_2 (SSRC of second source)                |
block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  2    :                               ...                             :
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |                  profile-specific extensions                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The format of the receiver report (RR) packet is the same as that of
the SR packet except that the packet type field contains the constant
201 and the five words of sender information are omitted (these are
the NTP and RTP timestamps and sender's packet and octet counts).
The remaining fields have the same meaning as for the SR packet.

An empty RR packet (RC = 0) MUST be put at the head of a compound
RTCP packet when there is no data transmission or reception to
report.

### 6.4.3 Extending the Sender and Receiver Reports

A profile SHOULD define profile-specific extensions to the sender
report and receiver report if there is additional information that
needs to be reported regularly about the sender or receivers.  This
method SHOULD be used in preference to defining another RTCP packet
type because it requires less overhead:

o  fewer octets in the packet (no RTCP header or SSRC field);

o  simpler and faster parsing because applications running under that
    profile would be programmed to always expect the extension fields
    in the directly accessible location after the reception reports.

The extension is a fourth section in the sender- or receiver-report
packet which comes at the end after the reception report blocks, if
any.  If additional sender information is required, then for sender
reports it would be included first in the extension section, but for
receiver reports it would not be present.  If information about
receivers is to be included, that data SHOULD be structured as an
array of blocks parallel to the existing array of reception report
blocks; that is, the number of blocks would be indicated by the RC
field.

### 6.4.4 Analyzing Sender and Receiver Reports

It is expected that reception quality feedback will be useful not
only for the sender but also for other receivers and third-party
monitors.  The sender may modify its transmissions based on the
feedback; receivers can determine whether problems are local,
regional or global; network managers may use profile-independent
monitors that receive only the RTCP packets and not the corresponding
RTP data packets to evaluate the performance of their networks for
multicast distribution.

Cumulative counts are used in both the sender information and
receiver report blocks so that differences may be calculated between
any two reports to make measurements over both short and long time
periods, and to provide resilience against the loss of a report.  The
difference between the last two reports received can be used to
estimate the recent quality of the distribution.  The NTP timestamp
is included so that rates may be calculated from these differences
over the interval between two reports.  Since that timestamp is
independent of the clock rate for the data encoding, it is possible
to implement encoding- and profile-independent quality monitors.

An example calculation is the packet loss rate over the interval
between two reception reports.  The difference in the cumulative
number of packets lost gives the number lost during that interval.
The difference in the extended last sequence numbers received gives
the number of packets expected during the interval.  The ratio of
these two is the packet loss fraction over the interval.  This ratio
should equal the fraction lost field if the two reports are
consecutive, but otherwise it may not.  The loss rate per second can
be obtained by dividing the loss fraction by the difference in NTP
timestamps, expressed in seconds.  The number of packets received is
the number of packets expected minus the number lost.  The number of

packets expected may also be used to judge the statistical validity
of any loss estimates.  For example, 1 out of 5 packets lost has a
lower significance than 200 out of 1000.

From the sender information, a third-party monitor can calculate the
average payload data rate and the average packet rate over an
interval without receiving the data.  Taking the ratio of the two
gives the average payload size.  If it can be assumed that packet
loss is independent of packet size, then the number of packets
received by a particular receiver times the average payload size (or
the corresponding packet size) gives the apparent throughput
available to that receiver.

In addition to the cumulative counts which allow long-term packet
loss measurements using differences between reports, the fraction
lost field provides a short-term measurement from a single report.
This becomes more important as the size of a session scales up enough
that reception state information might not be kept for all receivers
or the interval between reports becomes long enough that only one
report might have been received from a particular receiver.

The interarrival jitter field provides a second short-term measure of
network congestion.  Packet loss tracks persistent congestion while
the jitter measure tracks transient congestion.  The jitter measure
may indicate congestion before it leads to packet loss.  The
interarrival jitter field is only a snapshot of the jitter at the
time of a report and is not intended to be taken quantitatively.
Rather, it is intended for comparison across a number of reports from
one receiver over time or from multiple receivers, e.g., within a
single network, at the same time.  To allow comparison across
receivers, it is important the the jitter be calculated according to
the same formula by all receivers.

Because the jitter calculation is based on the RTP timestamp which
represents the instant when the first data in the packet was sampled,
any variation in the delay between that sampling instant and the time
the packet is transmitted will affect the resulting jitter that is
calculated.  Such a variation in delay would occur for audio packets
of varying duration.  It will also occur for video encodings because
the timestamp is the same for all the packets of one frame but those
packets are not all transmitted at the same time.  The variation in
delay until transmission does reduce the accuracy of the jitter
calculation as a measure of the behavior of the network by itself,
but it is appropriate to include considering that the receiver buffer
must accommodate it.  When the jitter calculation is used as a
comparative measure, the (constant) component due to variation in
delay until transmission subtracts out so that a change in the
network jitter component can then be observed unless it is relatively
small.  If the change is small, then it is likely to be
inconsequential.

## 6.5 SDES: Source Description RTCP Packet


        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    SC   |  PT=SDES=202  |             length            |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_1                          |
  1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_2                          |
  2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

The SDES packet is a three-level structure composed of a header and
zero or more chunks, each of which is composed of items describing
the source identified in that chunk.  The items are described
individually in subsequent sections.

version (V), padding (P), length:
    As described for the SR packet (see Section 6.4.1).

packet type (PT): 8 bits
    Contains the constant 202 to identify this as an RTCP SDES packet.

source count (SC): 5 bits
    The number of SSRC/CSRC chunks contained in this SDES packet.  A
    value of zero is valid but useless.

Each chunk consists of an SSRC/CSRC identifier followed by a list of
zero or more items, which carry information about the SSRC/CSRC.
Each chunk starts on a 32-bit boundary.  Each item consists of an 8-
bit type field, an 8-bit octet count describing the length of the
text (thus, not including this two-octet header), and the text
itself.  Note that the text can be no longer than 255 octets, but
this is consistent with the need to limit RTCP bandwidth consumption.


The text is encoded according to the UTF-8 encoding specified in RFC
2279 [5].  US-ASCII is a subset of this encoding and requires no
additional encoding.  The presence of multi-octet encodings is
indicated by setting the most significant bit of a character to a
value of one.

Items are contiguous, i.e., items are not individually padded to a
32-bit boundary.  Text is not null terminated because some multi-
octet encodings include null octets.  The list of items in each chunk
MUST be terminated by one or more null octets, the first of which is
interpreted as an item type of zero to denote the end of the list.
No length octet follows the null item type octet, but additional null
octets MUST be included if needed to pad until the next 32-bit
boundary.  Note that this padding is separate from that indicated by
the P bit in the RTCP header.  A chunk with zero items (four null
octets) is valid but useless.

End systems send one SDES packet containing their own source
identifier (the same as the SSRC in the fixed RTP header).  A mixer
sends one SDES packet containing a chunk for each contributing source
from which it is receiving SDES information, or multiple complete
SDES packets in the format above if there are more than 31 such
sources (see Section 7).

The SDES items currently defined are described in the next sections.
Only the CNAME item is mandatory.  Some items shown here may be
useful only for particular profiles, but the item types are all
assigned from one common space to promote shared use and to simplify
profile-independent applications.  Additional items may be defined in
a profile by registering the type numbers with IANA as described in
Section 15.

### 6.5.1 CNAME: Canonical End-Point Identifier SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    CNAME=1    |     length    | user and domain name        ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The CNAME identifier has the following properties:

o  Because the randomly allocated SSRC identifier may change if a
    conflict is discovered or if a program is restarted, the CNAME
    item MUST be included to provide the binding from the SSRC
    identifier to an identifier for the source (sender or receiver)
    that remains constant.

o  Like the SSRC identifier, the CNAME identifier SHOULD also be
    unique among all participants within one RTP session.

o  To provide a binding across multiple media tools used by one
    participant in a set of related RTP sessions, the CNAME SHOULD be
    fixed for that participant.

o  To facilitate third-party monitoring, the CNAME SHOULD be suitable
    for either a program or a person to locate the source.

Therefore, the CNAME SHOULD be derived algorithmically and not
entered manually, when possible.  To meet these requirements, the
following format SHOULD be used unless a profile specifies an
alternate syntax or semantics.  The CNAME item SHOULD have the format
"user@host", or "host" if a user name is not available as on single-
user systems.  For both formats, "host" is either the fully qualified
domain name of the host from which the real-time data originates,
formatted according to the rules specified in RFC 1034 [6], RFC 1035
[7] and Section 2.1 of RFC 1123 [8]; or the standard ASCII
representation of the host's numeric address on the interface used
for the RTP communication.  For example, the standard ASCII
representation of an IP Version 4 address is "dotted decimal", also
known as dotted quad, and for IP Version 6, addresses are textually
represented as groups of hexadecimal digits separated by colons (with
variations as detailed in RFC 3513 [23]).  Other address types are
expected to have ASCII representations that are mutually unique.  The
fully qualified domain name is more convenient for a human observer
and may avoid the need to send a NAME item in addition, but it may be
difficult or impossible to obtain reliably in some operating
environments.  Applications that may be run in such environments
SHOULD use the ASCII representation of the address instead.

Examples are "doe@sleepy.example.com", "doe@192.0.2.89" or
"doe@2201:056D::112E:144A:1E24" for a multi-user system.  On a system
with no user name, examples would be "sleepy.example.com",
"192.0.2.89" or "2201:056D::112E:144A:1E24".

The user name SHOULD be in a form that a program such as "finger" or
"talk" could use, i.e., it typically is the login name rather than
the personal name.  The host name is not necessarily identical to the
one in the participant's electronic mail address.

This syntax will not provide unique identifiers for each source if an
application permits a user to generate multiple sources from one
host.  Such an application would have to rely on the SSRC to further
identify the source, or the profile for that application would have
to specify additional syntax for the CNAME identifier.

If each application creates its CNAME independently, the resulting
CNAMEs may not be identical as would be required to provide a binding
across multiple media tools belonging to one participant in a set of
related RTP sessions.  If cross-media binding is required, it may be
necessary for the CNAME of each tool to be externally configured with
the same value by a coordination tool.

Application writers should be aware that private network address
assignments such as the Net-10 assignment proposed in RFC 1918 [24]
may create network addresses that are not globally unique.  This
would lead to non-unique CNAMEs if hosts with private addresses and
no direct IP connectivity to the public Internet have their RTP
packets forwarded to the public Internet through an RTP-level
translator.  (See also RFC 1627 [25].)  To handle this case,
applications MAY provide a means to configure a unique CNAME, but the
burden is on the translator to translate CNAMEs from private
addresses to public addresses if necessary to keep private addresses
from being exposed.

### 6.5.2 NAME: User Name SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     NAME=2    |     length    | common name of source       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

This is the real name used to describe the source, e.g., "John Doe,
Bit Recycler".  It may be in any form desired by the user.  For
applications such as conferencing, this form of name may be the most
desirable for display in participant lists, and therefore might be
sent most frequently of those items other than CNAME.  Profiles MAY
establish such priorities.  The NAME value is expected to remain
constant at least for the duration of a session.  It SHOULD NOT be
relied upon to be unique among all participants in the session.

### 6.5.3 EMAIL: Electronic Mail Address SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    EMAIL=3    |     length    | email address of source     ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The email address is formatted according to RFC 2822 [9], for
example, "John.Doe@example.com".  The EMAIL value is expected to
remain constant for the duration of a session.

### 6.5.4 PHONE: Phone Number SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    PHONE=4    |     length    | phone number of source      ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The phone number SHOULD be formatted with the plus sign replacing the
international access code.  For example, "+1 908 555 1212" for a
number in the United States.

### 6.5.5 LOC: Geographic User Location SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     LOC=5     |     length    | geographic location of site ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Depending on the application, different degrees of detail are
appropriate for this item.  For conference applications, a string
like "Murray Hill, New Jersey" may be sufficient, while, for an
active badge system, strings like "Room 2A244, AT&T BL MH" might be
appropriate.  The degree of detail is left to the implementation
and/or user, but format and content MAY be prescribed by a profile.
The LOC value is expected to remain constant for the duration of a
session, except for mobile hosts.

### 6.5.6 TOOL: Application or Tool Name SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     TOOL=6    |     length    |name/version of source appl. ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

A string giving the name and possibly version of the application
generating the stream, e.g., "videotool 1.2".  This information may
be useful for debugging purposes and is similar to the Mailer or
Mail-System-Version SMTP headers.  The TOOL value is expected to
remain constant for the duration of the session.

### 6.5.7 NOTE: Notice/Status SDES Item

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     NOTE=7    |     length    | note about the source       ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The following semantics are suggested for this item, but these or
other semantics MAY be explicitly defined by a profile.  The NOTE
item is intended for transient messages describing the current state
of the source, e.g., "on the phone, can't talk".  Or, during a
seminar, this item might be used to convey the title of the talk.  It
should be used only to carry exceptional information and SHOULD NOT
be included routinely by all participants because this would slow
down the rate at which reception reports and CNAME are sent, thus
impairing the performance of the protocol.  In particular, it SHOULD
NOT be included as an item in a user's configuration file nor
automatically generated as in a quote-of-the-day.

Since the NOTE item may be important to display while it is active,
the rate at which other non-CNAME items such as NAME are transmitted
might be reduced so that the NOTE item can take that part of the RTCP
bandwidth.  When the transient message becomes inactive, the NOTE
item SHOULD continue to be transmitted a few times at the same
repetition rate but with a string of length zero to signal the
receivers.  However, receivers SHOULD also consider the NOTE item
inactive if it is not received for a small multiple of the repetition
rate, or perhaps 20-30 RTCP intervals.

### 6.5.8 PRIV: Private Extensions SDES Item

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     PRIV=8    |     length    | prefix length |prefix string...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ...             |                  value string               ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

This item is used to define experimental or application-specific SDES
extensions.  The item contains a prefix consisting of a length-string
pair, followed by the value string filling the remainder of the item
and carrying the desired information.  The prefix length field is 8
bits long.  The prefix string is a name chosen by the person defining
the PRIV item to be unique with respect to other PRIV items this
application might receive.  The application creator might choose to
use the application name plus an additional subtype identification if


needed.  Alternatively, it is RECOMMENDED that others choose a name
based on the entity they represent, then coordinate the use of the
name within that entity.

Note that the prefix consumes some space within the item's total
length of 255 octets, so the prefix should be kept as short as
possible.  This facility and the constrained RTCP bandwidth SHOULD
NOT be overloaded; it is not intended to satisfy all the control
communication requirements of all applications.

SDES PRIV prefixes will not be registered by IANA.  If some form of
the PRIV item proves to be of general utility, it SHOULD instead be
assigned a regular SDES item type registered with IANA so that no
prefix is required.  This simplifies use and increases transmission
efficiency.

## 6.6 BYE: Goodbye RTCP Packet

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |V=2|P|    SC   |   PT=BYE=203  |             length            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           SSRC/CSRC                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      :                              ...                              :
      +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
(opt) |     length    |               reason for leaving            ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The BYE packet indicates that one or more sources are no longer
active.

version (V), padding (P), length:
    As described for the SR packet (see Section 6.4.1).

packet type (PT): 8 bits
    Contains the constant 203 to identify this as an RTCP BYE packet.

source count (SC): 5 bits
    The number of SSRC/CSRC identifiers included in this BYE packet.
    A count value of zero is valid, but useless.

The rules for when a BYE packet should be sent are specified in
Sections 6.3.7 and 8.2.

If a BYE packet is received by a mixer, the mixer SHOULD forward the
BYE packet with the SSRC/CSRC identifier(s) unchanged.  If a mixer
shuts down, it SHOULD send a BYE packet listing all contributing
sources it handles, as well as its own SSRC identifier.  Optionally,
the BYE packet MAY include an 8-bit octet count followed by that many
octets of text indicating the reason for leaving, e.g., "camera
malfunction" or "RTP loop detected".  The string has the same
encoding as that described for SDES.  If the string fills the packet
to the next 32-bit boundary, the string is not null terminated.  If
not, the BYE packet MUST be padded with null octets to the next 32-
bit boundary.  This padding is separate from that indicated by the P
bit in the RTCP header.

## 6.7 APP: Application-Defined RTCP Packet

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P| subtype |   PT=APP=204  |             length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           SSRC/CSRC                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          name (ASCII)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   application-dependent data                ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The APP packet is intended for experimental use as new applications
and new features are developed, without requiring packet type value
registration.  APP packets with unrecognized names SHOULD be ignored.
After testing and if wider use is justified, it is RECOMMENDED that
each APP packet be redefined without the subtype and name fields and
registered with IANA using an RTCP packet type.

version (V), padding (P), length:
    As described for the SR packet (see Section 6.4.1).

subtype: 5 bits
    May be used as a subtype to allow a set of APP packets to be
    defined under one unique name, or for any application-dependent
    data.

packet type (PT): 8 bits
    Contains the constant 204 to identify this as an RTCP APP packet.

name: 4 octets
    A name chosen by the person defining the set of APP packets to be
    unique with respect to other APP packets this application might
    receive.  The application creator might choose to use the
    application name, and then coordinate the allocation of subtype
    values to others who want to define new packet types for the
    application.  Alternatively, it is RECOMMENDED that others choose
    a name based on the entity they represent, then coordinate the use
    of the name within that entity.  The name is interpreted as a
    sequence of four ASCII characters, with uppercase and lowercase
    characters treated as distinct.

application-dependent data: variable length
    Application-dependent data may or may not appear in an APP packet.
    It is interpreted by the application and not RTP itself.  It MUST
    be a multiple of 32 bits long.
