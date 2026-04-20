# Appendix B - Changes from RFC 1889

Most of this RFC is identical to RFC 1889.  There are no changes in
the packet formats on the wire, only changes to the rules and
algorithms governing how the protocol is used.  The biggest change is
an enhancement to the scalable timer algorithm for calculating when
to send RTCP packets:

o  The algorithm for calculating the RTCP transmission interval
    specified in Sections 6.2 and 6.3 and illustrated in Appendix A.7
    is augmented to include "reconsideration" to minimize transmission
    in excess of the intended rate when many participants join a
    session simultaneously, and "reverse reconsideration" to reduce
    the incidence and duration of false participant timeouts when the
    number of participants drops rapidly.  Reverse reconsideration is
    also used to possibly shorten the delay before sending RTCP SR
    when transitioning from passive receiver to active sender mode.

o  Section 6.3.7 specifies new rules controlling when an RTCP BYE
    packet should be sent in order to avoid a flood of packets when
    many participants leave a session simultaneously.

o  The requirement to retain state for inactive participants for a
    period long enough to span typical network partitions was removed
    from Section 6.2.1.  In a session where many participants join for
    a brief time and fail to send BYE, this requirement would cause a
    significant overestimate of the number of participants.  The
    reconsideration algorithm added in this revision compensates for
    the large number of new participants joining simultaneously when a
    partition heals.

It should be noted that these enhancements only have a significant
effect when the number of session participants is large (thousands)
and most of the participants join or leave at the same time.  This
makes testing in a live network difficult.  However, the algorithm
was subjected to a thorough analysis and simulation to verify its
performance.  Furthermore, the enhanced algorithm was designed to
interoperate with the algorithm in RFC 1889 such that the degree of
reduction in excess RTCP bandwidth during a step join is proportional
to the fraction of participants that implement the enhanced
algorithm.  Interoperation of the two algorithms has been verified
experimentally on live networks.

Other functional changes were:

o  Section 6.2.1 specifies that implementations may store only a
    sampling of the participants' SSRC identifiers to allow scaling to
    very large sessions.  Algorithms are specified in RFC 2762 [21].


o  In Section 6.2 it is specified that RTCP sender and non-sender
    bandwidths may be set as separate parameters of the session rather
    than a strict percentage of the session bandwidth, and may be set
    to zero.  The requirement that RTCP was mandatory for RTP sessions
    using IP multicast was relaxed.  However, a clarification was also
    added that turning off RTCP is NOT RECOMMENDED.

o  In Sections 6.2, 6.3.1 and Appendix A.7, it is specified that the
    fraction of participants below which senders get dedicated RTCP
    bandwidth changes from the fixed 1/4 to a ratio based on the RTCP
    sender and non-sender bandwidth parameters when those are given.
    The condition that no bandwidth is dedicated to senders when there
    are no senders was removed since that is expected to be a
    transitory state.  It also keeps non-senders from using sender
    RTCP bandwidth when that is not intended.

o  Also in Section 6.2 it is specified that the minimum RTCP interval
    may be scaled to smaller values for high bandwidth sessions, and
    that the initial RTCP delay may be set to zero for unicast
    sessions.

o  Timing out a participant is to be based on inactivity for a number
    of RTCP report intervals calculated using the receiver RTCP
    bandwidth fraction even for active senders.

o  Sections 7.2 and 7.3 specify that translators and mixers should
    send BYE packets for the sources they are no longer forwarding.

o  Rule changes for layered encodings are defined in Sections 2.4,
    6.3.9, 8.3 and 11.  In the last of these, it is noted that the
    address and port assignment rule conflicts with the SDP
    specification, RFC 2327 [15], but it is intended that this
    restriction will be relaxed in a revision of RFC 2327.

o  The convention for using even/odd port pairs for RTP and RTCP in
    Section 11 was clarified to refer to destination ports.  The
    requirement to use an even/odd port pair was removed if the two
    ports are specified explicitly.  For unicast RTP sessions,
    distinct port pairs may be used for the two ends (Sections 3, 7.1
    and 11).

o  A new Section 10 was added to explain the requirement for
    congestion control in applications using RTP.

o  In Section 8.2, the requirement that a new SSRC identifier MUST be
    chosen whenever the source transport address is changed has been
    relaxed to say that a new SSRC identifier MAY be chosen.
    Correspondingly, it was clarified that an implementation MAY


    choose to keep packets from the new source address rather than the
    existing source address when an SSRC collision occurs between two
    other participants, and SHOULD do so for applications such as
    telephony in which some sources such as mobile entities may change
    addresses during the course of an RTP session.

o  An indentation bug in the RFC 1889 printing of the pseudo-code for
    the collision detection and resolution algorithm in Section 8.2
    has been corrected by translating the syntax to pseudo C language,
    and the algorithm has been modified to remove the restriction that
    both RTP and RTCP must be sent from the same source port number.

o  The description of the padding mechanism for RTCP packets was
    clarified and it is specified that padding MUST only be applied to
    the last packet of a compound RTCP packet.

o  In Section A.1, initialization of base_seq was corrected to be seq
    rather than seq - 1, and the text was corrected to say the bad
    sequence number plus 1 is stored.  The initialization of max_seq
    and other variables for the algorithm was separated from the text
    to make clear that this initialization must be done in addition to
    calling the init_seq() function (and a few words lost in RFC 1889
    when processing the document from source to output form were
    restored).

o  Clamping of number of packets lost in Section A.3 was corrected to
    use both positive and negative limits.

o  The specification of "relative" NTP timestamp in the RTCP SR
    section now defines these timestamps to be based on the most
    common system-specific clock, such as system uptime, rather than
    on session elapsed time which would not be the same for multiple
    applications started on the same machine at different times.

Non-functional changes:

o  It is specified that a receiver MUST ignore packets with payload
    types it does not understand.

o  In Fig. 2, the floating point NTP timestamp value was corrected,
    some missing leading zeros were added in a hex number, and the UTC
    timezone was specified.

o  The inconsequence of NTP timestamps wrapping around in the year
    2036 is explained.

o  The policy for registration of RTCP packet types and SDES types
    was clarified in a new Section 15, IANA Considerations.  The
    suggestion that experimenters register the numbers they need and
    then unregister those which prove to be unneeded has been removed
    in favor of using APP and PRIV.  Registration of profile names was
    also specified.

o  The reference for the UTF-8 character set was changed from an
    X/Open Preliminary Specification to be RFC 2279.

o  The reference for RFC 1597 was updated to RFC 1918 and the
    reference for RFC 2543 was updated to RFC 3261.

o  The last paragraph of the introduction in RFC 1889, which
    cautioned implementors to limit deployment in the Internet, was
    removed because it was deemed no longer relevant.

o  A non-normative note regarding the use of RTP with Source-Specific
    Multicast (SSM) was added in Section 6.

o  The definition of "RTP session" in Section 3 was expanded to
    acknowledge that a single session may use multiple destination
    transport addresses (as was always the case for a translator or
    mixer) and to explain that the distinguishing feature of an RTP
    session is that each corresponds to a separate SSRC identifier
    space.  A new definition of "multimedia session" was added to
    reduce confusion about the word "session".

o  The meaning of "sampling instant" was explained in more detail as
    part of the definition of the timestamp field of the RTP header in
    Section 5.1.

o  Small clarifications of the text have been made in several places,
    some in response to questions from readers.  In particular:

    -  In RFC 1889, the first five words of the second sentence of
        Section 2.2 were lost in processing the document from source to
        output form, but are now restored.

    -  A definition for "RTP media type" was added in Section 3 to
        allow the explanation of multiplexing RTP sessions in Section
        5.2 to be more clear regarding the multiplexing of multiple
        media.  That section also now explains that multiplexing
        multiple sources of the same medium based on SSRC identifiers
        may be appropriate and is the norm for multicast sessions.

    -  The definition for "non-RTP means" was expanded to include
        examples of other protocols constituting non-RTP means.


    -  The description of the session bandwidth parameter is expanded
        in Section 6.2, including a clarification that the control
        traffic bandwidth is in addition to the session bandwidth for
        the data traffic.

    -  The effect of varying packet duration on the jitter calculation
        was explained in Section 6.4.4.

    -  The method for terminating and padding a sequence of SDES items
        was clarified in Section 6.5.

    -  IPv6 address examples were added in the description of SDES
        CNAME in Section 6.5.1, and "example.com" was used in place of
        other example domain names.

    -  The Security section added a formal reference to IPSEC now that
        it is available, and says that the confidentiality method
        defined in this specification is primarily to codify existing
        practice.  It is RECOMMENDED that stronger encryption
        algorithms such as Triple-DES be used in place of the default
        algorithm, and noted that the SRTP profile based on AES will be
        the correct choice in the future.  A caution about the weakness
        of the RTP header as an initialization vector was added.  It
        was also noted that payload-only encryption is necessary to
        allow for header compression.

    -  The method for partial encryption of RTCP was clarified; in
        particular, SDES CNAME is carried in only one part when the
        compound RTCP packet is split.

    -  It is clarified that only one compound RTCP packet should be
        sent per reporting interval and that if there are too many
        active sources for the reports to fit in the MTU, then a subset
        of the sources should be selected round-robin over multiple
        intervals.

    -  A note was added in Appendix A.1 that packets may be saved
        during RTP header validation and delivered upon success.

    -  Section 7.3 now explains that a mixer aggregating SDES packets
        uses more RTCP bandwidth due to longer packets, and a mixer
        passing through RTCP naturally sends packets at higher than the
        single source rate, but both behaviors are valid.

    -  Section 13 clarifies that an RTP application may use multiple
        profiles but typically only one in a given session.
