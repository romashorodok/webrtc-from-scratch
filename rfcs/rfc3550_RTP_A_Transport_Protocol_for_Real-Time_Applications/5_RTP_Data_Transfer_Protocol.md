# 5. RTP Data Transfer Protocol

## 5.1 RTP Fixed Header Fields

   The RTP header has the following format:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The first twelve octets are present in every RTP packet, while the
list of CSRC identifiers is present only when inserted by a mixer.
The fields have the following meaning:

version (V): 2 bits
    This field identifies the version of RTP.  The version defined by
    this specification is two (2).  (The value 1 is used by the first
    draft version of RTP and the value 0 is used by the protocol
    initially implemented in the "vat" audio tool.)

padding (P): 1 bit
    If the padding bit is set, the packet contains one or more
    additional padding octets at the end which are not part of the
    payload.  The last octet of the padding contains a count of how
    many padding octets should be ignored, including itself.  Padding
    may be needed by some encryption algorithms with fixed block sizes
    or for carrying several RTP packets in a lower-layer protocol data
    unit.

extension (X): 1 bit
    If the extension bit is set, the fixed header MUST be followed by
    exactly one header extension, with a format defined in Section
    5.3.1.

CSRC count (CC): 4 bits
    The CSRC count contains the number of CSRC identifiers that follow
    the fixed header.


marker (M): 1 bit
    The interpretation of the marker is defined by a profile.  It is
    intended to allow significant events such as frame boundaries to
    be marked in the packet stream.  A profile MAY define additional
    marker bits or specify that there is no marker bit by changing the
    number of bits in the payload type field (see Section 5.3).

payload type (PT): 7 bits
    This field identifies the format of the RTP payload and determines
    its interpretation by the application.  A profile MAY specify a
    default static mapping of payload type codes to payload formats.
    Additional payload type codes MAY be defined dynamically through
    non-RTP means (see Section 3).  A set of default mappings for
    audio and video is specified in the companion RFC 3551 [1].  An
    RTP source MAY change the payload type during a session, but this
    field SHOULD NOT be used for multiplexing separate media streams
    (see Section 5.2).

    A receiver MUST ignore packets with payload types that it does not
    understand.

sequence number: 16 bits
    The sequence number increments by one for each RTP data packet
    sent, and may be used by the receiver to detect packet loss and to
    restore packet sequence.  The initial value of the sequence number
    SHOULD be random (unpredictable) to make known-plaintext attacks
    on encryption more difficult, even if the source itself does not
    encrypt according to the method in Section 9.1, because the
    packets may flow through a translator that does.  Techniques for
    choosing unpredictable numbers are discussed in [17].

timestamp: 32 bits
    The timestamp reflects the sampling instant of the first octet in
    the RTP data packet.  The sampling instant MUST be derived from a
    clock that increments monotonically and linearly in time to allow
    synchronization and jitter calculations (see Section 6.4.1).  The
    resolution of the clock MUST be sufficient for the desired
    synchronization accuracy and for measuring packet arrival jitter
    (one tick per video frame is typically not sufficient).  The clock
    frequency is dependent on the format of data carried as payload
    and is specified statically in the profile or payload format
    specification that defines the format, or MAY be specified
    dynamically for payload formats defined through non-RTP means.  If
    RTP packets are generated periodically, the nominal sampling
    instant as determined from the sampling clock is to be used, not a
    reading of the system clock.  As an example, for fixed-rate audio
    the timestamp clock would likely increment by one for each
    sampling period.  If an audio application reads blocks covering


    160 sampling periods from the input device, the timestamp would be
    increased by 160 for each such block, regardless of whether the
    block is transmitted in a packet or dropped as silent.

    The initial value of the timestamp SHOULD be random, as for the
    sequence number.  Several consecutive RTP packets will have equal
    timestamps if they are (logically) generated at once, e.g., belong
    to the same video frame.  Consecutive RTP packets MAY contain
    timestamps that are not monotonic if the data is not transmitted
    in the order it was sampled, as in the case of MPEG interpolated
    video frames.  (The sequence numbers of the packets as transmitted
    will still be monotonic.)

    RTP timestamps from different media streams may advance at
    different rates and usually have independent, random offsets.
    Therefore, although these timestamps are sufficient to reconstruct
    the timing of a single stream, directly comparing RTP timestamps
    from different media is not effective for synchronization.
    Instead, for each medium the RTP timestamp is related to the
    sampling instant by pairing it with a timestamp from a reference
    clock (wallclock) that represents the time when the data
    corresponding to the RTP timestamp was sampled.  The reference
    clock is shared by all media to be synchronized.  The timestamp
    pairs are not transmitted in every data packet, but at a lower
    rate in RTCP SR packets as described in Section 6.4.

    The sampling instant is chosen as the point of reference for the
    RTP timestamp because it is known to the transmitting endpoint and
    has a common definition for all media, independent of encoding
    delays or other processing.  The purpose is to allow synchronized
    presentation of all media sampled at the same time.

    Applications transmitting stored data rather than data sampled in
    real time typically use a virtual presentation timeline derived
    from wallclock time to determine when the next frame or other unit
    of each medium in the stored data should be presented.  In this
    case, the RTP timestamp would reflect the presentation time for
    each unit.  That is, the RTP timestamp for each unit would be
    related to the wallclock time at which the unit becomes current on
    the virtual presentation timeline.  Actual presentation occurs
    some time later as determined by the receiver.

    An example describing live audio narration of prerecorded video
    illustrates the significance of choosing the sampling instant as
    the reference point.  In this scenario, the video would be
    presented locally for the narrator to view and would be
    simultaneously transmitted using RTP.  The "sampling instant" of a
    video frame transmitted in RTP would be established by referencing

    its timestamp to the wallclock time when that video frame was
    presented to the narrator.  The sampling instant for the audio RTP
    packets containing the narrator's speech would be established by
    referencing the same wallclock time when the audio was sampled.
    The audio and video may even be transmitted by different hosts if
    the reference clocks on the two hosts are synchronized by some
    means such as NTP.  A receiver can then synchronize presentation
    of the audio and video packets by relating their RTP timestamps
    using the timestamp pairs in RTCP SR packets.

SSRC: 32 bits
    The SSRC field identifies the synchronization source.  This
    identifier SHOULD be chosen randomly, with the intent that no two
    synchronization sources within the same RTP session will have the
    same SSRC identifier.  An example algorithm for generating a
    random identifier is presented in Appendix A.6.  Although the
    probability of multiple sources choosing the same identifier is
    low, all RTP implementations must be prepared to detect and
    resolve collisions.  Section 8 describes the probability of
    collision along with a mechanism for resolving collisions and
    detecting RTP-level forwarding loops based on the uniqueness of
    the SSRC identifier.  If a source changes its source transport
    address, it must also choose a new SSRC identifier to avoid being
    interpreted as a looped source (see Section 8.2).

CSRC list: 0 to 15 items, 32 bits each
    The CSRC list identifies the contributing sources for the payload
    contained in this packet.  The number of identifiers is given by
    the CC field.  If there are more than 15 contributing sources,
    only 15 can be identified.  CSRC identifiers are inserted by
    mixers (see Section 7.1), using the SSRC identifiers of
    contributing sources.  For example, for audio packets the SSRC
    identifiers of all sources that were mixed together to create a
    packet are listed, allowing correct talker indication at the
    receiver.

## 5.2 Multiplexing RTP Sessions

For efficient protocol processing, the number of multiplexing points
should be minimized, as described in the integrated layer processing
design principle [10].  In RTP, multiplexing is provided by the
destination transport address (network address and port number) which
is different for each RTP session.  For example, in a teleconference
composed of audio and video media encoded separately, each medium
SHOULD be carried in a separate RTP session with its own destination
transport address.


Separate audio and video streams SHOULD NOT be carried in a single
RTP session and demultiplexed based on the payload type or SSRC
fields.  Interleaving packets with different RTP media types but
using the same SSRC would introduce several problems:

1. If, say, two audio streams shared the same RTP session and the
    same SSRC value, and one were to change encodings and thus acquire
    a different RTP payload type, there would be no general way of
    identifying which stream had changed encodings.

2. An SSRC is defined to identify a single timing and sequence number
    space.  Interleaving multiple payload types would require
    different timing spaces if the media clock rates differ and would
    require different sequence number spaces to tell which payload
    type suffered packet loss.

3. The RTCP sender and receiver reports (see Section 6.4) can only
    describe one timing and sequence number space per SSRC and do not
    carry a payload type field.

4. An RTP mixer would not be able to combine interleaved streams of
    incompatible media into one stream.

5. Carrying multiple media in one RTP session precludes: the use of
    different network paths or network resource allocations if
    appropriate; reception of a subset of the media if desired, for
    example just audio if video would exceed the available bandwidth;
    and receiver implementations that use separate processes for the
    different media, whereas using separate RTP sessions permits
    either single- or multiple-process implementations.

Using a different SSRC for each medium but sending them in the same
RTP session would avoid the first three problems but not the last
two.

On the other hand, multiplexing multiple related sources of the same
medium in one RTP session using different SSRC values is the norm for
multicast sessions.  The problems listed above don't apply: an RTP
mixer can combine multiple audio sources, for example, and the same
treatment is applicable for all of them.  It may also be appropriate
to multiplex streams of the same medium using different SSRC values
in other scenarios where the last two problems do not apply.

## 5.3 Profile-Specific Modifications to the RTP Header

The existing RTP data packet header is believed to be complete for
the set of functions required in common across all the application
classes that RTP might support.  However, in keeping with the ALF
design principle, the header MAY be tailored through modifications or
additions defined in a profile specification while still allowing
profile-independent monitoring and recording tools to function.

o  The marker bit and payload type field carry profile-specific
    information, but they are allocated in the fixed header since many
    applications are expected to need them and might otherwise have to
    add another 32-bit word just to hold them.  The octet containing
    these fields MAY be redefined by a profile to suit different
    requirements, for example with more or fewer marker bits.  If
    there are any marker bits, one SHOULD be located in the most
    significant bit of the octet since profile-independent monitors
    may be able to observe a correlation between packet loss patterns
    and the marker bit.

o  Additional information that is required for a particular payload
    format, such as a video encoding, SHOULD be carried in the payload
    section of the packet.  This might be in a header that is always
    present at the start of the payload section, or might be indicated
    by a reserved value in the data pattern.

o  If a particular class of applications needs additional
    functionality independent of payload format, the profile under
    which those applications operate SHOULD define additional fixed
    fields to follow immediately after the SSRC field of the existing
    fixed header.  Those applications will be able to quickly and
    directly access the additional fields while profile-independent
    monitors or recorders can still process the RTP packets by
    interpreting only the first twelve octets.

If it turns out that additional functionality is needed in common
across all profiles, then a new version of RTP should be defined to
make a permanent change to the fixed header.

### 5.3.1 RTP Header Extension

An extension mechanism is provided to allow individual
implementations to experiment with new payload-format-independent
functions that require additional information to be carried in the
RTP data packet header.  This mechanism is designed so that the
header extension may be ignored by other interoperating
implementations that have not been extended.

Note that this header extension is intended only for limited use.
Most potential uses of this mechanism would be better done another
way, using the methods described in the previous section.  For
example, a profile-specific extension to the fixed header is less
expensive to process because it is not conditional nor in a variable
location.  Additional information required for a particular payload
format SHOULD NOT use this header extension, but SHOULD be carried in
the payload section of the packet.

  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      defined by profile       |           length              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        header extension                       |
   |                             ....                              |


If the X bit in the RTP header is one, a variable-length header
extension MUST be appended to the RTP header, following the CSRC list
if present.  The header extension contains a 16-bit length field that
counts the number of 32-bit words in the extension, excluding the
four-octet extension header (therefore zero is a valid length).  Only
a single extension can be appended to the RTP data header.  To allow
multiple interoperating implementations to each experiment
independently with different header extensions, or to allow a
particular implementation to experiment with more than one type of
header extension, the first 16 bits of the header extension are left
open for distinguishing identifiers or parameters.  The format of
these 16 bits is to be defined by the profile specification under
which the implementations are operating.  This RTP specification does
not define any header extensions itself.
