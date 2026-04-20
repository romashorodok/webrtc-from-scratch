Appendix A. Design Considerations
One of the main issues regarding the BUNDLE grouping extensions has been whether, in offers and answers, the same port value can be inserted in "m=" lines associated with a BUNDLE group, as the purpose of the extension is to negotiate the usage of a single transport for media specified by the "m=" sections. Issues with both approaches, discussed in Appendix A, have been raised. The outcome was to specify a mechanism that uses offers with both different and identical port values.

Below are the primary issues that have been considered when defining the "BUNDLE" grouping extension:

1)
Interoperability with existing User Agents (UAs).
2)
Interoperability with intermediary Back-to-Back User Agent (B2BUA) and proxy entities.
3)
The number of ICE candidates and the time to gather them.
4)
Different error scenarios and when they occur.
5)
SDP offer/answer impacts, including usage of port number value zero.
A.1. UA Interoperability
Consider the following SDP offer/answer exchange, where Alice sends an offer to Bob:

SDP Offer

    v=0
    o=alice 2890844526 2890844526 IN IP4 atlanta.example.com
    s=
    c=IN IP4 atlanta.example.com
    t=0 0

    m=audio 10000 RTP/AVP 97
    a=rtpmap:97 iLBC/8000
    m=video 10002 RTP/AVP 97
    a=rtpmap:97 H261/90000
SDP Answer

    v=0
    o=bob 2808844564 2808844564 IN IP4 biloxi.example.com
    s=
    c=IN IP4 biloxi.example.com
    t=0 0

    m=audio 20000 RTP/AVP 97
    a=rtpmap:97 iLBC/8000
    m=video 20002 RTP/AVP 97
    a=rtpmap:97 H261/90000
[RFC4961] specifies a way of doing symmetric RTP, but that is a later extension to RTP, and Bob cannot assume that Alice supports [RFC4961]. This means that Alice may be sending RTP from a different port than 10000 or 10002 -- some implementations simply send the RTP from an ephemeral port. When Bob's endpoint receives an RTP packet, the only way that Bob knows if the packet is to be passed to the video or audio codec is by looking at the port it was received on. This prompted some SDP implementations to use a port number as an index to find the correct "m=" line in the SDP, since each "m"= section contains a different port number. As a result, some implementations that do support symmetric RTP and ICE still use an SDP data structure where SDP with "m=" sections with the same port such as:

SDP Offer

    v=0
    o=alice 2890844526 2890844526 IN IP4 atlanta.example.com
    s=
    c=IN IP4 atlanta.example.com
    t=0 0

    m=audio 10000 RTP/AVP 97
    a=rtpmap:97 iLBC/8000
    m=video 10000 RTP/AVP 98
    a=rtpmap:98 H261/90000
will result in the second "m=" section being considered an SDP error because it has the same port as the first line.

A.2. Usage of Port Number Value Zero
In an offer or answer, the media specified by an "m=" section can be disabled/rejected by setting the port number value to zero. This is different from, e.g., using the SDP direction attributes, where RTCP traffic will continue even if the SDP 'inactive' attribute is indicated for the associated "m=" section.

If each "m=" section associated with a BUNDLE group were to contain different port values and one of those port values were used for a BUNDLE address:port associated with the BUNDLE group, problems would occur if an endpoint wants to disable/reject the "m=" section associated with that port by setting the port value to zero. After that, no "m=" section would contain the port value that is used for the BUNDLE address:port. In addition, it is unclear what would happen to the ICE candidates associated with the "m=" section, as they are also used for the BUNDLE address:port.

A.3. B2BUA and Proxy Interoperability
Some back-to-back user agents may be configured in a mode where if the incoming call leg contains an SDP attribute the B2BUA does not understand, the B2BUA still generates that SDP attribute in the Offer for the outgoing call leg. Consider a B2BUA that did not understand the SDP 'rtcp' attribute, defined in [RFC3605], yet acted this way. Further, assume that the B2BUA was configured to tear down any call where it did not see any RTCP for 5 minutes. In this case, if the B2BUA received an Offer like:

SDP Offer

    v=0
    o=alice 2890844526 2890844526 IN IP4 atlanta.example.com
    s=
    c=IN IP4 atlanta.example.com
    t=0 0

    m=audio 49170 RTP/AVP 0
    a=rtcp:53020
it would be looking for RTCP on port 49171 but would not see any because the RTCP would be on port 53020, and after five minutes, it would tear down the call. Similarly, a B2BUA that did not understand BUNDLE yet put it in its offer may be looking for media on the wrong port and tear down the call. It is worth noting that a B2BUA that generated an Offer with capabilities it does not understand is not compliant with the specifications.

A.3.1. Traffic Policing
Sometimes intermediaries do not act as B2BUAs, in the sense that they don't modify SDP bodies nor do they terminate SIP dialogs. However, they may still use SDP information (e.g., IP address and port) in order to control traffic gating functions and to set traffic policing rules. There might be rules that will trigger a session to be terminated in case media is not sent or received on the ports retrieved from the SDP. This typically occurs once the session is already established and ongoing.

A.3.2. Bandwidth Allocation
Sometimes, intermediaries do not act as B2BUAs, in the sense that they don't modify SDP bodies nor do they terminate SIP dialogs. However, they may still use SDP information (e.g., codecs and media types) in order to control bandwidth allocation functions. The bandwidth allocation is done per "m=" section, which means that it might not be enough if media specified by all "m=" sections try to use that bandwidth. That may simply lead to either a bad user experience or termination of the call.

A.4. Candidate Gathering
When using ICE, a candidate needs to be gathered for each port. This takes approximately 20 ms extra for each extra "m=" section due to the NAT pacing requirements. All of this gathering can be overlapped with other things while, e.g., a web page is loading to minimize the impact. If the client only wants to generate Traversal Using Relays around NAT (TURN) or STUN ICE candidates for one of the "m=" lines and then use Trickle ICE [RFC8838] to get the non-host ICE candidates for the rest of the "m=" sections, it MAY do that and will not need any additional gathering time.

Some people have suggested a TURN extension to get a bunch of TURN allocations at once. This would only provide a single STUN result, so in cases where the other end did not support BUNDLE, it may cause more use of the TURN server, but it would be quick in the cases where both sides supported BUNDLE and would fall back to a successful call in the other cases.

