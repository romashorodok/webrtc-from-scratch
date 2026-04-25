# 4. Requirements and Recommendations
The purpose of SDP is to convey information about media streams in multimedia sessions to allow the recipients of a session description to participate in the session. SDP is primarily intended for use with Internet protocols, although it is sufficiently general that it can describe multimedia conferences in other network environments. Media streams can be many-to-many. Sessions need not be continually active.

Thus far, multicast-based sessions on the Internet have differed from many other forms of conferencing in that anyone receiving the traffic can join the session (unless the session traffic is encrypted). In such an environment, SDP serves two primary purposes. It is a means to communicate the existence of a session, and it is a means to convey sufficient information to enable joining and participating in the session. In a unicast environment, only the latter purpose is likely to be relevant.

An SDP description includes the following:

Session name and purpose
Time(s) the session is active
The media comprising the session
Information needed to receive those media (addresses, ports, formats, etc.)
As resources necessary to participate in a session may be limited, some additional information may also be desirable:

Information about the bandwidth to be used by the session
Contact information for the person responsible for the session
In general, SDP must convey sufficient information to enable applications to join a session (with the possible exception of encryption keys) and to announce the resources to be used to any nonparticipants that may need to know. (This latter feature is primarily useful when SDP is used with a multicast session announcement protocol.)
