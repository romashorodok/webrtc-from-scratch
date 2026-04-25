## B.9.  Selecting Candidate Type Preference

One criterion for selecting type and local preference values is the
use of a data intermediary, such as a TURN server, a tunnel service
such as a VPN server, or NAT.  With a data intermediary, if data is
sent to that candidate, it will first transit the data intermediary
before being received.  One type of candidate that involves a data
intermediary is the relayed candidate.  Another type is the host
candidate, which is obtained from a VPN interface.  When data is
transited through a data intermediary, it can have a positive or
negative effect on the latency between transmission and reception.
It may or may not increase the packet losses, because of the
additional router hops that may be taken.  It may increase the cost
of providing service, since data will be routed in and right back out
of a data intermediary run by a provider.  If these concerns are
important, the type preference for relayed candidates needs to be
carefully chosen.

Another criterion for selecting preferences is the IP address family.
ICE works with both IPv4 and IPv6.  It provides a transition
mechanism that allows dual-stack hosts to prefer connectivity over
IPv6 but to fall back to IPv4 in case the v6 networks are
disconnected.  Implementation SHOULD follow the guidelines from
[RFC8421] to avoid excessive delays in the connectivity-check phase
if broken paths exist.

Another criterion for selecting preferences is topological awareness.
This is beneficial for candidates that make use of intermediaries.
In those cases, if an ICE agent has preconfigured or dynamically
discovered knowledge of the topological proximity of the
intermediaries to itself, it can use that to assign higher local
preferences to candidates obtained from closer intermediaries.

Another criterion for selecting preferences might be security or
privacy.  If a user is a telecommuter, and therefore connected to a
corporate network and a local home network, the user may prefer their
voice traffic to be routed over the VPN or similar tunnel in order to
keep it on the corporate network when communicating within the
enterprise but may use the local network when communicating with
users outside of the enterprise.  In such a case, a VPN address would
have a higher local preference than any other address.
