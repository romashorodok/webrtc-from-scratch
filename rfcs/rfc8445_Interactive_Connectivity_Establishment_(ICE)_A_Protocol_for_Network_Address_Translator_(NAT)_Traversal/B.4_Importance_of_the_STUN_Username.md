## B.4.  Importance of the STUN Username

ICE requires the usage of message integrity with STUN using its
short-term credential functionality.  The actual short-term
credential is formed by exchanging username fragments in the
candidate exchange.  The need for this mechanism goes beyond just
security; it is actually required for correct operation of ICE in the
first place.

Consider ICE agents L, R, and Z.  L and R are within private
enterprise 1, which is using 10.0.0.0/8.  Z is within private
enterprise 2, which is also using 10.0.0.0/8.  As it turns out, R and
Z both have IP address 10.0.1.1.  L sends candidates to Z.  Z
responds to L with its host candidates.  In this case, those
candidates are 10.0.1.1:8866 and 10.0.1.1:8877.  As it turns out, R
is in a session at that same time and is also using 10.0.1.1:8866 and
10.0.1.1:8877 as host candidates.  This means that R is prepared to
accept STUN messages on those ports, just as Z is.  L will send a
STUN request to 10.0.1.1:8866 and another to 10.0.1.1:8877.  However,
these do not go to Z as expected.  Instead, they go to R!  If R just
replied to them, L would believe it has connectivity to Z, when in
fact it has connectivity to a completely different user, R.  To fix
this, STUN short-term credential mechanisms are used.  The username
fragments are sufficiently random; thus it is highly unlikely that R
would be using the same values as Z.  Consequently, R would reject
the STUN request since the credentials were invalid.  In essence, the
STUN username fragments provide a form of transient host identifiers,
bound to a particular session established as part of the candidate
exchange.

An unfortunate consequence of the non-uniqueness of IP addresses is
that, in the above example, R might not even be an ICE agent.  It
could be any host, and the port to which the STUN packet is directed
could be any ephemeral port on that host.  If there is an application
listening on this socket for packets, and it is not prepared to
handle malformed packets for whatever protocol is in use, the
operation of that application could be affected.  Fortunately, since
the ports exchanged are ephemeral and usually drawn from the dynamic
or registered range, the odds are good that the port is not used to
run a server on host R, but rather is the agent side of some
protocol.  This decreases the probability of hitting an allocated
port, due to the transient nature of port usage in this range.
However, the possibility of a problem does exist, and network
deployers need to be prepared for it.  Note that this is not a
problem specific to ICE; stray packets can arrive at a port at any
time for any type of protocol, especially ones on the public
Internet.  As such, this requirement is just restating a general
design guideline for Internet applications -- be prepared for unknown
packets on any port.


