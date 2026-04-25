## B.7.  Why Prefer Peer-Reflexive Candidates?

Section 5.1.2 describes procedures for computing the priority of a
candidate based on its type and local preferences.  That section
requires that the type preference for peer-reflexive candidates
always be higher than server reflexive.  Why is that?  The reason has
to do with the security considerations in Section 19.  It is much
easier for an attacker to cause an ICE agent to use a false server-
reflexive candidate rather than a false peer-reflexive candidate.
Consequently, attacks against address gathering with Binding requests
are thwarted by ICE by preferring the peer-reflexive candidates.

