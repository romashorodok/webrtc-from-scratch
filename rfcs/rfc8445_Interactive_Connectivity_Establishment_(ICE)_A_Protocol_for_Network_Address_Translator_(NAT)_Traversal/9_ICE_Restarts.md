# 9.  ICE Restarts

An ICE agent MAY restart ICE for existing data streams.  An ICE
restart causes all previous states of the data streams, excluding the
roles of the agents, to be flushed.  The only difference between an
ICE restart and a brand new data session is that during the restart,
data can continue to be sent using existing data sessions, and a new
data session always requires the roles to be determined.

The following actions can be accomplished only by using an ICE
restart (the agent MUST use ICE restarts to do so):

o  Change the destinations of data streams.

o  Change from a lite implementation to a full implementation.

o  Change from a full implementation to a lite implementation.

To restart ICE, an agent MUST change both the password and the
username fragment for the data stream(s) being restarted.

When the ICE is restarted, the candidate set for the new ICE session
might include some, none, or all of the candidates used in the
current ICE session.

As described in Section 6.1.1, agents MUST NOT redetermine the roles
as part as an ICE restart, unless certain criteria that require the
roles to be redetermined are fulfilled.
