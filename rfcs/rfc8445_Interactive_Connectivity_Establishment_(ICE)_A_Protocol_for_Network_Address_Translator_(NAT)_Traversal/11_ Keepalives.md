# 11.  Keepalives

All endpoints MUST send keepalives for each data session.  These
keepalives serve the purpose of keeping NAT bindings alive for the
data session.  The keepalives SHOULD be sent using a format that is
supported by its peer.  ICE endpoints allow for STUN-based keepalives
for UDP streams, and as such, STUN keepalives MUST be used when an
ICE agent is a full ICE implementation and is communicating with a
peer that supports ICE (lite or full).


An agent MUST send a keepalive on each candidate pair that is used
for sending data if no packet has been sent on that pair in the last
Tr seconds.  Agents SHOULD use a Tr value of 15 seconds.  Agents MAY
use a bigger value but MUST NOT use a value smaller than 15 seconds.

Once selected pairs have been produced for a data stream, keepalives
are only sent on those pairs.

An agent MUST stop sending keepalives on a data stream if the data
stream is removed.  If the ICE session is terminated, an agent MUST
stop sending keepalives on all data streams.

An agent MAY use another value for Tr, e.g., based on configuration
or network/NAT characteristics.  For example, if an agent has a
dynamic way to discover the binding lifetimes of the intervening
NATs, it can use that value to determine Tr.  Administrators
deploying ICE in more controlled networking environments SHOULD set
Tr to the longest duration possible in their environment.

When STUN is being used for keepalives, a STUN Binding Indication is
used [RFC5389].  The Indication MUST NOT utilize any authentication
mechanism.  It SHOULD contain the FINGERPRINT attribute to aid in
demultiplexing, but it SHOULD NOT contain any other attributes.  It
is used solely to keep the NAT bindings alive.  The Binding
Indication is sent using the same local and remote candidates that
are being used for data.  Though Binding Indications are used for
keepalives, an agent MUST be prepared to receive a connectivity check
as well.  If a connectivity check is received, a response is
generated as discussed in [RFC5389], but there is no impact on ICE
processing otherwise.

Agents MUST by default use STUN keepalives.  Individual ICE usages
and ICE extensions MAY specify usage-/extension-specific keepalives.
