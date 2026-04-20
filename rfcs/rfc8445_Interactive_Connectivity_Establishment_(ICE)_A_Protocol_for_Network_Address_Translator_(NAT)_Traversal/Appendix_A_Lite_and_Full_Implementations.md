# Appendix A.  Lite and Full Implementations

ICE allows for two types of implementations.  A full implementation
supports the controlling and controlled roles in a session and can
also perform address gathering.  In contrast, a lite implementation
is a minimalist implementation that does little but respond to STUN
checks, and it only supports the controlled role in a session.

Because ICE requires both endpoints to support it in order to bring
benefits to either endpoint, incremental deployment of ICE in a
network is more complicated.  Many sessions involve an endpoint that
is, by itself, not behind a NAT and not one that would worry about
NAT traversal.  A very common case is to have one endpoint that
requires NAT traversal (such as a VoIP hard phone or soft phone) make
a call to one of these devices.  Even if the phone supports a full
ICE implementation, ICE won't be used at all if the other device
doesn't support it.  The lite implementation allows for a low-cost
entry point for these devices.  Once they support the lite
implementation, full implementations can connect to them and get the
full benefits of ICE.

Consequently, a lite implementation is only appropriate for devices
that will *always* be connected to the public Internet and have a
public IP address at which it can receive packets from any
correspondent.  ICE will not function when a lite implementation is
placed behind a NAT.

ICE allows a lite implementation to have a single IPv4 host candidate
and several IPv6 addresses.  In that case, candidate pairs are
selected by the controlling agent using a static algorithm, such as
the one in RFC 6724, which is recommended by this specification.
However, static mechanisms for address selection are always prone to
error, since they can never reflect the actual topology or provide
actual guarantees on connectivity.  They are always heuristics.
Consequently, if an ICE agent is implementing ICE just to select
between its IPv4 and IPv6 addresses, and none of its IP addresses are
behind NAT, usage of full ICE is still RECOMMENDED in order to
provide the most robust form of address selection possible.

It is important to note that the lite implementation was added to
this specification to provide a stepping stone to full
implementation.  Even for devices that are always connected to the
public Internet with just a single IPv4 address, a full
implementation is preferable if achievable.  Full implementations
also obtain the security benefits of ICE unrelated to NAT traversal.
Finally, it is often the case that a device that finds itself with a
public address today will be placed in a network tomorrow where it
will be behind a NAT.  It is difficult to definitively know, over the
lifetime of a device or product, if it will always be used on the
public Internet.  Full implementation provides assurance that
communications will always work.