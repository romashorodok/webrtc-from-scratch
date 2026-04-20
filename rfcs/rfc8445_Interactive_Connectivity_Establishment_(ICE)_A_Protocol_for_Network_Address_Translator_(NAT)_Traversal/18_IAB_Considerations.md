# 18.  IAB Considerations

The IAB has studied the problem of "Unilateral Self-Address Fixing"
(UNSAF), which is the general process by which an ICE agent attempts
to determine its address in another realm on the other side of a NAT
through a collaborative protocol reflection mechanism [RFC3424].  ICE
is an example of a protocol that performs this type of function.
Interestingly, the process for ICE is not unilateral, but bilateral,
and the difference has a significant impact on the issues raised by
the IAB.  Indeed, ICE can be considered a Bilateral Self-Address
Fixing (B-SAF) protocol, rather than an UNSAF protocol.  Regardless,
the IAB has mandated that any protocols developed for this purpose
document a specific set of considerations.  This section meets those
requirements.

## 18.1.  Problem Definition

From RFC 3424, any UNSAF proposal needs to provide:

    Precise definition of a specific, limited-scope problem that is to
    be solved with the UNSAF proposal.  A short term fix should not be
    generalized to solve other problems.  Such generalizations lead to
    the the prolonged dependence on and usage of the supposed short
    term fix -- meaning that it is no longer accurate to call it
    "short term".

The specific problems being solved by ICE are:

    Providing a means for two peers to determine the set of transport
    addresses that can be used for communication.

    Providing a means for an agent to determine an address that is
    reachable by another peer with which it wishes to communicate.

## 18.2.  Exit Strategy

From RFC 3424, any UNSAF proposal needs to provide:

    Description of an exit strategy/transition plan.  The better short
    term fixes are the ones that will naturally see less and less use
    as the appropriate technology is deployed.

ICE itself doesn't easily get phased out.  However, it is useful even
in a globally connected Internet, to serve as a means for detecting
whether a router failure has temporarily disrupted connectivity, for
example.  ICE also helps prevent certain security attacks that have
nothing to do with NAT.  However, what ICE does is help phase out
other UNSAF mechanisms.  ICE effectively picks amongst those

mechanisms, prioritizing ones that are better and deprioritizing ones
that are worse.  As NATs begin to dissipate as IPv6 is introduced,
server-reflexive and relayed candidates (both forms of UNSAF
addresses) simply never get used, because higher-priority
connectivity exists to the native host candidates.  Therefore, the
servers get used less and less and can eventually be removed when
their usage goes to zero.

Indeed, ICE can assist in the transition from IPv4 to IPv6.  It can
be used to determine whether to use IPv6 or IPv4 when two dual-stack
hosts communicate with SIP (IPv6 gets used).  It can also allow a
network with both 6to4 and native v6 connectivity to determine which
address to use when communicating with a peer.


## 18.3.  Brittleness Introduced by ICE

From RFC 3424, any UNSAF proposal needs to provide:

    Discussion of specific issues that may render systems more
    "brittle".  For example, approaches that involve using data at
    multiple network layers create more dependencies, increase
    debugging challenges, and make it harder to transition.

ICE actually removes brittleness from existing UNSAF mechanisms.  In
particular, classic STUN (as described in RFC 3489 [RFC3489]) has
several points of brittleness.  One of them is the discovery process
that requires an ICE agent to try to classify the type of NAT it is
behind.  This process is error prone.  With ICE, that discovery
process is simply not used.  Rather than unilaterally assessing the
validity of the address, its validity is dynamically determined by
measuring connectivity to a peer.  The process of determining
connectivity is very robust.

Another point of brittleness in classic STUN and any other unilateral
mechanism is its absolute reliance on an additional server.  ICE
makes use of a server for allocating unilateral addresses, but it
allows agents to directly connect if possible.  Therefore, in some
cases, the failure of a STUN server would still allow for a call to
progress when ICE is used.

Another point of brittleness in classic STUN is that it assumes the
STUN server is on the public Internet.  Interestingly, with ICE, that
is not necessary.  There can be a multitude of STUN servers in a
variety of address realms.  ICE will discover the one that has
provided a usable address.

The most troubling point of brittleness in classic STUN is that it
doesn't work in all network topologies.  In cases where there is a
shared NAT between each agent and the STUN server, traditional STUN
may not work.  With ICE, that restriction is removed.

Classic STUN also introduces some security considerations.
Fortunately, those security considerations are also mitigated by ICE.

Consequently, ICE serves to repair the brittleness introduced in
classic STUN, and it does not introduce any additional brittleness
into the system.

The penalty of these improvements is that ICE increases session
establishment times.

## 18.4.  Requirements for a Long-Term Solution

From RFC 3424, any UNSAF proposal needs to provide the following:

    Identify requirements for longer term, sound technical solutions;
    contribute to the process of finding the right longer term
    solution.

Our conclusions from RFC 3489 remain unchanged.  However, we feel ICE
actually helps because we believe it can be part of the long-term
solution.

## 18.5.  Issues with Existing NAPT Boxes

From RFC 3424, any UNSAF proposal needs to provide:

    Discussion of the impact of the noted practical issues with
    existing, deployed NA[P]Ts and experience reports.

A number of NAT boxes are now being deployed into the market that try
to provide "generic" ALG functionality.  These generic ALGs hunt for
IP addresses, in either text or binary form within a packet, and
rewrite them if they match a binding.  This interferes with classic
STUN.  However, the update to STUN [RFC5389] uses an encoding that
hides these binary addresses from generic ALGs.

Existing NAPT boxes have non-deterministic and typically short
expiration times for UDP-based bindings.  This requires
implementations to send periodic keepalives to maintain those
bindings.  ICE uses a default of 15 s, which is a very conservative
estimate.  Eventually, over time, as NAT boxes become compliant to
behave [RFC4787], this minimum keepalive will become deterministic and well known, and the ICE timers can be adjusted.  Having a way to
discover and control the minimum keepalive interval would be far
better still.
