## B.3.  Purpose of the Related-Address and Related-Port Attributes

The candidate attribute contains two values that are not used at all
by ICE itself -- related address and related port.  Why are they
present?

There are two motivations for its inclusion.  The first is
diagnostic.  It is very useful to know the relationship between the
different types of candidates.  By including it, an ICE agent can
know which relayed candidate is associated with which reflexive
candidate, which in turn is associated with a specific host
candidate.  When checks for one candidate succeed but not for others,
this provides useful diagnostics on what is going on in the network.

The second reason has to do with off-path Quality-of-Service (QoS)
mechanisms.  When ICE is used in environments such as PacketCable
2.0, proxies will, in addition to performing normal SIP operations,
inspect the SDP in SIP messages and extract the IP address and port
for data traffic.  They can then interact, through policy servers,
with access routers in the network, to establish guaranteed QoS for
the data flows.  This QoS is provided by classifying the RTP traffic
based on 5-tuple and then providing it a guaranteed rate, or marking
its DSCP appropriately.  When a residential NAT is present, and a
relayed candidate gets selected for data, this relayed candidate will
be a transport address on an actual TURN server.  That address says
nothing about the actual transport address in the access router that
would be used to classify packets for QoS treatment.  Rather, the
server-reflexive candidate towards the TURN server is needed.  By
carrying the translation in the SDP, the proxy can use that transport
address to request QoS from the access router.

