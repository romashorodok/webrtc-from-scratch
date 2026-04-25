## B.8.  Why Are Binding Indications Used for Keepalives?

Data keepalives are described in Section 11.  These keepalives make
use of STUN when both endpoints are ICE capable.  However, rather
than using a Binding request transaction (which generates a
response), the keepalives use an Indication.  Why is that?

The primary reason has to do with network QoS mechanisms.  Once data
begins flowing, network elements will assume that the data stream has
a fairly regular structure, making use of periodic packets at fixed
intervals, with the possibility of jitter.  If an ICE agent is
sending data packets, and then receives a Binding request, it would
need to generate a response packet along with its data packets.  This
will increase the actual bandwidth requirements for the 5-tuple
carrying the data packets and introduce jitter in the delivery of
those packets.  Analysis has shown that this is a concern in certain
Layer 2 access networks that use fairly tight packet schedulers for
data.

Additionally, using a Binding Indication allows integrity to be
disabled, which may result in better performance.  This is useful for
large-scale endpoints, such as Public Switched Telephone Network
(PSTN) gateways and Session Border Controllers (SBCs).

