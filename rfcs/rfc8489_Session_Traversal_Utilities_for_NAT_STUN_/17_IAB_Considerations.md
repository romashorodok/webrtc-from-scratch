# 17.  IAB Considerations

The IAB has studied the problem of Unilateral Self-Address Fixing
(UNSAF), which is the general process by which a client attempts to
determine its address in another realm on the other side of a NAT
through a collaborative protocol reflection mechanism [RFC3424].
STUN can be used to perform this function using a Binding request/
response transaction if one agent is behind a NAT and the other is on
the public side of the NAT.

The IAB has suggested that protocols developed for this purpose
document a specific set of considerations.  Because some STUN Usages
provide UNSAF functions (such as ICE [RFC8445]) and others do not
(such as SIP Outbound [RFC5626]), answers to these considerations
need to be addressed by the usages themselves.