# 15.  Examples

This section shows two ICE examples: one using IPv4 addresses and one
using IPv6 addresses.

To facilitate understanding, transport addresses are listed using
variables that have mnemonic names.  The format of the name is
entity-type-seqno: "entity" refers to the entity whose IP address the
transport address is on and is one of "L", "R", "STUN", or "NAT".
The type is either "PUB" for transport addresses that are public or
"PRIV" for transport addresses that are private [RFC1918].  Finally,
seq-no is a sequence number that is different for each transport
address of the same type on a particular entity.  Each variable has
an IP address and port, denoted by varname.IP and varname.PORT,
respectively, where varname is the name of the variable.

In the call flow itself, STUN messages are annotated with several
attributes.  The "S=" attribute indicates the source transport
address of the message.  The "D=" attribute indicates the destination
transport address of the message.  The "MA=" attribute is used in
STUN Binding response messages and refers to the mapped address.
"USE-CAND" implies the presence of the USE-CANDIDATE attribute.

The call flow examples omit STUN authentication operations and focus
on a single data stream between two full implementations.

## 15.1.  Example with IPv4 Addresses

   The example below is using the topology shown in Figure 7.


                                  +-------+
                                  |STUN   |
                                  |Server |
                                  +-------+
                                      |
                           +---------------------+
                           |                     |
                           |      Internet       |
                           |                     |
                           +---------------------+
                             |                |
                             |                |
                      +---------+             |
                      |   NAT   |             |
                      +---------+             |
                           |                  |
                           |                  |
                        +-----+            +-----+
                        |  L  |            |  R  |
                        +-----+            +-----+

                        Figure 7: Example Topology


In the example, ICE agents L and R are full ICE implementations.
Both agents have a single IPv4 address, and both are configured with
the same STUN server.  The NAT has an endpoint-independent mapping
property and an address-dependent filtering property.  The IP
addresses of the ICE agents, the STUN server, and the NAT are shown
below:

   ENTITY                   IP Address  Mnemonic name
   --------------------------------------------------
   ICE Agent L:             10.0.1.1    L-PRIV-1
   ICE Agent R:             192.0.2.1   R-PUB-1
   STUN Server:             192.0.2.2   STUN-PUB-1
   NAT (Public):            192.0.2.3   NAT-PUB-1


             L             NAT           STUN             R
             |STUN alloc.   |              |              |
             |(1) STUN Req  |              |              |
             |S=$L-PRIV-1   |              |              |
             |D=$STUN-PUB-1 |              |              |
             |------------->|              |              |
             |              |(2) STUN Req  |              |
             |              |S=$NAT-PUB-1  |              |
             |              |D=$STUN-PUB-1 |              |
             |              |------------->|              |
             |              |(3) STUN Res  |              |
             |              |S=$STUN-PUB-1 |              |
             |              |D=$NAT-PUB-1  |              |
             |              |MA=$NAT-PUB-1 |              |
             |              |<-------------|              |
             |(4) STUN Res  |              |              |
             |S=$STUN-PUB-1 |              |              |
             |D=$L-PRIV-1   |              |              |
             |MA=$NAT-PUB-1 |              |              |
             |<-------------|              |              |
             |(5) L's Candidate Information|              |
             |------------------------------------------->|
             |              |              |              | STUN
             |              |              |              | alloc.
             |              |              |(6) STUN Req  |
             |              |              |S=$R-PUB-1    |
             |              |              |D=$STUN-PUB-1 |
             |              |              |<-------------|
             |              |              |(7) STUN Res  |
             |              |              |S=$STUN-PUB-1 |
             |              |              |D=$R-PUB-1    |
             |              |              |MA=$R-PUB-1   |
             |              |              |------------->|


             |(8) R's Candidate Information|              |
             |<-------------------------------------------|
             |              |         (9) Bind Req        |Begin
             |              |         S=$R-PUB-1          |Connectivity
             |              |         D=$L-PRIV-1         |Checks
             |              |         <-------------------|
             |              |         Dropped             |
             |(10) Bind Req |              |              |
             |S=$L-PRIV-1   |              |              |
             |D=$R-PUB-1    |              |              |
             |------------->|              |              |
             |              |(11) Bind Req |              |
             |              |S=$NAT-PUB-1  |              |
             |              |D=$R-PUB-1    |              |
             |              |---------------------------->|
             |              |(12) Bind Res |              |
             |              |S=$R-PUB-1    |              |
             |              |D=$NAT-PUB-1  |              |
             |              |MA=$NAT-PUB-1 |              |
             |              |<----------------------------|
             |(13) Bind Res |              |              |
             |S=$R-PUB-1    |              |              |
             |D=$L-PRIV-1   |              |              |
             |MA=$NAT-PUB-1 |              |              |
             |<-------------|              |              |
             |Data          |              |              |
             |===========================================>|
             |              |              |              |
             |              |(14) Bind Req |              |
             |              |S=$R-PUB-1    |              |
             |              |D=$NAT-PUB-1  |              |
             |              |<----------------------------|
             |(15) Bind Req |              |              |
             |S=$R-PUB-1    |              |              |
             |D=$L-PRIV-1   |              |              |
             |<-------------|              |              |
             |(16) Bind Res |              |              |
             |S=$L-PRIV-1   |              |              |
             |D=$R-PUB-1    |              |              |
             |MA=$R-PUB-1   |              |              |
             |------------->|              |              |
             |              |(17) Bind Res |              |
             |              |S=$NAT-PUB-1  |              |
             |              |D=$R-PUB-1    |              |
             |              |MA=$R-PUB-1   |              |
             |              |---------------------------->|
             |Data          |              |              |
             |<===========================================|


             |              |              |              |
                                .......
             |              |              |              |
             |(18) Bind Req |              |              |
             |S=$L-PRIV-1   |              |              |
             |D=$R-PUB-1    |              |              |
             |USE-CAND      |              |              |
             |------------->|              |              |
             |              |(19) Bind Req |              |
             |              |S=$NAT-PUB-1  |              |
             |              |D=$R-PUB-1    |              |
             |              |USE-CAND      |              |
             |              |---------------------------->|
             |              |(20) Bind Res |              |
             |              |S=$R-PUB-1    |              |
             |              |D=$NAT-PUB-1  |              |
             |              |MA=$NAT-PUB-1 |              |
             |              |<----------------------------|
             |(21) Bind Res |              |              |
             |S=$R-PUB-1    |              |              |
             |D=$L-PRIV-1   |              |              |
             |MA=$NAT-PUB-1 |              |              |
             |<-------------|              |              |
             |              |              |              |

                          Figure 8: Example Flow


Messages 1-4: Agent L gathers a host candidate from its local IP
address, and from that it sends a STUN Binding request to the STUN
server.  The request creates a NAT binding.  The NAT public IP
address of the binding becomes agent L's server-reflexive candidate.

Message 5: Agent L sends its local candidate information to agent R,
using the signaling protocol associated with the ICE usage.

Messages 6-7: Agent R gathers a host candidate from its local IP
address, and from that it sends a STUN Binding request to the STUN
server.  Since agent R is not behind a NAT, R's server-reflexive
candidate will be identical to the host candidate.

Message 8: Agent R sends its local candidate information to agent L,
using the signaling protocol associated with the ICE usage.

Since both agents are full ICE implementations, the initiating agent
(agent L) becomes the controlling agent.


Agents L and R both pair up the candidates.  Both agents initially
have two pairs.  However, agent L will prune the pair containing its
server-reflexive candidate, resulting in just one (L1).  At agent L,
this pair has a local candidate of $L_PRIV_1 and a remote candidate
of $R_PUB_1.  At agent R, there are two pairs.  The highest-priority
pair (R1) has a local candidate of $R_PUB_1 and a remote candidate of
$L_PRIV_1, and the second pair (R2) has a local candidate of $R_PUB_1
and a remote candidate of $NAT_PUB_1.  The pairs are shown below (the
pair numbers are for reference purposes only):

                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PRIV_1      R_PUB_1       L1

   ICE Agent R:             R_PUB_1       L_PRIV_1      R1
                            R_PUB_1       NAT_PUB_1     R2

   Message 9: Agent R initiates a connectivity check for pair #2.  As
   the remote candidate of the pair is the private address of agent L,
   the check will not be successful, as the request cannot be routed
   from R to L, and will be dropped by the network.

   Messages 10-13: Agent L initiates a connectivity check for pair L1.
   The check succeeds, and L creates a new pair (L2).  The local
   candidate of the new pair is $NAT_PUB_1, and the remote candidate is
   $R_PUB_1.  The pair (L2) is added to the valid list of agent L.
   Agent L can now send and receive data on the pair (L2) if it wishes.

                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PRIV_1      R_PUB_1       L1
                            NAT_PUB_1     R_PUB_1       L2        X

   ICE Agent R:             R_PUB_1       L_PRIV_1      R1
                            R_PUB_1       NAT_PUB_1     R2

Messages 14-17: When agent R receives the Binding request from agent
L (message 11), it will initiate a triggered connectivity check.  The
pair matches one of agent R's existing pairs (R2).  The check
succeeds, and the pair (R2) is added to the valid list of agent R.
Agent R can now send and receive data on the pair (R2) if it wishes.


                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PRIV_1      R_PUB_1       L1
                            NAT_PUB_1     R_PUB_1       L2        X

   ICE Agent R:             R_PUB_1       L_PRIV_1      R1
                            R_PUB_1       NAT_PUB_1     R2        X

Messages 18-21: At some point, the controlling agent (agent L)
decides to nominate a pair (L2) in the valid list.  It performs a
connectivity check on the pair (L2) and includes the USE-CANDIDATE
attribute in the Binding request.  As the check succeeds, agent L
sets the nominated flag value of the pair (L2) to 'true', and agent R
sets the nominated flag value of the matching pair (R2) to 'true'.
As there are no more components associated with the stream, the
nominated pairs become the selected pairs.  Consequently, processing
for this stream moves into the Completed state.  The ICE process also
moves into the Completed state.

## 15.2.  Example with IPv6 Addresses

   The example below is using the topology shown in Figure 9.

                                +-------+
                                |STUN   |
                                |Server |
                                +-------+
                                    |
                         +---------------------+
                         |                     |
                         |      Internet       |
                         |                     |
                         +---------------------+
                            |                |
                            |                |
                            |                |
                            |                |
                            |                |
                            |                |
                            |                |
                         +-----+          +-----+
                         |  L  |          |  R  |
                         +-----+          +-----+

                        Figure 9: Example Topology

In the example, ICE agents L and R are full ICE implementations.
Both agents have a single IPv6 address, and both are configured with
the same STUN server.  The IP addresses of the ICE agents and the
STUN server are shown below:


   ENTITY                   IP Address  mnemonic name
   --------------------------------------------------
   ICE Agent L:             2001:db8::3   L-PUB-1
   ICE Agent R:             2001:db8::5   R-PUB-1
   STUN Server:             2001:db8::9   STUN-PUB-1


             L                           STUN             R
             |STUN alloc.                  |              |
             |(1) STUN Req                 |              |
             |S=$L-PUB-1                   |              |
             |D=$STUN-PUB-1                |              |
             |---------------------------->|              |
             |(2) STUN Res                 |              |
             | S=$STUN-PUB-1               |              |
             | D=$L-PUB-1                  |              |
             | MA=$L-PUB-1                 |              |
             |<----------------------------|              |
             |(3) L's Candidate Information|              |
             |------------------------------------------->|
             |                             |              | STUN
             |                             |              | alloc.
             |                             |(4) STUN Req  |
             |                             |S=$R-PUB-1    |
             |                             |D=$STUN-PUB-1 |
             |                             |<-------------|
             |                             |(5) STUN Res  |
             |                             |S=$STUN-PUB-1 |
             |                             |D=$R-PUB-1    |
             |                             |MA=$R-PUB-1   |
             |                             |------------->|
             |(6) R's Candidate Information|              |
             |<-------------------------------------------|
             |(7) Bind Req                 |              |
             |S=$L-PUB-1                   |              |
             |D=$R-PUB-1                   |              |
             |------------------------------------------->|
             |(8) Bind Res                 |              |
             |S=$R-PUB-1                   |              |
             |D=$L-PUB-1                   |              |
             |MA=$L-PUB-1                  |              |
             |<-------------------------------------------|

             |Data                         |              |
             |===========================================>|
             |                             |              |
             |(9) Bind Req                 |              |
             |S=$R-PUB-1                   |              |
             |D=$L-PUB-1                   |              |
             |<-------------------------------------------|
             |(10) Bind Res                |              |
             |S=$L-PUB-1                   |              |
             |D=$R-PUB-1                   |              |
             |MA=$R-PUB-1                  |              |
             |------------------------------------------->|
             |Data                         |              |
             |<===========================================|
             |                             |              |
                                .......
             |                             |              |
             |(11) Bind Req                |              |
             |S=$L-PUB-1                   |              |
             |D=$R-PUB-1                   |              |
             |USE-CAND                     |              |
             |------------------------------------------->|
             |(12) Bind Res                |              |
             |S=$R-PUB-1                   |              |
             |D=$L-PUB-1                   |              |
             |MA=$L-PUB-1                  |              |
             |<-------------------------------------------|
             |              |              |              |

                          Figure 10: Example Flow

Messages 1-2: Agent L gathers a host candidate from its local IP
address, and from that it sends a STUN Binding request to the STUN
server.  Since agent L is not behind a NAT, L's server-reflexive
candidate will be identical to the host candidate.

Message 3: Agent L sends its local candidate information to agent R,
using the signaling protocol associated with the ICE usage.

Messages 4-5: Agent R gathers a host candidate from its local IP
address, and from that it sends a STUN Binding request to the STUN
server.  Since agent R is not behind a NAT, R's server-reflexive
candidate will be identical to the host candidate.

Message 6: Agent R sends its local candidate information to agent L,
using the signaling protocol associated with the ICE usage.

Since both agents are full ICE implementations, the initiating agent
(agent L) becomes the controlling agent.

Agents L and R both pair up the candidates.  Both agents initially
have one pair each.  At agent L, the pair (L1) has a local candidate
of $L_PUB_1 and a remote candidate of $R_PUB_1.  At agent R, the pair
(R1) has a local candidate of $R_PUB_1 and a remote candidate of
$L_PUB_1.  The pairs are shown below (the pair numbers are for
reference purpose only):


                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PUB_1       R_PUB_1       L1

   ICE Agent R:             R_PUB_1       L_PUB_1       R1

Messages 7-8: Agent L initiates a connectivity check for pair L1.
The check succeeds, and the pair (L1) is added to the valid list of
agent L.  Agent L can now send and receive data on the pair (L1) if
it wishes.

                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PUB_1       R_PUB_1       L1         X

   ICE Agent R:             R_PUB_1       L_PUB_1       R1

Messages 9-10: When agent R receives the Binding request from agent L
(message 7), it will initiate a triggered connectivity check.  The
pair matches agent R's existing pair (R1).  The check succeeds, and
the pair (R1) is added to the valid list of agent R.  Agent R can now
send and receive data on the pair (R1) if it wishes.

                            Pairs
   ENTITY                   Local         Remote     Pair #     Valid
   ------------------------------------------------------------------
   ICE Agent L:             L_PUB_1       R_PUB_1       L1         X

   ICE Agent R:             R_PUB_1       L_PUB_1       R1         X

Messages 11-12: At some point, the controlling agent (agent L)
decides to nominate a pair (L1) in the valid list.  It performs a
connectivity check on the pair (L1) and includes the USE-CANDIDATE
attribute in the Binding request.  As the check succeeds, agent L
sets the nominated flag value of the pair (L1) to 'true', and agent R
sets the nominated flag value of the matching pair (R1) to 'true'.
As there are no more components associated with the stream, the
nominated pairs become the selected pairs.  Consequently, processing
for this stream moves into the Completed state.  The ICE process also
moves into the Completed state.