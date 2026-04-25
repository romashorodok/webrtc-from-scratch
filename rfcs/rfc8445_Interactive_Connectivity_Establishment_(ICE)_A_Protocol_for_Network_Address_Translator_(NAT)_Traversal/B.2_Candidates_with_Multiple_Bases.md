## B.2.  Candidates with Multiple Bases

Section 5.1.3 talks about eliminating candidates that have the same
transport address and base.  However, candidates with the same
transport addresses but different bases are not redundant.  When can
an ICE agent have two candidates that have the same IP address and
port but different bases?  Consider the topology of Figure 11:

          +----------+
          | STUN Srvr|
          +----------+
               |
               |
             -----
           //     \\
          |         |
         |  B:net10  |
          |         |
           \\     //
             -----
               |
               |
          +----------+
          |   NAT    |
          +----------+
               |
               |
             -----
           //     \\
          |    A    |
         |192.168/16 |
          |         |
           \\     //
             -----
               |
               |
               |192.168.1.100      -----
          +----------+           //     \\             +----------+
          |          |          |         |            |          |
          | Initiator|---------|  C:net10  |-----------| Responder|
          |          |10.0.1.100|         | 10.0.1.101 |          |
          +----------+           \\     //             +----------+
                                   -----

           Figure 11: Identical Candidates with Different Bases


In this case, the initiating agent is multihomed.  It has one IP
address, 10.0.1.100, on network C, which is a net 10 private network.
The responding agent is on this same network.  The initiating agent
is also connected to network A, which is 192.168/16, and has an IP
address of 192.168.1.100.  There is a NAT on this network, natting
into network B, which is another net 10 private network, but it is
not connected to network C.  There is a STUN server on network B.

The initiating agent obtains a host candidate on its IP address on
network C (10.0.1.100:2498) and a host candidate on its IP address on
network A (192.168.1.100:3344).  It performs a STUN query to its
configured STUN server from 192.168.1.100:3344.  This query passes
through the NAT, which happens to assign the binding 10.0.1.100:2498.
The STUN server reflects this in the STUN Binding response.  Now, the
initiating agent has obtained a server-reflexive candidate with a
transport address that is identical to a host candidate
(10.0.1.100:2498).  However, the server-reflexive candidate has a
base of 192.168.1.100:3344, and the host candidate has a base of
10.0.1.100:2498.

