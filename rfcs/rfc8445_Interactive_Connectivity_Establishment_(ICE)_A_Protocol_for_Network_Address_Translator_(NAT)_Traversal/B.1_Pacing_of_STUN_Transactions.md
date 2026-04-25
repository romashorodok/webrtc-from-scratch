## B.1.  Pacing of STUN Transactions

STUN transactions used to gather candidates and to verify
connectivity are paced out at an approximate rate of one new
transaction every Ta milliseconds.  Each transaction, in turn, has a
retransmission timer RTO that is a function of Ta as well.  Why are
these transactions paced, and why are these formulas used?

Sending of these STUN requests will often have the effect of creating
bindings on NAT devices between the client and the STUN servers.
Experience has shown that many NAT devices have upper limits on the
rate at which they will create new bindings.  Discussions in the IETF
ICE WG during the work on this specification concluded that once
every 5 ms is well supported.  This is why Ta has a lower bound of
5 ms.  Furthermore, transmission of these packets on the network
makes use of bandwidth and needs to be rate limited by the ICE agent.
Deployments based on earlier draft versions of [RFC5245] tended to
overload rate-constrained access links and perform poorly overall, in
addition to negatively impacting the network.  As a consequence, the
pacing ensures that the NAT device does not get overloaded and that
traffic is kept at a reasonable rate.

The definition of a "reasonable" rate is that STUN MUST NOT use more
bandwidth than the RTP itself will use, once data starts flowing.
The formula for Ta is designed so that, if a STUN packet were sent
every Ta seconds, it would consume the same amount of bandwidth as
RTP packets, summed across all data streams.  Of course, STUN has
retransmits, and the desire is to pace those as well.  For this
reason, RTO is set such that the first retransmit on the first
transaction happens just as the first STUN request on the last
transaction occurs.  Pictorially:

              First Packets              Retransmits



                    |                        |
                    |                        |
             -------+------           -------+------
            /               \        /               \
           /                 \      /                 \

           +--+    +--+    +--+    +--+    +--+    +--+
           |A1|    |B1|    |C1|    |A2|    |B2|    |C2|
           +--+    +--+    +--+    +--+    +--+    +--+

        ---+-------+-------+-------+-------+-------+------------ Time
           0       Ta      2Ta     3Ta     4Ta     5Ta


In this picture, there are three transactions that will be sent (for
example, in the case of candidate gathering, there are three host
candidate/STUN server pairs).  These are transactions A, B, and C.
The retransmit timer is set so that the first retransmission on the
first transaction (packet A2) is sent at time 3Ta.

Subsequent retransmits after the first will occur even less
frequently than Ta milliseconds apart, since STUN uses an exponential
backoff on its retransmissions.

This mechanism of a global minimum pacing interval of 5 ms is not
generally applicable to transport protocols, but it is applicable to
ICE based on the following reasoning.

o  Start with the following rules that would be generally applicable
    to transport protocols:

    1.  Let MaxBytes be the maximum number of bytes allowed to be
        outstanding in the network at startup, which SHOULD be 14600,
        as defined in Section 2 of [RFC6928].

    2.  Let HTO be the transaction timeout, which SHOULD be 2*RTT if
        RTT is known or 500 ms otherwise.  This is based on the RTO
        for STUN messages from [RFC5389] and the TCP initial RTO,
        which is 1 sec in [RFC6298].

    3.  Let MinPacing be the minimum pacing interval between
        transactions, which is 5 ms (see above).


   o  Observe that agents typically do not know the RTT for ICE
      transactions (connectivity checks in particular), meaning that HTO
      will almost always be 500 ms.

   o  Observe that a MinPacing of 5 ms and HTO of 500 ms gives at most
      100 packets/HTO, which for a typical ICE check of less than 120
      bytes means a maximum of 12000 outstanding bytes in the network,
      which is less than the maximum expressed by rule 1.

   o  Thus, for ICE, the rule set reduces to just the MinPacing rule,
      which is equivalent to having a global Ta value.

