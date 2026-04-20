# 14.  Setting Ta and RTO

## 14.1.  General

During the ICE gathering phase (Section 5.1.1) and while ICE is
performing connectivity checks (Section 7), an ICE agent triggers
STUN and TURN transactions.  These transactions are paced at a rate
indicated by Ta, and the retransmission interval for each transaction
is calculated based on the retransmission timer for the STUN
transactions (RTO) [RFC5389].

This section describes how the Ta and RTO values are computed during
the ICE gathering phase and while ICE is performing connectivity
checks.

NOTE: Previously, in RFC 5245, different formulas were defined for
computing Ta and RTO, depending on whether or not ICE was used for a
real-time data stream (e.g., RTP).

The formulas below result in a behavior whereby an agent will send
its first packet for every single connectivity check before
performing a retransmit.  This can be seen in the formulas for the
RTO (which represents the retransmit interval).  Those formulas scale
with N, the number of checks to be performed.  As a result of this,
ICE maintains a nicely constant rate, but it becomes more sensitive
to packet loss.  The loss of the first single packet for any
connectivity check is likely to cause that pair to take a long time
to be validated, and instead, a lower-priority check (but one for
which there was no packet loss) is much more likely to complete
first.  This results in ICE performing suboptimally, choosing lower-
priority pairs over higher-priority pairs.

## 14.2.  Ta

ICE agents SHOULD use a default Ta value, 50 ms, but MAY use another
value based on the characteristics of the associated data.

If an agent wants to use a Ta value other than the default value, the
agent MUST indicate the proposed value to its peer during the
establishment of the ICE session.  Both agents MUST use the higher
value of the proposed values.  If an agent does not propose a value,
the default value is used for that agent when comparing which value
is higher.

Regardless of the Ta value chosen for each agent, the combination of
all transactions from all agents (if a given implementation runs
several concurrent agents) MUST NOT be sent more often than once
every 5 ms (as though there were one global Ta value for pacing all
agents).  See Appendix B.1 for the background of using a value of
5 ms with ICE.

NOTE: Appendix C shows examples of required bandwidth, using
different Ta values.

## 14.3.  RTO

During the ICE gathering phase, ICE agents SHOULD calculate the RTO
value using the following formula:

    RTO = MAX (500ms, Ta * (Num-Of-Cands))

    Num-Of-Cands: the number of server-reflexive and relay candidates

For connectivity checks, agents SHOULD calculate the RTO value using
the following formula:

    RTO = MAX (500ms, Ta * N * (Num-Waiting + Num-In-Progress))

    N: the total number of connectivity checks to be performed.

    Num-Waiting: the number of checks in the checklist set in the
    Waiting state.

    Num-In-Progress: the number of checks in the checklist set in the
    In-Progress state.

    Note that the RTO will be different for each transaction as the
    number of checks in the Waiting and In-Progress states change.


Agents MAY calculate the RTO value using other mechanisms than those
described above.  Agents MUST NOT use an RTO value smaller than
500 ms.
