# 4 Protocol Operation

The offer/answer exchange assumes the existence of a higher layer
protocol (such as SIP) which is capable of exchanging SDP for the
purposes of session establishment between agents.

Protocol operation begins when one agent sends an initial offer to
another agent.  An offer is initial if it is outside of any context
that may have already been established through the higher layer
protocol.  It is assumed that the higher layer protocol provides
maintenance of some kind of context which allows the various SDP
exchanges to be associated together.

The agent receiving the offer MAY generate an answer, or it MAY
reject the offer.  The means for rejecting an offer are dependent on
the higher layer protocol.  The offer/answer exchange is atomic; if
the answer is rejected, the session reverts to the state prior to the
offer (which may be absence of a session).

At any time, either agent MAY generate a new offer that updates the
session.  However, it MUST NOT generate a new offer if it has
received an offer which it has not yet answered or rejected.
Furthermore, it MUST NOT generate a new offer if it has generated a
prior offer for which it has not yet received an answer or a
rejection.  If an agent receives an offer after having sent one, but
before receiving an answer to it, this is considered a "glare"
condition.

    The term glare was originally used in circuit switched
    telecommunications networks to describe the condition where two
    switches both attempt to seize the same available circuit on the
    same trunk at the same time.  Here, it means both agents have
    attempted to send an updated offer at the same time.

The higher layer protocol needs to provide a means for resolving such
conditions.  The higher layer protocol will need to provide a means
for ordering of messages in each direction.  SIP meets these
requirements [7].
