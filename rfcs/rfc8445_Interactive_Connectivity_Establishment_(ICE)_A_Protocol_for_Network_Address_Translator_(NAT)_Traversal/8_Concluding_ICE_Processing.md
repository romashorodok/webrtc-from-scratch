# 8.  Concluding ICE Processing

This section describes how an ICE agent completes ICE.

## 8.1.  Procedures for Full Implementations

Concluding ICE involves nominating pairs by the controlling agent and
updating state machinery.

### 8.1.1.  Nominating Pairs

Prior to nominating, the controlling agent lets connectivity checks
continue until some stopping criterion is met.  After that, based on
an evaluation criterion, the controlling agent picks a pair among the
valid pairs in the valid list for nomination.

Once the controlling agent has picked a valid pair for nomination, it
repeats the connectivity check that produced this valid pair (by
enqueueing the pair that generated the check into the triggered-check
queue), this time with the USE-CANDIDATE attribute
(Section 7.2.5.3.4).  The procedures for the controlled agent are
described in Section 7.3.1.5.

Eventually, if the nominations succeed, both the controlling and
controlled agents will have a single nominated pair in the valid list
for each component of the data stream.  Once an ICE agent sets the
state of the checklist to Completed (when there is a nominated pair
for each component of the data stream), that pair becomes the
selected pair for that agent and is used for sending and receiving
data for that component of the data stream.

If an agent is not able to produce selected pairs for each component
of a data stream, the agent MUST take proper actions for informing
the other agent, e.g., by removing the stream.  The exact actions are
outside the scope of this specification.

The criteria for stopping the connectivity checks and for picking a
pair for nomination are outside the scope of this specification.
They are a matter of local optimization.  The only requirement is
that the agent MUST eventually pick one and only one candidate pair
and generate a check for that pair with the USE-CANDIDATE attribute
set.

Once the controlling agent has successfully nominated a candidate
pair (Section 7.2.5.3.4), the agent MUST NOT nominate another pair
for same component of the data stream within the ICE session.  Doing
so requires an ICE restart.

A controlling agent that does not support this specification (i.e.,
it is implemented according to RFC 5245) might nominate more than one
candidate pair.  This was referred to as "aggressive nomination" in
RFC 5245.  If more than one candidate pair is nominated by the
controlling agent, and if the controlled agent accepts multiple
nominations requests, the agents MUST produce the selected pairs and
use the pairs with the highest priority.

The usage of the 'ice2' ICE option (Section 10) by endpoints
supporting this specification is supposed to prevent controlling
agents that are implemented according to RFC 5245 from using
aggressive nomination.

NOTE: In RFC 5245, usage of "aggressive nomination" allowed agents to
continuously nominate pairs, before a pair was eventually selected,
in order to allow sending of data on those pairs.  In this
specification, data can always be sent on any valid pair, without
nomination.  Hence, there is no longer a need for aggressive
nomination.

### 8.1.2.  Updating Checklist and ICE States

For both a controlling and a controlled agent, when a candidate pair
for a component of a data stream gets nominated, it might impact
other pairs in the checklist associated with the data stream.  It
might also impact the state of the checklist:

o  Once a candidate pair for a component of a data stream has been
    nominated, and the state of the checklist associated with the data
    stream is Running, the ICE agent MUST remove all candidate pairs
    for the same component from the checklist and from the triggered-
    check queue.  If the state of a pair is In-Progress, the agent
    cancels the In-Progress transaction.  Cancellation means that the
    agent will not retransmit the Binding requests associated with the
    connectivity-check transaction, will not treat the lack of
    response to be a failure, but will wait the duration of the
    transaction timeout for a response.

o  Once candidate pairs for each component of a data stream have been
    nominated, and the state of the checklist associated with the data
    stream is Running, the ICE agent sets the state of the checklist
    to Completed.

o  Once a candidate pair for a component of a data stream has been
    nominated, an agent MUST continue to respond to any Binding
    request it might still receive for the nominated pair and for any
    remaining candidate pairs in the checklist associated with the



    data stream.  As defined in Section 7.3.1.4, when the state of a
    pair is Succeeded, an agent will no longer generate triggered
    checks when receiving a Binding request for the pair.

Once the state of each checklist in the checklist set is Completed,
the agent sets the state of the ICE session to Completed.

If the state of a checklist is Failed, ICE has not been able to
successfully complete the process for the data stream associated with
the checklist.  The correct behavior depends on the state of the
checklists in the checklist set.  If the controlling agent wants to
continue the session without the data stream associated with the
Failed checklist, and if there are still one or more checklists in
Running or Completed mode, the agent can let the ICE processing
continue.  The agent MUST take proper actions for removing the failed
data stream.  If the controlling agent does not want to continue the
session and MUST terminate the session, the state of the ICE session
is set to Failed.

If the state of each checklist in the checklist set is Failed, the
state of the ICE session is set to Failed.  Unless the controlling
agent wants to continue the session without the data streams, it MUST
terminate the session.

## 8.2.  Procedures for Lite Implementations

When ICE concludes, a lite ICE agent can free host candidates that
were not used by ICE, as described in Section 8.3.

If the peer is a full agent, once the lite agent accepts a nomination
request for a candidate pair, the lite agent considers the pair
nominated.  Once there are nominated pairs for each component of a
data stream, the pairs become the selected pairs for the components
of the data stream.  Once the lite agent has produced selected pairs
for all components of all data streams, the ICE session state is set
to Completed.

If the peer is a lite agent, the agent pairs local candidates with
remote candidates that are of the same data stream and have the same
component, transport protocol, and IP address family.  For each
component of each data stream, if there is only one candidate pair,
that pair is added to the valid list.  If there is more than one
pair, it is RECOMMENDED that an agent follow the procedures of RFC
6724 [RFC6724] to select a pair and add it to the valid list.

If all of the components for all data streams had one pair, the state
of ICE processing is Completed.  Otherwise, the controlling agent
MUST send an updated candidate list to reconcile different agents
selecting different candidate pairs.  ICE processing is complete
after and only after the updated candidate exchange is complete.

## 8.3.  Freeing Candidates

### 8.3.1.  Full Implementation Procedures

The rules in this section describe when it is safe for an agent to
cease sending or receiving checks on a candidate that did not become
a selected candidate (i.e., is not associated with a selected pair)
and when to free the candidate.

Once a checklist has reached the Completed state, the agent SHOULD
wait an additional three seconds, and then it can cease responding to
checks or generating triggered checks on all local candidates other
than the ones that became selected candidates.  Once all ICE sessions
have ceased using a given local candidate (a candidate may be used by
multiple ICE sessions, e.g., in forking scenarios), the agent can
free that candidate.  The three-second delay handles cases when
aggressive nomination is used, and the selected pairs can quickly
change after ICE has completed.

Freeing of server-reflexive candidates is never explicit; it happens
by lack of a keepalive.

### 8.3.2.  Lite Implementation Procedures

A lite implementation can free candidates that did not become
selected candidates as soon as ICE processing has reached the
Completed state for all ICE sessions using those candidates.
