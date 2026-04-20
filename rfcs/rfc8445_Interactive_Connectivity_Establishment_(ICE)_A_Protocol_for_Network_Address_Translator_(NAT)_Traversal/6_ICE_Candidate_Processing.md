# 6.  ICE Candidate Processing

Once an ICE agent has gathered its candidates and exchanged
candidates with its peer (Section 5), it will determine its own role.
In addition, full implementations will form checklists and begin
performing connectivity checks with the peer.

## 6.1.  Procedures for Full Implementation

### 6.1.1.  Determining Role

For each session, each ICE agent (initiating and responding) takes on
a role.  There are two roles -- controlling and controlled.  The
controlling agent is responsible for the choice of the final
candidate pairs used for communications.  The sections below describe
in detail the actual procedures followed by controlling and
controlled agents.

The rules for determining the role and the impact on behavior are as
follows:

Both agents are full:  The initiating agent that started the ICE
    processing MUST take the controlling role, and the other MUST take
    the controlled role.  Both agents will form checklists, run the
    ICE state machines, and generate connectivity checks.  The
    controlling agent will execute the logic in Section 8.1 to
    nominate pairs that will become (if the connectivity checks
    associated with the nominations succeed) the selected pairs, and
    then both agents end ICE as described in Section 8.1.2.

One agent full, one lite:  The full agent MUST take the controlling
    role, and the lite agent MUST take the controlled role.  The full
    agent will form checklists, run the ICE state machines, and
    generate connectivity checks.  That agent will execute the logic
    in Section 8.1 to nominate pairs that will become (if the
    connectivity checks associated with the nominations succeed) the
    selected pairs and use the logic in Section 8.1.2 to end ICE.  The
    lite implementation will just listen for connectivity checks,
    receive them and respond to them, and then conclude ICE as
    described in Section 8.2.  For the lite implementation, the state
    of ICE processing for each data stream is considered to be
    Running, and the state of ICE overall is Running.

Both lite:  The initiating agent that started the ICE processing MUST
    take the controlling role, and the other MUST take the controlled
    role.  In this case, no connectivity checks are ever sent.
    Rather, once the candidates are exchanged, each agent performs the
    processing described in Section 8 without connectivity checks.  It
    is possible that both agents will believe they are controlled or
    controlling.  In the latter case, the conflict is resolved through
    glare detection capabilities in the signaling protocol enabling
    the candidate exchange.  The state of ICE processing for each data
    stream is considered to be Running, and the state of ICE overall
    is Running.

Once the roles are determined for a session, they persist throughout
the lifetime of the session.  The roles can be redetermined as part
of an ICE restart (Section 9), but an ICE agent MUST NOT redetermine
the role as part of an ICE restart unless one or more of the
following criteria is fulfilled:

Full becomes lite:  If the controlling agent is full, and switches to
    lite, the roles MUST be redetermined if the peer agent is also
    full.


Role conflict:  If the ICE restart causes a role conflict, the roles
    might be redetermined due to the role conflict procedures in
    Section 7.3.1.1.

NOTE: There are certain Third Party Call Control (3PCC) [RFC3725]
scenarios where an ICE restart might cause a role conflict.

NOTE: The agents need to inform each other whether they are full or
lite before the roles are determined.  The mechanism for that is
specific to the signaling protocol and outside the scope of the
document.

An agent MUST accept if the peer initiates a redetermination of the
roles even if the criteria for doing so are not fulfilled.  This can
happen if the peer is compliant with RFC 5245.

### 6.1.2.  Forming the Checklists

There is one checklist for each data stream.  To form a checklist,
initiating and responding ICE agents form candidate pairs, compute
pair priorities, order pairs by priority, prune pairs, remove lower-
priority pairs, and set checklist states.  If candidates are added to
a checklist (e.g., due to detection of peer-reflexive candidates),
the agent will re-perform these steps for the updated checklist.

#### 6.1.2.1.  Checklist State

Each checklist has a state, which captures the state of ICE checks
for the data stream associated with the checklist.  The states are:

Running:  The checklist is neither Completed nor Failed yet.
    Checklists are initially set to the Running state.

Completed:  The checklist contains a nominated pair for each
    component of the data stream.

Failed:  The checklist does not have a valid pair for each component
    of the data stream, and all of the candidate pairs in the
    checklist are in either the Failed or the Succeeded state.  In
    other words, at least one component of the checklist has candidate
    pairs that are all in the Failed state, which means the component
    has failed, which means the checklist has failed.

#### 6.1.2.2.  Forming Candidate Pairs

The ICE agent pairs each local candidate with each remote candidate
for the same component of the same data stream with the same IP
address family.  It is possible that some of the local candidates

won't get paired with remote candidates, and some of the remote
candidates won't get paired with local candidates.  This can happen
if one agent doesn't include candidates for all of the components for
a data stream.  If this happens, the number of components for that
data stream is effectively reduced and is considered to be equal to
the minimum across both agents of the maximum component ID provided
by each agent across all components for the data stream.

In the case of RTP, this would happen when one agent provides
candidates for RTCP, and the other does not.  As another example, the
initiating agent can multiplex RTP and RTCP on the same port
[RFC5761].  However, since the initiating agent doesn't know if the
peer agent can perform such multiplexing, it includes candidates for
RTP and RTCP on separate ports.  If the peer agent can perform such
multiplexing, it would include just a single component for each
candidate -- for the combined RTP/RTCP mux.  ICE would end up acting
as if there was just a single component for this candidate.

With IPv6, it is common for a host to have multiple host candidates
for each interface.  To keep the amount of resulting candidate pairs
reasonable and to avoid candidate pairs that are highly unlikely to
work, IPv6 link-local addresses MUST NOT be paired with other than
link-local addresses.

The candidate pairs whose local and remote candidates are both the
default candidates for a particular component is called the "default
candidate pair" for that component.  This is the pair that would be
used to transmit data if both agents had not been ICE aware.


   Figure 5 shows the properties of and relationships between transport
   addresses, candidates, candidate pairs, and checklists.

              +--------------------------------------------+
              |                                            |
              | +---------------------+                    |
              | |+----+ +----+ +----+ |   +Type            |
              | || IP | |Port| |Tran| |   +Priority        |
              | ||Addr| |    | |    | |   +Foundation      |
              | |+----+ +----+ +----+ |   +Component ID    |
              | |      Transport      |   +Related Address |
              | |        Addr         |                    |
              | +---------------------+   +Base            |
              |             Candidate                      |
              +--------------------------------------------+
              *                                         *
              *    *************************************
              *    *
            +-------------------------------+
            |                               |
            | Local     Remote              |
            | +----+    +----+   +default?  |
            | |Cand|    |Cand|   +valid?    |
            | +----+    +----+   +nominated?|
            |                    +State     |
            |                               |
            |                               |
            |          Candidate Pair       |
            +-------------------------------+
            *                              *
            *                  ************
            *                  *
            +------------------+
            |  Candidate Pair  |
            +------------------+
            +------------------+
            |  Candidate Pair  |
            +------------------+
            +------------------+
            |  Candidate Pair  |
            +------------------+

                 Checklist


                Figure 5: Conceptual Diagram of a Checklist

#### 6.1.2.3.  Computing Pair Priority and Ordering Pairs

The ICE agent computes a priority for each candidate pair.  Let G be
the priority for the candidate provided by the controlling agent.
Let D be the priority for the candidate provided by the controlled
agent.  The priority for a pair is computed as follows:

    pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

The agent sorts each checklist in decreasing order of candidate pair
priority.  If two pairs have identical priority, the ordering amongst
them is arbitrary.

#### 6.1.2.4.  Pruning the Pairs

This sorted list of candidate pairs is used to determine a sequence
of connectivity checks that will be performed.  Each check involves
sending a request from a local candidate to a remote candidate.
Since an ICE agent cannot send requests directly from a reflexive
candidate (server reflexive or peer reflexive), but only from its
base, the agent next goes through the sorted list of candidate pairs.
For each pair where the local candidate is reflexive, the candidate
MUST be replaced by its base.

The agent prunes each checklist.  This is done by removing a
candidate pair if it is redundant with a higher-priority candidate
pair in the same checklist.  Two candidate pairs are redundant if
their local candidates have the same base and their remote candidates
are identical.  The result is a sequence of ordered candidate pairs,
called the "checklist" for that data stream.

#### 6.1.2.5.  Removing Lower-Priority Pairs

In order to limit the attacks described in Section 19.5.1, an ICE
agent MUST limit the total number of connectivity checks the agent
performs across all checklists in the checklist set.  This is done by
limiting the total number of candidate pairs in the checklist set.
The default limit of candidate pairs for the checklist set is 100,
but the value MUST be configurable.  The limit is enforced by, within
in each checklist, discarding lower-priority candidate pairs until
the total number of candidate pairs in the checklist set is smaller
than the limit value.  The discarding SHOULD be done evenly so that
the number of candidate pairs in each checklist is reduced the same
amount.

It is RECOMMENDED that a lower-limit value than the default is picked
when possible, and that the value is set to the maximum number of
plausible candidate pairs that might be created in an actual deployment configuration. 
The requirement for configuration is meant to provide a tool for fixing this value in the field if, once deployed, it is found to be problematic.

##### 6.1.2.6.  Computing Candidate Pair States

Each candidate pair in the checklist has a foundation (the
combination of the foundations of the local and remote candidates in
the pair) and one of the following states:

Waiting:  A check has not been sent for this pair, but the pair is
    not Frozen.

In-Progress:  A check has been sent for this pair, but the
    transaction is in progress.

Succeeded:  A check has been sent for this pair, and it produced a
    successful result.

Failed:  A check has been sent for this pair, and it failed (a
    response to the check was never received, or a failure response
    was received).

Frozen:  A check for this pair has not been sent, and it cannot be
    sent until the pair is unfrozen and moved into the Waiting state.





   Pairs move between states as shown in Figure 6.

      +-----------+
      |           |
      |           |
      |  Frozen   |
      |           |
      |           |
      +-----------+
            |
            |unfreeze
            |
            V
      +-----------+         +-----------+
      |           |         |           |
      |           | perform |           |
      |  Waiting  |-------->|In-Progress|
      |           |         |           |
      |           |         |           |
      +-----------+         +-----------+
                                  / |
                                //  |
                              //    |
                            //      |
                           /        |
                         //         |
               failure //           |success
                     //             |
                    /               |
                  //                |
                //                  |
              //                    |
             V                      V
      +-----------+         +-----------+
      |           |         |           |
      |           |         |           |
      |   Failed  |         | Succeeded |
      |           |         |           |
      |           |         |           |
      +-----------+         +-----------+

              Figure 6: Pair State Finite State Machine (FSM)


The initial states for each pair in a checklist are computed by
performing the following sequence of steps:

1.  The checklists are placed in an ordered list (the order is
    determined by each ICE usage), called the "checklist set".

2.  The ICE agent initially places all candidate pairs in the Frozen
    state.

3.  The agent sets all of the checklists in the checklist set to the
    Running state.

4.  For each foundation, the agent sets the state of exactly one
    candidate pair to the Waiting state (unfreezing it).  The
    candidate pair to unfreeze is chosen by finding the first
    candidate pair (ordered by the lowest component ID and then the
    highest priority if component IDs are equal) in the first
    checklist (according to the usage-defined checklist set order)
    that has that foundation.

NOTE: The procedures above are different from RFC 5245, where only
candidate pairs in the first checklist were initially placed in the
Waiting state.  Now it applies to candidate pairs in the first
checklist that have that foundation, even if the checklist is not the
first one in the checklist set.

The table below illustrates an example.

Table legend:

Each row (m1, m2,...) represents a checklist associated with a
data stream. m1 represents the first checklist in the checklist
set.

Each column (f1, f2,...) represents a foundation.  Every candidate
pair within a given column share the same foundation.

f-cp represents a candidate pair in the Frozen state.

w-cp represents a candidate pair in the Waiting state.

1.  The agent sets all of the pairs in the checklist set to the
    Frozen state.

        f1    f2    f3    f4    f5
    -----------------------------
m1 | f-cp  f-cp  f-cp
    |
m2 | f-cp  f-cp  f-cp  f-cp
    |
m3 | f-cp                    f-cp


2.  For each foundation, the candidate pair with the lowest
    component ID is placed in the Waiting state, unless a
    candidate pair associated with the same foundation has
    already been put in the Waiting state in one of the
    other examined checklists in the checklist set.

        f1    f2    f3    f4    f5
    -----------------------------
m1 | w-cp  w-cp  w-cp
    |
m2 | f-cp  f-cp  f-cp  w-cp
    |
m3 | f-cp                    w-cp

                    Table 1: Pair State Example

In the first checklist (m1), the candidate pair for each foundation
is placed in the Waiting state, as no pairs for the same foundations
have yet been placed in the Waiting state.

In the second checklist (m2), the candidate pair for foundation f4 is
placed in the Waiting state.  The candidate pair for foundations f1,
f2, and f3 are kept in the Frozen state, as candidate pairs for those foundations have already been placed in the Waiting state (within checklist m1).

In the third checklist (m3), the candidate pair for foundation f5 is
placed in the Waiting state.  The candidate pair for foundation f1 is
kept in the Frozen state, as a candidate pair for that foundation has
already been placed in the Waiting state (within checklist m1).

Once each checklist have been processed, one candidate pair for each
foundation in the checklist set has been placed in the Waiting state.

### 6.1.3.  ICE State

The ICE agent has a state determined by the state of the checklists.
The state is Completed if all checklists are Completed, Failed if all
checklists are Failed, or Running otherwise.

### 6.1.4.  Scheduling Checks

#### 6.1.4.1.  Triggered-Check Queue

Once the ICE agent has computed the checklists and created the
checklist set, as described in Section 6.1.2, the agent will begin
performing connectivity checks (ordinary and triggered).  For
triggered connectivity checks, the agent maintains a FIFO queue for
each checklist, referred to as the "triggered-check queue", which
contains candidate pairs for which checks are to be sent at the next
available opportunity.  The triggered-check queue is initially empty.

#### 6.1.4.2.  Performing Connectivity Checks

The generation of ordinary and triggered connectivity checks is
governed by timer Ta.  As soon as the initial states for the
candidate pairs in the checklist set have been set, a check is
performed for a candidate pair within the first checklist in the
Running state, following the procedures in Section 7.  After that,
whenever Ta fires the next checklist in the Running state in the
checklist set is picked, and a check is performed for a candidate
within that checklist.  After the last checklist in the Running state
in the checklist set has been processed, the first checklist is
picked again, etc.

Whenever Ta fires, the ICE agent will perform a check for a candidate
pair within the checklist that was picked by performing the following
steps:

1.  If the triggered-check queue associated with the checklist
    contains one or more candidate pairs, the agent removes the top
    pair from the queue, performs a connectivity check on that pair,
    puts the candidate pair state to In-Progress, and aborts the
    subsequent steps.

2.  If there is no candidate pair in the Waiting state, and if there
    are one or more pairs in the Frozen state, the agent checks the
    foundation associated with each pair in the Frozen state.  For a
    given foundation, if there is no pair (in any checklist in the
    checklist set) in the Waiting or In-Progress state, the agent
    puts the candidate pair state to Waiting and continues with the
    next step.

3.  If there are one or more candidate pairs in the Waiting state,
    the agent picks the highest-priority candidate pair (if there are
    multiple pairs with the same priority, the pair with the lowest
    component ID is picked) in the Waiting state, performs a
    connectivity check on that pair, puts the candidate pair state to
    In-Progress, and aborts the subsequent steps.

4.  If this step is reached, no check could be performed for the
    checklist that was picked.  So, without waiting for timer Ta to
    expire again, select the next checklist in the Running state and
    return to step #1.  If this happens for every single checklist in
    the Running state, meaning there are no remaining candidate pairs
    to perform connectivity checks for, abort these steps.

Once the agent has picked a candidate pair for which a connectivity
check is to be performed, the agent starts a check and sends the
Binding request from the base associated with the local candidate of
the pair to the remote candidate of the pair, as described in
Section 7.2.4.

Based on local policy, an agent MAY choose to terminate performing
the connectivity checks for one or more checklists in the checklist
set at any time.  However, only the controlling agent is allowed to
conclude ICE (Section 8).

To compute the message integrity for the check, the agent uses the
remote username fragment and password learned from the candidate
information obtained from its peer.  The local username fragment is
known directly by the agent for its own candidate.

## 6.2.  Lite Implementation Procedures

Lite implementations skip most of the steps in Section 6 except for
verifying the peer's ICE support and determining its role in the ICE
processing.

If the lite implementation is the controlling agent (which will only
happen if the peer ICE agent is also a lite implementation), it
selects a candidate pair based on the ones in the candidate exchange
(for IPv4, there is only ever one pair) and then updates the peer
with the new candidate information reflecting that selection, if
needed (it is never needed for an IPv4-only host).

