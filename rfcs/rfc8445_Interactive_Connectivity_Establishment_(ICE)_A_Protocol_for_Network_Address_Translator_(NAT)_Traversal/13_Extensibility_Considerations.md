# 13.  Extensibility Considerations

This specification makes very specific choices about how both ICE
agents in a session coordinate to arrive at the set of candidate
pairs that are selected for data.  It is anticipated that future
specifications will want to alter these algorithms, whether they are
simple changes like timer tweaks or larger changes like a revamp of
the priority algorithm.  When such a change is made, providing
interoperability between the two agents in a session is critical.

First, ICE provides the ICE option concept.  Each extension or change
to ICE is associated with an ICE option.  When an agent supports such
an extension or change, it provides the ICE option to the peer agent
as part of the candidate exchange.

One of the complications in achieving interoperability is that ICE
relies on a distributed algorithm running on both agents to converge
on an agreed set of candidate pairs.  If the two agents run different
algorithms, it can be difficult to guarantee convergence on the same
candidate pairs.  The nomination procedure described in Section 8
eliminates some of the need for tight coordination by delegating the
selection algorithm completely to the controlling agent, and ICE will
converge perfectly even when both agents use different pair
prioritization algorithms.  One of the keys to such convergence is
triggered checks, which ensure that the nominated pair is validated
by both agents.

ICE is also extensible to other data streams beyond RTP and for
transport protocols beyond UDP.  Extensions to ICE for non-RTP data
streams need to specify how many components they utilize and assign
component IDs to them, starting at 1 for the most important component
ID.  Specifications for new transport protocols MUST define how, if
at all, various steps in the ICE processing differ from UDP.