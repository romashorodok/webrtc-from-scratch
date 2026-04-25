## B.5.  The Candidate Pair Priority Formula

The priority for a candidate pair has an odd form.  It is:

    pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

Why is this?  When the candidate pairs are sorted based on this
value, the resulting sorting has the MAX/MIN property.  This means
that the pairs are first sorted based on decreasing value of the
minimum of the two priorities.  For pairs that have the same value of
the minimum priority, the maximum priority is used to sort amongst
them.  If the max and the min priorities are the same, the
controlling agent's priority is used as the tiebreaker in the last
part of the expression.  The factor of 2*32 is used since the
priority of a single candidate is always less than 2*32, resulting in
the pair priority being a "concatenation" of the two component
priorities.  This creates the MAX/MIN sorting.  MAX/MIN ensures that,
for a particular ICE agent, a lower-priority candidate is never used
until all higher-priority candidates have been tried.

