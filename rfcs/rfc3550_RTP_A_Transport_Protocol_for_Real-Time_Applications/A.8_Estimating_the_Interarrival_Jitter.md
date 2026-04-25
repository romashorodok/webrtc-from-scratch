## A.8 Estimating the Interarrival Jitter

The code fragments below implement the algorithm given in Section
6.4.1 for calculating an estimate of the statistical variance of the
RTP data interarrival time to be inserted in the interarrival jitter
field of reception reports.  The inputs are r->ts, the timestamp from
the incoming packet, and arrival, the current time in the same units.
Here s points to state for the source; s->transit holds the relative
transit time for the previous packet, and s->jitter holds the
estimated jitter.  The jitter field of the reception report is
measured in timestamp units and expressed as an unsigned integer, but
the jitter estimate is kept in a floating point.  As each data packet
arrives, the jitter estimate is updated:

    int transit = arrival - r->ts;
    int d = transit - s->transit;
    s->transit = transit;
    if (d < 0) d = -d;
    s->jitter += (1./16.) * ((double)d - s->jitter);

When a reception report block (to which rr points) is generated for
this member, the current jitter estimate is returned:

    rr->jitter = (u_int32) s->jitter;

Alternatively, the jitter estimate can be kept as an integer, but
scaled to reduce round-off error.  The calculation is the same except
for the last line:

    s->jitter += d - ((s->jitter + 8) >> 4);

In this case, the estimate is sampled for the reception report as:

    rr->jitter = s->jitter >> 4;


