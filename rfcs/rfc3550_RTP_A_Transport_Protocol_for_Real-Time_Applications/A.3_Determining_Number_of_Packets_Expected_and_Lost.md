## A.3 Determining Number of Packets Expected and Lost

In order to compute packet loss rates, the number of RTP packets
expected and actually received from each source needs to be known,
using per-source state information defined in struct source
referenced via pointer s in the code below.  The number of packets
received is simply the count of packets as they arrive, including any
late or duplicate packets.  The number of packets expected can be
computed by the receiver as the difference between the highest
sequence number received (s->max_seq) and the first sequence number
received (s->base_seq).  Since the sequence number is only 16 bits
and will wrap around, it is necessary to extend the highest sequence
number with the (shifted) count of sequence number wraparounds
(s->cycles).  Both the received packet count and the count of cycles
are maintained the RTP header validity check routine in Appendix A.1.

    extended_max = s->cycles + s->max_seq;
    expected = extended_max - s->base_seq + 1;

The number of packets lost is defined to be the number of packets
expected less the number of packets actually received:

    lost = expected - s->received;

Since this signed number is carried in 24 bits, it should be clamped
at 0x7fffff for positive loss or 0x800000 for negative loss rather
than wrapping around.

The fraction of packets lost during the last reporting interval
(since the previous SR or RR packet was sent) is calculated from
differences in the expected and received packet counts across the
interval, where expected_prior and received_prior are the values
saved when the previous reception report was generated:

    expected_interval = expected - s->expected_prior;
    s->expected_prior = expected;
    received_interval = s->received - s->received_prior;
    s->received_prior = s->received;
    lost_interval = expected_interval - received_interval;
    if (expected_interval == 0 || lost_interval <= 0) fraction = 0;
    else fraction = (lost_interval << 8) / expected_interval;

The resulting fraction is an 8-bit fixed point number with the binary
point at the left edge.

