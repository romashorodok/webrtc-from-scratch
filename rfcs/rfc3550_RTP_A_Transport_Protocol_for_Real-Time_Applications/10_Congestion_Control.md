# 10. Congestion Control

All transport protocols used on the Internet need to address
congestion control in some way [31].  RTP is not an exception, but
because the data transported over RTP is often inelastic (generated
at a fixed or controlled rate), the means to control congestion in
RTP may be quite different from those for other transport protocols
such as TCP.  In one sense, inelasticity reduces the risk of
congestion because the RTP stream will not expand to consume all
available bandwidth as a TCP stream can.  However, inelasticity also
means that the RTP stream cannot arbitrarily reduce its load on the
network to eliminate congestion when it occurs.

Since RTP may be used for a wide variety of applications in many
different contexts, there is no single congestion control mechanism
that will work for all.  Therefore, congestion control SHOULD be
defined in each RTP profile as appropriate.  For some profiles, it
may be sufficient to include an applicability statement restricting
the use of that profile to environments where congestion is avoided
by engineering.  For other profiles, specific methods such as data
rate adaptation based on RTCP feedback may be required.
