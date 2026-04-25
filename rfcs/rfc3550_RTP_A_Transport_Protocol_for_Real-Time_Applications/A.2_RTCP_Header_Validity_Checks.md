## A.2 RTCP Header Validity Checks

The following checks should be applied to RTCP packets.

o  RTP version field must equal 2.

o  The payload type field of the first RTCP packet in a compound
    packet must be equal to SR or RR.

o  The padding bit (P) should be zero for the first packet of a
    compound RTCP packet because padding should only be applied, if it
    is needed, to the last packet.

o  The length fields of the individual RTCP packets must add up to
    the overall length of the compound RTCP packet as received.  This
    is a fairly strong check.

The code fragment below performs all of these checks.  The packet
type is not checked for subsequent packets since unknown packet types
may be present and should be ignored.

    u_int32 len;        /* length of compound RTCP packet in words */
    rtcp_t *r;          /* RTCP header */
    rtcp_t *end;        /* end of compound RTCP packet */

    if ((*(u_int16 *)r & RTCP_VALID_MASK) != RTCP_VALID_VALUE) {
        /* something wrong with packet format */
    }
    end = (rtcp_t *)((u_int32 *)r + len);

    do r = (rtcp_t *)((u_int32 *)r + r->common.length + 1);
    while (r < end && r->common.version == 2);


    if (r != end) {
        /* something wrong with packet format */
    }

