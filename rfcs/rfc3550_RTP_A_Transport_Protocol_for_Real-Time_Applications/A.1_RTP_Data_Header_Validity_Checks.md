## A.1 RTP Data Header Validity Checks

An RTP receiver should check the validity of the RTP header on
incoming packets since they might be encrypted or might be from a
different application that happens to be misaddressed.  Similarly, if
encryption according to the method described in Section 9 is enabled,
the header validity check is needed to verify that incoming packets
have been correctly decrypted, although a failure of the header
validity check (e.g., unknown payload type) may not necessarily
indicate decryption failure.

Only weak validity checks are possible on an RTP data packet from a
source that has not been heard before:

o  RTP version field must equal 2.

o  The payload type must be known, and in particular it must not be
    equal to SR or RR.

o  If the P bit is set, then the last octet of the packet must
    contain a valid octet count, in particular, less than the total
    packet length minus the header size.


o  The X bit must be zero if the profile does not specify that the
    header extension mechanism may be used.  Otherwise, the extension
    length field must be less than the total packet size minus the
    fixed header length and padding.

o  The length of the packet must be consistent with CC and payload
    type (if payloads have a known length).

The last three checks are somewhat complex and not always possible,
leaving only the first two which total just a few bits.  If the SSRC
identifier in the packet is one that has been received before, then
the packet is probably valid and checking if the sequence number is
in the expected range provides further validation.  If the SSRC
identifier has not been seen before, then data packets carrying that
identifier may be considered invalid until a small number of them
arrive with consecutive sequence numbers.  Those invalid packets MAY
be discarded or they MAY be stored and delivered once validation has
been achieved if the resulting delay is acceptable.

The routine update_seq shown below ensures that a source is declared
valid only after MIN_SEQUENTIAL packets have been received in
sequence.  It also validates the sequence number seq of a newly
received packet and updates the sequence state for the packet's
source in the structure to which s points.

When a new source is heard for the first time, that is, its SSRC
identifier is not in the table (see Section 8.2), and the per-source
state is allocated for it, s->probation is set to the number of
sequential packets required before declaring a source valid
(parameter MIN_SEQUENTIAL) and other variables are initialized:

    init_seq(s, seq);
    s->max_seq = seq - 1;
    s->probation = MIN_SEQUENTIAL;

A non-zero s->probation marks the source as not yet valid so the
state may be discarded after a short timeout rather than a long one,
as discussed in Section 6.2.1.

After a source is considered valid, the sequence number is considered
valid if it is no more than MAX_DROPOUT ahead of s->max_seq nor more
than MAX_MISORDER behind.  If the new sequence number is ahead of
max_seq modulo the RTP sequence number range (16 bits), but is
smaller than max_seq, it has wrapped around and the (shifted) count
of sequence number cycles is incremented.  A value of one is returned
to indicate a valid sequence number.


Otherwise, the value zero is returned to indicate that the validation
failed, and the bad sequence number plus 1 is stored.  If the next
packet received carries the next higher sequence number, it is
considered the valid start of a new packet sequence presumably caused
by an extended dropout or a source restart.  Since multiple complete
sequence number cycles may have been missed, the packet loss
statistics are reset.

Typical values for the parameters are shown, based on a maximum
misordering time of 2 seconds at 50 packets/second and a maximum
dropout of 1 minute.  The dropout parameter MAX_DROPOUT should be a
small fraction of the 16-bit sequence number space to give a
reasonable probability that new sequence numbers after a restart will
not fall in the acceptable range for sequence numbers from before the
restart.

void init_seq(source *s, u_int16 seq)
{
    s->base_seq = seq;
    s->max_seq = seq;
    s->bad_seq = RTP_SEQ_MOD + 1;   /* so seq == bad_seq is false */
    s->cycles = 0;
    s->received = 0;
    s->received_prior = 0;
    s->expected_prior = 0;
    /* other initialization */
}

int update_seq(source *s, u_int16 seq)
{
    u_int16 udelta = seq - s->max_seq;
    const int MAX_DROPOUT = 3000;
    const int MAX_MISORDER = 100;
    const int MIN_SEQUENTIAL = 2;

    /*
    * Source is not valid until MIN_SEQUENTIAL packets with
    * sequential sequence numbers have been received.
    */
    if (s->probation) {
        /* packet is in sequence */
        if (seq == s->max_seq + 1) {
            s->probation--;
            s->max_seq = seq;
            if (s->probation == 0) {
                init_seq(s, seq);
                s->received++;
                return 1;


            }
        } else {
            s->probation = MIN_SEQUENTIAL - 1;
            s->max_seq = seq;
        }
        return 0;
    } else if (udelta < MAX_DROPOUT) {
        /* in order, with permissible gap */
        if (seq < s->max_seq) {
            /*
            * Sequence number wrapped - count another 64K cycle.
            */
            s->cycles += RTP_SEQ_MOD;
        }
        s->max_seq = seq;
    } else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
        /* the sequence number made a very large jump */
        if (seq == s->bad_seq) {
            /*
            * Two sequential packets -- assume that the other side
            * restarted without telling us so just re-sync
            * (i.e., pretend this was the first packet).
            */
            init_seq(s, seq);
        }
        else {
            s->bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
            return 0;
        }
    } else {
        /* duplicate or reordered packet */
    }
    s->received++;
    return 1;
}

The validity check can be made stronger requiring more than two
packets in sequence.  The disadvantages are that a larger number of
initial packets will be discarded (or delayed in a queue) and that
high packet loss rates could prevent validation.  However, because
the RTCP header validation is relatively strong, if an RTCP packet is
received from a source before the data packets, the count could be
adjusted so that only two packets are required in sequence.  If
initial data loss for a few seconds can be tolerated, an application
MAY choose to discard all data packets from a source until a valid
RTCP packet has been received from that source.


Depending on the application and encoding, algorithms may exploit
additional knowledge about the payload format for further validation.
For payload types where the timestamp increment is the same for all
packets, the timestamp values can be predicted from the previous
packet received from the same source using the sequence number
difference (assuming no change in payload type).

A strong "fast-path" check is possible since with high probability
the first four octets in the header of a newly received RTP data
packet will be just the same as that of the previous packet from the
same SSRC except that the sequence number will have increased by one.
Similarly, a single-entry cache may be used for faster SSRC lookups
in applications where data is typically received from one source at a
time.

