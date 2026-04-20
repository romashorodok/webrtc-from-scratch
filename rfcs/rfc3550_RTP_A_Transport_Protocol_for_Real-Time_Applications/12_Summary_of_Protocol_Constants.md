# 12. Summary of Protocol Constants

This section contains a summary listing of the constants defined in
this specification.

The RTP payload type (PT) constants are defined in profiles rather
than this document.  However, the octet of the RTP header which
contains the marker bit(s) and payload type MUST avoid the reserved
values 200 and 201 (decimal) to distinguish RTP packets from the RTCP
SR and RR packet types for the header validation procedure described

in Appendix A.1.  For the standard definition of one marker bit and a
7-bit payload type field as shown in this specification, this
restriction means that payload types 72 and 73 are reserved.

## 12.1 RTCP Packet Types

abbrev.  name                 value
SR       sender report          200
RR       receiver report        201
SDES     source description     202
BYE      goodbye                203
APP      application-defined    204

These type values were chosen in the range 200-204 for improved
header validity checking of RTCP packets compared to RTP packets or
other unrelated packets.  When the RTCP packet type field is compared
to the corresponding octet of the RTP header, this range corresponds
to the marker bit being 1 (which it usually is not in data packets)
and to the high bit of the standard payload type field being 1 (since
the static payload types are typically defined in the low half).
This range was also chosen to be some distance numerically from 0 and
255 since all-zeros and all-ones are common data patterns.

Since all compound RTCP packets MUST begin with SR or RR, these codes
were chosen as an even/odd pair to allow the RTCP validity check to
test the maximum number of bits with mask and value.

Additional RTCP packet types may be registered through IANA (see
Section 15).

## 12.2 SDES Types

abbrev.  name                            value
END      end of SDES list                    0
CNAME    canonical name                      1
NAME     user name                           2
EMAIL    user's electronic mail address      3
PHONE    user's phone number                 4
LOC      geographic user location            5
TOOL     name of application or tool         6
NOTE     notice about the source             7
PRIV     private extensions                  8

Additional SDES types may be registered through IANA (see Section
15).