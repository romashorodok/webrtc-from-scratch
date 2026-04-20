# 4. Byte Order, Alignment, and Time Format

All integer fields are carried in network byte order, that is, most
significant byte (octet) first.  This byte order is commonly known as
big-endian.  The transmission order is described in detail in [3].
Unless otherwise noted, numeric constants are in decimal (base 10).

All header data is aligned to its natural length, i.e., 16-bit fields
are aligned on even offsets, 32-bit fields are aligned at offsets
divisible by four, etc.  Octets designated as padding have the value
zero.

Wallclock time (absolute date and time) is represented using the
timestamp format of the Network Time Protocol (NTP), which is in
seconds relative to 0h UTC on 1 January 1900 [4].  The full
resolution NTP timestamp is a 64-bit unsigned fixed-point number with
the integer part in the first 32 bits and the fractional part in the
last 32 bits.  In some fields where a more compact representation is
appropriate, only the middle 32 bits are used; that is, the low 16
bits of the integer part and the high 16 bits of the fractional part.
The high 16 bits of the integer part must be determined
independently.

An implementation is not required to run the Network Time Protocol in
order to use RTP.  Other time sources, or none at all, may be used
(see the description of the NTP timestamp field in Section 6.4.1).
However, running NTP may be useful for synchronizing streams
transmitted from separate hosts.

The NTP timestamp will wrap around to zero some time in the year
2036, but for RTP purposes, only differences between pairs of NTP
timestamps are used.  So long as the pairs of timestamps can be
assumed to be within 68 years of each other, using modular arithmetic
for subtractions and comparisons makes the wraparound irrelevant.

