import enum


class MessageClass(enum.IntEnum):
    Request = 0x00  # 0b00
    Indication = 0x01  # 0b01
    SuccessResponse = 0x02  # 0b10
    ErrorResponse = 0x03  # 0b11


class Method(enum.IntEnum):
    Binding = 0x001
    Allocate = 0x003
    Refresh = 0x004
    Send = 0x006
    Data = 0x007
    CreatePermission = 0x008
    ChannelBind = 0x009


# Bit Positions
# Method (M):

# Bits 0-3: 0000000000001111 (rightmost 4 bits)
method_a_bits = 0xF  # 0b0000000000001111
# Bits 6-8: 0000000001110000 (3 bits after the first 4 bits)
method_b_bits = 0x70  # 0b0000000001110000
# Bits 9-11: 0000111110000000 (5 bits after the middle 3 bits)
method_d_bits = 0xF80  # 0b0000111110000000

method_b_shift = 1
method_d_shift = 2

# Class (C):
# Bit 4 (C0) and bit 7 (C1) represent the class.

# Bitmask C0 = 0 (request) or 1 (response)
c0_bit = 0x1
# Bitmask C1 = 0 (indication) or 1 (error response)
c1_bit = 0x2

# Bit 4: 0000000000000001 << 4 (shifted left by 4 bits)
# Bit 7: 0000000000000001 << 7 (shifted left by 7 bits)
class_c0_shift = 4
class_c1_shift = 7

# Example 16-bit value from STUN packet
# stun_packet_value = 0b0000000100100011  # Example value
# Extracting the 14-bit STUN Message Type

# Before Shift (x): 0b1100110011001100 (52428 in decimal)
# After Shift (result = x >> 2): 0b0011001100110011 (13107 in decimal)
# Shift operation move fist two bits to the end
# Then by 14 bitmask limit 14 rightmost or least significant: 11001100110011
# After this limit by bitmask of 0x3FFF which is eq to 14 bits
# Bitmask 0x3FFF: 0011 1111 1111 1111 (14 bits set to 1)
# stun_message_type = (stun_packet_value >> 2) & 0x3FFF

class MessageType:
    def __init__(self, method: Method, message_class: MessageClass):
        self.method = method
        self.message_class = message_class

    def to_uint16_bytes(self) -> bytes:
        """
        Create 16 bits of STUN message type. 16 bits = 2 bytes. 1 byte = uint8

        By stun protocol first two most significant bits is always zero. Next 14
        bits is combination of method and class.

        m (Method): Bits 0-3, 6-8, and 9-11 represent the method.
        c (Class):  Bits 4 and 7 represent the class

        References:
        https://github.com/pion/stun/blob/79bd9b6bd0f15d21127bfc207cf57114746c4c69/message.go#L546
        https://datatracker.ietf.org/doc/html/rfc5389#section-6

        Example of 0x119 same as 1001(Method) 11(MessageClass):

        Response Header: 0x119
        a (right 4 bits): 00000000001001
        b (3 bits after A, before shift): 00000000000000
        d (5 bits after B, before shift): 00000000000000

        b (after shift): 00000000000000
        d (after shift): 00000000000000
        m (after combining a, b, d): 00000000001001

        c0 (after shift): 00000000010000
        c1 (after shift): 00000100000000
        message_class (after combining c0, c1): 00000100010000

        result (final combined value): 00000100011001
        Response header: 1001 11
        """
        #  0                 1
        #  2  3  4 5 6 7 8 9 0 1 2 3 4 5
        # +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
        # |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
        # |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
        # +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
        # Figure 3: Format of STUN Message Type Field

        # method contain 12 bits

        # Read figure from right to left
        # Splitting M into A(M0-M3), B(M4-M6), D(M7-M11).
        m = int(self.method)
        a = m & method_a_bits  # A = M * 0b0000000000001111 (right 4 bits)
        b = m & method_b_bits  # B = M * 0b0000000001110000 (3 bits after A)
        d = m & method_d_bits  # D = M * 0b0000111110000000 (5 bits after B)

        # print(f"a (right 4 bits): {a:014b}")
        # print(f"b (3 bits after A, before shift): {b:014b}")
        # print(f"d (5 bits after B, before shift): {d:014b}")
        # b_shifted = b << method_b_shift
        # d_shifted = d << method_d_shift
        # print(f"b (after shift): {b_shifted:014b}")
        # print(f"d (after shift): {d_shifted:014b}")
        # m = a + b_shifted + d_shifted
        # print(f"m (after combining a, b, d): {m:014b}")

        # Shifting to add "holes" for C0 (at 4 bit) and C1 (8 bit).
        m = a | (b << method_b_shift) | (d << method_d_shift)

        # C0 is zero bit of C, C1 is first bit.
        # C0 = C * 0b01, C1 = (C * 0b10) >> 1
        # Ct = C0 << 4 + C1 << 8.
        # Optimizations: "((C * 0b10) >> 1) << 8" as "(C * 0b10) << 7"
        # We need C0 shifted by 4, and C1 by 8 to fit "11" and "7" positions
        # (see figure 3).
        c = int(self.message_class)
        c0 = (c & c0_bit) << class_c0_shift
        c1 = (c & c1_bit) << class_c1_shift
        message_class = c0 | c1

        # print(f"c0 (after shift): {c0:014b}")
        # print(f"c1 (after shift): {c1:014b}")
        # print(f"message_class (after combining c0, c1): {message_class:014b}")
        # print(f"result (final combined value): {m+message_class:014b}")

        return (m | message_class).to_bytes(2, "big")

    @staticmethod
    def from_int(v: int) -> "MessageType":
        # Decoding class.
        # We are taking first bit from v >> 4 and second from v >> 7.
        c0 = (v >> class_c0_shift) & c0_bit
        c1 = (v >> class_c1_shift) & c1_bit
        message_class = c0 | c1

        # Decoding method.
        a = v & method_a_bits
        b = (v >> method_b_shift) & method_b_bits
        d = (v >> method_d_shift) & method_d_bits
        method = a | b | d

        return MessageType(Method(method), MessageClass(message_class))

    def __str__(self):
        return f"{self.method:b} {self.message_class:b}"
