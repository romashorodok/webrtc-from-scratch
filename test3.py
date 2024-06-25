import ipaddress
from typing import Tuple, Union
import os

COOKIE = 0x2112A442  # Example value, replace with the actual COOKIE value
IPV4_PROTOCOL = 0x01
IPV6_PROTOCOL = 0x02
PADDING = 4


def nearest_padded_value_length(length: int) -> int:
    padding_needed = (PADDING - (length % PADDING)) % PADDING
    return padding_needed


def xor_address(data: bytes, transaction_id: bytes) -> bytes:
    xpad = (
        (COOKIE >> 16).to_bytes(2, "big") + COOKIE.to_bytes(4, "big") + transaction_id
    )
    xdata = data[:2]  # Copy the first 2 bytes without change
    for i in range(2, len(data)):
        xdata += (data[i] ^ xpad[i - 2]).to_bytes(1, "big")
    return xdata


def pack_address(value: Tuple[str, int]) -> bytes:
    ip_address = ipaddress.ip_address(value[0])
    if isinstance(ip_address, ipaddress.IPv4Address):
        protocol = IPV4_PROTOCOL
    else:
        protocol = IPV6_PROTOCOL
    return (
        b"\x00"
        + protocol.to_bytes(1, "big")
        + value[1].to_bytes(2, "big")
        + ip_address.packed
    )


def pack_xor_address(value: Tuple[str, int], transaction_id: bytes) -> bytes:
    return xor_address(pack_address(value), transaction_id)


def unpack_address(data: bytes) -> Tuple[str, int]:
    if len(data) < 4:
        raise ValueError("STUN address length is less than 4 bytes")
    protocol = data[1]
    port = int.from_bytes(data[2:4], "big")
    address = data[4:]
    if protocol == IPV4_PROTOCOL:
        if len(address) != 4:
            raise ValueError("STUN address has invalid length for IPv4")
        return (str(ipaddress.IPv4Address(address)), port)
    elif protocol == IPV6_PROTOCOL:
        if len(address) != 16:
            raise ValueError("STUN address has invalid length for IPv6")
        return (str(ipaddress.IPv6Address(address)), port)
    else:
        raise ValueError("STUN address has unknown protocol")


def unpack_xor_address(data: bytes, transaction_id: bytes) -> Tuple[str, int]:
    return unpack_address(xor_address(data, transaction_id))


# 192.168.0.102
# address = ("127.0.0.1", 9999)
# address = ("192.168.0.101", 63166)
address = ("192.168.0.101", 9999)

t = pack_address(address)
print(list(t))

test = unpack_address(t)
print(test)


def new_session_id():
    # Generate a 64-bit random number
    id = int.from_bytes(os.urandom(8), "big")
    # Set the highest bit to zero
    id &= ~(1 << 63)
    return id


# Example usage
session_id = new_session_id()
print(f"Generated session ID: {session_id}")

# transaction = b"c29af266c7567699951beeb9"
#
# xor_addr = pack_xor_address(address, transaction)
# print(list(xor_addr))
#
# address = unpack_xor_address(xor_addr, transaction)
#
# print(address)
