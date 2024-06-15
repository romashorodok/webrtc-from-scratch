import ipaddress
from typing import Tuple


COOKIE = 0x2112A442
IPV4_PROTOCOL = 1
IPV6_PROTOCOL = 2


def xor_address(data: bytes, transaction_id: bytes) -> bytes:
    xpad = (
        (COOKIE >> 16).to_bytes(2, "big") + COOKIE.to_bytes(4, "big") + transaction_id
    )
    xdata = data[0:2]
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


def pack_bytes(value: bytes) -> bytes:
    return value


def pack_error_code(value: Tuple[int, str]) -> bytes:
    return (
        b"\x00"
        + (value[0] // 100).to_bytes(1, "big")
        + (value[0] % 100).to_bytes(1, "big")
        + value[1].encode("utf8")
    )


def pack_none(value: None) -> bytes:
    return b""


def pack_string(value: str) -> bytes:
    return value.encode("utf8")


def pack_unsigned(value: int) -> bytes:
    return value.to_bytes(4, "big")


def pack_unsigned_short(value: int) -> bytes:
    return value.to_bytes(2, "big") + b"\x00\x00"


def pack_unsigned_64(value: int) -> bytes:
    return value.to_bytes(8, "big")


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


def unpack_bytes(data: bytes) -> bytes:
    return data


def unpack_error_code(data: bytes) -> Tuple[int, str]:
    if len(data) < 4:
        raise ValueError("STUN error code is less than 4 bytes")
    code_high = data[2]
    code_low = data[3]
    reason = data[4:].decode("utf8")
    return (code_high * 100 + code_low, reason)


def unpack_none(data: bytes) -> None:
    return None


def unpack_string(data: bytes) -> str:
    return data.decode("utf8")


def unpack_unsigned(data: bytes) -> int:
    return int.from_bytes(data[:4], "big")


def unpack_unsigned_short(data: bytes) -> int:
    return int.from_bytes(data[:2], "big")


def unpack_unsigned_64(data: bytes) -> int:
    return int.from_bytes(data[:8], "big")

