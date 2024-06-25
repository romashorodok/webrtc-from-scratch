import ipaddress
import binascii
import hmac
from typing import Tuple


MESSAGE_HEADER_LENGTH = 20
ATTRIBUTE_HEADER_SIZE = 4

COOKIE = 0x2112A442
COOKIE_UINT32_BYTES = COOKIE.to_bytes(4, "big")

IPV4_PROTOCOL = 0x01
IPV6_PROTOCOL = 0x02


def is_stun(b: memoryview) -> bool:
    if len(b) < MESSAGE_HEADER_LENGTH:
        return False
    extracted_value = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
    return extracted_value == COOKIE


# STUN aligns attributes on 32-bit boundaries, attributes whose content
# is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
# padding so that its value contains a multiple of 4 bytes.  The
# padding bits are ignored, and may be any value.
# https://tools.ietf.org/html/rfc5389#section-15
PADDING = 4


def nearest_padded_value_length(length: int) -> int:
    return (PADDING - (length % PADDING)) % PADDING


def assoc_body_length(data: bytes, length: int) -> bytes:
    return data[0:2] + length.to_bytes(2, "big") + data[4:]


def mutate_body_length(data: bytearray, length: int):
    length_bytes = length.to_bytes(2, "big")
    data[2:4] = length_bytes


_FINGERPRINT_LENGTH = 8  # Type 2 byte + Header 2 byte + Value 4 byte
_FINGERPRINT_XOR = 0x5354554E


def message_fingerprint(data: bytes) -> int:
    check_data = assoc_body_length(
        data, len(data) - MESSAGE_HEADER_LENGTH + _FINGERPRINT_LENGTH
    )
    return binascii.crc32(check_data) ^ _FINGERPRINT_XOR


_INTEGRITY_LENGTH = 24


def message_integrity(data: bytes, key: bytes) -> bytes:
    check_data = assoc_body_length(
        data, len(data) - MESSAGE_HEADER_LENGTH + _INTEGRITY_LENGTH
    )
    return hmac.new(key, check_data, "sha1").digest()


def pack_bytes(value: bytes) -> bytes:
    return value


def pack_error_code(value: Tuple[int, str]) -> bytes:
    return (
        b"\x00"
        + (value[0] // 100).to_bytes(1, "big")
        + (value[0] % 100).to_bytes(1, "big")
        + value[1].encode("utf8")
    )


def pack_none() -> bytes:
    return b""


def pack_string(value: str) -> bytes:
    return value.encode("utf8")


def pack_unsigned(value: int) -> bytes:
    return value.to_bytes(4, "big")


def pack_unsigned_short(value: int) -> bytes:
    return value.to_bytes(2, "big") + b"\x00\x00"


def pack_unsigned_64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def xor_address(data: bytes, transaction_id: bytes) -> bytes:
    xpad = (
        (COOKIE >> 16).to_bytes(2, "big") + COOKIE.to_bytes(4, "big") + transaction_id
    )
    xdata = data[:2]  # Copy the first 2 bytes without change
    for i in range(2, len(data)):
        xdata += (data[i] ^ xpad[i - 2]).to_bytes(1, "big")
    return xdata


def pack_address(value: tuple[str, int]) -> bytes:
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


def pack_xor_address(value: tuple[str, int], transaction_id: bytes) -> bytes:
    return xor_address(pack_address(value), transaction_id)


def unpack_address(data: bytes) -> tuple[str, int]:
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


def unpack_xor_address(data: bytes, transaction_id: bytes) -> tuple[str, int]:
    return unpack_address(xor_address(data, transaction_id))


###


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
