import asyncio
import binascii
import enum
import hmac
import ipaddress
from collections import OrderedDict
from struct import pack, unpack
from types import MethodType
from typing import Callable, Dict, List, Optional, Tuple
from binascii import unhexlify
import hashlib

import os

COOKIE = 0x2112A442
FINGERPRINT_LENGTH = 8
FINGERPRINT_XOR = 0x5354554E
HEADER_LENGTH = 20
INTEGRITY_LENGTH = 24
IPV4_PROTOCOL = 1
IPV6_PROTOCOL = 2
TRANSACTION_ID_SIZE = 12

RETRY_MAX = 6
RETRY_RTO = 0.5


def random_transaction_id() -> bytes:
    return os.urandom(12)


def set_body_length(data: bytes, length: int) -> bytes:
    return data[0:2] + pack("!H", length) + data[4:]


def message_fingerprint(data: bytes) -> int:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + FINGERPRINT_LENGTH)
    return binascii.crc32(check_data) ^ FINGERPRINT_XOR


def message_integrity(data: bytes, key: bytes) -> bytes:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + INTEGRITY_LENGTH)
    return hmac.new(key, check_data, "sha1").digest()


def xor_address(data: bytes, transaction_id: bytes) -> bytes:
    xpad = pack("!HI", COOKIE >> 16, COOKIE) + transaction_id
    xdata = data[0:2]
    for i in range(2, len(data)):
        xdata += int.to_bytes(data[i] ^ xpad[i - 2], 1, "big", signed=False)
    return xdata


def pack_address(value: Tuple[str, int]) -> bytes:
    ip_address = ipaddress.ip_address(value[0])
    if isinstance(ip_address, ipaddress.IPv4Address):
        protocol = IPV4_PROTOCOL
    else:
        protocol = IPV6_PROTOCOL
    return pack("!BBH", 0, protocol, value[1]) + ip_address.packed


def pack_bytes(value: bytes) -> bytes:
    return value


def pack_error_code(value: Tuple[int, str]) -> bytes:
    return pack("!HBB", 0, value[0] // 100, value[0] % 100) + value[1].encode("utf8")


def pack_none(value: None) -> bytes:
    return b""


def pack_string(value: str) -> bytes:
    return value.encode("utf8")


def pack_unsigned(value: int) -> bytes:
    return pack("!I", value)


def pack_unsigned_short(value: int) -> bytes:
    return pack("!H", value) + b"\x00\x00"


def pack_unsigned_64(value: int) -> bytes:
    return pack("!Q", value)


def pack_xor_address(value: Tuple[str, int], transaction_id: bytes) -> bytes:
    return xor_address(pack_address(value), transaction_id)


def unpack_address(data: bytes) -> Tuple[str, int]:
    if len(data) < 4:
        raise ValueError("STUN address length is less than 4 bytes")
    reserved, protocol, port = unpack("!BBH", data[0:4])
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
    reserved, code_high, code_low = unpack("!HBB", data[0:4])
    reason = data[4:].decode("utf8")
    return (code_high * 100 + code_low, reason)


def unpack_none(data: bytes) -> None:
    return None


def unpack_string(data: bytes) -> str:
    return data.decode("utf8")


def unpack_unsigned(data: bytes) -> int:
    return unpack("!I", data)[0]


def unpack_unsigned_short(data: bytes) -> int:
    return unpack("!H", data[0:2])[0]


def unpack_unsigned_64(data: bytes) -> int:
    return unpack("!Q", data)[0]


AttributeEntry = Tuple[int, str, Callable, Callable]

# https://datatracker.ietf.org/doc/html/rfc5389#section-18.2
ATTRIBUTES: List[AttributeEntry] = [
    (0x0001, "MAPPED-ADDRESS", pack_address, unpack_address),
    (0x0003, "CHANGE-REQUEST", pack_unsigned, unpack_unsigned),
    (0x0004, "SOURCE-ADDRESS", pack_address, unpack_address),
    (0x0005, "CHANGED-ADDRESS", pack_address, unpack_address),
    (0x0006, "USERNAME", pack_string, unpack_string),
    (0x0008, "MESSAGE-INTEGRITY", pack_bytes, unpack_bytes),
    (0x0009, "ERROR-CODE", pack_error_code, unpack_error_code),
    (0x000C, "CHANNEL-NUMBER", pack_unsigned_short, unpack_unsigned_short),
    (0x000D, "LIFETIME", pack_unsigned, unpack_unsigned),
    (0x0012, "XOR-PEER-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0014, "REALM", pack_string, unpack_string),
    (0x0015, "NONCE", pack_bytes, unpack_bytes),
    (0x0016, "XOR-RELAYED-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0019, "REQUESTED-TRANSPORT", pack_unsigned, unpack_unsigned),
    (0x0020, "XOR-MAPPED-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0024, "PRIORITY", pack_unsigned, unpack_unsigned),
    (0x0025, "USE-CANDIDATE", pack_none, unpack_none),
    (0x8022, "SOFTWARE", pack_string, unpack_string),
    (0x8028, "FINGERPRINT", pack_unsigned, unpack_unsigned),
    (0x8029, "ICE-CONTROLLED", pack_unsigned_64, unpack_unsigned_64),
    (0x802A, "ICE-CONTROLLING", pack_unsigned_64, unpack_unsigned_64),
    (0x802B, "RESPONSE-ORIGIN", pack_address, unpack_address),
    (0x802C, "OTHER-ADDRESS", pack_address, unpack_address),
]

ATTRIBUTES_BY_TYPE: Dict[int, AttributeEntry] = {}
ATTRIBUTES_BY_NAME: Dict[str, AttributeEntry] = {}
for attr in ATTRIBUTES:
    ATTRIBUTES_BY_TYPE[attr[0]] = attr
    ATTRIBUTES_BY_NAME[attr[1]] = attr


class Class(enum.IntEnum):
    REQUEST = 0x000
    INDICATION = 0x010
    RESPONSE = 0x100
    ERROR = 0x110


class Method(enum.IntEnum):
    BINDING = 0x1
    SHARED_SECRET = 0x2
    ALLOCATE = 0x3
    REFRESH = 0x4
    SEND = 0x6
    DATA = 0x7
    CREATE_PERMISSION = 0x8
    CHANNEL_BIND = 0x9


class MessageType:
    BINDING_REQUEST = (Method.BINDING, Class.REQUEST)
    BINDING_RESPONSE = (Method.BINDING, Class.RESPONSE)


class Message:
    def __init__(
        self, msg_type: Tuple[Method, Class], transaction_id: Optional[bytes] = None
    ):
        self.message_method, self.message_class = msg_type
        self.type = self._compute_message_type(self.message_method, self.message_class)
        self.length = 0
        self.transaction_id = transaction_id or self._new_transaction_id()
        self.attributes = OrderedDict()
        self.raw = bytearray(HEADER_LENGTH)

    def __repr__(self):
        return (
            f"Message(message_method=Method.{self.message_method.name}, "
            f"message_class=Class.{self.message_class.name}, "
            f"transaction_id={self.transaction_id.hex()}, "
            f"attributes={self.attributes})"
        )

    def _new_transaction_id(self) -> bytes:
        return os.urandom(TRANSACTION_ID_SIZE)

    @staticmethod
    def _compute_message_type(message_method: Method, message_class: Class) -> int:
        return (
            (message_method.value & 0xF80) << 2
            | (message_class.value & 0x03) << 4
            | (message_method.value & 0xF)
        )

    def encode(self):
        self.raw = self.raw[:HEADER_LENGTH]
        self.raw[0:2] = pack("!H", self.type)
        self.raw[2:4] = pack("!H", self.length)
        self.raw[4:8] = pack("!I", COOKIE)
        self.raw[8:20] = self.transaction_id
        for attr_type, attr_value in self.attributes.items():
            encoded_attr = self._encode_attribute(attr_type, attr_value)
            self.raw.extend(encoded_attr)
        self._write_length()

    def _write_length(self):
        self.length = len(self.raw) - HEADER_LENGTH
        self.raw[2:4] = pack("!H", self.length)

    def _encode_attribute(self, attr_type: int, attr_value: bytes) -> bytes:
        attr_len = len(attr_value)
        pad_len = (4 - attr_len % 4) % 4
        padding = b"\x00" * pad_len
        return pack("!HH", attr_type, attr_len) + attr_value + padding

    def add_attribute(self, attr_type: int, attr_value: bytes):
        self.attributes[attr_type] = attr_value

    def add_message_integrity(self, key: bytes):
        self.encode()
        self.raw.extend(pack("!HH", 0x0008, 20))  # MESSAGE-INTEGRITY attribute header
        integrity = hmac.new(key, self.raw, "sha1").digest()
        self.raw.extend(integrity)

    def add_fingerprint(self):
        self.encode()
        fingerprint = binascii.crc32(self.raw) ^ FINGERPRINT_XOR
        self.raw.extend(pack("!HHI", 0x8028, 4, fingerprint))


def parse_message(data: bytes, integrity_key: Optional[bytes] = None) -> Message:
    if len(data) < HEADER_LENGTH:
        raise ValueError("STUN message length is less than 20 bytes")

    message_type, length, cookie, transaction_id = unpack(
        "!HHI12s", data[:HEADER_LENGTH]
    )
    print(cookie == COOKIE)
    if cookie != COOKIE:
        raise ValueError("Invalid STUN magic cookie")

    message_method = Method((message_type >> 2) & 0xF80 | (message_type & 0xF))
    message_class = Class((message_type >> 4) & 0x03)
    message = Message((message_method, message_class), transaction_id)

    pos = HEADER_LENGTH
    while pos < len(data):
        attr_type, attr_len = unpack("!HH", data[pos : pos + 4])
        attr_value = data[pos + 4 : pos + 4 + attr_len]
        message.add_attribute(attr_type, attr_value)
        pos += 4 + attr_len
        pos += (4 - attr_len % 4) % 4  # Skip padding

    if integrity_key:
        calculated_integrity = hmac.new(
            integrity_key, data[: len(data) - 24], "sha1"
        ).digest()
        received_integrity = message.attributes.pop(0x0008, None)
        if received_integrity != calculated_integrity:
            raise ValueError("STUN message integrity does not match")

    fingerprint_attr = message.attributes.get(0x8028)
    if fingerprint_attr:
        (received_fingerprint,) = unpack("!I", fingerprint_attr)
        calculated_fingerprint = binascii.crc32(data[: len(data) - 8]) ^ FINGERPRINT_XOR
        if received_fingerprint != calculated_fingerprint:
            raise ValueError("STUN message fingerprint does not match")

    return message


def padding_length(length: int) -> int:
    """
    STUN message attributes are padded to a 4-byte boundary.
    """
    rest = length % 4
    if rest == 0:
        return 0
    else:
        return 4 - rest


# Correctly structured STUN message with a single attribute


def read_message(name):
    path = os.path.join(os.path.dirname(__file__), "data", name)
    with open(path, "rb") as fp:
        return fp.read()


def verify_message_integrity(data: bytes, key: bytes) -> bool:
    if len(data) < HEADER_LENGTH:
        raise ValueError("STUN message length is less than 20 bytes")

    # Extract message type, length, cookie, and transaction ID
    message_type, length, cookie, transaction_id = unpack(
        "!HHI12s", data[:HEADER_LENGTH]
    )
    print(f"Cookie in message: {cookie}, Expected cookie: {COOKIE}")
    if cookie != COOKIE:
        raise ValueError("Invalid STUN magic cookie")

    pos = HEADER_LENGTH
    integrity_offset = None
    attributes = OrderedDict()

    while pos < len(data):
        attr_type, attr_len = unpack("!HH", data[pos : pos + 4])
        attr_value = data[pos + 4 : pos + 4 + attr_len]
        attributes[attr_type] = attr_value
        if attr_type == 0x0008:  # MESSAGE-INTEGRITY
            integrity_offset = pos
        pos += 4 + attr_len
        pos += (4 - attr_len % 4) % 4  # Skip padding

    if integrity_offset is None:
        raise ValueError("MESSAGE-INTEGRITY attribute not found")

    # Calculate the HMAC-SHA1 over the data up to the MESSAGE-INTEGRITY attribute
    integrity_data = data[:integrity_offset]
    integrity_data += pack(
        "!HH", 0x0008, 20
    )  # MESSAGE-INTEGRITY attribute header with length

    calculated_integrity = hmac.new(key, integrity_data, hashlib.sha1).digest()

    # Extract the integrity value from the attribute
    received_integrity = attributes[0x0008]

    print(
        f"Received integrity: {received_integrity}, Calculated integrity: {calculated_integrity}"
    )

    return received_integrity == calculated_integrity


try:
    # data = read_message("binding_request_ice_controlling.bin")
    # data = read_message("binding_response.bin")
    # print(data)
    #
    # message = parse_message(data)
    # message.encode()
    #
    # messageSecond = parse_message(data)
    # messageSecond.add_message_integrity(b"second")
    # messageSecond.add_fingerprint()
    # raw = messageSecond.raw
    # messageSecond.encode()
    #
    # raw = messageSecond.raw
    # print(raw)
    # print(bytearray(data))

    request = Message(msg_type=MessageType.BINDING_RESPONSE)
    request.add_message_integrity(b"test")
    # request.add_fingerprint()

    request_msg = parse_message(request.raw)
    request_msg.encode()

    res = verify_message_integrity(request_msg.raw, b"test")
    print(res)

    # for attr_type, raw_value in request_msg.attributes.items():
    #     attr_entry = ATTRIBUTES_BY_TYPE.get(attr_type)
    #     if attr_entry:
    #         attr_name = attr_entry[1]
    #         unpack_function = attr_entry[3]
    #         unpacked_value = unpack_string(raw_value)
    #         print(f"Attribute: {attr_name}, Unpacked Value: {unpacked_value}")
    #     else:
    #         print(f"Unknown attribute type: {attr_type}, Raw Value: {raw_value}")

except ValueError as e:
    print("Value error:", e)
