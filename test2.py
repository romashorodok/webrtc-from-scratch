from typing import Any
import os
import binascii
import hmac

from ice import stun

COOKIE = 0x2112A442
COOKIE_UINT32_BYTES = COOKIE.to_bytes(4, "big")

FINGERPRINT_LENGTH = 8  # Type 2 byte + Header 2 byte + Value 4 byte
FINGERPRINT_XOR = 0x5354554E

HEADER_LENGTH = 20
INTEGRITY_LENGTH = 24
IPV4_PROTOCOL = 1
IPV6_PROTOCOL = 2
TRANSACTION_ID_SIZE = 12


def set_body_length(data: bytes, length: int) -> bytes:
    return data[0:2] + length.to_bytes(2, "big") + data[4:]


def message_fingerprint(data: bytes) -> int:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + FINGERPRINT_LENGTH)
    return binascii.crc32(check_data) ^ FINGERPRINT_XOR


def message_integrity(data: bytes, key: bytes) -> bytes:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + INTEGRITY_LENGTH)
    return hmac.new(key, check_data, "sha1").digest()


def set_length(data: bytearray, length: int):
    length_bytes = length.to_bytes(2, "big")
    data[2:4] = length_bytes


ATTRIBUTE_HEADER_SIZE = 4
ATTRIBUTE_PADDING = 4


class Message:
    def __init__(
        self, message_type: stun.MessageType, transaction_id: bytes | None = None
    ):
        self.message_type = message_type
        self.transaction_id = transaction_id or self._new_transaction_id()
        self.attributes = list[stun.Attribute[Any]]()

    def __repr__(self):
        return (
            f"Message(message_method=Method.{self.message_type.method.name}, "
            f"message_class=Class.{self.message_type.message_class.name}, "
            f"transaction_id={self.transaction_id.hex()}, "
            f"attributes={self.attributes})"
        )

    def _new_transaction_id(self) -> bytes:
        return os.urandom(TRANSACTION_ID_SIZE)

    def add_attribute(self, attr: stun.Attribute[Any]):
        self.attributes.append(attr)

    def encode(self, pwd: bytes | None = None) -> bytes:
        buf = bytearray(HEADER_LENGTH)
        buf[0:2] = self.message_type.to_uint16_bytes()
        buf[4:8] = COOKIE_UINT32_BYTES
        buf[8:HEADER_LENGTH] = self.transaction_id

        for attr in self.attributes:
            attr_data = attr.marshal()
            attr_alloc_len = ATTRIBUTE_HEADER_SIZE + len(attr_data) - 1
            attr_buf = bytearray(attr_alloc_len)

            attr_buf[0:2] = attr.type_to_uint16_bytes()
            attr_len = len(attr_data)

            set_length(attr_buf, attr_len)
            attr_buf[4:attr_len] = attr_data

            buf += attr_buf

        if pwd:
            integrity = stun.MessageIntegrity(message_integrity(buf, pwd))
            integrity_data = integrity.marshal()
            integrity_len = len(integrity_data)

            buf += (
                integrity.type_to_uint16_bytes()
                + integrity_len.to_bytes(2, "big")
                + integrity_data
            )

        fingerprint = stun.Fingerprint(message_fingerprint(buf))
        fingerprint_data = fingerprint.marshal()
        fingerprint_len = len(fingerprint_data)

        buf += (
            fingerprint.TYPE.to_bytes(2, "big")
            + fingerprint_len.to_bytes(2, "big")
            + fingerprint_data
        )

        length = len(buf) - HEADER_LENGTH
        set_length(buf, length)

        return bytes(buf)

    @staticmethod
    def parse(data: bytes, pwd: bytes | None = None) -> "Message":
        if len(data) < HEADER_LENGTH:
            raise ValueError("Data is too short to be a valid STUN message")

        message_type = int.from_bytes(data[0:2], "big")
        message_length = int.from_bytes(data[2:4], "big")
        cookie = int.from_bytes(data[4:8], "big")
        transaction_id = data[8:20]

        print("Length", message_length)

        if cookie != COOKIE:
            raise ValueError("Invalid magic cookie")

        message = Message(stun.MessageType.from_int(message_type), transaction_id)

        offset = HEADER_LENGTH
        end_offset = HEADER_LENGTH + message_length

        while offset < end_offset:
            if offset + ATTRIBUTE_HEADER_SIZE > len(data):
                raise ValueError(
                    "Invalid STUN message: attribute length exceeds data length"
                )

            attr_type = int.from_bytes(data[offset : offset + 2], "big")
            attr_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            attr_value = data[offset + 4 : offset + 4 + attr_length]

            if attr_type not in stun.ATTRIBUTE_REGISTRY:
                print(
                    f"STUN type not in registry: attr_type={attr_type}, attr_length={attr_length}, attr_decode_len={len(list(list(attr_value)))}, attr_value={list(attr_value)}"
                )
                # NOTE: if type is unknown agent must reject it
                offset += ATTRIBUTE_HEADER_SIZE + attr_length
                offset += (4 - (offset % 4)) % 4
                continue

            attr_cls = stun.get_attribute_from_registry(attr_type)
            attr = attr_cls.unmarshal(data=attr_value, transaction_id=transaction_id)

            if isinstance(attr, stun.MessageIntegrity):
                if not pwd:
                    raise ValueError("STUN message contain integrity provide key")

                expected_integrity = attr.value
                received_integrity = message_integrity(data[:offset], key=pwd)
                if expected_integrity != received_integrity:
                    raise ValueError("STUN message integrity mismatch")
            elif isinstance(attr, stun.Fingerprint):
                expected_fingerprint = attr.value
                received_fingerprint = message_fingerprint(data[:offset])
                if expected_fingerprint != received_fingerprint:
                    raise ValueError("STUN message fingerprint mismatch")
            else:
                message.add_attribute(attr)

            # Update offset, ensuring 32-bit alignment
            offset += ATTRIBUTE_HEADER_SIZE + attr_length
            # Add padding to ensure 32-bit alignment
            offset += (4 - (offset % 4)) % 4

        return message


def is_stun(b: bytes) -> bool:
    if len(b) < HEADER_LENGTH:
        return False
    extracted_value = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
    return extracted_value == COOKIE


msg = Message(stun.MessageType(stun.Method.Binding, stun.MessageClass.Request))
msg.add_attribute(stun.Username("username", "password"))

encoded_message = msg.encode(b"test")

data = encoded_message
print(list(data))
print(msg)

resp = Message.parse(data, b"test")

print(resp)

# msg = stun.MessageType(stun.Method.Binding, stun.MessageClass.Request)
# print(list(msg.to_uint16_bytes()))
