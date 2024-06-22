import os

from typing import Any

from .attr import Fingerprint, MessageIntegrity

from .message_type import MessageType
from .attr import Attribute, ATTRIBUTE_REGISTRY, get_attribute_from_registry
from .utils import (
    COOKIE,
    COOKIE_UINT32_BYTES,
    MESSAGE_HEADER_LENGTH,
    ATTRIBUTE_HEADER_SIZE,
    message_integrity,
    message_fingerprint,
    mutate_body_length,
)

_TRANSACTION_ID_SIZE = 12


class Message:
    def __init__(self, message_type: MessageType, transaction_id: bytes | None = None):
        self.message_type = message_type
        self.transaction_id = transaction_id or self._new_transaction_id()
        self.attributes = list[Attribute[Any]]()

    def __repr__(self):
        return (
            f"Message(message_method=Method.{self.message_type.method.name}, "
            f"message_class=Class.{self.message_type.message_class.name}, "
            f"transaction_id={self.transaction_id.hex()}, "
            f"attributes={self.attributes})"
        )

    def _new_transaction_id(self) -> bytes:
        return os.urandom(_TRANSACTION_ID_SIZE)

    def add_attribute(self, attr: Attribute[Any]):
        self.attributes.append(attr)

    def encode(self, pwd: bytes | None = None) -> bytes:
        buf = bytearray(MESSAGE_HEADER_LENGTH)
        buf[0:2] = self.message_type.to_uint16_bytes()
        buf[4:8] = COOKIE_UINT32_BYTES
        buf[8:MESSAGE_HEADER_LENGTH] = self.transaction_id

        for attr in self.attributes:
            buf += attr.write_to_buf()

        if pwd:
            integrity = MessageIntegrity(message_integrity(buf, pwd))
            integrity.write_to_buf(buf)

        fingerprint = Fingerprint(message_fingerprint(buf))
        fingerprint.write_to_buf(buf)

        length = len(buf) - MESSAGE_HEADER_LENGTH
        mutate_body_length(buf, length)

        return bytes(buf)

    @staticmethod
    def parse(data: bytes, pwd: bytes | None = None) -> "Message":
        if len(data) < MESSAGE_HEADER_LENGTH:
            raise ValueError("Data is too short to be a valid STUN message")

        message_type = int.from_bytes(data[0:2], "big")
        message_length = int.from_bytes(data[2:4], "big")
        cookie = int.from_bytes(data[4:8], "big")
        transaction_id = data[8:20]

        if cookie != COOKIE:
            raise ValueError("Invalid magic cookie")

        message = Message(MessageType.from_int(message_type), transaction_id)

        offset = MESSAGE_HEADER_LENGTH
        end_offset = MESSAGE_HEADER_LENGTH + message_length

        while offset < end_offset:
            if offset + ATTRIBUTE_HEADER_SIZE > len(data):
                raise ValueError(
                    "Invalid STUN message: attribute length exceeds data length"
                )

            attr_type = int.from_bytes(data[offset : offset + 2], "big")
            attr_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            attr_value = data[offset + 4 : offset + 4 + attr_length]

            if attr_type not in ATTRIBUTE_REGISTRY:
                print(
                    f"STUN type not in registry: attr_type={attr_type}, attr_length={attr_length}, attr_decode_len={len(list(list(attr_value)))}, attr_value={list(attr_value)}"
                )
                # NOTE: if type is unknown agent must reject it
                offset += ATTRIBUTE_HEADER_SIZE + attr_length
                offset += (4 - (offset % 4)) % 4
                continue

            attr_cls = get_attribute_from_registry(attr_type)
            attr = attr_cls.unmarshal(data=attr_value, transaction_id=transaction_id)

            if isinstance(attr, MessageIntegrity):
                if not pwd:
                    raise ValueError("STUN message contain integrity provide key")

                expected_integrity = attr.value
                received_integrity = message_integrity(data[:offset], key=pwd)
                if expected_integrity != received_integrity:
                    raise ValueError("STUN message integrity mismatch")
            elif isinstance(attr, Fingerprint):
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
