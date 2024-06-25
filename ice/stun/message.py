import os

from typing import Any, Type

from .message_type import MessageType
from .attr import Attribute
from .attr import Fingerprint, MessageIntegrity, T
from .utils import (
    COOKIE_UINT32_BYTES,
    MESSAGE_HEADER_LENGTH,
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

    def encode(self, pwd: bytes | None = None) -> memoryview:
        buf = bytearray(MESSAGE_HEADER_LENGTH)
        buf[0:2] = self.message_type.to_uint16_bytes()
        buf[4:8] = COOKIE_UINT32_BYTES
        buf[8:MESSAGE_HEADER_LENGTH] = self.transaction_id

        for attr in self.attributes:
            attr.write_to_buf(buf)

        if pwd:
            integrity = MessageIntegrity(message_integrity(buf, pwd))
            integrity.write_to_buf(buf)

        fingerprint = Fingerprint(message_fingerprint(buf))
        fingerprint.write_to_buf(buf)

        length = len(buf) - MESSAGE_HEADER_LENGTH
        mutate_body_length(buf, length)

        return memoryview(buf)

    def _new_transaction_id(self) -> bytes:
        return os.urandom(_TRANSACTION_ID_SIZE)

    def add_attribute(self, _attr: Attribute[Any]):
        self.attributes.append(_attr)

    def get_attribute(self, attr_type: Type[T]) -> T | None:
        for attr in self.attributes:
            if isinstance(attr, attr_type):
                return attr
