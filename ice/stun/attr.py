from abc import ABC, abstractmethod
import hmac
from typing import Any, Dict, Generic, TypeVar, override, Type

from .utils import pack_unsigned, unpack_unsigned
from .utils import pack_bytes, unpack_bytes
from .utils import pack_string, unpack_string

T = TypeVar("T")


class Attribute(Generic[T], ABC):
    TYPE: int = 0
    NAME: str = ""

    @abstractmethod
    def marshal(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def unmarshal(data: bytes, transaction_id: bytes | None = None) -> "Attribute[T]":
        raise NotImplementedError

    @classmethod
    def type_to_uint16_bytes(cls) -> bytes:
        return cls.TYPE.to_bytes(2, "big")


class Fingerprint(Attribute[int]):
    TYPE = 0x8028
    NAME = "FINGERPRINT"

    def __init__(self, value: int) -> None:
        self.value = value

    @override
    def marshal(self) -> bytes:
        return pack_unsigned(self.value)

    @staticmethod
    def unmarshal(data: bytes, transaction_id: bytes | None = None) -> "Fingerprint":
        return Fingerprint(unpack_unsigned(data))

    def __repr__(self) -> str:
        return f"Fingerprint(value={self.value})"


class MessageIntegrity(Attribute[bytes]):
    TYPE = 0x0008
    NAME = "MESSAGE-INTEGRITY"

    def __init__(self, value: bytes) -> None:
        self.value = value

    @override
    def marshal(self) -> bytes:
        return pack_bytes(self.value)

    @staticmethod
    def unmarshal(
        data: bytes, transaction_id: bytes | None = None
    ) -> "MessageIntegrity":
        return MessageIntegrity(unpack_bytes(data))

    def __repr__(self) -> str:
        return f"MessageIntegrity(value={list(self.value)})"


class Username(Attribute[str]):
    TYPE = 0x0006
    NAME = "USERNAME"

    def __init__(self, ufrag: str, pwd: str) -> None:
        self.ufrag = ufrag
        self.pwd = pwd

    @override
    def marshal(self) -> bytes:
        return pack_string(self.ufrag + ":" + self.pwd)

    @staticmethod
    def unmarshal(data: bytes, transaction_id: bytes | None = None) -> "Username":
        ufrag, pwd = unpack_string(data).split(":")
        return Username(ufrag, pwd)

    def __repr__(self) -> str:
        return f"Username(ufrag={self.ufrag}, pwd={self.pwd})"


ATTRIBUTE_REGISTRY: Dict[int, Type[Attribute[Any]]] = {
    Username.TYPE: Username,
    Fingerprint.TYPE: Fingerprint,
    MessageIntegrity.TYPE: MessageIntegrity,
}


def get_attribute_from_registry(type_: int) -> Type[Attribute[Any]]:
    attribute_class = ATTRIBUTE_REGISTRY[type_]
    return attribute_class
