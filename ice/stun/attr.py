from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, TypeVar, override, Type


from .utils import (
    nearest_padded_value_length,
    pack_none,
    pack_unsigned,
    unpack_none,
    unpack_unsigned,
)
from .utils import pack_bytes, unpack_bytes
from .utils import pack_string, unpack_string
from .utils import mutate_body_length
from .utils import pack_unsigned_64, unpack_unsigned_64
from .utils import pack_xor_address, unpack_xor_address

T = TypeVar("T")


class Attribute(Generic[T], ABC):
    TYPE: int = 0
    NAME: str = ""

    @abstractmethod
    def marshal(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "Attribute[T]":
        raise NotImplementedError

    @classmethod
    def type_to_uint16_bytes(cls) -> bytes:
        return cls.TYPE.to_bytes(2, "big")

    @abstractmethod
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        attr_data = self.marshal()
        attr_len = len(attr_data)

        mutate_body_length(attr_buf, attr_len)
        attr_buf.extend(
            self.type_to_uint16_bytes() + attr_len.to_bytes(2, "big") + attr_data
        )

        padding_bytes_to_add = nearest_padded_value_length(attr_len)
        if padding_bytes_to_add > 0:
            attr_buf.extend(b"\x00" * padding_bytes_to_add)
            # print("Add padding", padding_bytes_to_add)

        return attr_buf


class Fingerprint(Attribute[int]):
    TYPE = 0x8028
    NAME = "FINGERPRINT"

    def __init__(self, value: int) -> None:
        self.value = value

    @override
    def marshal(self) -> bytes:
        return pack_unsigned(self.value)

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "Fingerprint":
        return Fingerprint(unpack_unsigned(data))

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

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
        data: bytearray, transaction_id: bytes | None = None
    ) -> "MessageIntegrity":
        return MessageIntegrity(unpack_bytes(data))

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"MessageIntegrity(value={list(self.value)})"


class Username(Attribute[str]):
    TYPE = 0x0006
    NAME = "USERNAME"

    def __init__(self, remote_ufrag: str, local_ufrag: str) -> None:
        self._remote_ufrag = remote_ufrag
        self._local_ufrag = local_ufrag

    @override
    def marshal(self) -> bytes:
        return pack_string(self._remote_ufrag + ":" + self._local_ufrag)

    @staticmethod
    def unmarshal(data: bytearray, transaction_id: bytes | None = None) -> "Username":
        remote_ufrag, local_ufrag = unpack_string(data).split(":")
        return Username(remote_ufrag, local_ufrag)

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"Username(_remote_ufrag={self._remote_ufrag}, _local_ufrag={self._local_ufrag})"


class Priority(Attribute[int]):
    TYPE = 0x0024
    NAME = "PRIORITY"

    def __init__(self, priority: int) -> None:
        self._priority = priority

    @override
    def marshal(self) -> bytes:
        return pack_unsigned(self._priority)

    @staticmethod
    def unmarshal(data: bytearray, transaction_id: bytes | None = None) -> "Priority":
        return Priority(unpack_unsigned(data))

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"Priority(_priority={self._priority})"


class ICEControlling(Attribute[int]):
    TYPE = 0x802A
    NAME = "ICE-CONTROLLING"

    def __init__(self, tie_breaker: int) -> None:
        self._tie_breaker = tie_breaker

    @override
    def marshal(self) -> bytes:
        return pack_unsigned_64(self._tie_breaker)

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "ICEControlling":
        return ICEControlling(unpack_unsigned_64(data))

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"ICEControlling(_tie_breaker={self._tie_breaker})"


class ICEControlled(Attribute[int]):
    TYPE = 0x8029
    NAME = "ICE-CONTROLLED"

    def __init__(self, tie_breaker: int) -> None:
        self._tie_breaker = tie_breaker

    @override
    def marshal(self) -> bytes:
        return pack_unsigned_64(self._tie_breaker)

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "ICEControlled":
        return ICEControlled(unpack_unsigned_64(data))

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"ICEControlled(_tie_breaker={self._tie_breaker})"


class XORMappedAddress(Attribute[str]):
    TYPE = 0x0020
    NAME = "XOR-MAPPED-ADDRESS"

    def __init__(self, transaction_id: bytes, address: tuple[str, int]) -> None:
        self._transaction_id = transaction_id
        self._address = address

    @property
    def address(self) -> tuple[str, int]:
        return self._address

    @override
    def marshal(self) -> bytes:
        return pack_xor_address(self._address, self._transaction_id)

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "XORMappedAddress":
        if transaction_id is None:
            raise ValueError(f"{XORMappedAddress.NAME} must have transaction_id")
        return XORMappedAddress(
            transaction_id, unpack_xor_address(bytes(data), transaction_id)
        )

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return f"XORMappedAddress(_transaction_id={self._transaction_id}, _address={self._address})"


class UseCandidate(Attribute[None]):
    TYPE = 0x0025
    NAME = "USE-CANDIDATE"

    @override
    def marshal(self) -> bytes:
        return pack_none()

    @staticmethod
    def unmarshal(
        data: bytearray, transaction_id: bytes | None = None
    ) -> "UseCandidate":
        return UseCandidate()

    @override
    def write_to_buf(self, attr_buf: bytearray) -> bytearray:
        return super().write_to_buf(attr_buf)

    def __repr__(self) -> str:
        return "UseCandidate()"


ATTRIBUTE_REGISTRY: Dict[int, Type[Attribute[Any]]] = {
    Username.TYPE: Username,
    Priority.TYPE: Priority,
    Fingerprint.TYPE: Fingerprint,
    MessageIntegrity.TYPE: MessageIntegrity,
    ICEControlled.TYPE: ICEControlled,
    ICEControlling.TYPE: ICEControlling,
    XORMappedAddress.TYPE: XORMappedAddress,
    UseCandidate.TYPE: UseCandidate,
}


def get_attribute_from_registry(type_: int) -> Type[Attribute[Any]]:
    attribute_class = ATTRIBUTE_REGISTRY[type_]
    return attribute_class
