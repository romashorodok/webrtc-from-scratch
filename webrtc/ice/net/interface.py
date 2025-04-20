import socket
import psutil
import sys

from enum import Enum


class Address:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class Interface:
    def __init__(self, name: str, mtu: int, address: str, family: socket.AddressFamily):
        self.address = address

        self.family = family
        self.name = name
        self.mtu = mtu

    @property
    def address(self) -> Address:
        return self._address

    @address.setter
    def address(self, value: str):
        self._address = Address(value)


class InterfaceProvider(Enum):
    UNKNOWN = 0
    PSUTIL = 1


def interface_factory(
    provider: InterfaceProvider,
    families: list[socket.AddressFamily],
    loopback: bool = False,
) -> list[Interface]:
    match provider:
        case InterfaceProvider.PSUTIL:
            ifaces: list[Interface] = []

            stats = psutil.net_if_stats()

            for nic, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in families:
                        if addr.address.startswith("127.") and not loopback:
                            continue

                        st = stats[nic]
                        ifaces.append(
                            Interface(
                                name=nic,
                                mtu=st.mtu,
                                address=addr.address,
                                family=addr.family,
                            )
                        )
            return ifaces
        case _:
            print(f"not found interface provider: {provider}")
            sys.exit(1)
