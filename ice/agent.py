import asyncio

from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from .net import udp_mux, Interface
from .candidate_base import CandidateBase

# TODO: make selectors for controling and controlled agent type

# Component-- candidate weight to build ice priority


class CandidateType(Enum):
    Host = 1


@dataclass
class AgentOptions:
    is_controlling: bool
    candidate_types: list[CandidateType]
    interfaces: list[Interface]


async def coro_echo(transport: asyncio.DatagramTransport, candidate: CandidateBase):
    try:
        while True:
            await asyncio.sleep(1)
            if candidate._addr:
                transport.sendto("echo from agent".encode(), candidate._addr)
    except RuntimeError as e:
        _ = e


class Agent:
    def __init__(self, options: AgentOptions) -> None:
        self._options = options
        self._loop = asyncio.get_event_loop()

    async def _gather_candidates_local(self):
        for interface in self._options.interfaces:
            candidate = CandidateBase()
            print(
                "Gather host base candidate",
                datetime.now(),
            )

            transport, protocol = await asyncio.wrap_future(
                asyncio.run_coroutine_threadsafe(
                    self._loop.create_datagram_endpoint(
                        lambda: udp_mux.UDPMux(candidate),
                        local_addr=(interface.address, 9999),
                    ),
                    self._loop,
                )
            )
            print("Listen at", interface.address, 9999)
            _ = protocol

            self._loop.create_task(coro_echo(transport, candidate))

            try:
                while True:
                    await asyncio.sleep(2)
                    data = await candidate._queue.get()
                    msg = data.decode()
                    print(f"Received message: {msg}")
            finally:
                transport.close()

    def gather_candidates(self):
        for candidate_type in self._options.candidate_types:
            match candidate_type:
                case CandidateType.Host:
                    self._loop.create_task(self._gather_candidates_local())
                case _:
                    pass
