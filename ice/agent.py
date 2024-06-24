import asyncio

from dataclasses import dataclass
from enum import Enum

import ice.net
from ice.net.udp_mux import MultiUDPMux

from .candidate_base import CandidateBase
from .utils import generate_pwd, generate_ufrag


class CandidateType(Enum):
    Host = 1


@dataclass
class AgentOptions:
    is_controlling: bool
    candidate_types: list[CandidateType]
    interfaces: list[ice.net.Interface]


class AgentCredentials:
    @property
    def pwd(self) -> str:
        return self._pwd

    @pwd.setter
    def pwd(self, value: str):
        # TODO: When None must stop agent and restart with new ufraw/pwd
        print("pwd", value)
        self._pwd = value

    @property
    def ufrag(self) -> str:
        return self._ufrag

    @ufrag.setter
    def ufrag(self, value: str):
        # TODO: When None must stop agent and restart with new ufraw/pwd
        print("ufrag", value)
        self._ufrag = value


class Agent(AgentCredentials):
    def __init__(self, options: AgentOptions) -> None:
        self._options = options
        self._loop = asyncio.get_event_loop()
        self.ufrag = generate_ufrag()
        self.pwd = generate_pwd()
        self.udp = MultiUDPMux(options.interfaces, self._loop)

    async def _gather_host_candidate(self):
        candidate = CandidateBase()

        port = 9999
        muxers = await self.udp.bind(self.ufrag, candidate, port)
        for _, muxer in muxers.items():
            print("Listen at", muxer.addr_str(), "port:", port)

        self._loop.create_task(candidate.accept(self.ufrag.encode()))

    def gather_candidates(self):
        for candidate_type in self._options.candidate_types:
            match candidate_type:
                case CandidateType.Host:
                    self._loop.create_task(self._gather_host_candidate())
                case _:
                    pass
