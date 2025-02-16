import asyncio
import queue
from datetime import datetime, timedelta

from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Callable, Protocol

from . import stun
from . import net

from .net.types import (
    Address,
    MuxConnProtocol,
    MuxProtocol,
    NetworkType,
    LocalCandidate,
    Packet,
    RemoteCandidate,
)
from .net.udp_mux import Interceptor, MultiUDPMux
from .stun_message import stun_message_parse_attrs, stun_message_parse_header
from webrtc.utils import impl_protocol, AsyncEventEmitter, Handler_T

from .candidate_base import (
    CandidateBase,
    CandidateType,
    parse_candidate_str,
)
from .utils import generate_pwd, generate_tie_breaker, generate_ufrag, cmp


@dataclass
class AgentOptions:
    candidate_types: list[CandidateType]
    udp: MultiUDPMux
    interfaces: list[net.Interface]


class CandidatePairState(Enum):
    UNSET = 0
    WAITING = 1
    INPROGRESS = 2
    FAILED = 3
    SUCCEEDED = 4


class CandidatePair:
    def __init__(
        self,
        local_ufrag: str,
        local_pwd: str,
        remote_ufrag: str,
        remote_pwd: str,
        local: LocalCandidate,
        remote: RemoteCandidate,
        nominate_on_binding: bool = True,
    ) -> None:
        self._local_ufrag = local_ufrag
        self._local_pwd = local_pwd
        self._remote_ufrag = remote_ufrag
        self._remote_pwd = remote_pwd

        self._local = local
        self._remote = remote
        self._nominate_on_binding = nominate_on_binding
        self._state = CandidatePairState.UNSET

    # TODO: this should handle two candidate stun/rtp|rtcp inbound/outbound
    # But connection to send must be in remote candidate may be introduce:
    # RemoteCandidate/LocalCandidate but this must wrap a different tpye of Candidates too

    def get_pair_priority(self, controlling: bool) -> int:
        """
        RFC 5245 - 5.7.2.  Computing Pair Priority and Ordering Pairs
        Let G be the priority for the candidate provided by the controlling
        agent.  Let D be the priority for the candidate provided by the
        controlled agent.
        pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
        """

        if controlling:
            g = self._local.unwrap.priority
            d = self._remote.unwrap.priority
        else:
            g = self._remote.unwrap.priority
            d = self._local.unwrap.priority

        return (1 << 32 - 1) * min(g, d) + 2 * max(g, d) + cmp(g, d)

    def get_pair_id(self) -> str:
        return (
            f"{self.local_candidate.unwrap.to_ice_str()}"
            ":"
            f"{self.remote_candidate.unwrap.to_ice_str()}"
        )

    @property
    def state(self) -> CandidatePairState:
        """The state property."""
        return self._state

    @state.setter
    def state(self, value: CandidatePairState):
        self._state = value

    @property
    def local_candidate(self) -> LocalCandidate:
        return self._local

    @property
    def remote_candidate(self) -> RemoteCandidate:
        return self._remote

    @property
    def local_ufrag(self) -> str:
        return self._local_ufrag

    @property
    def local_pwd(self) -> bytes:
        return self._local_pwd.encode()

    @property
    def remote_ufrag(self) -> str:
        return self._remote_ufrag

    @property
    def remote_pwd(self) -> bytes:
        return self._remote_pwd.encode()


class CandidatePairRegistry:
    def __init__(self) -> None:
        self._check_list = dict[str, CandidatePair]()

    def append(self, pair: CandidatePair):
        self._check_list[pair.get_pair_id()] = pair

    def best_pair_priority(self, controlling: bool) -> CandidatePair | None:
        best: CandidatePair | None = None

        for _, pair in self._check_list.items():
            if pair._state != CandidatePairState.SUCCEEDED:
                continue

            if best is None:
                best = pair
            elif best.get_pair_priority(controlling) < pair.get_pair_priority(
                controlling
            ):
                best = pair

        return best

    def get_pair_list(self) -> dict[str, CandidatePair]:
        return self._check_list.copy()


@dataclass
class BindingCachedMessage:
    message: stun.Message
    destination: tuple[str, int]
    timestamp: datetime
    use_candidate_attr: bool = False


MAX_BINDING_REQUEST_TIMEOUT = timedelta(milliseconds=4000)


class BindingRequestCacheRegistry:
    def __init__(self) -> None:
        self._registry = dict[bytes, BindingCachedMessage]()
        self._lock = asyncio.Lock()

    def invalidate_pending_binding_requests(self, filter_time: datetime):
        initial_size = len(self._registry)

        keys_to_remove = []
        for transaction_id, cache in self._registry.items():
            if filter_time - cache.timestamp > MAX_BINDING_REQUEST_TIMEOUT:
                keys_to_remove.append(transaction_id)

        for transaction_id in keys_to_remove:
            self._registry.pop(transaction_id)

        bind_requests_removed = initial_size - len(self._registry)
        if bind_requests_removed > 0:
            print(
                f"Discarded {bind_requests_removed} binding requests, because they expired"
            )

    async def cache_message(self, msg: stun.Message, dst: tuple[str, int]):
        async with self._lock:
            self.invalidate_pending_binding_requests(datetime.now())

            cache = BindingCachedMessage(msg, dst, datetime.now())

            if msg.get_attribute(stun.UseCandidate):
                cache.use_candidate_attr = True

            self._registry[msg.transaction_id] = cache

    def get_cache_message(self, transaction_id: bytes) -> BindingCachedMessage | None:
        return self._registry.get(transaction_id)


class SelectorEvent(StrEnum):
    NOMINATE = "nominate"


# CandidatePairState.SUCCEEDED must be seted by connectivity checks as fast as possible
# Or set on Binding SuccessResponse
# Steps:
# 1. Controlled agent send binding request
# 2. Controlling agent send binding request
# 3. Controlling agent send succes XOR-ADDRESS
# 4. Controlled agent send success XOR-ADDRESS
# 5. Controlling agent set candidate state as SUCCESS
# 6. Controlled agent send binding request again
# 7. Controlling agent recv that binding request and nominate that pair with
#    binding request with USE-CANDIDATE attr
# 8. Controlled agent recv that binding and set that pair as selected or there
#    may be additional logic to set candidate as selected on controlled side
class SelectorProtocol(Protocol):
    def start(self): ...

    # 2. Try set CandidatePairState.SUCCEEDED on both sides
    # Controlling side if state SUCCEEDED it will nominate pair and send stun with UseCandidate attr
    async def on_binding_success(
        self, pair: CandidatePair, conn: MuxConnProtocol, msg: stun.Message
    ): ...

    async def on_success_response(
        self,
        pair: CandidatePair,
        conn: MuxConnProtocol,
        msg: stun.Message,
        source: Address,
    ): ...

    # 1. Firstly check if candidate is an alive
    async def send_ping_stun_message(
        self, pair: CandidatePair, conn: MuxConnProtocol
    ): ...

    # Part of event emitter
    def on(
        self, event: str, f: Handler_T | None = None
    ) -> Handler_T | Callable[[Handler_T], Handler_T]: ...

    def remove_all_listeners(self, event: str | None = None): ...


@impl_protocol(SelectorProtocol)
class ControllingSelector(AsyncEventEmitter):
    def __init__(self, pair_registry: CandidatePairRegistry, tie_breaker: int) -> None:
        super().__init__()

        self._nominated_pair: CandidatePair | None = None
        self._start_time: datetime | None = None
        self._pair_registry = pair_registry
        self._tie_breaker = tie_breaker
        self._local_binding_cache = BindingRequestCacheRegistry()

    def start(self):
        self._start_time = datetime.now()
        self._nominated_pair = None
        print("Start ControllingSelector agent selector")

    def _set_nominate_pair(self, pair: CandidatePair):
        self._nominated_pair = pair
        self.emit(SelectorEvent.NOMINATE, pair)

    async def _stun_nominate_pair(self, pair: CandidatePair, conn: MuxConnProtocol):
        msg = stun.Message(
            stun.MessageType(stun.Method.Binding, stun.MessageClass.Request)
        )
        msg.add_attribute(stun.Username(pair.remote_ufrag, pair.local_ufrag))
        msg.add_attribute(stun.UseCandidate())
        msg.add_attribute(stun.ICEControlling(self._tie_breaker))
        msg.add_attribute(stun.Priority(pair.local_candidate.unwrap.priority))

        await self._local_binding_cache.cache_message(
            msg,
            (
                pair.remote_candidate.unwrap.address,
                pair.remote_candidate.unwrap.port,
            ),
        )

        print(
            f"Ping STUN (nominate candidate pair) from {pair.local_ufrag} to {pair.remote_ufrag}"
        )

        conn.sendto(msg.encode(pair.remote_pwd))

    async def on_binding_success(
        self, pair: CandidatePair, conn: MuxConnProtocol, msg: stun.Message
    ):
        msg = stun.Message(
            stun.MessageType(stun.Method.Binding, stun.MessageClass.SuccessResponse),
            msg.transaction_id,
        )
        msg.add_attribute(
            stun.XORMappedAddress(
                msg.transaction_id,
                (
                    pair.remote_candidate.unwrap.address,
                    pair.remote_candidate.unwrap.port,
                ),
            )
        )
        conn.sendto(msg.encode(pair.local_pwd))

        # TODO: check also selected pair like this s.agent.getSelectedPair() == nil
        # But what is diff between nominated_pair
        # SelectedPair may be mean that pair is currently runnign, nominated may be not running
        if pair.state == CandidatePairState.SUCCEEDED and self._nominated_pair is None:
            await self._stun_nominate_pair(pair, conn)

    async def on_success_response(
        self,
        pair: CandidatePair,
        conn: MuxConnProtocol,
        msg: stun.Message,
        source: Address,
    ):
        binding_request = self._local_binding_cache.get_cache_message(
            bytes(msg.transaction_id)
        )
        if binding_request is None:
            print(
                f"Discard message from ({pair.remote_ufrag}), unknown transaction_id: {msg.transaction_id}"
            )
            raise ValueError(
                f"Discard message from ({pair.remote_ufrag}), unknown transaction_id: {msg.transaction_id}"
            )

        transaction_addr, transaction_port = binding_request.destination
        source_addr, source_port = source.address, source.port

        # TODO: What is symmetric NAT. Is it 1:NAT ???
        # NOTE: Each connection from an internal host to an external host is given a unique mapping in the NAT device. Different connections to different external hosts will have different mappings. Is it like NAT:NAT ???
        # https://github.com/pion/ice/blob/2a9fdb5c0dde845df6a5cb4709e619dbb6164786/selection.go#L133
        if transaction_addr != source_addr or transaction_port != source_port:
            print(
                f"Discard message from ({pair.remote_ufrag}), source and transaction does not match expected({transaction_addr}:{transaction_port}), actual({source_addr}:{source_port})"
            )
            raise ValueError(
                f"Discard message from ({pair.remote_ufrag}), source and transaction does not match expected({transaction_addr}:{transaction_port}), actual({source_addr}:{source_port})"
            )

        pair.state = CandidatePairState.SUCCEEDED

        if binding_request.use_candidate_attr and self._nominated_pair is None:
            self._set_nominate_pair(pair)

    async def send_ping_stun_message(self, pair: CandidatePair, conn: MuxConnProtocol):
        msg = stun.Message(
            stun.MessageType(stun.Method.Binding, stun.MessageClass.Request)
        )
        msg.add_attribute(stun.Username(pair.remote_ufrag, pair.local_ufrag))
        msg.add_attribute(stun.ICEControlling(self._tie_breaker))
        msg.add_attribute(stun.Priority(pair.local_candidate.unwrap.priority))

        await self._local_binding_cache.cache_message(
            msg,
            (
                pair.remote_candidate.unwrap.address,
                pair.remote_candidate.unwrap.port,
            ),
        )

        conn.sendto(msg.encode(pair.remote_pwd))


@impl_protocol(SelectorProtocol)
class ControlledSelector(AsyncEventEmitter):
    def __init__(self, pair_registry: CandidatePairRegistry, tie_breaker: int) -> None:
        super().__init__()

        self._pair_registry = pair_registry
        self._tie_breaker = tie_breaker
        self._selected_pair: CandidatePair | None = None
        self._local_binding_cache = BindingRequestCacheRegistry()

    def start(self):
        print("Start ControlledSelector agent selector")

    async def on_binding_success(
        self, pair: CandidatePair, conn: MuxConnProtocol, msg: stun.Message
    ):
        useCandidate = msg.get_attribute(stun.UseCandidate)

        if useCandidate:
            print("Controlled selector has found use candidate to nominate pair")
            if pair.state == CandidatePairState.SUCCEEDED:
                print(f"Controlled selector pair has correct state {pair.state}")
                print(f"Controlled selector pair: {self._selected_pair}")
                # If the state of this pair is Succeeded, it means that the check
                # previously sent by this pair produced a successful response and
                # generated a valid pair (Section 7.2.5.3.2).  The agent sets the
                # nominated flag value of the valid pair to true.

                # Or even if use candidate exists may be force nominate that pair
                if self._selected_pair is None or self._selected_pair.get_pair_priority(
                    False
                ) < pair.get_pair_priority(False):
                    print(
                        f"Controlled selector must set remote({pair.remote_ufrag}) local({pair.local_ufrag})"
                    )
                elif self._selected_pair != pair:
                    print(
                        f"Ignore nominated new pair {pair}, already selected {self._selected_pair}"
                    )
        else:
            # If the received Binding request triggered a new check to be
            # enqueued in the triggered-check queue (Section 7.3.1.4), once the
            # check is sent and if it generates a successful response, and
            # generates a valid pair, the agent sets the nominated flag of the
            # pair to true.  If the request fails (Section 7.2.5.2), the agent
            # MUST remove the candidate pair from the valid list, set the
            # candidate pair state to Failed, and set the checklist state to
            # Failed.
            pair._nominate_on_binding = True

        msg = stun.Message(
            stun.MessageType(stun.Method.Binding, stun.MessageClass.SuccessResponse),
            msg.transaction_id,
        )
        msg.add_attribute(
            stun.XORMappedAddress(
                msg.transaction_id,
                (
                    pair.remote_candidate.unwrap.address,
                    pair.remote_candidate.unwrap.port,
                ),
            )
        )
        conn.sendto(msg.encode(pair.local_pwd))

        await self.send_ping_stun_message(pair, conn)

    async def on_success_response(
        self,
        pair: CandidatePair,
        conn: MuxConnProtocol,
        msg: stun.Message,
        source: Address,
    ):
        pair.state = CandidatePairState.SUCCEEDED

        if pair._nominate_on_binding:
            if self._selected_pair is None or self._selected_pair.get_pair_priority(
                False
            ) < pair.get_pair_priority(False):
                # TODO: set selected pair
                print(f"Controlled selector Nominate pair on {pair}")
                self._selected_pair = pair
            elif self._selected_pair != pair:
                print(
                    f"Ignore nominated new pair {pair}, already selected {self._selected_pair}"
                )

    async def send_ping_stun_message(self, pair: CandidatePair, conn: MuxConnProtocol):
        msg = stun.Message(
            stun.MessageType(stun.Method.Binding, stun.MessageClass.Request)
        )
        msg.add_attribute(stun.Username(pair.remote_ufrag, pair.local_ufrag))
        msg.add_attribute(stun.ICEControlling(self._tie_breaker))
        msg.add_attribute(stun.Priority(pair.local_candidate.unwrap.priority))

        await self._local_binding_cache.cache_message(
            msg,
            (
                pair.remote_candidate.unwrap.address,
                pair.remote_candidate.unwrap.port,
            ),
        )

        conn.sendto(msg.encode(pair.remote_pwd))


async def ping_routine(
    selector: SelectorProtocol, pair: CandidatePair, conn: MuxConnProtocol
):
    pass
    # while True:
    #     await asyncio.sleep(5)
    #     await selector.send_ping_stun_message(pair, conn)


class CandidatePairTransport:
    def __init__(self, conn: MuxConnProtocol) -> None:
        self._conn: MuxConnProtocol = conn

        self._rtp = queue.Queue[Packet]()
        self._rtcp = queue.Queue[Packet]()
        self._dtls = Interceptor()

    def pipe(self, pkt: Packet):
        first_byte = pkt.data[0]
        if first_byte > 19 and first_byte < 64:
            self._dtls.put_nowait(pkt)
        elif net.is_rtcp(pkt.data):
            self._rtcp.put_nowait(pkt)
        else:
            self._rtp.put_nowait(pkt)

    async def recv_dtls(self) -> Packet:
        return await self._dtls.get()

    def recv_rtp_sync(self) -> Packet:
        return self._rtp.get()

    def recv_rtcp_sync(self) -> Packet:
        return self._rtcp.get()

    def sendto(self, data: bytes):
        self._conn.sendto(data)


class CandidatePairControllerEvent(StrEnum):
    NOMINATE_TRANSPORT = "nominate-transport"


class CandidatePairController(AsyncEventEmitter):
    def __init__(
        self, pair: CandidatePair, selector: SelectorProtocol, tie_breaker: int
    ) -> None:
        super().__init__()

        self._pair = pair

        self.__selector = selector
        self.__tie_breaker = tie_breaker
        self.__conn = pair.local_candidate.mux.intercept(
            self._pair.remote_candidate.unwrap
        )
        self.__transport = CandidatePairTransport(self.__conn)

    def __pair_nominate(self, _: CandidatePair):
        self.emit(CandidatePairControllerEvent.NOMINATE_TRANSPORT, self.__transport)

    async def start(self):
        self.__selector.start()
        self.__selector.on(SelectorEvent.NOMINATE, self.__pair_nominate)
        await self.ping_remote_candidate()

        print("Start candidate pair selector", self._pair)
        while True:
            pkt = await self.__conn.recvfrom()

            if stun.is_stun(pkt.data):
                await self._on_inbound_stun(pkt)
            else:
                await self._on_inbound_pkt(pkt)

    async def _on_inbound_pkt(self, pkt: Packet):
        # print("Recv rtp wait 10 sec.", pkt.data.tolist())
        self.__transport.pipe(pkt)

    async def _on_stun_binding_request(self, pkt: Packet, msg: stun.Message):
        # print("On stun binding request", msg)
        await self.__selector.on_binding_success(self._pair, self.__conn, msg)
        # print("On stun binding request", self._pair.state)

    async def _on_stun_success_response(self, pkt: Packet, msg: stun.Message):
        await self.__selector.on_success_response(
            self._pair, self.__conn, msg, pkt.source
        )
        # print("On stun binding success response", self._pair.state)

    async def _on_inbound_stun(self, pkt: Packet):
        try:
            msg = stun_message_parse_header(pkt)

            match msg.message_type.method:
                case stun.Method.Binding:
                    match msg.message_type.message_class:
                        case stun.MessageClass.Request:
                            msg = stun_message_parse_attrs(
                                pkt, msg, self._pair.local_pwd
                            )
                            await self._on_stun_binding_request(pkt, msg)
                        case stun.MessageClass.SuccessResponse:
                            msg = stun_message_parse_attrs(
                                pkt, msg, self._pair.remote_pwd
                            )
                            await self._on_stun_success_response(pkt, msg)

                        case _:
                            print(
                                f"Unhandled STUN message class for method {msg.message_type.method}"
                            )
                case _:
                    print("Unhandled STUN message type")
        except ValueError as e:
            raise e
            # print("Invalid stun message or creds", e)

    async def ping_remote_candidate(self):
        """
        Check agent connectivity. STUN binding request must not nominate candidates.
        """
        # TODO: wait some time if candidate state will not changed retry ping
        # NOTE: How to make state observing/notifying
        await self.__selector.send_ping_stun_message(self._pair, self.__conn)

    def get_transport(self) -> CandidatePairTransport:
        return self.__transport


class CandidatePairControllerRegistry:
    def __init__(self) -> None:
        self._check_list = dict[str, CandidatePairController]()

    def append(self, controller: CandidatePairController):
        pair = controller._pair
        self._check_list[pair.get_pair_id()] = controller

    def get(self, pair_id: str) -> CandidatePairController | None:
        return self._check_list.get(pair_id)


# Role Determination: The peers determine their roles (controlling or controlled) based on the ICE tie-breaking algorithm. The peer with the higher tie-breaker value becomes the controlling agent


class AgentRole(Enum):
    Unknown = "unknown"
    Controlling = "controlling"
    Controlled = "controlled"


class AgentEvent:
    CANDIDATE_PAIR_CONTROLLER = "candidate-pair-controller"


# Controlling agent must know remote user credentials
class Agent(AsyncEventEmitter):
    def __init__(self, options: AgentOptions) -> None:
        super().__init__()

        self._tie_breaker = generate_tie_breaker()
        self._local_ufrag = generate_ufrag()
        self._local_pwd = generate_pwd()
        self._remote_ufrag: str | None = None
        self._remote_pwd: str | None = None
        self._role: AgentRole = AgentRole.Unknown

        self._options = options
        self._udp = options.udp
        self._loop = asyncio.get_event_loop()
        self._on_candidate: Callable[[CandidateBase], None] | None = None

        self._local_candidates = dict[NetworkType, list[LocalCandidate]]()
        self._remote_candidates = dict[NetworkType, list[CandidateBase]]()

        self._pair_registry = CandidatePairRegistry()
        self._controller_registry = CandidatePairControllerRegistry()

        self._candidate_pair_transports = list[CandidatePairTransport]()

    def set_on_candidate(self, on_candidate: Callable[[CandidateBase], None]):
        self._on_candidate = on_candidate

    async def _gather_host_candidate(self):
        for _, handler in self._udp.inbound_handlers().items():
            candidate = CandidateBase()

            mux = self._udp.bind(self._local_ufrag, handler, candidate)
            await self._add_local_candidate(LocalCandidate(candidate, mux))

            if self._on_candidate:
                self._on_candidate(candidate)

    async def gather_candidates(self):
        coros = []
        for candidate_type in self._options.candidate_types:
            match candidate_type:
                case CandidateType.Host:
                    coros.append(
                        asyncio.ensure_future(
                            self._gather_host_candidate(), loop=self._loop
                        )
                    )
                case _:
                    pass
        await asyncio.gather(*coros)

    def _on_nominate_pair(self, pair: CandidatePair):
        print("TODO: _on_nominate_pair", pair)

    def _start_controller(self, pair: CandidatePair):
        if self._role:
            selector = ControllingSelector(self._pair_registry, self._tie_breaker)
        else:
            selector = ControlledSelector(self._pair_registry, self._tie_breaker)

        # selector.start()
        # selector.on(SelectorEvent.NOMINATE, self._on_nominate_pair)

        # pair_controller =
        print("Emit controller??")
        self.emit(
            AgentEvent.CANDIDATE_PAIR_CONTROLLER,
            CandidatePairController(pair, selector, self._tie_breaker),
        )

        # self._controller_registry.append(pair_controller)
        # self._candidate_pair_transports.append(pair_controller.get_transport())
        # self._loop.create_task(pair_controller.start())
        # self._loop.create_task(pair_controller.ping_remote_candidate())
        # self._loop.create_task(ping_routine(selector, pair, pair_controller._conn))

    # Look at func (s *controllingSelector) ContactCandidates() to know more
    def connect(self, controlling: bool):
        print("start connection", controlling, self._remote_ufrag, self._remote_pwd)

        print(self._pair_registry.get_pair_list())
        print("Pair registry", self._pair_registry)

        if controlling:
            self._role = AgentRole.Controlling
        else:
            self._role = AgentRole.Controlled

        print("pair list", self._pair_registry.get_pair_list().items())

        for id, pair in self._pair_registry.get_pair_list().items():
            controller = self._controller_registry.get(id)

            if controller:
                print("Found already negotiated controller")
                continue

            self._start_controller(pair)

        return

    def dial(self):
        "Initiates a connection to another peer"
        self._role = AgentRole.Controlling
        self.connect(True)

    def accept(self):
        self._role = AgentRole.Controlled
        self.connect(False)

    async def get_local_candidates(self):
        # async with self._candidate_lock:
        buf = list[LocalCandidate]()

        for _, candidates in self._local_candidates.items():
            buf.extend(candidates)

        return buf

    async def _add_candidate_pair(self, local: LocalCandidate, remote: CandidateBase):
        # async with self._candidate_pair_lock:
        remote_conn = local.mux.intercept(remote)

        if self._remote_ufrag is None or self._remote_pwd is None:
            raise ValueError("Unable add canddiate ")

        # TODO: may be better provide some object ref that hold ufrag, pwd to make dynamic replacement of credentials
        pair = CandidatePair(
            self._local_ufrag,
            self._local_pwd,
            self._remote_ufrag,
            self._remote_pwd,
            local,
            RemoteCandidate(remote, remote_conn),
        )

        print("Added candidate pair", pair.get_pair_id())

        self._pair_registry.append(pair)

    async def _add_local_candidate(self, local: LocalCandidate):
        # async with self._candidate_lock:
        net_type = local.unwrap.get_network_type()
        pool = self._local_candidates.get(net_type)
        if pool is None:
            pool = list[LocalCandidate]()
            self._local_candidates[net_type] = pool

        found = False
        for c in pool:
            if c == local:
                found = True
                break

        if not found:
            pool.append(local)
        else:
            return

        remotes = self._remote_candidates.get(net_type)
        if remotes:
            for remote in remotes:
                self._loop.create_task(self._add_candidate_pair(local, remote))

    async def _add_remote_candidate(self, remote: CandidateBase):
        # print("add remote candidate befre lock")
        # async with self._candidate_lock:
        print("add remote candidate after lock")
        net_type = remote.get_network_type()
        pool = self._remote_candidates.get(net_type)
        if pool is None:
            pool = list[CandidateBase]()
            self._remote_candidates[net_type] = pool

        found = False
        for c in pool:
            if c == remote:
                found = True
                break

        if not found:
            pool.append(remote)
        else:
            return

        locals = self._local_candidates.get(net_type)
        if locals:
            for local in locals:
                self._loop.create_task(self._add_candidate_pair(local, remote))

    def add_remote_candidate(self, candidate_raw: str):
        remote = parse_candidate_str(candidate_raw)
        if not remote:
            return
        self._loop.create_task(self._add_remote_candidate(remote))

    def get_local_credentials(self) -> tuple[str, str]:
        return (self._local_ufrag, self._local_pwd)

    # TODO: may remote this
    def set_remote_credentials(self, ufrag: str, pwd: str):
        self._remote_ufrag = ufrag
        self._remote_pwd = pwd

    def get_role(self) -> AgentRole:
        return self._role
