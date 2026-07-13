import socket
import re
import asyncio
import inspect
import hashlib
import secrets
import queue
from datetime import datetime, timedelta

from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Any, Callable, Protocol, cast

from . import stun
from . import net

from .net.types import (
    Address,
    CandidateProtocol,
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
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.performance import ObservedComponent, event_loop, task
from webrtc.runtime_services import FailurePolicy
from webrtc.lifecycle import ICECondition, require_timeout, wait_for_event, wait_until
from webrtc.tracing import perf_mark, perf_measured_async
from webrtc.domain_events import IcePairNominated, emit_domain_event

from .candidate_base import (
    CandidateBase,
    CandidateType,
    parse_candidate_str,
)
from .utils import generate_pwd, generate_tie_breaker, generate_ufrag, cmp


_PAIR_OBSERVABILITY_KEY = secrets.token_bytes(16)


def _observable_pair_id_value(pair_id: str) -> str:
    """Return a process-local identity without a reversible address digest."""
    return hashlib.blake2s(
        pair_id.encode(), key=_PAIR_OBSERVABILITY_KEY, digest_size=8,
    ).hexdigest()


def _observable_pair_id(pair: "CandidatePair") -> str:
    """Return stable nomination identity without exposing candidate addresses."""
    return _observable_pair_id_value(pair.get_pair_id())


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


def _candidate_metadata(candidate: CandidateProtocol) -> dict[str, object]:
    return {
        "address": candidate.address,
        "port": candidate.port,
        "network_type": candidate.get_network_type().value,
        "candidate_type": getattr(candidate, "candidate_type", None),
        "priority": candidate.priority,
    }


def _pair_metadata(pair: CandidatePair) -> dict[str, object]:
    return {
        "pair_id": pair.get_pair_id(),
        "local_address": pair.local_candidate.unwrap.address,
        "local_port": pair.local_candidate.unwrap.port,
        "remote_address": pair.remote_candidate.unwrap.address,
        "remote_port": pair.remote_candidate.unwrap.port,
        "local_ufrag": pair.local_ufrag,
        "remote_ufrag": pair.remote_ufrag,
    }


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
            get_logger().debug(
                Component.ICE,
                "Discarded expired binding requests",
                count=bind_requests_removed,
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
        get_logger().debug(Component.ICE, "Started controlling ICE selector")

    def _set_nominate_pair(self, pair: CandidatePair):
        get_logger().debug(
            Component.ICE,
            "Nominating candidate pair",
            pair_id=pair.get_pair_id(),
        )
        emit_domain_event(IcePairNominated, pair_id=_observable_pair_id(pair))
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

        get_logger().trace(
            Component.ICE,
            "Sending STUN nomination request",
            local_ufrag=pair.local_ufrag,
            remote_ufrag=pair.remote_ufrag,
        )

        perf_mark(
            "ice",
            "stun",
            "tx",
            metadata={**_pair_metadata(pair), "use_candidate": True, "counter.ice.stun_tx": 1},
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
        perf_mark(
            "ice",
            "stun",
            "tx",
            metadata={**_pair_metadata(pair), "message_class": "success_response", "counter.ice.stun_tx": 1},
        )

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
            get_logger().warn(
                Component.ICE,
                "Discarding STUN success response with unknown transaction ID",
                remote_ufrag=pair.remote_ufrag,
                transaction_id=msg.transaction_id,
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
            get_logger().warn(
                Component.ICE,
                "Discarding STUN success response from unexpected source",
                remote_ufrag=pair.remote_ufrag,
                expected=f"{transaction_addr}:{transaction_port}",
                actual=f"{source_addr}:{source_port}",
            )
            raise ValueError(
                f"Discard message from ({pair.remote_ufrag}), source and transaction does not match expected({transaction_addr}:{transaction_port}), actual({source_addr}:{source_port})"
            )

        pair.state = CandidatePairState.SUCCEEDED
        perf_mark("ice", "candidate_pair", "succeeded", metadata=_pair_metadata(pair))
        perf_mark("ice", "stun", "success", metadata={**_pair_metadata(pair), "counter.ice.stun_success": 1})

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

        perf_mark(
            "ice",
            "stun",
            "tx",
            metadata={**_pair_metadata(pair), "use_candidate": False, "counter.ice.stun_tx": 1},
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
        get_logger().debug(Component.ICE, "Started controlled ICE selector")

    async def on_binding_success(
        self, pair: CandidatePair, conn: MuxConnProtocol, msg: stun.Message
    ):
        useCandidate = msg.get_attribute(stun.UseCandidate)

        if useCandidate:
            get_logger().debug(Component.ICE, "Received STUN UseCandidate")
            # When the controlling agent sends UseCandidate, we should nominate the pair
            # The controlling agent has already verified connectivity, so we can trust this
            if self._selected_pair is None or self._selected_pair.get_pair_priority(
                False
            ) < pair.get_pair_priority(False):
                get_logger().debug(
                    Component.ICE,
                    "Nominating candidate pair via UseCandidate",
                    pair_id=pair.get_pair_id(),
                )
                perf_mark(
                    "ice",
                    "candidate_pair",
                    "nominated",
                    metadata=_pair_metadata(pair),
                )
                self._selected_pair = pair
                # Emit NOMINATE event to trigger DTLS transport setup
                self.emit(SelectorEvent.NOMINATE, pair)
            elif self._selected_pair != pair:
                get_logger().debug(
                    Component.ICE,
                    "Ignoring lower-priority nominated candidate pair",
                    pair_id=pair.get_pair_id(),
                    selected_pair_id=self._selected_pair.get_pair_id(),
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
        perf_mark(
            "ice",
            "stun",
            "tx",
            metadata={**_pair_metadata(pair), "message_class": "success_response", "counter.ice.stun_tx": 1},
        )

        await self.send_ping_stun_message(pair, conn)

    async def on_success_response(
        self,
        pair: CandidatePair,
        conn: MuxConnProtocol,
        msg: stun.Message,
        source: Address,
    ):
        pair.state = CandidatePairState.SUCCEEDED
        perf_mark("ice", "candidate_pair", "succeeded", metadata=_pair_metadata(pair))
        perf_mark("ice", "stun", "success", metadata={**_pair_metadata(pair), "counter.ice.stun_success": 1})

        if pair._nominate_on_binding:
            if self._selected_pair is None or self._selected_pair.get_pair_priority(
                False
            ) < pair.get_pair_priority(False):
                get_logger().debug(
                    Component.ICE,
                    "Nominating candidate pair",
                    pair_id=pair.get_pair_id(),
                )
                perf_mark(
                    "ice",
                    "candidate_pair",
                    "nominated",
                    metadata=_pair_metadata(pair),
                )
                self._selected_pair = pair
                # Emit NOMINATE event to trigger DTLS transport setup
                self.emit(SelectorEvent.NOMINATE, pair)
            elif self._selected_pair != pair:
                get_logger().debug(
                    Component.ICE,
                    "Ignoring lower-priority nominated candidate pair",
                    pair_id=pair.get_pair_id(),
                    selected_pair_id=self._selected_pair.get_pair_id(),
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

        perf_mark(
            "ice",
            "stun",
            "tx",
            metadata={**_pair_metadata(pair), "use_candidate": False, "counter.ice.stun_tx": 1},
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
    def __init__(self, conn: MuxConnProtocol, *, pair_id: str | None = None) -> None:
        self._conn: MuxConnProtocol = conn
        self._pair_id = pair_id
        self._observability_id = (
            _observable_pair_id_value(pair_id) if pair_id is not None else None
        )
        if pair_id is not None:
            set_trace_pair_id = getattr(conn, "set_trace_pair_id", None)
            if set_trace_pair_id is not None:
                set_trace_pair_id(pair_id)

        # self._rtp = queue.Queue[Packet]()
        # self._rtcp = queue.Queue[Packet]()
        self._rtp = Interceptor(maxsize=2048, drop_oldest=True, queue_id="ice-rtp")
        self._rtcp = Interceptor(queue_id="ice-rtcp")
        self._dtls = Interceptor(queue_id="ice-dtls")

        # Packet classification stats
        self._total_packets = 0
        self._dtls_count = 0
        self._rtcp_count = 0
        self._rtp_count = 0

    @property
    def observability_id(self) -> str | None:
        return self._observability_id

    def _demux_metadata(self, packet_kind: str, pkt: Packet) -> dict[str, object]:
        metadata: dict[str, object] = {
            "flow_direction": "rx", "packet_kind": packet_kind,
            "size_bytes": len(pkt.data),
        }
        if self._pair_id is not None:
            metadata["pair_id"] = self._pair_id
        return metadata

    def pipe(self, pkt: Packet):
        logger = get_logger()
        config = get_config()

        if not pkt.data:
            self._demux_failed(pkt, "empty")
        first_byte = pkt.data[0]
        if not (20 <= first_byte < 64 or 128 <= first_byte < 192):
            self._demux_failed(pkt, "unsupported")

        self._total_packets += 1

        # Extract RTP info if it looks like RTP (starts with 0x80-0x9f typically)
        pkt_type = "UNKNOWN"

        if first_byte > 19 and first_byte < 64:
            # DTLS packet
            self._dtls_count += 1
            pkt_type = "DTLS"
            if self._dtls_count <= config.log_first_n_packets or self._dtls_count % config.log_every_n_packets == 0:
                logger.trace(Component.ICE, f"DTLS packet -> dtls queue",
                           count=self._dtls_count, size=len(pkt.data))
            self._queue_demuxed_packet(self._dtls, pkt, "dtls")
            perf_mark(
                "ice", "packet_demux", "dtls",
                metadata={**self._demux_metadata("dtls", pkt), "counter.ice.demux_dtls": 1},
            )
        elif net.is_rtcp(pkt.data):
            if len(pkt.data) < 4:
                self._demux_failed(pkt, "malformed_rtcp")
            # RTCP packet
            self._rtcp_count += 1
            pkt_type = "RTCP"
            self._queue_demuxed_packet(self._rtcp, pkt, "rtcp")
            rtcp_metadata = self._demux_metadata("rtcp", pkt)
            if len(pkt.data) >= 8:
                rtcp_metadata["ssrc"] = int.from_bytes(pkt.data[4:8], "big")
            perf_mark(
                "ice", "packet_demux", "rtcp",
                metadata={**rtcp_metadata, "counter.ice.demux_rtcp": 1},
            )
        else:
            if len(pkt.data) < 12:
                self._demux_failed(pkt, "malformed_rtp")
            # RTP packet
            self._rtp_count += 1
            pkt_type = "RTP"

            # Header-only extraction is deliberately outside the UDP callback.
            seq = int.from_bytes(pkt.data[2:4], "big")
            ssrc = int.from_bytes(pkt.data[8:12], "big")
            rtp_metadata = self._demux_metadata("rtp", pkt)
            rtp_metadata.update({"ssrc": ssrc, "sequence_number": seq})
            if config.log_packet_details:
                payload_type = pkt.data[1] & 0x7F

                # Log using packet logger
                if self._rtp_count <= config.log_first_n_packets or self._rtp_count % config.log_every_n_packets == 0:
                    logger.log_packet(Component.ICE, "RX", self._rtp_count,
                                    seq=seq, ssrc=ssrc, size=len(pkt.data), pt=payload_type)

            self._queue_demuxed_packet(self._rtp, pkt, "rtp")
            perf_mark(
                "ice", "packet_demux", "rtp",
                metadata={**rtp_metadata, "counter.ice.demux_rtp": 1},
            )

        # Log demux statistics periodically
        if config.log_packet_counts and (self._total_packets <= 50 or self._total_packets % 100 == 0):
            rtp_pct = 100 * self._rtp_count / self._total_packets
            rtcp_pct = 100 * self._rtcp_count / self._total_packets
            dtls_pct = 100 * self._dtls_count / self._total_packets

            logger.log_stats(Component.ICE,
                           total=self._total_packets,
                           RTP=f"{self._rtp_count} ({rtp_pct:.1f}%)",
                           RTCP=f"{self._rtcp_count} ({rtcp_pct:.1f}%)",
                           DTLS=f"{self._dtls_count} ({dtls_pct:.1f}%)")

    def _queue_demuxed_packet(self, queue: Interceptor, pkt: Packet, packet_kind: str) -> None:
        try:
            queue.put_nowait(pkt)
        except Exception as exc:
            self._demux_failed(pkt, "queue_rejected", exc)

    def _demux_failed(
        self, pkt: Packet, demux_reason: str, exc: Exception | None = None
    ) -> None:
        failure = exc or ValueError(f"Unable to demux {demux_reason} ICE transport datagram")
        perf_mark(
            "ice", "packet_demux", "failed",
            metadata={
                **self._demux_metadata("unknown", pkt), "demux_reason": demux_reason,
                "error_stage": "packet_demux", "exception_class": failure.__class__.__name__,
                "counter.ice.demux_failed": 1,
            },
        )
        if exc is not None:
            raise ValueError(f"Unable to demux {demux_reason} ICE transport datagram") from exc
        raise failure

    async def recv_dtls(self) -> Packet:
        return await self._dtls.get()

    async def recv_rtp(self) -> Packet:
        return await self._rtp.get()

    async def recv_rtcp(self) -> Packet:
        return await self._rtcp.get()

    def sendto(self, data: bytes):
        # Debug: log first byte to distinguish packet types (RTP starts with 0x80-0x8f)
        self._conn.sendto(data)


class CandidatePairControllerEvent(StrEnum):
    NOMINATE_TRANSPORT = "nominate-transport"


class CandidatePairController(AsyncEventEmitter, ObservedComponent):
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
        self.__transport = CandidatePairTransport(self.__conn, pair_id=pair.get_pair_id())
        self.__nominated = asyncio.Event()
        self._task_handle: asyncio.Task[None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._closing = False
        self._closed = False

    @event_loop
    def __pair_nominate(self, _: CandidatePair):
        get_logger().debug(
            Component.ICE,
            "Emitting nominated transport",
            pair_id=self._pair.get_pair_id(),
        )
        self.__nominated.set()
        emit_domain_event(
            IcePairNominated, pair_id=_observable_pair_id(self._pair)
        )
        self.emit(CandidatePairControllerEvent.NOMINATE_TRANSPORT, self.__transport)

    @task(
        name="ice:candidate-pair-controller",
        kind="ice",
        state="ice",
        metadata={"expected_long_running": True, "loop_role": "controller"},
        failure=FailurePolicy.FAIL_CONNECTION,
    )
    async def start(self):
        self.__selector.start()
        self.__selector.on(SelectorEvent.NOMINATE, self.__pair_nominate)
        controller_metadata = {
            "pair_id": self._pair.get_pair_id(), "flow_direction": "rx",
        }
        perf_mark(
            "ice", "controller", "loop_started",
            metadata={**controller_metadata, "expected_long_running": True},
        )
        await self.ping_remote_candidate()

        get_logger().debug(
            Component.ICE,
            "Started candidate pair selector",
            pair_id=self._pair.get_pair_id(),
        )
        while True:
            pkt: Packet | None = None
            try:
                pkt = await self.__conn.recvfrom()
                is_stun = stun.is_stun(pkt.data)
                packet_kind = "stun" if is_stun else "unknown"
                packet_metadata = {
                    **controller_metadata, "size_bytes": len(pkt.data),
                    "packet_kind": packet_kind,
                }
                perf_mark(
                    "ice", "controller", "packet_received",
                    metadata={**packet_metadata, "counter.ice.controller_packets_received": 1},
                )

                if is_stun:
                    await self._on_inbound_stun(pkt)
                    route = "stun"
                else:
                    await self._on_inbound_pkt(pkt)
                    route = "transport"
                perf_mark(
                    "ice", "controller", "packet_routed",
                    metadata={**packet_metadata, "route": route, "counter.ice.controller_packets_routed": 1},
                )
            except Exception as exc:
                metadata = dict(controller_metadata)
                if pkt is not None:
                    metadata["size_bytes"] = len(pkt.data)
                perf_mark(
                    "ice", "controller", "packet_failed",
                    metadata={
                        **metadata, "error_stage": "dequeue_branch_or_route",
                        "exception_class": exc.__class__.__name__,
                        "counter.ice.controller_packets_failed": 1,
                    },
                )
                raise

    async def start_managed(self) -> asyncio.Task[None]:
        """Atomically start and retain the controller's managed task."""
        if self._closing or self._closed:
            raise RuntimeError("candidate pair controller is closing")
        if self._task_handle is None:
            self._task_handle = cast(asyncio.Task[None], self.start())
        return cast(asyncio.Task[None], self._task_handle)

    async def _close(self) -> None:
        task_handle = self._task_handle
        if task_handle is not None and not task_handle.done():
            task_handle.cancel()
        if task_handle is not None:
            await asyncio.gather(task_handle, return_exceptions=True)
        self._task_handle = None
        self.remove_all_listeners()
        await self.__selector.aclose()
        await super().aclose()
        self._closed = True

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closing = True
        if self._close_task is None or (
            self._close_task.done()
            and (self._close_task.cancelled() or self._close_task.exception() is not None)
        ):
            self._close_task = asyncio.create_task(
                self._close(), name="ice:candidate-pair-controller-close"
            )
        await asyncio.shield(self._close_task)

    async def _on_inbound_pkt(self, pkt: Packet):
        self.__transport.pipe(pkt)

    async def _on_stun_binding_request(self, pkt: Packet, msg: stun.Message):
        perf_mark("ice", "stun", "rx", metadata={**_pair_metadata(self._pair), "message_class": "request", "counter.ice.stun_rx": 1})
        await self.__selector.on_binding_success(self._pair, self.__conn, msg)

    async def _on_stun_success_response(self, pkt: Packet, msg: stun.Message):
        perf_mark("ice", "stun", "rx", metadata={**_pair_metadata(self._pair), "message_class": "success_response", "counter.ice.stun_rx": 1})
        await self.__selector.on_success_response(
            self._pair, self.__conn, msg, pkt.source
        )

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
                            get_logger().debug(
                                Component.ICE,
                                "Unhandled STUN message class",
                                method=msg.message_type.method,
                                message_class=msg.message_type.message_class,
                            )
                case _:
                    get_logger().debug(
                        Component.ICE,
                        "Unhandled STUN message type",
                        method=msg.message_type.method,
                    )
        except ValueError as e:
            raise e

    async def ping_remote_candidate(self):
        """
        Check agent connectivity. STUN binding request must not nominate candidates.
        """
        # TODO: wait some time if candidate state will not changed retry ping
        # NOTE: How to make state observing/notifying
        await self.__selector.send_ping_stun_message(self._pair, self.__conn)

    @event_loop
    def get_transport(self) -> CandidatePairTransport:
        return self.__transport

    @property
    def nominated(self) -> bool:
        return self.__nominated.is_set()


class CandidatePairControllerRegistry:
    def __init__(self) -> None:
        self._check_list = dict[str, CandidatePairController]()

    def append(self, controller: CandidatePairController):
        pair = controller._pair
        self._check_list[pair.get_pair_id()] = controller

    def get(self, pair_id: str) -> CandidatePairController | None:
        return self._check_list.get(pair_id)

    def controllers(self) -> list[CandidatePairController]:
        return list(self._check_list.values())


# Role Determination: The peers determine their roles (controlling or controlled) based on the ICE tie-breaking algorithm. The peer with the higher tie-breaker value becomes the controlling agent


class AgentRole(Enum):
    Unknown = "unknown"
    Controlling = "controlling"
    Controlled = "controlled"


class AgentEvent:
    CANDIDATE_PAIR_CONTROLLER = "candidate-pair-controller"


mdns_pattern = re.compile(r"\b(?:[a-zA-Z0-9_-]+\.)*local\.?\b")


# Controlling agent must know remote user credentials
class Agent(AsyncEventEmitter, ObservedComponent):
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
        self._gathering_complete = asyncio.Event()

    async def aclose(self) -> None:
        await self.aclose_controllers()
        for transport in reversed(self._candidate_pair_transports):
            closer = getattr(transport, "aclose", None) or getattr(transport, "close", None)
            if closer is not None:
                result = closer()
                if inspect.isawaitable(result):
                    await result
        self._candidate_pair_transports.clear()
        await self._udp.aclose()
        await super().aclose()

    async def aclose_controllers(self) -> None:
        for controller in reversed(self._controller_registry.controllers()):
            await controller.aclose()

    @event_loop
    def set_on_candidate(self, on_candidate: Callable[[CandidateBase], None]):
        self._on_candidate = on_candidate

    async def _gather_host_candidate(self):
        for _, handler in self._udp.inbound_handlers().items():
            candidate = CandidateBase()

            mux = self._udp.bind(self._local_ufrag, handler, candidate)
            await self._add_local_candidate(LocalCandidate(candidate, mux))

            if self._on_candidate:
                self._on_candidate(candidate)

    @perf_measured_async("ice", "gather")
    async def gather_candidates(self):
        coros = []
        for candidate_type in self._options.candidate_types:
            match candidate_type:
                case CandidateType.Host:
                    coros.append(
                        self._gather_host_candidate()
                    )
                case _:
                    pass
        await asyncio.gather(*coros)
        self._gathering_complete.set()

    @event_loop
    def _on_nominate_pair(self, pair: CandidatePair):
        get_logger().debug(
            Component.ICE,
            "Candidate pair nominated",
            pair_id=pair.get_pair_id(),
        )

    @event_loop
    def _start_controller(self, pair: CandidatePair):
        if self._role == AgentRole.Controlling:
            selector = ControllingSelector(self._pair_registry, self._tie_breaker)
        else:
            selector = ControlledSelector(self._pair_registry, self._tie_breaker)

        # Create controller and register it to prevent duplicates
        pair_controller = CandidatePairController(pair, selector, self._tie_breaker)
        self._controller_registry.append(pair_controller)

        get_logger().debug(
            Component.ICE,
            "Emitting candidate pair controller",
            pair_id=pair.get_pair_id(),
        )
        self.emit(
            AgentEvent.CANDIDATE_PAIR_CONTROLLER,
            pair_controller,
        )

    # Look at func (s *controllingSelector) ContactCandidates() to know more
    @event_loop
    def connect(self, controlling: bool):
        if self._remote_ufrag is None or self._remote_pwd is None:
            raise RuntimeError("ICE remote credentials are not set")

        if controlling:
            self._role = AgentRole.Controlling
        else:
            self._role = AgentRole.Controlled

        get_logger().debug(
            Component.ICE,
            "Starting ICE connectivity checks",
            controlling=controlling,
            candidate_pair_count=len(self._pair_registry.get_pair_list()),
        )

        for id, pair in self._pair_registry.get_pair_list().items():
            controller = self._controller_registry.get(id)

            if controller:
                get_logger().debug(
                    Component.ICE,
                    "Candidate pair controller already exists",
                    pair_id=id,
                )
                continue

            self._start_controller(pair)

        return

    @event_loop
    def dial(self):
        "Initiates a connection to another peer"
        self._role = AgentRole.Controlling
        self.connect(True)

    @event_loop
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

        if mdns_pattern.search(remote.address):
            try:
                ip = socket.gethostbyname(remote.address)
                get_logger().debug(
                    Component.ICE,
                    "Resolved mDNS candidate address",
                    hostname=remote.address,
                    address=ip,
                )
                remote.set_address(ip)
            except socket.gaierror as exc:
                get_logger().error(
                    Component.ICE,
                    "Could not resolve mDNS candidate address",
                    hostname=remote.address,
                    error=str(exc),
                )
                raise

        # TODO: may be better provide some object ref that hold ufrag, pwd to make dynamic replacement of credentials
        pair = CandidatePair(
            self._local_ufrag,
            self._local_pwd,
            self._remote_ufrag,
            self._remote_pwd,
            local,
            RemoteCandidate(remote, remote_conn),
        )

        get_logger().debug(
            Component.ICE,
            "Added candidate pair",
            pair_id=pair.get_pair_id(),
        )

        self._pair_registry.append(pair)
        perf_mark("ice", "candidate_pair", "created", metadata=_pair_metadata(pair))

        # If role is already set (connect() was called), start controller for this new pair
        if self._role != AgentRole.Unknown:
            controller = self._controller_registry.get(pair.get_pair_id())
            if not controller:
                get_logger().debug(
                    Component.ICE,
                    "Starting controller for late-added candidate pair",
                    pair_id=pair.get_pair_id(),
                )
                self._start_controller(pair)

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

        perf_mark(
            "ice",
            "candidate",
            "gathered",
            metadata={**_candidate_metadata(local.unwrap), "counter.ice.candidates": 1},
        )

        remotes = self._remote_candidates.get(net_type)
        if remotes:
            for remote in remotes:
                await self._add_candidate_pair(local, remote)

    async def _add_remote_candidate(self, remote: CandidateBase):
        # async with self._candidate_lock:
        get_logger().debug(
            Component.ICE,
            "Adding remote candidate",
            address=remote.address,
            port=remote.port,
        )
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

        perf_mark("ice", "candidate", "remote_added", metadata=_candidate_metadata(remote))

        locals = self._local_candidates.get(net_type)
        if locals:
            for local in locals:
                await self._add_candidate_pair(local, remote)

    async def add_remote_candidate(self, candidate_raw: str):
        remote = parse_candidate_str(candidate_raw)
        if not remote:
            return
        await self._add_remote_candidate(remote)

    @event_loop
    def get_local_credentials(self) -> tuple[str, str]:
        return (self._local_ufrag, self._local_pwd)

    # TODO: may remote this
    @event_loop
    def set_remote_credentials(self, ufrag: str, pwd: str):
        self._remote_ufrag = ufrag
        self._remote_pwd = pwd
        perf_mark(
            "ice",
            "remote_credentials",
            "set",
            metadata={"remote_ufrag": ufrag, "password_length": len(pwd)},
        )

    @event_loop
    def get_role(self) -> AgentRole:
        return self._role

    @event_loop
    def _has_succeeded_candidate_pair(self) -> bool:
        return any(
            pair.state == CandidatePairState.SUCCEEDED
            for pair in self._pair_registry.get_pair_list().values()
        )

    @event_loop
    def _has_nominated_pair(self) -> bool:
        return any(
            controller.nominated
            for controller in self._controller_registry.controllers()
        )

    @event_loop
    def _has_nominated_transport_ready(self) -> bool:
        return self._has_nominated_pair()

    async def wait(self, condition: ICECondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        match condition:
            case ICECondition.GATHERING_COMPLETE:
                await wait_for_event(self._gathering_complete, timeout=timeout)
            case ICECondition.CANDIDATE_PAIR_SUCCEEDED:
                await wait_until(
                    self._has_succeeded_candidate_pair,
                    timeout=timeout,
                )
            case ICECondition.NOMINATED:
                await wait_until(self._has_nominated_pair, timeout=timeout)
            case ICECondition.NOMINATED_TRANSPORT_READY:
                await wait_until(
                    self._has_nominated_transport_ready,
                    timeout=timeout,
                )
            case _:
                raise ValueError(f"unsupported ICE condition: {condition}")
