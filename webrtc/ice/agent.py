import socket
import re
import asyncio
import hashlib
import secrets
import queue
from datetime import datetime, timedelta
import time

from dataclasses import dataclass, replace as dataclass_replace
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
from webrtc.utils import impl_protocol
from webrtc.logger import get_logger, Component
from webrtc.config import get_config
from webrtc.runtime_services import (
    FailurePolicy, OwnedTaskHandle, current_execution_scope,
)
from webrtc.machine_specs import MACHINE_SPECS
from webrtc.state_machine import (
    InlineStateMachineRunner, MachineCommand, PreparedTransition, ReplyPort,
    TransitionCommit,
)
from webrtc.lifecycle import ICECondition, require_timeout, wait_until
from webrtc.tracing import perf_mark, perf_measured_async

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
    return _observable_pair_id_value(pair.entity_id)


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


class _PairCommand(StrEnum):
    WAIT = "wait"
    CHECK = "check"
    SUCCEED = "succeed"
    NOMINATE = "nominate"
    FAIL = "fail"
    CLOSE = "close"


@dataclass(frozen=True, slots=True)
class CandidatePairSnapshot:
    state: str
    local: LocalCandidate
    remote: RemoteCandidate
    nominated: bool = False


class _CandidatePairRunner(
    InlineStateMachineRunner
):
    async def step(self, command: MachineCommand[object, TransitionCommit]):
        proposed = {
            _PairCommand.WAIT: "waiting", _PairCommand.CHECK: "in-progress",
            _PairCommand.SUCCEED: "succeeded", _PairCommand.NOMINATE: "nominated",
            _PairCommand.FAIL: "failed", _PairCommand.CLOSE: "closed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported candidate-pair command: {command.kind}")
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )


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
        self._success_commit: TransitionCommit | None = None
        self._nomination_commit: TransitionCommit | None = None
        self._authority = CandidatePairSnapshot("frozen", local, remote)
        self._runtime = current_execution_scope()
        raw_pair_key = (
            f"{self.local_candidate.unwrap.to_ice_str()}:"
            f"{self.remote_candidate.unwrap.to_ice_str()}"
        )
        base = (
            self._runtime.allocate_domain_entity_id("candidate-pair")
            if hasattr(self._runtime, "allocate_domain_entity_id")
            else f"candidate-pair:{secrets.token_hex(6)}"
        )
        self.entity_id = f"{base}:{_observable_pair_id_value(raw_pair_key)}"
        self._command_id = 0
        self._runner = _CandidatePairRunner(
            MACHINE_SPECS["candidate-pair"], entity_id=self.entity_id,
            mailbox_capacity=8,
            controller=getattr(self._runtime, "transition_controller", None),
            transition_sink=self._on_transition,
        )
        if hasattr(self._runtime, "start_machine"):
            self._machine_handle = self._runtime.compose_domain_runner(
                self, self._runner, role="candidate-pair", bind=False,
                commit_sink=self._on_transition,
            )
            self._submit(_PairCommand.WAIT)
        else:
            self._machine_handle = None

    def _on_transition(self, commit: TransitionCommit) -> None:
        if commit.to_state == "succeeded":
            self._success_commit = commit
        elif commit.to_state == "nominated":
            self._nomination_commit = commit
        self._authority = dataclass_replace(
            self._authority, state=commit.to_state,
            nominated=commit.to_state == "nominated",
        )

    def _submit(
        self, kind: _PairCommand, *, cause_id: object | None = None,
        reply: ReplyPort[TransitionCommit] | None = None,
    ) -> None:
        self._command_id += 1
        self._runner.try_submit(MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        ))

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

    @property
    def state(self) -> CandidatePairState:
        """Compatibility projection of the authoritative pair snapshot."""
        return {
            "frozen": CandidatePairState.UNSET,
            "waiting": CandidatePairState.WAITING,
            "in-progress": CandidatePairState.INPROGRESS,
            "succeeded": CandidatePairState.SUCCEEDED,
            "nominated": CandidatePairState.SUCCEEDED,
            "failed": CandidatePairState.FAILED,
            "closed": CandidatePairState.FAILED,
        }[self._authority.state]

    @property
    def pair_snapshot(self) -> CandidatePairSnapshot:
        return self._authority

    async def mark_succeeded(self, cause_id: object) -> TransitionCommit:
        state = self._authority.state
        if state == "succeeded":
            if self._success_commit is None:
                raise RuntimeError("pair success provenance is unavailable")
            return self._success_commit
        if state in {"frozen", "waiting"}:
            checked = ReplyPort[TransitionCommit]()
            self._submit(_PairCommand.CHECK, cause_id=cause_id, reply=checked)
            await checked.wait()
        reply = ReplyPort[TransitionCommit]()
        self._submit(_PairCommand.SUCCEED, cause_id=cause_id, reply=reply)
        return await reply.wait()

    async def mark_nominated(self, success: TransitionCommit) -> TransitionCommit:
        if (
            success.entity_id != self.entity_id
            or success.machine_type != "candidate-pair"
            or success.to_state != "succeeded"
            or success.revision != self._runner.snapshot().revision
        ):
            raise RuntimeError("nomination requires the exact current pair success commit")
        reply = ReplyPort[TransitionCommit]()
        self._submit(_PairCommand.NOMINATE, cause_id=success.cause, reply=reply)
        return await reply.wait()

    async def mark_failed(self, cause_id: object) -> TransitionCommit:
        reply = ReplyPort[TransitionCommit]()
        self._submit(_PairCommand.FAIL, cause_id=cause_id, reply=reply)
        return await reply.wait()

    async def aclose(self) -> None:
        if self._machine_handle is None or self._authority.state == "closed":
            return
        reply = ReplyPort[TransitionCommit]()
        self._submit(_PairCommand.CLOSE, reply=reply)
        await reply.wait()
        await self._machine_handle.wait()
        self._runtime.remove_owner(self.entity_id, self._runner.epoch)

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
        "candidate_id": "candidate:" + _observable_pair_id_value(
            candidate.to_ice_str()
        ),
        "network_type": candidate.get_network_type().value,
        "candidate_type": getattr(candidate, "candidate_type", None),
        "priority": candidate.priority,
    }


def _pair_metadata(pair: CandidatePair) -> dict[str, object]:
    return {
        "pair_id": pair.entity_id,
    }


class CandidatePairRegistry:
    def __init__(self) -> None:
        self._check_list = dict[str, CandidatePair]()

    def append(self, pair: CandidatePair):
        self._check_list[pair.entity_id] = pair

    def best_pair_priority(self, controlling: bool) -> CandidatePair | None:
        best: CandidatePair | None = None

        for _, pair in self._check_list.items():
            if pair.pair_snapshot.state not in {"succeeded", "nominated"}:
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
    monotonic_timestamp: float = 0.0
    use_candidate_attr: bool = False


MAX_BINDING_REQUEST_TIMEOUT = timedelta(milliseconds=4000)


class BindingRequestCacheRegistry:
    def __init__(self) -> None:
        self._registry = dict[bytes, BindingCachedMessage]()

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
        """Cache on the ICE controller loop; no competing writer is permitted."""
        now = datetime.now()
        self.invalidate_pending_binding_requests(now)
        cache = BindingCachedMessage(msg, dst, now, time.monotonic())
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

    async def aclose(self): ...


class ControllingSelector:
    def __init__(
        self, pair_registry: CandidatePairRegistry, tie_breaker: int,
        nominate: Callable[[CandidatePair], Any] | None = None,
    ) -> None:

        self._nominated_pair: CandidatePair | None = None
        self._start_time: datetime | None = None
        self._pair_registry = pair_registry
        self._tie_breaker = tie_breaker
        self._local_binding_cache = BindingRequestCacheRegistry()
        self._nominate = nominate

    async def aclose(self) -> None:
        return None

    def start(self):
        self._start_time = datetime.now()
        self._nominated_pair = None
        get_logger().debug(Component.ICE, "Started controlling ICE selector")

    async def _set_nominate_pair(self, pair: CandidatePair):
        get_logger().debug(
            Component.ICE,
            "Nominating candidate pair",
            pair_id=pair.entity_id,
        )
        self._nominated_pair = pair
        if self._nominate is not None:
            await self._nominate(pair)

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
            pair_id=pair.entity_id,
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
        if (
            pair.pair_snapshot.state in {"succeeded", "nominated"}
            and self._nominated_pair is None
        ):
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
                pair_id=pair.entity_id,
            )
            raise ValueError(
                f"discarded STUN response for {pair.entity_id}: unknown transaction"
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
                pair_id=pair.entity_id,
            )
            raise ValueError(
                f"discarded STUN response for {pair.entity_id}: unexpected source"
            )

        success = await pair.mark_succeeded(
            f"{pair.entity_id}:stun-success:{bytes(msg.transaction_id).hex()}"
        )
        perf_mark("ice", "candidate_pair", "succeeded", metadata=_pair_metadata(pair))
        perf_mark("ice", "stun", "success", metadata={**_pair_metadata(pair), "counter.ice.stun_success": 1})

        if binding_request.use_candidate_attr and self._nominated_pair is None:
            await self._set_nominate_pair(pair)

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


class ControlledSelector:
    def __init__(
        self, pair_registry: CandidatePairRegistry, tie_breaker: int,
        nominate: Callable[[CandidatePair], Any] | None = None,
    ) -> None:

        self._pair_registry = pair_registry
        self._tie_breaker = tie_breaker
        self._selected_pair: CandidatePair | None = None
        self._local_binding_cache = BindingRequestCacheRegistry()
        self._nominate = nominate

    async def aclose(self) -> None:
        return None

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
                    pair_id=pair.entity_id,
                )
                perf_mark(
                    "ice",
                    "candidate_pair",
                    "nominated",
                    metadata=_pair_metadata(pair),
                )
                success = await pair.mark_succeeded(
                    f"{pair.entity_id}:use-candidate:{bytes(msg.transaction_id).hex()}"
                )
                self._selected_pair = pair
                if self._nominate is not None:
                    await self._nominate(pair, success)
            elif self._selected_pair != pair:
                get_logger().debug(
                    Component.ICE,
                    "Ignoring lower-priority nominated candidate pair",
                    pair_id=pair.entity_id,
                    selected_pair_id=self._selected_pair.entity_id,
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
        success = await pair.mark_succeeded(
            f"{pair.entity_id}:stun-success:{bytes(msg.transaction_id).hex()}"
        )
        perf_mark("ice", "candidate_pair", "succeeded", metadata=_pair_metadata(pair))
        perf_mark("ice", "stun", "success", metadata={**_pair_metadata(pair), "counter.ice.stun_success": 1})

        if pair._nominate_on_binding:
            if self._selected_pair is None or self._selected_pair.get_pair_priority(
                False
            ) < pair.get_pair_priority(False):
                get_logger().debug(
                    Component.ICE,
                    "Nominating candidate pair",
                    pair_id=pair.entity_id,
                )
                perf_mark(
                    "ice",
                    "candidate_pair",
                    "nominated",
                    metadata=_pair_metadata(pair),
                )
                self._selected_pair = pair
                if self._nominate is not None:
                    await self._nominate(pair, success)
            elif self._selected_pair != pair:
                get_logger().debug(
                    Component.ICE,
                    "Ignoring lower-priority nominated candidate pair",
                    pair_id=pair.entity_id,
                    selected_pair_id=self._selected_pair.entity_id,
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
    def __init__(self, conn: MuxConnProtocol, pair: CandidatePair) -> None:
        if not isinstance(pair, CandidatePair):
            raise TypeError("pair must be a CandidatePair")
        self._conn: MuxConnProtocol = conn
        self.pair = pair
        self.entity_id = pair.entity_id
        set_trace_pair_id = getattr(conn, "set_trace_pair_id", None)
        if set_trace_pair_id is not None:
            set_trace_pair_id(self.entity_id)

        # self._rtp = queue.Queue[Packet]()
        # self._rtcp = queue.Queue[Packet]()
        self._rtp = Interceptor(maxsize=2048, drop_oldest=True, queue_id="ice-rtp")
        self._rtcp = Interceptor(queue_id="ice-rtcp")
        self._dtls = Interceptor(queue_id="ice-dtls")

    def _demux_metadata(self, packet_kind: str, pkt: Packet) -> dict[str, object]:
        metadata: dict[str, object] = {
            "flow_direction": "rx", "packet_kind": packet_kind,
            "size_bytes": len(pkt.data),
        }
        metadata["pair_id"] = self.entity_id
        return metadata

    def pipe(self, pkt: Packet):
        if not pkt.data:
            self._demux_failed(pkt, "empty")
        first_byte = pkt.data[0]
        if not (20 <= first_byte < 64 or 128 <= first_byte < 192):
            self._demux_failed(pkt, "unsupported")

        if first_byte > 19 and first_byte < 64:
            # DTLS packet
            self._queue_demuxed_packet(self._dtls, pkt, "dtls")
            perf_mark(
                "ice", "packet_demux", "dtls",
                metadata={**self._demux_metadata("dtls", pkt), "counter.ice.demux_dtls": 1},
            )
        elif net.is_rtcp(pkt.data):
            if len(pkt.data) < 4:
                self._demux_failed(pkt, "malformed_rtcp")
            # RTCP packet
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

            # Header-only extraction is deliberately outside the UDP callback.
            seq = int.from_bytes(pkt.data[2:4], "big")
            ssrc = int.from_bytes(pkt.data[8:12], "big")
            rtp_metadata = self._demux_metadata("rtp", pkt)
            rtp_metadata.update({"ssrc": ssrc, "sequence_number": seq})
            self._queue_demuxed_packet(self._rtp, pkt, "rtp")
            perf_mark(
                "ice", "packet_demux", "rtp",
                metadata={**rtp_metadata, "counter.ice.demux_rtp": 1},
            )


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

    async def aclose(self) -> None:
        for queue in (self._rtp, self._rtcp, self._dtls):
            await queue.aclose()
        closer = getattr(self._conn, "aclose", None)
        if closer is not None:
            await closer()


class CandidatePairControllerEvent(StrEnum):
    NOMINATE_TRANSPORT = "nominate-transport"


class _ControllerCommand(StrEnum):
    START = "start"
    CHECK = "check"
    NOMINATE = "nominate"
    FORWARD = "forward"
    FAIL = "fail"
    CLOSE = "close"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class CandidatePairControllerSnapshot:
    state: str
    pair: CandidatePairSnapshot
    transport: CandidatePairTransport | None = None
    nominated: bool = False


class _CandidatePairControllerRunner(
    InlineStateMachineRunner
):
    def __init__(self, owner: "CandidatePairController", **kwargs: Any) -> None:
        super().__init__(MACHINE_SPECS["candidate-pair-controller"], **kwargs)
        self.owner = owner

    async def step(self, command: MachineCommand[object, TransitionCommit]):
        state = self.snapshot().state
        if command.kind == _ControllerCommand.START:
            proposed = "starting"
        elif command.kind == _ControllerCommand.CHECK:
            proposed = "checking"
        elif command.kind == _ControllerCommand.NOMINATE:
            if state == "nominated":
                raise RuntimeError("candidate pair controller is already nominated")
            proposed = "nominated"
        elif command.kind == _ControllerCommand.FORWARD:
            proposed = "forwarding"
        elif command.kind == _ControllerCommand.FAIL:
            proposed = "failed"
        elif command.kind == _ControllerCommand.CLOSE:
            proposed = "stopping"
        elif command.kind == _ControllerCommand.STOPPED:
            proposed = "stopped"
        else:
            raise ValueError(f"unsupported controller command: {command.kind}")
        return PreparedTransition(
            state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def commit(self, proposed, cause=None):
        commit = super().commit(proposed, cause)
        self.owner._commit_authority(commit)
        return commit

    async def after_commit(self, commit: TransitionCommit, effects: Any) -> None:
        if commit.to_state == "starting":
            self.owner._runner.try_submit(self.owner._command(_ControllerCommand.CHECK))
        elif commit.to_state == "checking":
            self.owner._launch_receive_pump()
        elif commit.to_state == "nominated":
            await self.owner._publish_nomination(commit, effects)
            self.owner._runner.try_submit(self.owner._command(
                _ControllerCommand.FORWARD, cause_id=commit.cause,
            ))
        elif commit.to_state == "stopping":
            await self.owner._reconcile_controller()
            self.owner._runner.try_submit(self.owner._command(_ControllerCommand.STOPPED))
        elif commit.to_state == "failed":
            await self.owner._publish_failure(commit, effects)
            self.owner._runner.try_submit(self.owner._command(
                _ControllerCommand.CLOSE, cause_id=commit.cause,
            ))


class CandidatePairController:
    def __init__(
        self, pair: CandidatePair, selector: SelectorProtocol, tie_breaker: int,
        *, owner: "Agent",
    ) -> None:
        self._pair = pair
        self.__selector = selector
        self.__tie_breaker = tie_breaker
        self.__conn = pair.local_candidate.mux.intercept(
            self._pair.remote_candidate.unwrap
        )
        self.__transport = CandidatePairTransport(
            self.__conn, pair,
        )
        self._owner = owner
        self._authority = CandidatePairControllerSnapshot("new", pair.pair_snapshot)
        self._receive_handle: OwnedTaskHandle[None] | None = None
        self._receive_start_waiter: asyncio.Future[
            OwnedTaskHandle[None] | BaseException
        ] | None = None
        self._receive_start_error: BaseException | None = None
        self._command_id = 0
        scope = current_execution_scope()
        self._runtime = scope if hasattr(scope, "start_machine") else None
        hint = getattr(owner, "entity_id", None)
        base = (
            self._runtime.allocate_domain_entity_id("candidate-pair-controller", hint=hint)
            if self._runtime is not None
            else f"candidate-pair-controller:{hint or secrets.token_hex(6)}"
        )
        self.entity_id = f"{base}:{_observable_pair_id(pair)}"
        self._runner = _CandidatePairControllerRunner(
            self, entity_id=self.entity_id, mailbox_capacity=32,
            controller=getattr(scope, "transition_controller", None),
            transition_sink=None,
        )
        if self._runtime is not None:
            self._machine_handle = self._runtime.compose_domain_runner(
                self, self._runner, role="candidate-pair-controller",
                adapter_name="ice_nomination", capture_name="capture_ice_nomination",
            )
            self._owner_removed = False
        else:
            self._machine_handle = None
            self._owner_removed = True

    def _commit_authority(self, commit: TransitionCommit) -> None:
        self._authority = CandidatePairControllerSnapshot(
            commit.to_state,
            self._pair.pair_snapshot,
            self.__transport if commit.to_state in {"nominated", "forwarding"} else None,
            commit.to_state in {"nominated", "forwarding"},
        )

    @property
    def controller_snapshot(self) -> CandidatePairControllerSnapshot:
        return self._authority

    async def __pair_nominate(
        self, pair: CandidatePair, success: TransitionCommit | None = None,
    ) -> None:
        if pair is not self._pair or self._authority.state != "checking":
            return
        if success is None:
            success = await pair.mark_succeeded(
                f"{self.entity_id}:connectivity-success"
            )
        pair_commit = await pair.mark_nominated(success)
        self._runner.try_submit(self._command(
            _ControllerCommand.NOMINATE, pair_commit, cause_id=pair_commit.cause,
        ))

    async def _publish_nomination(
        self, commit: TransitionCommit, pair_commit: object,
    ) -> None:
        get_logger().debug(
            Component.ICE, "Committed nominated transport",
            pair_id=self._pair.entity_id,
        )
        if not isinstance(pair_commit, TransitionCommit) or (
            pair_commit.entity_id != self._pair.entity_id
            or pair_commit.machine_type != "candidate-pair"
            or pair_commit.to_state != "nominated"
            or pair_commit.revision != self._pair._runner.snapshot().revision
            or pair_commit.cause != commit.cause
        ):
            raise RuntimeError("controller nomination lost its exact pair origin")
        await self._owner._controller_nominated(self.__transport, pair_commit)

    async def _publish_failure(
        self, commit: TransitionCommit, error: object,
    ) -> None:
        # Pair state is a sibling publication.  Its rejection must not prevent
        # the authoritative controller/agent/public-ICE failure chain.
        try:
            await self._pair.mark_failed(commit.cause)
        except Exception:
            pass
        failure = error if isinstance(error, BaseException) else RuntimeError(
            "candidate pair controller failed"
        )
        await self._owner._controller_failed(failure, commit)

    def _command(
        self, kind: _ControllerCommand, payload: object = None,
        reply: ReplyPort[TransitionCommit] | None = None,
        cause_id: object | None = None,
    ) -> MachineCommand[object, TransitionCommit]:
        self._command_id += 1
        return MachineCommand(
            kind, self._command_id, self._runner.epoch, payload, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        )

    async def _receive_loop(self):
        self.__selector.start()
        controller_metadata = {
            "pair_id": self._pair.entity_id, "flow_direction": "rx",
        }
        perf_mark(
            "ice", "controller", "loop_started",
            metadata=controller_metadata,
        )
        await self.ping_remote_candidate()

        get_logger().debug(
            Component.ICE,
            "Started candidate pair selector",
            pair_id=self._pair.entity_id,
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
            except asyncio.CancelledError:
                raise
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
                if self._authority.state != "stopped":
                    try:
                        self._runner.try_submit(self._command(
                            _ControllerCommand.FAIL, exc,
                            cause_id=f"{self.entity_id}:receive-failure",
                        ))
                    except Exception:
                        pass
                return

    def _launch_receive_pump(self) -> None:
        if self._runtime is None:
            error = RuntimeError("candidate pair controller requires an active Runtime")
            self._reject_receive_start(error)
            raise error
        if self._receive_handle is None:
            try:
                self._receive_handle = self._runtime.start_pump(
                    self._receive_loop, owner_entity_id=self.entity_id,
                    owner_epoch=self._runner.epoch,
                    name="ice:candidate-pair-receive", kind="ice",
                    failure=FailurePolicy.FAIL_CONNECTION,
                    metadata={"loop_role": "receive"},
                )
            except BaseException as error:
                self._reject_receive_start(error)
                raise
            self._resolve_receive_start(self._receive_handle)

    def _receive_start_future(
        self,
    ) -> asyncio.Future[OwnedTaskHandle[None] | BaseException]:
        if self._receive_start_waiter is None:
            self._receive_start_waiter = asyncio.get_running_loop().create_future()
            if self._receive_handle is not None:
                self._receive_start_waiter.set_result(self._receive_handle)
            elif self._receive_start_error is not None:
                self._receive_start_waiter.set_result(self._receive_start_error)
        return self._receive_start_waiter

    def _resolve_receive_start(self, handle: OwnedTaskHandle[None]) -> None:
        waiter = self._receive_start_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(handle)

    def _reject_receive_start(self, error: BaseException) -> None:
        if self._receive_handle is not None or self._receive_start_error is not None:
            return
        self._receive_start_error = error
        waiter = self._receive_start_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(error)

    async def start_managed(self) -> OwnedTaskHandle[None]:
        state = self._authority.state
        if state in {"checking", "nominated", "forwarding"} and self._receive_handle is not None:
            return self._receive_handle
        if state != "new":
            raise RuntimeError(f"candidate pair controller cannot start from {state}")
        # Selector outcomes are typed ingress into this controller; they never
        # execute peer callbacks from packet parsing code.
        self.__selector._nominate = self.__pair_nominate
        receive_start = self._receive_start_future()
        reply = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(_ControllerCommand.START, reply=reply))
        await reply.wait()
        outcome = await asyncio.shield(receive_start)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def _reconcile_controller(self) -> None:
        self._reject_receive_start(RuntimeError(
            "candidate pair controller closed before its receive pump started"
        ))
        if self._receive_handle is not None:
            self._receive_handle.cancel()
            try:
                await self._receive_handle.wait()
            except (asyncio.CancelledError, Exception):
                pass
            self._receive_handle = None
        await self.__selector.aclose()

    async def aclose(self) -> None:
        if self._authority.state == "stopped":
            if self._runtime is not None and not self._owner_removed:
                assert self._machine_handle is not None
                await self._machine_handle.wait()
                self._runtime.remove_owner(self.entity_id, self._runner.epoch)
                self._owner_removed = True
            return
        state = self._authority.state
        if state == "failed":
            pass
        reply = ReplyPort[TransitionCommit]()
        self._runner.try_submit(self._command(_ControllerCommand.CLOSE, reply=reply))
        await reply.wait()
        await self._runner.wait_terminal()
        if self._runtime is not None:
            assert self._machine_handle is not None
            await self._machine_handle.wait()
            self._runtime.remove_owner(self.entity_id, self._runner.epoch)
            self._owner_removed = True

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

    def get_transport(self) -> CandidatePairTransport:
        return self.__transport

    @property
    def nominated(self) -> bool:
        return self._authority.nominated


class CandidatePairControllerRegistry:
    def __init__(self) -> None:
        self._check_list = dict[str, CandidatePairController]()

    def append(self, controller: CandidatePairController):
        pair = controller._pair
        self._check_list[pair.entity_id] = controller

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


class _AgentCommand(StrEnum):
    WAIT_REMOTE = "wait-remote"
    CHECK = "check"
    CONNECT = "connect"
    COMPLETE = "complete"
    DISCONNECT = "disconnect"
    FAIL = "fail"
    CLOSE = "close"


@dataclass(frozen=True, slots=True)
class AgentProtocolSnapshot:
    """ICE fields used by credential, role, pair and transport admission."""

    state: str = "new"
    role: AgentRole = AgentRole.Unknown
    remote_credentials: tuple[str, str] | None = None
    local_candidates: tuple[LocalCandidate, ...] = ()
    remote_candidates: tuple[CandidateBase, ...] = ()
    candidate_pairs: tuple[CandidatePair, ...] = ()
    controllers: tuple[CandidatePairController, ...] = ()
    selected_transports: tuple[CandidatePairTransport, ...] = ()

class _AgentRunner(InlineStateMachineRunner):
    def __init__(self, owner: "Agent", *args, **kwargs) -> None:
        self.owner = owner
        super().__init__(*args, **kwargs)

    async def step(self, command: MachineCommand[object, TransitionCommit]):
        proposed = {
            _AgentCommand.WAIT_REMOTE: "waiting-remote",
            _AgentCommand.CHECK: "checking", _AgentCommand.CONNECT: "connected",
            _AgentCommand.COMPLETE: "completed",
            _AgentCommand.DISCONNECT: "disconnected",
            _AgentCommand.FAIL: "failed", _AgentCommand.CLOSE: "closed",
        }.get(command.kind)
        if proposed is None:
            raise ValueError(f"unsupported ICE-agent command: {command.kind}")
        return PreparedTransition(
            self.snapshot().state, proposed, command.payload, command.cause_id,
            command.expected_epoch, command.expected_revision,
        )

    def commit(self, proposed, cause=None):
        commit = super().commit(proposed, cause)
        self.owner._protocol = dataclass_replace(
            self.owner._protocol, state=commit.to_state,
        )
        return commit


# Controlling agent must know remote user credentials
class Agent:
    def __init__(
        self, options: AgentOptions, *, owner: Any,
    ) -> None:

        self._tie_breaker = generate_tie_breaker()
        self._local_ufrag = generate_ufrag()
        self._local_pwd = generate_pwd()
        self._protocol = AgentProtocolSnapshot()

        self._options = options
        self._udp = options.udp
        self._loop = asyncio.get_event_loop()
        self._on_candidate: Callable[[CandidateBase], None] | None = None

        self._local_candidates = dict[NetworkType, list[LocalCandidate]]()
        self._remote_candidates = dict[NetworkType, list[CandidateBase]]()

        self._pair_registry = CandidatePairRegistry()
        self._controller_registry = CandidatePairControllerRegistry()

        self._candidate_pair_transports = list[CandidatePairTransport]()
        self._owner = owner
        scope = current_execution_scope()
        self._runtime = scope if hasattr(scope, "start_machine") else None
        hint = getattr(owner, "entity_id", None)
        self.entity_id = (
            self._runtime.allocate_domain_entity_id("ice-agent", hint=hint)
            if self._runtime is not None
            else f"ice-agent:{hint or secrets.token_hex(6)}"
        )
        self._command_id = 0
        self._runner = _AgentRunner(
            self,
            MACHINE_SPECS["ice-agent"], entity_id=self.entity_id,
            mailbox_capacity=32,
            controller=getattr(scope, "transition_controller", None),
            transition_sink=None,
        )
        if self._runtime is not None:
            self._machine_handle = self._runtime.compose_domain_runner(
                self, self._runner, role="ice-agent",
            )
            self._submit_lifecycle(_AgentCommand.WAIT_REMOTE)
        else:
            self._machine_handle = None

    def _submit_lifecycle(
        self, kind: _AgentCommand, *, cause_id: object | None = None,
        reply: ReplyPort[TransitionCommit] | None = None,
    ) -> None:
        if self._machine_handle is None:
            return
        self._command_id += 1
        self._runner.try_submit(MachineCommand(
            kind, self._command_id, self._runner.epoch, None, reply,
            expected_revision=None,
            cause_id=cause_id or f"{self.entity_id}:{self._command_id}",
        ))

    async def aclose(self) -> None:
        await self.aclose_controllers()
        for transport in reversed(self._protocol.selected_transports):
            async_closer = getattr(transport, "aclose", None)
            if async_closer is not None:
                await async_closer()
            elif (closer := getattr(transport, "close", None)) is not None:
                closer()
        self._candidate_pair_transports.clear()
        for pair in reversed(self._protocol.candidate_pairs):
            await pair.aclose()
        await self._udp.aclose()
        if self._machine_handle is not None and self._protocol.state != "closed":
            reply = ReplyPort[TransitionCommit]()
            self._submit_lifecycle(_AgentCommand.CLOSE, reply=reply)
            await reply.wait()
            await self._machine_handle.wait()
            self._runtime.remove_owner(self.entity_id, self._runner.epoch)

    async def aclose_controllers(self) -> None:
        for controller in reversed(self._protocol.controllers):
            await controller.aclose()

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

    def _on_nominate_pair(self, pair: CandidatePair):
        get_logger().debug(
            Component.ICE,
            "Candidate pair nominated",
            pair_id=pair.entity_id,
        )

    def _start_controller(self, pair: CandidatePair):
        if self._protocol.role == AgentRole.Controlling:
            selector = ControllingSelector(self._pair_registry, self._tie_breaker)
        else:
            selector = ControlledSelector(self._pair_registry, self._tie_breaker)

        # Create controller and register it to prevent duplicates
        pair_controller = CandidatePairController(
            pair, selector, self._tie_breaker, owner=self,
        )
        self._protocol = dataclass_replace(
            self._protocol,
            controllers=(*self._protocol.controllers, pair_controller),
        )
        self._controller_registry.append(pair_controller)

        get_logger().debug(
            Component.ICE,
            "Emitting candidate pair controller",
            pair_id=pair.entity_id,
        )
        self._owner._on_controller(pair_controller)

    async def _controller_nominated(
        self, transport: CandidatePairTransport, commit: TransitionCommit,
    ) -> None:
        if (
            commit.machine_type != "candidate-pair"
            or commit.to_state != "nominated"
            or transport.entity_id != commit.entity_id
            or commit.entity_id not in {
                pair.entity_id for pair in self._protocol.candidate_pairs
            }
        ):
            raise RuntimeError("agent requires an exact registered pair nomination")
        if transport not in self._protocol.selected_transports:
            self._protocol = dataclass_replace(
                self._protocol,
                selected_transports=(*self._protocol.selected_transports, transport),
            )
            self._candidate_pair_transports.append(transport)
        reply = ReplyPort[TransitionCommit]()
        self._submit_lifecycle(
            _AgentCommand.CONNECT, cause_id=commit.cause, reply=reply,
        )
        if self._machine_handle is not None:
            await reply.wait()
        await self._owner._on_nominated(transport, commit)

    async def _controller_failed(
        self, error: BaseException, commit: TransitionCommit,
    ) -> None:
        if self._machine_handle is None or self._protocol.state in {"failed", "closed"}:
            return
        reply = ReplyPort[TransitionCommit]()
        self._submit_lifecycle(
            _AgentCommand.FAIL, cause_id=commit.cause, reply=reply,
        )
        agent_commit = await reply.wait()
        await self._owner._on_agent_failure(error, agent_commit)

    async def fail(
        self, error: BaseException, *, cause_id: object | None = None,
    ) -> TransitionCommit | None:
        """Commit the sole public ICE failure and notify the peer owner once."""
        if self._machine_handle is None:
            return None
        if self._protocol.state in {"failed", "closed"}:
            return None
        reply = ReplyPort[TransitionCommit]()
        self._submit_lifecycle(_AgentCommand.FAIL, cause_id=cause_id, reply=reply)
        commit = await reply.wait()
        await self._owner._on_agent_failure(error, commit)
        return commit

    # Look at func (s *controllingSelector) ContactCandidates() to know more
    def connect(self, controlling: bool):
        if self._protocol.remote_credentials is None:
            raise RuntimeError("ICE remote credentials are not set")

        role = AgentRole.Controlling if controlling else AgentRole.Controlled
        self._protocol = dataclass_replace(self._protocol, role=role)
        self._submit_lifecycle(_AgentCommand.CHECK)

        get_logger().debug(
            Component.ICE,
            "Starting ICE connectivity checks",
            controlling=controlling,
            candidate_pair_count=len(self._protocol.candidate_pairs),
        )

        for pair in self._protocol.candidate_pairs:
            controller = next(
                (item for item in self._protocol.controllers
                 if item._pair.entity_id == pair.entity_id),
                None,
            )

            if controller:
                get_logger().debug(
                    Component.ICE,
                    "Candidate pair controller already exists",
                    pair_id=pair.entity_id,
                )
                continue

            self._start_controller(pair)

        return

    def dial(self):
        "Initiates a connection to another peer"
        self.connect(True)

    def accept(self):
        self.connect(False)

    def mark_completed(self) -> None:
        if self._protocol.state == "connected":
            self._submit_lifecycle(_AgentCommand.COMPLETE)

    def mark_disconnected(self) -> None:
        if self._protocol.state in {"connected", "completed"}:
            self._submit_lifecycle(_AgentCommand.DISCONNECT)

    def recheck(self) -> None:
        if self._protocol.state == "disconnected":
            self._submit_lifecycle(_AgentCommand.CHECK)

    async def get_local_candidates(self):
        return list(self._protocol.local_candidates)

    async def _add_candidate_pair(self, local: LocalCandidate, remote: CandidateBase):
        # async with self._candidate_pair_lock:
        remote_conn = local.mux.intercept(remote)

        credentials = self._protocol.remote_credentials
        if credentials is None:
            raise ValueError("Unable add canddiate ")

        if mdns_pattern.search(remote.address):
            try:
                ip = await self._resolve_mdns(remote.address)
                get_logger().debug(
                    Component.ICE,
                    "Resolved mDNS candidate address",
                    candidate_id=_candidate_metadata(remote)["candidate_id"],
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
            credentials[0],
            credentials[1],
            local,
            RemoteCandidate(remote, remote_conn),
        )

        get_logger().debug(
            Component.ICE,
            "Added candidate pair",
            pair_id=pair.entity_id,
        )

        self._protocol = dataclass_replace(
            self._protocol, candidate_pairs=(*self._protocol.candidate_pairs, pair),
        )
        self._pair_registry.append(pair)
        perf_mark("ice", "candidate_pair", "created", metadata=_pair_metadata(pair))

        # If role is already set (connect() was called), start controller for this new pair
        if self._protocol.role != AgentRole.Unknown:
            controller = next(
                (item for item in self._protocol.controllers
                 if item._pair.entity_id == pair.entity_id),
                None,
            )
            if not controller:
                get_logger().debug(
                    Component.ICE,
                    "Starting controller for late-added candidate pair",
                    pair_id=pair.entity_id,
                )
                self._start_controller(pair)

    async def _resolve_mdns(self, hostname: str, *, timeout: float = 2.0) -> str:
        scope = current_execution_scope()
        if scope is not self._runtime or self._runtime is None:
            raise RuntimeError("mDNS resolution requires an active owning Runtime")
        handle = scope.call_worker(
            socket.gethostbyname, hostname,
            owner_entity_id=self.entity_id, owner_epoch=self._runner.epoch,
            name="ice:resolve-mdns",
        )
        try:
            async with asyncio.timeout(timeout):
                result = await handle.wait()
        except TimeoutError:
            handle.cancel()
            try:
                await handle.wait()
            except BaseException:
                pass
            raise TimeoutError(f"mDNS resolution timed out: {hostname}")
        if result.outcome != "success":
            assert result.exception is not None
            raise result.exception
        return cast(str, result.value)

    async def _add_local_candidate(self, local: LocalCandidate):
        # async with self._candidate_lock:
        net_type = local.unwrap.get_network_type()
        if any(candidate == local for candidate in self._protocol.local_candidates):
            return
        pool = self._local_candidates.get(net_type)
        if pool is None:
            pool = list[LocalCandidate]()
            self._local_candidates[net_type] = pool

        self._protocol = dataclass_replace(
            self._protocol,
            local_candidates=(*self._protocol.local_candidates, local),
        )
        pool.append(local)

        perf_mark(
            "ice",
            "candidate",
            "gathered",
            metadata={**_candidate_metadata(local.unwrap), "counter.ice.candidates": 1},
        )

        remotes = tuple(
            candidate for candidate in self._protocol.remote_candidates
            if candidate.get_network_type() == net_type
        )
        if remotes:
            for remote in remotes:
                await self._add_candidate_pair(local, remote)

    async def _add_remote_candidate(self, remote: CandidateBase):
        # async with self._candidate_lock:
        get_logger().debug(
            Component.ICE,
            "Adding remote candidate",
            candidate_id=_candidate_metadata(remote)["candidate_id"],
        )
        net_type = remote.get_network_type()
        if any(candidate == remote for candidate in self._protocol.remote_candidates):
            return
        pool = self._remote_candidates.get(net_type)
        if pool is None:
            pool = list[CandidateBase]()
            self._remote_candidates[net_type] = pool

        self._protocol = dataclass_replace(
            self._protocol,
            remote_candidates=(*self._protocol.remote_candidates, remote),
        )
        pool.append(remote)

        perf_mark("ice", "candidate", "remote_added", metadata=_candidate_metadata(remote))

        locals = tuple(
            candidate for candidate in self._protocol.local_candidates
            if candidate.unwrap.get_network_type() == net_type
        )
        if locals:
            for local in locals:
                await self._add_candidate_pair(local, remote)

    async def add_remote_candidate(self, candidate_raw: str):
        remote = parse_candidate_str(candidate_raw)
        if not remote:
            return
        await self._add_remote_candidate(remote)

    def get_local_credentials(self) -> tuple[str, str]:
        return (self._local_ufrag, self._local_pwd)

    # TODO: may remote this
    def set_remote_credentials(self, ufrag: str, pwd: str):
        self._protocol = dataclass_replace(
            self._protocol, remote_credentials=(ufrag, pwd),
        )
        perf_mark(
            "ice",
            "remote_credentials",
            "set",
            metadata={},
        )

    def get_role(self) -> AgentRole:
        return self._protocol.role

    def protocol_snapshot(self) -> AgentProtocolSnapshot:
        return self._protocol

    def _has_succeeded_candidate_pair(self) -> bool:
        protocol = getattr(self, "_protocol", None)
        if protocol is None:  # lightweight protocol test doubles
            pairs = self._pair_registry.get_pair_list().values()
        else:
            pairs = protocol.candidate_pairs
        return any(
            (
                pair.pair_snapshot.state in {"succeeded", "nominated"}
                if hasattr(pair, "pair_snapshot")
                else pair.state == CandidatePairState.SUCCEEDED
            )
            for pair in pairs
        )

    def _has_nominated_pair(self) -> bool:
        protocol = getattr(self, "_protocol", None)
        if protocol is None:  # lightweight protocol test doubles
            return any(
                controller.nominated
                for controller in self._controller_registry.controllers()
            )
        return bool(protocol.selected_transports)

    def _has_nominated_transport_ready(self) -> bool:
        protocol = getattr(self, "_protocol", None)
        if protocol is None:  # lightweight protocol test doubles
            return self._has_nominated_pair()
        return bool(protocol.selected_transports)

    async def wait(self, condition: ICECondition, timeout: float) -> None:
        timeout = require_timeout(timeout)
        match condition:
            case ICECondition.GATHERING_COMPLETE:
                raise ValueError(
                    "gathering completion is owned by ICEGatherer"
                )
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
