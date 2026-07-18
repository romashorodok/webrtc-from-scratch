from __future__ import annotations

import asyncio
import weakref
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from enum import StrEnum
from typing import Any

from .runtime_services import MissingExecutionScope
from .state_machine import begin_observation_dispatch, end_observation_dispatch


class SemanticRole(StrEnum):
    COMPONENT = "component"
    PEER_CONNECTION = "peer-connection"
    CANDIDATE_PAIR_CONTROLLER = "candidate-pair-controller"
    CANDIDATE_PAIR = "candidate-pair"
    ICE_GATHERER = "ice-gatherer"
    ICE_AGENT = "ice-agent"
    DTLS_TRANSPORT = "dtls-transport"
    DTLS_HANDSHAKE = "dtls-handshake"
    DTLS_CONNECTION = "dtls-connection"
    SRTP_SESSION = "srtp-session"
    LOG_DRAIN = "log-drain"
    RTP_RECEIVER = "rtp-receiver"
    RTP_TRANSCEIVER = "rtp-transceiver"
    UDP_MUX = "udp-mux"
    AUDIO_ANALYZER = "audio-analyzer"
    RUNTIME = "runtime"
    WORKER_LANE = "worker-lane"
    SIGNALING = "signaling"
    SELECTED_TRANSPORT = "selected-transport"
    SIGNALING_ATTACHMENTS = "signaling-attachments"
    MEDIA_ATTACHMENTS = "media-attachments"
    MEDIA_SEND = "media-send"
    INFRASTRUCTURE = "infrastructure"


_ROLES_BY_COMPONENT_NAME = {
    "PeerConnection": SemanticRole.PEER_CONNECTION,
    "CandidatePairController": SemanticRole.CANDIDATE_PAIR_CONTROLLER,
    "Agent": SemanticRole.ICE_AGENT,
    "DTLSTransport": SemanticRole.DTLS_TRANSPORT,
    "FSM": SemanticRole.DTLS_HANDSHAKE,
    "DTLSConn": SemanticRole.DTLS_CONNECTION,
    "Session": SemanticRole.SRTP_SESSION,
    "AsyncLogDrain": SemanticRole.LOG_DRAIN,
    "RTPReceiver": SemanticRole.RTP_RECEIVER,
    "RTPTransceiver": SemanticRole.RTP_TRANSCEIVER,
    "MultiUDPMux": SemanticRole.UDP_MUX,
    "AudioAnalyzer": SemanticRole.AUDIO_ANALYZER,
}


def default_semantic_role(subject: object) -> SemanticRole:
    """Controlled compatibility role; never derived from instance identifiers."""
    return _ROLES_BY_COMPONENT_NAME.get(type(subject).__name__, SemanticRole.COMPONENT)


@dataclass(frozen=True, slots=True)
class ObservationBinding:
    """Runtime-owned observation metadata for one composed object."""

    entity_id: str
    role: SemanticRole
    entity_role: SemanticRole
    owner_epoch: int
    operation_policy: Mapping[str, Any]
    policy_is_authoritative: bool
    runtime_root_utility: bool


@dataclass(frozen=True, slots=True)
class MachineObservation:
    """Runtime sidecar translating immutable commits into projection records."""

    entity_id: str
    epoch: int
    machine_type: str
    capture_effect: Callable[[Any, Any, Any], Any] | None
    capture_subject: Any
    facet_values: Callable[[Any, Any], Mapping[str, Any] | None] | None
    owner_entity_id: str | None
    observer_meta: str
    failure_diagnostic: str


class _MachineObservationSink:
    __accepts_effects__ = True

    def __init__(self, registry: "ObservationRegistry", observation: MachineObservation):
        self._registry = registry
        self._observation = observation

    def __call__(self, commit: Any, effects: Any = None) -> None:
        try:
            capture = self._observation.capture_effect
            if capture is None:
                captured = effects
            else:
                token = begin_observation_dispatch()
                try:
                    captured = capture(
                        self._observation.capture_subject, commit, effects,
                    )
                finally:
                    end_observation_dispatch(token)
            self._registry.enqueue_commit(self._observation, commit, captured)
        except BaseException:
            try:
                with self._registry._runtime.diagnostics.suspend_notifications():
                    self._registry._runtime.diagnostics[
                        "observation_admission_failures"
                    ] += 1
            except Exception:
                pass

    async def flush(self) -> None:
        # Yield to the scheduled callback: adapters never execute on the
        # domain runner's call stack.
        await self._registry.flush()


class ObservationRegistry:
    """Identity sidecar; protocol objects never carry these trace attributes."""

    _registry_by_identity: dict[
        int, tuple[weakref.ReferenceType[Any], weakref.ReferenceType["ObservationRegistry"]]
    ] = {}

    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self._bindings: dict[int, tuple[weakref.ReferenceType[Any], ObservationBinding]] = {}
        self._retired: dict[int, tuple[weakref.ReferenceType[Any], ObservationBinding]] = {}
        self._owners: dict[tuple[str, int], set[int]] = {}
        self._machines: dict[tuple[str, int], MachineObservation] = {}
        self._pending: deque[tuple[MachineObservation, Any, Any]] = deque()
        self._flush_scheduled = False
        self._flushing = False

    def observe_machine(
        self, *, entity_id: str, spec: Any, epoch: int = 1,
        facet_values: Callable[[Any, Any], Mapping[str, Any] | None] | None = None,
        capture_effect: Callable[[Any, Any, Any], Any] | None = None,
        capture_subject: Any = None,
        owner_entity_id: str | None = None, observer_meta: str = "exact",
        failure_diagnostic: str = "facet_observation_failures",
    ) -> Callable[[Any], None]:
        """Register a machine and return its failure-isolated commit observer.

        Registration and projection are deliberately sidecar concerns.  A
        state owner receives only this sink and continues to commit when the
        projection is absent or broken.
        """
        observation = MachineObservation(
            entity_id, epoch, spec.machine_type, capture_effect, capture_subject,
            facet_values, owner_entity_id,
            observer_meta, failure_diagnostic,
        )
        self._machines[(entity_id, epoch)] = observation
        try:
            self._runtime.projection.machines.register(entity_id, spec, epoch=epoch)
        except Exception:
            with self._runtime.diagnostics.suspend_notifications():
                self._runtime.diagnostics["machine_observation_failures"] += 1

        return _MachineObservationSink(self, observation)

    def enqueue_commit(
        self, observation: MachineObservation, commit: Any, effects: Any,
    ) -> None:
        """Defer observation so projection can never re-enter a state commit."""
        self._pending.append((observation, commit, effects))
        if self._flush_scheduled:
            return
        self._flush_scheduled = True
        try:
            asyncio.get_running_loop().call_soon(self._flush)
        except BaseException:
            self._flush_scheduled = False
            raise

    def _flush(self) -> None:
        if self._flushing:
            return
        self._flush_scheduled = False
        self._flushing = True
        token = begin_observation_dispatch()
        try:
            while self._pending:
                observation, commit, effects = self._pending.popleft()
                try:
                    self._observe_commit(observation, commit, effects)
                except Exception:
                    with self._runtime.diagnostics.suspend_notifications():
                        self._runtime.diagnostics["observation_dispatch_failures"] += 1
        finally:
            end_observation_dispatch(token)
            self._flushing = False
            if self._pending and not self._flush_scheduled:
                self._flush_scheduled = True
                try:
                    asyncio.get_running_loop().call_soon(self._flush)
                except BaseException:
                    self._flush_scheduled = False
                    try:
                        with self._runtime.diagnostics.suspend_notifications():
                            self._runtime.diagnostics[
                                "observation_admission_failures"
                            ] += 1
                    except Exception:
                        pass

    async def flush(self) -> None:
        await asyncio.sleep(0)
        if self._pending:
            self._flush()

    def _observe_commit(
        self, observation: MachineObservation, commit: Any, effects: Any,
    ) -> None:
        self._runtime.observe_transition(commit)
        if observation.facet_values is None:
            return
        try:
            values = observation.facet_values(commit, effects)
        except Exception:
            with self._runtime.diagnostics.suspend_notifications():
                self._runtime.diagnostics["facet_snapshot_failures"] += 1
            return
        if values is not None:
            self._runtime.observe_facets(
                commit, values, owner_entity_id=observation.owner_entity_id,
                observer_meta=observation.observer_meta,
                failure_diagnostic=observation.failure_diagnostic,
            )

    def remove_machine(self, entity_id: str, epoch: int) -> None:
        self._machines.pop((entity_id, epoch), None)

    def bind(
        self, subject: object, *, entity_id: str, role: str, owner_epoch: int,
        operation_policy: Mapping[str, Any], policy_is_authoritative: bool,
        entity_role: str | SemanticRole | None = None,
        runtime_root_utility: bool = False,
    ) -> ObservationBinding:
        if not entity_id:
            raise ValueError("observation entity_id must not be empty")
        try:
            semantic_role = SemanticRole(role)
            semantic_entity_role = SemanticRole(entity_role or role)
        except ValueError as error:
            raise ValueError("observation role must be a controlled semantic label") from error
        self._runtime.assert_owner_epoch(entity_id, owner_epoch)
        key = id(subject)
        located = self._registry_by_identity.get(key)
        if located is not None and located[0]() is subject:
            other = located[1]()
            if other is not None and other is not self:
                raise MissingExecutionScope("component observation binding belongs to another Runtime")

        owner_role = self.entity_role(entity_id, owner_epoch)
        if owner_role is not None and owner_role is not semantic_entity_role:
            raise ValueError(
                f"owner {entity_id}@{owner_epoch} already has semantic role {owner_role.value}"
            )

        def discard(reference: weakref.ReferenceType[Any]) -> None:
            current = self._bindings.get(key)
            if current is not None and current[0] is reference:
                self._discard_key(key, current[1])
            located = self._registry_by_identity.get(key)
            if located is not None and located[0] is reference:
                self._registry_by_identity.pop(key, None)
            retired = self._retired.get(key)
            if retired is not None and retired[0] is reference:
                self._retired.pop(key, None)

        reference = weakref.ref(subject, discard)
        previous = self._bindings.get(key)
        if previous is not None and previous[0]() is not subject:
            self._discard_key(key, previous[1])
        elif previous is not None:
            self._discard_key(key, previous[1])
        binding = ObservationBinding(
            entity_id, semantic_role, semantic_entity_role, owner_epoch,
            MappingProxyType(dict(operation_policy)),
            policy_is_authoritative, bool(runtime_root_utility),
        )
        self._bindings[key] = (reference, binding)
        self._retired.pop(key, None)
        self._registry_by_identity[key] = (reference, weakref.ref(self))
        self._owners.setdefault((entity_id, owner_epoch), set()).add(key)
        return binding

    def get(self, subject: object) -> ObservationBinding | None:
        item = self._bindings.get(id(subject))
        if item is None or item[0]() is not subject:
            retired = self._retired.get(id(subject))
            if retired is not None and retired[0]() is subject:
                return retired[1]
            located = self._registry_by_identity.get(id(subject))
            if located is not None and located[0]() is subject and located[1]() is not self:
                raise MissingExecutionScope(
                    "component observation binding belongs to another Runtime"
                )
            return None
        binding = item[1]
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # Worker descendants consume an immutable binding after their
            # submission was epoch-validated on the owner loop.
            pass
        else:
            self._runtime.assert_owner_epoch(binding.entity_id, binding.owner_epoch)
        return binding

    def unbind(self, subject: object) -> None:
        key = id(subject)
        item = self._bindings.get(key)
        if item is not None and item[0]() is subject:
            self._discard_key(key, item[1])
        self._retired.pop(key, None)

    def remove_owner(self, entity_id: str, owner_epoch: int) -> None:
        self.remove_machine(entity_id, owner_epoch)
        for key in tuple(self._owners.pop((entity_id, owner_epoch), ())):
            item = self._bindings.get(key)
            if item is not None:
                # Retain an authoritative OFF tombstone. Closed domain reads
                # remain callable while the Runtime is active, but cannot be
                # attributed to a stale owner or regain automatic discovery.
                from .operation_policy import is_production_component
                subject = item[0]()
                if subject is not None and is_production_component(subject):
                    self._retired[key] = (
                        item[0],
                        ObservationBinding(
                            item[1].entity_id, item[1].role, item[1].entity_role,
                            item[1].owner_epoch, MappingProxyType({}), True,
                            item[1].runtime_root_utility,
                        ),
                    )
                self._discard_key(key, item[1])

    def entity_role(
        self, entity_id: str, owner_epoch: int,
    ) -> SemanticRole | None:
        roles = {
            item[1].entity_role for key in self._owners.get((entity_id, owner_epoch), ())
            if (item := self._bindings.get(key)) is not None
        }
        return next(iter(roles)) if roles else None

    def _discard_key(self, key: int, binding: ObservationBinding) -> None:
        self._bindings.pop(key, None)
        located = self._registry_by_identity.get(key)
        if located is not None and located[1]() is self:
            self._registry_by_identity.pop(key, None)
        owner_keys = self._owners.get((binding.entity_id, binding.owner_epoch))
        if owner_keys is not None:
            owner_keys.discard(key)
            if not owner_keys:
                self._owners.pop((binding.entity_id, binding.owner_epoch), None)
