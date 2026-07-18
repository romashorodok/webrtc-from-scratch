import asyncio
from dataclasses import replace

import pytest

from webrtc import Runtime
from webrtc.performance import (
    ObservedComponent, TraceDetail, event_loop, observe, task, worker,
)
from webrtc.runtime_services import MissingExecutionScope, StaleOwnerEpoch


class _SidecarSubject(ObservedComponent):
    @event_loop
    def call(self) -> int:
        return 7


def test_stage2_sidecar_is_authoritative_for_owner_role_epoch_and_policy() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-sidecar") as runtime:
            subject = _SidecarSubject()
            entity_id = "component:stage2"
            runtime.register_owner(entity_id, epoch=3)
            policy = type(subject).__observations__
            binding = runtime.bind_observation(
                subject, entity_id=entity_id, role="component",
                owner_epoch=3, operation_policy=policy,
            )

            assert runtime.observation_registry.get(subject) is binding
            assert binding.entity_id == entity_id
            assert binding.role == "component"
            assert binding.entity_role == "component"
            assert binding.owner_epoch == 3
            assert binding.operation_policy == policy
            assert subject.call() == 7
            group = next(
                item for item in runtime.activity_groups.snapshots()
                if item.operation.endswith("_SidecarSubject.call")
            )
            assert (group.owner_entity_id, group.owner_epoch) == (entity_id, 3)
            assert {
                "entity_id", "owner_entity_id", "owner_epoch", "role",
                "operation_policy", "__worker_owner_binding__",
            }.isdisjoint(subject.__dict__)

            runtime.remove_owner(entity_id, 3)
            assert runtime.observation_registry.get(subject) is None

    asyncio.run(scenario())


def test_stage2_composed_policy_controls_observation_without_object_metadata() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-policy") as runtime:
            subject = _SidecarSubject()
            entity_id = "component:policy"
            runtime.register_owner(entity_id)
            compiled = type(subject).__observations__["call"]
            runtime.bind_observation(
                subject, entity_id=entity_id, role="component", owner_epoch=1,
                operation_policy={"call": replace(compiled, detail=TraceDetail.OFF)},
            )
            assert subject.call() == 7
            assert not any(
                item.operation_id == compiled.operation_id
                for item in runtime.activity_groups.snapshots()
            )
            runtime.remove_owner(entity_id, 1)

    asyncio.run(scenario())


def test_stage2_role_is_semantic_and_cannot_embed_an_entity_identifier() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-role") as runtime:
            subject = _SidecarSubject()
            runtime.register_owner("peer:private-identifier")
            with pytest.raises(ValueError, match="controlled semantic label"):
                runtime.bind_observation(
                    subject, entity_id="peer:private-identifier",
                    role="peer:private-identifier", owner_epoch=1,
                )
            runtime.remove_owner("peer:private-identifier", 1)

    asyncio.run(scenario())


def test_stage2_shared_entity_has_one_entity_role_and_distinct_operation_roles() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-shared-role") as runtime:
            handshake = _SidecarSubject()
            connection = _SidecarSubject()
            runtime.register_owner("dtls:shared")
            runtime.bind_observation(
                handshake, entity_id="dtls:shared", role="dtls-handshake",
                owner_epoch=1,
            )
            runtime.bind_observation(
                connection, entity_id="dtls:shared", role="dtls-connection",
                entity_role="dtls-handshake", owner_epoch=1,
            )
            assert runtime.observation_registry.entity_role(
                "dtls:shared", 1
            ) == "dtls-handshake"
            assert runtime.observation_registry.get(connection).role == "dtls-connection"
            with pytest.raises(ValueError, match="already has semantic role"):
                runtime.bind_observation(
                    _SidecarSubject(), entity_id="dtls:shared",
                    role="component", owner_epoch=1,
                )
            runtime.remove_owner("dtls:shared", 1)

    asyncio.run(scenario())


def test_stage2_explicit_empty_policy_suppresses_async_metaclass_fallback() -> None:
    class Subject(ObservedComponent):
        async def call(self) -> int:
            return 9

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-empty") as runtime:
            subject = Subject()
            runtime.register_owner("component:empty")
            runtime.bind_observation(
                subject, entity_id="component:empty", role="component",
                owner_epoch=1, operation_policy={},
            )
            assert await subject.call() == 9
            assert runtime.activity_groups.snapshots() == ()
            runtime.remove_owner("component:empty", 1)

    asyncio.run(scenario())


def test_stage2_unbound_receiver_call_kinds_auto_compose_one_root_sidecar() -> None:
    class RootUtility(ObservedComponent):
        @event_loop
        def inline_call(self) -> int:
            return 1

        async def async_call(self) -> int:
            return 2

        @task(name="root-task")
        @observe(detail="exact")
        async def task_call(self) -> int:
            return 3

        @observe(detail="exact")
        async def exact_call(self) -> int:
            return 4

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-root-sidecar") as runtime:
            subject = RootUtility()
            assert subject.inline_call() == 1
            binding = runtime.observation_registry.get(subject)
            assert binding is not None
            assert binding.runtime_root_utility
            assert binding.entity_id == runtime._runtime_entity_id
            assert binding.entity_role == "runtime"
            assert binding.role == "component"

            assert await subject.async_call() == 2
            assert await subject.task_call() == 3
            assert await subject.exact_call() == 4
            groups = {
                item.operation: (item.owner_entity_id, item.owner_role)
                for item in runtime.activity_groups.snapshots()
                if "RootUtility" in item.operation
            }
            assert len(groups) == 4
            assert set(groups.values()) == {
                (runtime._runtime_entity_id, "component")
            }

    asyncio.run(scenario())


def test_stage2_unbound_receiver_requiring_composition_is_rejected_for_all_calls() -> None:
    class Required(ObservedComponent):
        __requires_observation_binding__ = True

        @event_loop
        def inline_call(self) -> None:
            pass

        async def async_call(self) -> None:
            pass

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-required"):
            subject = Required()
            with pytest.raises(MissingExecutionScope, match="requires Runtime composition"):
                subject.inline_call()
            with pytest.raises(MissingExecutionScope, match="requires Runtime composition"):
                await subject.async_call()

    asyncio.run(scenario())


def test_stage2_sidecar_policies_cover_async_worker_task_and_exact_calls() -> None:
    class Subject(ObservedComponent):
        async def async_call(self) -> int:
            return 1

        @worker
        def worker_call(self) -> int:
            return 2

        @task(name="sidecar-task")
        async def task_call(self) -> int:
            return 3

        @observe(detail="exact")
        async def exact_call(self) -> int:
            return 4

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-kinds") as runtime:
            subject = Subject()
            entity = "component:kinds"
            runtime.register_owner(entity)
            compiled = type(subject).__observations__
            policy = {
                name: replace(item, detail=TraceDetail.EXACT)
                for name, item in compiled.items()
            }
            runtime.bind_observation(
                subject, entity_id=entity, role="component", owner_epoch=1,
                operation_policy=policy,
            )
            assert await subject.async_call() == 1
            assert await subject.worker_call() == 2
            assert await subject.task_call() == 3
            assert await subject.exact_call() == 4
            groups = runtime.activity_groups.snapshots()
            assert {item.operation_id for item in groups} == {
                item.operation_id for item in policy.values()
            }
            assert {(item.owner_entity_id, item.owner_role) for item in groups} == {
                (entity, "component")
            }
            runtime.remove_owner(entity, 1)

    asyncio.run(scenario())


def test_stage2_binding_rejects_stale_epoch_and_foreign_runtime() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-first") as first:
            subject = _SidecarSubject()
            first.register_owner("component:foreign")
            first.bind_observation(
                subject, entity_id="component:foreign", role="component",
                owner_epoch=1,
            )
            first._owner_epochs["component:foreign"] = 2
            with pytest.raises(StaleOwnerEpoch):
                subject.call()
            first._owner_epochs["component:foreign"] = 1

            async with Runtime(scope_id="stage2-second"):
                with pytest.raises(MissingExecutionScope, match="another Runtime"):
                    subject.call()
            first.remove_owner("component:foreign", 1)

    asyncio.run(scenario())


def test_stage2_compatibility_binder_writes_no_component_metadata() -> None:
    async def scenario() -> None:
        async with Runtime(scope_id="stage2-binder") as runtime:
            subject = _SidecarSubject()
            runtime.register_owner("component:binder")
            before = dict(subject.__dict__)
            subject.__bind_worker_owner__(
                runtime, "component:binder", 1, role="component"
            )
            assert subject.__dict__ == before
            binding = runtime.observation_registry.get(subject)
            assert binding is not None and not binding.runtime_root_utility
            runtime.remove_owner("component:binder", 1)

    asyncio.run(scenario())


def test_stage2_audio_analyzer_uses_worker_sidecar_owner_and_role() -> None:
    pytest.importorskip("numpy")
    from webrtc.audio.analyzer import AudioAnalyzer

    async def scenario() -> None:
        async with Runtime(scope_id="stage2-audio") as runtime:
            analyzer = AudioAnalyzer(fft_size=8)
            binding = runtime.observation_registry.get(analyzer)
            assert binding is not None
            assert binding.entity_id == runtime._worker_entity_id
            assert binding.role == "audio-analyzer"
            assert binding.entity_role == "worker-lane"
            spectrum, _ = await analyzer._compute_spectrum(bytes(16))
            assert len(spectrum) == analyzer.target_bins
            group = next(
                item for item in runtime.activity_groups.snapshots()
                if item.operation.endswith("AudioAnalyzer._compute_spectrum")
            )
            assert group.owner_entity_id == runtime._worker_entity_id
            assert group.owner_role == "audio-analyzer"

    asyncio.run(scenario())
