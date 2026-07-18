import asyncio
from types import SimpleNamespace

from webrtc.machine_specs import MACHINE_SPECS
from webrtc.runtime import Runtime
from webrtc.state_machine import SynchronousStateReducer
from webrtc.transceiver import (
    MediaCaps, RTPCodecKind, RTPReceiver, RTPTransceiver,
    RTPTransceiverDirection,
)
from webrtc import domain_observation


def test_runtime_machine_observer_runs_strictly_after_domain_commit():
    async def scenario():
        async with Runtime(scope_id="stage4-after-commit") as runtime:
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transport:after-commit",
            )
            seen = []

            def facets(commit, _effects):
                snapshot = runner.snapshot()
                seen.append((snapshot.state, snapshot.revision, commit.to_state))
                return {"ready": commit.to_state == "ready"}

            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec, epoch=runner.epoch,
                facet_values=facets,
            )
            commit = runner.transition("selecting", cause="check")
            await runtime.flush_observations()

            assert commit.revision == 1
            assert seen == [("selecting", 1, "selecting")]
            assert runtime.projection.machines.get(runner.entity_id).state == "selecting"

    asyncio.run(scenario())


def test_projection_failure_cannot_change_committed_state_or_progress(monkeypatch):
    async def scenario():
        async with Runtime(scope_id="stage4-projection-failure") as runtime:
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transport:projection-failure",
            )
            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec, epoch=runner.epoch,
                facet_values=lambda commit, effects: {"state": commit.to_state},
            )

            def broken_projection(_operation):
                raise RuntimeError("injected projection failure")

            monkeypatch.setattr(runtime.projection, "transition", broken_projection)
            first = runner.transition("selecting", cause="first")
            second = runner.transition("ready", cause="second")
            await runtime.flush_observations()

            assert (first.revision, second.revision) == (1, 2)
            assert runner.snapshot().state == "ready"
            assert runtime.diagnostics["transition_observation_failures"] == 2

    asyncio.run(scenario())


def test_machine_registration_and_facet_derivation_failures_are_diagnostic(monkeypatch):
    async def scenario():
        async with Runtime(scope_id="stage4-sidecar-failure") as runtime:
            original_register = runtime.projection.machines.register

            def broken_register(*args, **kwargs):
                raise RuntimeError("injected registration failure")

            monkeypatch.setattr(runtime.projection.machines, "register", broken_register)
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transport:registration-failure",
            )

            def broken_facets(_commit, _effects):
                raise RuntimeError("injected facet derivation failure")

            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec, epoch=runner.epoch,
                facet_values=broken_facets,
            )
            monkeypatch.setattr(runtime.projection.machines, "register", original_register)

            commit = runner.transition("selecting", cause="still-commits")
            await runtime.flush_observations()
            assert commit.revision == runner.snapshot().revision == 1
            assert runner.snapshot().state == "selecting"
            assert runtime.diagnostics["machine_observation_failures"] == 1
            assert runtime.diagnostics["facet_snapshot_failures"] == 1

    asyncio.run(scenario())


def test_transceiver_adapter_failure_cannot_change_activation_or_shutdown(monkeypatch):
    async def scenario():
        async with Runtime(scope_id="stage4-transceiver-failure") as runtime:
            def broken_facets(*args, **kwargs):
                raise RuntimeError("injected transceiver facet failure")

            monkeypatch.setattr(runtime.projection, "merge_values", broken_facets)
            transceiver = RTPTransceiver(
                object(), MediaCaps(), RTPCodecKind.Audio,
                RTPTransceiverDirection.Sendonly,
                observability_id="transceiver:stage4-failure",
            )
            commit = await transceiver.wait_active()
            assert commit.to_state == "active"
            assert transceiver._runner.snapshot().state == "active"
            assert runtime.diagnostics["facet_observation_failures"] >= 1
            await transceiver.aclose()
            assert transceiver._runner.snapshot().state == "stopped"

    asyncio.run(scenario())


def test_projection_callback_cannot_reenter_domain_commit(monkeypatch):
    async def scenario():
        async with Runtime(scope_id="stage4-no-reentry") as runtime:
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transport:no-reentry",
            )
            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec, epoch=runner.epoch,
            )

            def reenter(_operation):
                runner.transition("ready", cause="observer-reentry")

            monkeypatch.setattr(runtime.projection, "transition", reenter)
            runner.transition("selecting", cause="domain")
            await runtime.flush_observations()
            assert runner.snapshot().state == "selecting"
            assert runner.snapshot().revision == 1
            assert runtime.diagnostics["transition_observation_failures"] == 1

    asyncio.run(scenario())


def test_enqueue_admission_failure_cannot_fail_command_or_runtime_shutdown(monkeypatch):
    async def scenario():
        runtime = Runtime(scope_id="stage4-enqueue-failure")
        async with runtime:
            def broken_enqueue(*args, **kwargs):
                raise MemoryError("injected observation queue admission failure")

            monkeypatch.setattr(runtime.observation_registry, "enqueue_commit", broken_enqueue)
            transceiver = RTPTransceiver(
                object(), MediaCaps(), RTPCodecKind.Audio,
                RTPTransceiverDirection.Sendonly,
                observability_id="transceiver:enqueue-failure",
            )
            commit = await transceiver.wait_active()
            assert commit.to_state == "active"
            await transceiver.aclose()
            assert transceiver._runner.snapshot().state == "stopped"
            assert runtime.diagnostics["observation_admission_failures"] >= 2

        assert runtime.state.value == "closed"

    asyncio.run(scenario())


def test_deferred_adapter_uses_immutable_commit_time_capture():
    async def scenario():
        async with Runtime(scope_id="stage4-immutable-evidence") as runtime:
            negotiated = SimpleNamespace(
                direction=SimpleNamespace(value="sendonly"), mid="old-mid",
                codecs=(SimpleNamespace(mime_type="audio/opus"),),
                sender=None, receiver=None,
            )
            subject = SimpleNamespace(
                _negotiated=negotiated,
                _kind=SimpleNamespace(value="audio"),
            )
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transceiver:capture",
            )
            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec,
                facet_values=domain_observation.transceiver,
                capture_effect=domain_observation.capture_transceiver,
                capture_subject=subject,
            )
            runner.transition("selecting", cause="capture")

            # Mutate the live component before the queued observer turn.
            subject._negotiated = SimpleNamespace(
                direction=SimpleNamespace(value="recvonly"), mid="new-mid",
                codecs=(), sender=None, receiver=None,
            )
            await runtime.flush_observations()
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item.value
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == runner.entity_id
            }
            assert facets["direction"] == "sendonly"
            assert facets["mid"] == "old-mid"
            assert facets["codecs"] == "audio/opus"

    asyncio.run(scenario())


def test_capture_callback_cannot_reenter_domain_commit():
    async def scenario():
        async with Runtime(scope_id="stage4-capture-no-reentry") as runtime:
            runner = SynchronousStateReducer(
                MACHINE_SPECS["transport"], entity_id="transport:capture-no-reentry",
            )

            def adversarial_capture(_subject, _commit, effects):
                runner.transition("ready", cause="nested-capture")
                return effects

            runner._transition_sink = runtime.observe_machine(
                runner.entity_id, runner.spec,
                capture_effect=adversarial_capture,
            )
            outer = runner.transition("selecting", cause="outer")
            await runtime.flush_observations()

            assert outer.revision == 1
            assert runner.snapshot().revision == 1
            assert runner.snapshot().state == "selecting"
            assert runtime.diagnostics["observation_admission_failures"] == 1
            assert runtime.projection.machines.get(runner.entity_id).state == "new"

    asyncio.run(scenario())


def test_receiver_sink_sees_atomic_bound_authority():
    async def scenario():
        async with Runtime(scope_id="stage4-receiver-authority"):
            receiver = RTPReceiver(
                MediaCaps(), RTPCodecKind.Audio,
                observability_id="receiver:atomic-authority",
            )
            original = receiver._runner._transition_sink
            seen = []

            def probe(commit, effects):
                snapshot = receiver.receiver_snapshot
                seen.append((commit.to_state, snapshot.state, snapshot.transport))
                original(commit, effects)

            probe.__accepts_effects__ = True
            receiver._runner._transition_sink = probe
            transport = object()
            receiver.bind(transport)

            assert seen[0] == ("bound", "bound", transport)
            assert receiver.receiver_snapshot.transport is transport
            await receiver.aclose()

    asyncio.run(scenario())
