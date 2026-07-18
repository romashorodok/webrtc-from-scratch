import asyncio
from types import SimpleNamespace

import pytest

from webrtc import Runtime
from webrtc.observability import MachineTransitionOp
from webrtc.peer_components import (
    AttachmentController, PeerConnectionLogInbox, PeerEventInbox,
)
from webrtc.runtime_services import StaleOwnerEpoch, WrongRuntimeLoop


def _machine(runtime, entity_id):
    snapshot = runtime.projection.machines.get(entity_id)
    assert snapshot is not None
    return snapshot


def _facets(runtime, entity_id):
    return {
        item.facet_id.rsplit(":", 1)[-1]: item
        for item in runtime.projection.facets.snapshots()
        if item.owner_entity_id == entity_id
    }


def test_stage6_attachment_registry_is_bounded_stable_and_idempotent():
    class Attachment:
        def __init__(self): self.events = []
        async def start(self): self.events.append("start")
        async def stop(self): self.events.append("stop")
        async def aclose(self): self.events.append("close")

    async def scenario():
        controller = AttachmentController("test", capacity=2)
        with pytest.raises(RuntimeError, match="Runtime-bound"):
            controller.attach(Attachment())
        async with Runtime(scope_id="stage6-attachment") as runtime:
            controller.bind(runtime, "attachment-registry:test")
            first, second = Attachment(), Attachment()
            controller.attach(first)
            with pytest.raises(ValueError, match="already registered"):
                controller.attach(first)
            controller.start(); controller.start()
            controller.attach(second)  # attach-after-start
            with pytest.raises(OverflowError):
                controller.attach(Attachment())
            await asyncio.sleep(0.01)
            children = [
                item for item in runtime.projection.machines.snapshots()
                if item.entity_id.startswith("attachment-registry:test:attachment:")
            ]
            assert len(children) == 2
            assert len({item.entity_id for item in children}) == 2
            assert {item.state for item in children} == {"active"}
            await controller.aclose()
            assert runtime.projection.machines.get("attachment-registry:test") is None
            assert all(runtime.projection.machines.get(item.entity_id) is None for item in children)
            assert first.events == second.events == ["start", "stop", "close"]

    asyncio.run(scenario())


def test_stage6_attachment_close_during_start_preserves_causal_failure():
    class Attachment:
        def __init__(self): self.entered=asyncio.Event(); self.release=asyncio.Event()
        async def start(self): self.entered.set(); await self.release.wait(); raise LookupError("start-cause")
        async def stop(self): pass

    async def scenario():
        async with Runtime(scope_id="stage6-attachment-race") as runtime:
            controller=AttachmentController("race"); controller.bind(runtime,"attachment-registry:race")
            attachment=Attachment(); controller.attach(attachment); controller.start()
            await attachment.entered.wait()
            closing=asyncio.create_task(controller.aclose())
            attachment.release.set()
            with pytest.raises(LookupError, match="start-cause"):
                await closing
            assert not any(":attachment:" in item.entity_id for item in runtime.projection.machines.snapshots())

    asyncio.run(scenario())


def test_stage6_peer_inbox_reserves_terminal_and_reconciles_counters():
    async def scenario():
        async with Runtime(scope_id="stage6-peer-queue") as runtime:
            inbox=PeerEventInbox(maxsize=1); inbox.bind(runtime,"queue:stage6:peer")
            assert inbox.offer_nowait("ordinary")
            assert not inbox.offer_nowait("overflow")
            terminal={"type":"closed","reason":"test"}
            assert inbox.offer_nowait(terminal)  # reserved terminal capacity
            inbox.close()
            assert inbox.receive_nowait() == "ordinary"
            assert inbox.receive_nowait() is terminal
            await inbox.aclose()
            assert runtime.projection.machines.get("queue:stage6:peer") is None
            assert (inbox.admitted,inbox.delivered,inbox.rejected,inbox.dropped)==(2,2,1,1)
            assert inbox.high_water == 2

    asyncio.run(scenario())


def test_stage6_log_queue_terminal_drain_and_exact_accounting():
    async def scenario():
        async with Runtime(scope_id="stage6-log-queue") as runtime:
            inbox=PeerConnectionLogInbox(maxsize=2); inbox.bind(runtime,"queue:stage6:log")
            ordinary=SimpleNamespace(level=SimpleNamespace(value=1))
            debug=SimpleNamespace(level=SimpleNamespace(value=4))
            assert inbox.put_nowait(ordinary); assert inbox.put_nowait(ordinary)
            assert not inbox.put_nowait(debug)
            inbox.stop_intake(); assert len(inbox.drain_batch(2)) == 2
            await inbox.aclose()
            assert runtime.projection.machines.get("queue:stage6:log") is None
            facets=_facets(runtime,"queue:stage6:log")
            assert facets == {}

    asyncio.run(scenario())


def test_stage6_runtime_owner_rejects_wrong_loop_epoch_and_terminal_children():
    async def scenario():
        async with Runtime(scope_id="stage6-owner") as runtime:
            runtime.register_owner("owner",epoch=1)
            blocker=asyncio.Event()
            child=runtime.start_pump(blocker.wait,owner_entity_id="owner",owner_epoch=1,name="owned")
            with pytest.raises(AssertionError,match="live children"):
                runtime.remove_owner("owner",1)
            with pytest.raises(StaleOwnerEpoch):
                runtime.assert_owner_epoch("owner",2)
            errors=[]
            def other_loop():
                async def mutate():
                    try: runtime.assert_owner_epoch("owner",1)
                    except BaseException as error: errors.append(error)
                asyncio.run(mutate())
            await asyncio.to_thread(other_loop)
            assert isinstance(errors[0],WrongRuntimeLoop)
            blocker.set(); await child.wait(); runtime.remove_owner("owner",1)

    asyncio.run(scenario())


def test_stage6_observability_lifecycle_health_recovery_and_disabled_path():
    async def scenario():
        async with Runtime(scope_id="stage6-health") as runtime:
            entity="observability:stage6-health"
            sub=runtime.trace_patch_subscribe(maxsize=1); await sub.get()
            for index in range(2):
                snapshot = _machine(runtime,entity)
                runtime.projection.merge_values(
                    entity,runtime.new_producer_dot(),{f"pressure_{index}":index},
                    observer_meta="exact", source_entity_id=entity,
                    source_epoch=snapshot.machine_epoch,
                    source_revision=snapshot.revision,
                    source_order=runtime.projection.new_facet_source_order(),
                ); runtime.trace_patch_flush()
            await asyncio.sleep(0.01)
            assert _machine(runtime,entity).state == "degraded"
            assert (await sub.get())["event"] == "trace:resync_required"
            assert (await sub.get())["event"] == "trace:snapshot"
            await asyncio.sleep(0.01)
            assert _machine(runtime,entity).state == "active"
        assert runtime.projection.machines.get(entity) is None
        transitions=[x.to_state for x in runtime.projection.machines.transition_snapshots() if x.entity_id==entity]
        assert transitions == ["starting","active","degraded","active","draining","stopped"]

        async with Runtime(scope_id="stage6-disabled",tracing_enabled=False) as disabled:
            assert _machine(disabled,"observability:stage6-disabled").state == "active"
            assert _facets(disabled,"observability:stage6-disabled")["enabled"].value is False
        assert disabled.projection.machines.get("observability:stage6-disabled") is None

    asyncio.run(scenario())


def test_stage6_slow_subscriber_gets_durable_terminal_schema2_snapshot():
    async def scenario():
        runtime=Runtime(scope_id="stage6-final"); await runtime.__aenter__()
        sub=runtime.trace_patch_subscribe(maxsize=1); await sub.get()
        entity="observability:stage6-final"; snapshot=_machine(runtime,entity)
        runtime.projection.merge_values(
            entity,runtime.new_producer_dot(),{"pending":True},
            observer_meta="exact", source_entity_id=entity,
            source_epoch=snapshot.machine_epoch, source_revision=snapshot.revision,
            source_order=runtime.projection.new_facet_source_order(),
        ); runtime.trace_patch_flush()  # deliberately leave this unread
        await runtime.__aexit__(None,None,None)
        terminal=await asyncio.wait_for(sub.get(),1)
        assert terminal["event"] == "trace:terminal"
        assert terminal["data"]["schema"] == 2 and terminal["data"]["terminal"] is True
        observed=next(x for x in terminal["data"]["machines"] if x["entity_id"]=="observability:stage6-final")
        assert observed["state"] == "stopped"
        health={x["facet_id"].rsplit(":",1)[-1]:x for x in terminal["data"]["facets"] if x["owner_entity_id"]==observed["entity_id"]}
        assert "health" not in health  # lifecycle exists only on the machine

    asyncio.run(scenario())


def test_stage6_facet_future_gap_replay_metadata_and_old_epoch_rejection():
    async def scenario():
        async with Runtime(scope_id="stage6-facet") as runtime:
            from webrtc.machine_specs import MACHINE_SPECS
            entity="queue:stage6-facet"
            runtime.projection.machines.register(entity,MACHINE_SPECS["queue"],epoch=1)
            snap=_machine(runtime,entity)
            runtime.projection.merge_values(
                entity,runtime.new_producer_dot(),{"future":"held"},
                observer_meta="exact", source_entity_id=entity,
                source_epoch=snap.machine_epoch, source_revision=snap.revision+1,
                source_order=runtime.projection.new_facet_source_order(),
            )
            assert "future" not in _facets(runtime,entity)
            runtime.projection.transition(MachineTransitionOp(
                entity,"queue","open","closing",1,snap.revision+1,
                runtime.new_producer_dot(),cause_id="gap-close",
            ))
            future=_facets(runtime,entity)["future"]
            assert future.value == "held" and future.observer_meta == "exact"
            assert future.source_revision == snap.revision+1 and future.source_order > 0
            runtime.projection.facets.remove_owner(entity,1)
            from webrtc.observability import FacetOp
            assert not runtime.projection.facets.apply(FacetOp(
                f"{entity}:old",entity,1,True,1,runtime.new_producer_dot(),
                "exact",entity,1,snap.revision+1,1,
            ))
            assert runtime.diagnostics["stale_facet_owner_epoch"] == 1

    asyncio.run(scenario())
