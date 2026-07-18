import asyncio
import webrtc_rs

from webrtc import Runtime
from webrtc.dtls.certificate import Certificate
from webrtc.dtls.fsm import FSM, FSMState, StartHandshake
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.observability import FacetOp, FacetStore, ProducerDot
from webrtc.runtime_services import Borrowed
from webrtc.state_machine import TransitionController
from webrtc.performance import ObservedComponent, worker


class SelectedWorker(ObservedComponent):
    @worker
    def serve(self):
        return None


def _bare_fsm(controller=None):
    class Remote:
        async def sendto(self, data):
            return None

    fsm = FSM(
        Remote(), Certificate(webrtc_rs.Certificate()),
        asyncio.Queue(maxsize=64),
    )
    fsm._runner._state = "sending"
    fsm._runner._revision = 0
    fsm.entity_id = "dtls-handshake-phase:test"
    fsm._runner.entity_id = fsm.entity_id
    fsm._transition_controller = controller
    fsm._runner.controller = controller
    fsm._projection = None
    fsm.handshake_complete = asyncio.Event()
    fsm.state.get_srtp_keying_material = lambda: SRTPKeyingMaterial(
        b"a" * 16, b"b" * 16, b"c" * 14, b"d" * 14,
    )
    fsm._complete_handshake = lambda _keys: fsm.handshake_complete.set()
    return fsm


def test_dtls_before_commit_stops_then_release_commits_one_revision():
    async def scenario():
        controller = TransitionController(timeout=1)
        controller.pause_at("dtls-handshake-phase", to_state="finished", phase="before_commit")
        fsm = _bare_fsm(controller)
        task = asyncio.create_task(
            fsm._transition(FSMState.Finished, StartHandshake())
        )
        reached = await controller.wait_until("dtls-handshake-phase", "finished")
        assert fsm.handshake_state is FSMState.Sending
        assert fsm.transition_revision == 0
        assert not fsm.handshake_complete.is_set()
        controller.release(reached.checkpoint_id)
        await task
        assert fsm.handshake_state is FSMState.Finished
        assert fsm.transition_revision == 1
        assert fsm.handshake_complete.is_set()

    asyncio.run(scenario())


def test_dtls_terminal_checkpoint_observes_completion_and_revision():
    async def scenario():
        controller = TransitionController(timeout=1)
        controller.pause_at("dtls-handshake-phase", to_state="finished", phase="terminal")
        fsm = _bare_fsm(controller)
        task = asyncio.create_task(
            fsm._transition(FSMState.Finished, StartHandshake())
        )
        reached = await controller.wait_until("dtls-handshake-phase", "finished", phase="terminal")
        assert fsm.handshake_state is FSMState.Finished
        assert fsm.transition_revision == reached.revision == 1
        assert fsm.handshake_complete.is_set()
        assert not task.done()
        controller.release(reached.checkpoint_id)
        await task

    asyncio.run(scenario())


def test_facet_values_are_bounded_redacted_and_cardinality_limited():
    diagnostics = __import__("collections").Counter()
    store = FacetStore(
        runtime_epoch=1, diagnostics=diagnostics, limit=2, max_string_length=4
    )
    dot = lambda sequence: ProducerDot(1, 1, sequence)
    assert store.apply(FacetOp("peer:name", "peer", 1, "abcdefgh", 1, dot(1), "aggregate", "peer", 1, 1, 1))
    assert store.snapshots()[0].value == "abcd"
    assert not store.apply(FacetOp("peer:certificate", "peer", 1, "secret", 1, dot(2), "aggregate", "peer", 1, 2, 2))
    assert store.apply(FacetOp("peer:depth", "peer", 1, 3, 1, dot(3), "aggregate", "peer", 1, 3, 3))
    assert not store.apply(FacetOp("peer:third", "peer", 1, True, 1, dot(4), "aggregate", "peer", 1, 4, 4))
    assert diagnostics["facet_redactions"] == 1
    assert diagnostics["facet_cardinality_overflow"] == 1


def test_srtp_readiness_boolean_is_not_mistaken_for_key_material():
    diagnostics = __import__("collections").Counter()
    store = FacetStore(runtime_epoch=1, diagnostics=diagnostics)

    assert store.apply(FacetOp(
        "dtls:peer:srtp_keys_ready", "dtls:peer", 1, True, 1,
            ProducerDot(1, 1, 1),
            "aggregate", "dtls:peer", 1, 1, 1,
        ))
    assert store.snapshots()[0].value is True
    assert diagnostics["facet_redactions"] == 0


def test_srtp_delivery_facets_aggregate_and_publish_health_transitions():
    async def scenario():
        async with Runtime(
            scope_id="scope", trace_patch_cadence=60,
            srtp_delivery_facet_cadence=60,
        ) as runtime:
            for ssrc in range(100):
                runtime.record_srtp_delivery(
                    protocol="rtp", stream_id="rtp", delivered=True
                )

            # Packet-rate success does not revise projection state per packet.
            assert not any(
                item.owner_entity_id == "queue:scope:rtp"
                for item in runtime.projection.facets.snapshots()
            )
            runtime.trace_patch_flush()
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == "queue:scope:rtp"
            }
            assert facets["delivered_packets"].value == 100
            assert facets["dropped_packets"].value == 0
            assert facets["delivery_health"].value == "healthy"
            assert {item.revision for item in facets.values()} == {1}

            # A failure changes health immediately and retains a stable reason.
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="rtp", delivered=False,
                failure_reason="stream_queue_full",
            )
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == "queue:scope:rtp"
            }
            assert facets["delivered_packets"].value == 100
            assert facets["dropped_packets"].value == 1
            assert facets["delivery_health"].value == "degraded"
            assert facets["last_failure"].value == "stream_queue_full"

            # One successful packet is not treated as instant recovery.  A
            # drop-free reporting interval is the recovery boundary.
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="rtp", delivered=True
            )
            health_revision = facets["delivery_health"].revision
            assert next(
                item for item in runtime.projection.facets.snapshots()
                if item.facet_id.endswith(":delivery_health")
            ).value == "degraded"
            runtime.trace_patch_flush()
            facets = {
                item.facet_id.rsplit(":", 1)[-1]: item
                for item in runtime.projection.facets.snapshots()
                if item.owner_entity_id == "queue:scope:rtp"
            }
            assert facets["delivered_packets"].value == 101
            assert facets["delivery_health"].value == "healthy"
            assert facets["delivery_health"].revision == health_revision + 1
            assert facets["last_failure"].value == "stream_queue_full"

    asyncio.run(scenario())


def test_srtp_delivery_facets_publish_on_their_cadence():
    async def scenario():
        async with Runtime(
            scope_id="scope", srtp_delivery_facet_cadence=0.001
        ) as runtime:
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="rtp", delivered=True
            )
            runtime.record_srtp_delivery(
                protocol="rtp", stream_id="rtp", delivered=True
            )
            await asyncio.sleep(0.01)
            delivered = next(
                item for item in runtime.projection.facets.snapshots()
                if item.facet_id == "queue:scope:rtp:delivered_packets"
            )
            assert delivered.value == 2
            assert delivered.revision == 1

    asyncio.run(scenario())


def test_runtime_shutdown_releases_transition_checkpoint():
    async def scenario():
        controller = TransitionController(timeout=30)
        controller.pause_at("dtls-handshake-phase", to_state="finished")
        async with Runtime(transition_controller=Borrowed(controller)) as runtime:
            fsm = _bare_fsm(controller)
            transition = runtime.start(
                lambda: fsm._transition(FSMState.Finished, StartHandshake()),
                name="paused-transition",
            )
            await controller.wait_until("dtls-handshake-phase", "finished")
            await runtime.aclose()
            assert transition.done()

    asyncio.run(scenario())


def test_worker_call_projects_worker_lane_without_exact_call_node():
    async def scenario():
        async with Runtime(scope_id="scope") as runtime:
            await SelectedWorker().serve()
            await asyncio.sleep(0)
            machine = runtime.projection.machines.get(runtime._worker_entity_id)
            assert machine is not None
            assert machine.state == "idle"
            assert machine.revision >= 2
            assert not any(
                item["name"].endswith("serve") for item in runtime.trace_live_tree()
            )

    asyncio.run(scenario())
