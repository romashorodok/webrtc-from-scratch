import asyncio

import pytest

from webrtc.ice.agent import CandidatePair, CandidatePairController, CandidatePairTransport
from webrtc import Runtime
from webrtc.ice.net.types import Address, Packet
from webrtc.ice.net.udp_mux import InterfaceMuxUDPHandler, Interceptor, UDPMuxConn
from webrtc.tracing import PerformanceRecorder, use_performance_recorder


class _DatagramTransport:
    def __init__(self):
        self.sent = []

    def get_extra_info(self, name):
        if name == "sockname":
            return ("127.0.0.1", 5000)
        assert name == "socket"
        return None

    def sendto(self, data, address):
        self.sent.append((bytes(data), address))


def _pair(entity_id: str) -> CandidatePair:
    pair = CandidatePair.__new__(CandidatePair)
    pair.entity_id = entity_id
    return pair


def _events(recorder):
    return {event.name: event for event in recorder.events()}


def test_interceptor_bounds_backlog_and_keeps_freshest_packets():
    async def scenario():
        interceptor = Interceptor(maxsize=2, drop_oldest=True)
        address = Address("127.0.0.1", 5000)
        interceptor.put_nowait(Packet(address, b"old"))
        interceptor.put_nowait(Packet(address, b"kept"))
        interceptor.put_nowait(Packet(address, b"new"))

        assert (await interceptor.get()).data == b"kept"
        assert (await interceptor.get()).data == b"new"

    asyncio.run(scenario())


def test_udp_bound_rx_tx_and_unbound_drop_are_traced():
    transport = _DatagramTransport()
    handler = InterfaceMuxUDPHandler(type("Interface", (), {"address": "127.0.0.1"})(), 5000)
    handler.connection_made(transport)
    interceptor = Interceptor()
    handler.bind_interceptor("127.0.0.2", 6000, interceptor)
    conn = UDPMuxConn(transport, ("127.0.0.2", 6000), interceptor)
    recorder = PerformanceRecorder()

    with use_performance_recorder(recorder):
        conn.sendto(b"\x16" + b"x" * 12)
        handler.datagram_received(b"abc", ("127.0.0.2", 6000))
        handler.datagram_received(b"lost", ("127.0.0.3", 6001))

    events = _events(recorder)
    assert events["udp.datagram.tx"].metadata["packet_kind"] == "dtls"
    assert events["udp.datagram.tx"].metadata["counter.udp.datagrams_tx"] == 1
    assert events["udp.datagram.rx"].metadata["counter.udp.datagrams_rx"] == 1
    assert events["udp.datagram.unbound_dropped"].metadata["drop_reason"] == "unbound"
    assert not any(
        "address" in key or key.endswith("_port")
        for event in events.values() for key in event.metadata
    )


def test_ice_demux_emits_each_route_and_records_malformed_failure():
    recorder = PerformanceRecorder()
    pair = _pair("candidate-pair:pair-1")
    transport = CandidatePairTransport(
        type("Conn", (), {"sendto": lambda *_: None})(), pair,
    )

    with use_performance_recorder(recorder):
        transport.pipe(Packet(Address("127.0.0.2", 6000), b"\x16" + b"x" * 12))
        transport.pipe(Packet(Address("127.0.0.2", 6000), b"\x80\x60" + b"x" * 10))
        transport.pipe(Packet(Address("127.0.0.2", 6000), b"\x80\xc8\x00\x00"))
        with pytest.raises(ValueError, match="empty"):
            transport.pipe(Packet(Address("127.0.0.2", 6000), b""))

    events = _events(recorder)
    for name in ("ice.packet_demux.dtls", "ice.packet_demux.rtp", "ice.packet_demux.rtcp"):
        assert events[name].metadata["pair_id"] == pair.entity_id
    assert events["ice.packet_demux.failed"].metadata["demux_reason"] == "empty"


def test_controller_traces_packet_before_branch_and_after_routing():
    class Selector:
        def start(self):
            pass

        def on(self, *_):
            pass

        async def send_ping_stun_message(self, *_):
            pass

    class Conn:
        def __init__(self):
            self.queue = asyncio.Queue()

        async def recvfrom(self):
            return await self.queue.get()

    async def scenario():
        conn = Conn()
        controller = CandidatePairController.__new__(CandidatePairController)
        controller._pair = _pair("candidate-pair:pair-1")
        controller._CandidatePairController__selector = Selector()
        controller._CandidatePairController__conn = conn
        controller._CandidatePairController__transport = CandidatePairTransport(
            conn, controller._pair,
        )
        recorder = PerformanceRecorder()
        async with Runtime(scope_id="socket-ice") as runtime:
            runtime.register_owner("candidate-pair:test", epoch=1)
            runtime.bind_observation(
                controller, entity_id="candidate-pair:test",
                role="candidate-pair-controller", owner_epoch=1,
            )
            with use_performance_recorder(recorder):
                # Exercise the loop body directly; production starts this
                # pump only through CandidatePairController.start_managed().
                task = asyncio.create_task(controller._receive_loop())
                await conn.queue.put(Packet(Address("127.0.0.2", 6000), b"\x80\x60" + b"x" * 10))
                await asyncio.sleep(0)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
        names = [event.name for event in recorder.events()]
        assert names.index("ice.controller.packet_received") < names.index("ice.packet_demux.rtp")
        assert names.index("ice.packet_demux.rtp") < names.index("ice.controller.packet_routed")

    asyncio.run(scenario())
