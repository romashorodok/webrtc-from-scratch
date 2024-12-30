import asyncio

from webrtc.dtls.dtls_record import ClientHello, Message, RecordLayer
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight0(FlightTransition):
    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        state.remote_random = None
        return

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        client_hello = await handshake_message_ch.get()
        if not isinstance(client_hello, ClientHello):
            print("Flight 0 must receive a client hello.")
            return Flight.FLIGHT0

        if not state.remote_random and client_hello.random:
            state.remote_random = client_hello.random
        elif not state.remote_random:
            print("Flight 0 client hello must contain a random.")
            return Flight.FLIGHT0

        return Flight.FLIGHT2
