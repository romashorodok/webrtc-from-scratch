import asyncio

from webrtc.dtls.dtls_record import ClientHello, ExtendedMasterSecret, Message, RecordLayer
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight0(FlightTransition):
    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
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

        # Check for Extended Master Secret extension (RFC 7627)
        if client_hello.extensions:
            for ext in client_hello.extensions:
                if isinstance(ext, ExtendedMasterSecret):
                    state.use_extended_master_secret = True
                    print("Flight 0: Extended Master Secret requested by client")
                    break

        return Flight.FLIGHT2
