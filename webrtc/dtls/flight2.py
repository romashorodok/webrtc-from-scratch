import asyncio

from webrtc.dtls.dtls_record import ClientHello, ExtendedMasterSecret, Message, RecordLayer
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight2(FlightTransition):
    __msg = DEFAULT_FACTORY

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        return [
            self.__msg.hello_verify_request(state.cookie),
        ]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        client_hello = await handshake_message_ch.get()
        if not isinstance(client_hello, ClientHello):
            print(
                "Flight 1 must receive a client hello after a HelloVerifyRequest. Reset state to Flight 0"
            )
            return Flight.FLIGHT0

        if not client_hello.cookie:
            print("Flight 0 client hello must contain a cookie.")
            return Flight.FLIGHT0

        if state.cookie != client_hello.cookie:
            print("Flight 0 must contain a same remote and local cookie")
            return Flight.FLIGHT0

        # Check for Extended Master Secret extension (RFC 7627)
        # This ClientHello (with cookie) is the one used for handshake hash
        if client_hello.extensions:
            for ext in client_hello.extensions:
                if isinstance(ext, ExtendedMasterSecret):
                    state.use_extended_master_secret = True
                    print("Flight 2: Extended Master Secret requested by client")
                    break

        return Flight.FLIGHT4
