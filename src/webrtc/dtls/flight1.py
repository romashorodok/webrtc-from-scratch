import asyncio

from webrtc.dtls.dtls_record import HandshakeMessageType, Message, RecordLayer
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight1(FlightTransition):
    __msg = DEFAULT_FACTORY

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        state.remote_random = None
        return [
            self.__msg.client_hello(
                state.local_random.marshal_fixed(),
                None,
                [state.pending_cipher_suite.cipher_suite_id()],
                [state.local_keypair.curve],
                [state.local_keypair.signature_hash_algorithm],
            )
        ]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        handshake_messages = list[Message]()
        while True:
            # TODO: timeout and make a fallback to flight 1
            message = await handshake_message_ch.get()
            handshake_messages.append(message)

            match message.message_type:
                case HandshakeMessageType.HelloVerifyRequest:
                    if not message.cookie:
                        print("Flight 1 Server must return a cookie")
                        return Flight.FLIGHT1

                    state.cookie = message.cookie
                    return Flight.FLIGHT3
                case HandshakeMessageType.ServerHelloDone:
                    if not message.cookie:
                        print("Flight 1 Server must return a cookie")
                        return Flight.FLIGHT1

                    state.cookie = message.cookie

                    state.pending_remote_handshake_messages = handshake_messages
                    return Flight.FLIGHT5
                case _:
                    pass
