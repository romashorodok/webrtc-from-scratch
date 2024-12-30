import asyncio
import binascii

from webrtc.dtls.dtls_record import (
    Certificate,
    HandshakeMessageType,
    KeyServerExchange,
    Message,
    RecordLayer,
    ServerHello,
)
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight3(FlightTransition):
    __msg = DEFAULT_FACTORY

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        return [
            self.__msg.client_hello(
                state.local_random.marshal_fixed(),
                state.cookie,
                [state.pending_cipher_suite.cipher_suite_id()],
                [state.local_keypair.curve],
                [state.local_keypair.signature_hash_algorithm],
            )
        ]

    def __handle_server_key_exchange(self, state: State, message: KeyServerExchange):
        # NOTE: This library not support generate a pre shared key with ECDH for X25519 curve
        # case EllipticCurveGroup.X25519:
        #     state.local_keypair = Keypair.generate_X25519()
        # case _:
        #     raise ValueError(
        #         f"Unsupported {message.named_curve} curve unable create pre master secret"
        #     )

        # TODO: Here an error

        # named_curve: EllipticCurveGroup | None = None
        # signature_hash_algorithm: SignatureHashAlgorithm | None = None
        # pubkey: bytes | None = None
        # signature: bytes | None = None

        # TODO: Is it must use a pub key instead of ?
        # state.pre_master_secret = state.local_keypair.generate_shared_key()

        # print(
        #     "Flight 3 Shared pre master secret",
        #     binascii.hexlify(state.pre_master_secret),
        #     len(state.pre_master_secret),
        # )

        ...

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        handshake_messages = list[Message]()
        while True:
            # TODO: timeout and make a fallback to flight 1
            print("Flight 3 wait")
            message = await handshake_message_ch.get()
            handshake_messages.append(message)

            match message.message_type:
                case HandshakeMessageType.KeyServerExchange:
                    if not isinstance(message, KeyServerExchange):
                        raise ValueError(
                            "Flight 3 message must be a instance of KeyServerExchange"
                        )
                    if (
                        not message.named_curve
                        and state.local_keypair.curve != message.named_curve
                    ):
                        raise ValueError("Flight 3 message key server must be defined")

                    try:
                        self.__handle_server_key_exchange(state, message)
                    except Exception as e:
                        print("Unable generate pre shared master key", e)

                case HandshakeMessageType.Certificate:
                    if not isinstance(message, Certificate):
                        raise ValueError(
                            "Flight 3 message must be a instance of Certificate"
                        )
                    if not message.certificates:
                        raise ValueError(
                            "Flight3 not found required remote certificates"
                        )

                    state.remote_peer_certificates = message.certificates

                case HandshakeMessageType.ServerHello:
                    if not isinstance(message, ServerHello):
                        raise ValueError(
                            "Flight 3 message must be a instance of ServerHello"
                        )

                    state.remote_random = message.random

                    if not message.cipher_suite:
                        raise ValueError("Flight 3 message must contain cipher suite")

                    if (
                        message.cipher_suite
                        != state.pending_cipher_suite.cipher_suite_id()
                    ):
                        raise ValueError("Flight 3 different cipher suite")

                    print("Cipher suite", state.pending_cipher_suite)

                    # cipher_suite_cls = CIPHER_SUITES_CLASSES.get(message.cipher_suite)
                    # if not cipher_suite_cls:
                    #     raise ValueError(
                    #         f"Flight 3 not found cipher suite {message.cipher_suite}"
                    #     )
                    # state.pending_cipher_suite = cipher_suite_cls()

                case HandshakeMessageType.ServerHelloDone:
                    state.pending_remote_handshake_messages = handshake_messages
                    print("Flight 3 done")
                    return Flight.FLIGHT5
                case _:
                    pass
