import asyncio

from webrtc.dtls.dtls_record import (
    Certificate,
    ExtendedMasterSecret,
    HandshakeMessageType,
    KeyServerExchange,
    Message,
    RecordLayer,
    ServerHello,
)
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

    def __handle_server_key_exchange(self, state: State, message: KeyServerExchange):
        # Compute pre-master secret using ECDH with Rust keypair
        if not message.pubkey:
            raise ValueError("KeyServerExchange must have pubkey")
        state.pre_master_secret = state.local_keypair.compute_shared_secret(
            message.pubkey
        )

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        # When server skips HelloVerifyRequest, we receive all server messages directly.
        # We need to process them here before transitioning to Flight5.
        while True:
            # TODO: timeout and make a fallback to flight 1
            message = await handshake_message_ch.get()

            match message.message_type:
                case HandshakeMessageType.HelloVerifyRequest:
                    if not message.cookie:
                        print("Flight 1 Server must return a cookie")
                        return Flight.FLIGHT1

                    state.cookie = message.cookie
                    return Flight.FLIGHT3

                case HandshakeMessageType.ServerHello:
                    # Server skipped HelloVerifyRequest, process ServerHello directly
                    if not isinstance(message, ServerHello):
                        raise ValueError("Flight 1 message must be a ServerHello instance")

                    state.remote_random = message.random
                    print(f"Flight 1: ServerHello received, remote_random set")

                    if not message.cipher_suite:
                        raise ValueError("Flight 1 ServerHello must contain cipher suite")

                    if message.cipher_suite != state.pending_cipher_suite.cipher_suite_id():
                        raise ValueError(f"Flight 1 different cipher suite: {message.cipher_suite} vs {state.pending_cipher_suite.cipher_suite_id()}")

                    # Check for Extended Master Secret extension (RFC 7627)
                    if message.extensions:
                        for ext in message.extensions:
                            if isinstance(ext, ExtendedMasterSecret):
                                state.use_extended_master_secret = True
                                print("Flight 1: Extended Master Secret negotiated")
                                break

                case HandshakeMessageType.Certificate:
                    if not isinstance(message, Certificate):
                        raise ValueError("Flight 1 message must be a Certificate instance")
                    if not message.certificates:
                        raise ValueError("Flight 1 not found required remote certificates")

                    state.remote_peer_certificates = message.certificates
                    print(f"Flight 1: Certificate received, {len(message.certificates)} cert(s)")

                case HandshakeMessageType.KeyServerExchange:
                    if not isinstance(message, KeyServerExchange):
                        raise ValueError("Flight 1 message must be a KeyServerExchange instance")
                    if not message.named_curve and state.local_keypair.curve != message.named_curve:
                        raise ValueError("Flight 1 key server named_curve mismatch")

                    try:
                        self.__handle_server_key_exchange(state, message)
                        print(f"Flight 1: KeyServerExchange processed, pre_master_secret computed")
                    except Exception as e:
                        print(f"Flight 1: Unable to generate pre shared master key: {e}")

                case HandshakeMessageType.CertificateRequest:
                    # Optional: server requests client certificate
                    print("Flight 1: CertificateRequest received")

                case HandshakeMessageType.ServerHelloDone:
                    # Cookie is optional - server may skip HelloVerifyRequest
                    # and proceed directly with ServerHello, Certificate, etc.
                    if hasattr(message, 'cookie') and message.cookie:
                        state.cookie = message.cookie

                    print("Flight 1: ServerHelloDone received, transitioning to Flight 5")
                    return Flight.FLIGHT5

                case _:
                    print(f"Flight 1: Ignoring message type {message.message_type}")
