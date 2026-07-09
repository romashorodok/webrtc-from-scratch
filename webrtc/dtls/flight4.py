import asyncio
import binascii
import hashlib
import logging

logger = logging.getLogger("webrtc.dtls.flight4")

from webrtc.dtls.dtls_record import (
    Certificate,
    CertificateType,
    CertificateVerify,
    ClientKeyExchange,
    Handshake,
    HandshakeMessageType,
    Message,
    RecordLayer,
    SignatureHashAlgorithm,
)
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.dtls_typing import EllipticCurveGroup
from webrtc.dtls.flight_state import Flight, FlightTransition, HandshakeCacheKey, State
from webrtc.dtls.dtls_cipher_suite import generate_server_signature
from webrtc.dtls.prf import prf_master_secret, prf_extended_master_secret


class Flight4(FlightTransition):
    __msg = DEFAULT_FACTORY

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        if not state.remote_random:
            raise ValueError("Not found remote random")

        # keypair = Keypair.generate_X25519()
        # keypair = state.local_keypair

        # signature = generate_server_signature(
        #     state.remote_random,
        #     state.local_random.marshal_fixed(),
        #     state.local_certificate.pubkey_der,
        #     # keypair.publicKey.to_der(),
        #     # keypair.publicKey,
        #     keypair.curve,
        #     # state.local_keypair.privateKey,
        # )

        # signature = hashlib.sha256(signature).digest()
        # signature = state.local_certificate.signkey.sign(
        #     signature, ec.ECDSA(hashes.SHA256())
        # )

        # signature = state.local_keypair.generate_server_signature(
        #     state.remote_random,
        #     state.local_random.marshal_fixed(),
        #     state.local_keypair.privateKey,
        # )

        # signature = state.local_keypair.generate_server_signature(
        #     state.remote_random,
        #     state.local_random.marshal_fixed(),
        # )

        signature_input = generate_server_signature(
            state.remote_random,
            state.local_random.marshal_fixed(),
            state.local_keypair.public_key_bytes(),
            state.local_keypair.curve,
        )
        signature = state.local_certificate.sign(signature_input)
        curve = state.local_keypair.curve

        return [
            self.__msg.server_hello(
                state.local_random.marshal_fixed(),
                state.pending_cipher_suite,
                state.use_extended_master_secret,
            ),
            self.__msg.certificate([state.local_certificate]),
            self.__msg.key_server_exchange(
                signature,
                curve,
                state.local_keypair.signature_hash_algorithm,
                state.local_keypair.public_key_bytes(),
            ),
            self.__msg.certificate_request(
                [CertificateType.ECDSA], [state.local_keypair.signature_hash_algorithm]
            ),
            self.__msg.server_hello_done(),
        ]

    def __setup_cipher_suite(
        self, state: State, client_key_exchange: ClientKeyExchange, session_hash_for_ems: bytes | None = None
    ):
        logger.info("__setup_cipher_suite: starting cipher suite initialization")

        if not client_key_exchange.pubkey:
            logger.error("__setup_cipher_suite: client pubkey is missing")
            raise ValueError("Not found pubkey")

        logger.debug(f"__setup_cipher_suite: client pubkey length={len(client_key_exchange.pubkey)}")

        # Compute pre-master secret using ECDH
        pre_master_secret = state.local_keypair.compute_shared_secret(
            client_key_exchange.pubkey
        )

        logger.debug(f"__setup_cipher_suite: pre_master_secret={binascii.hexlify(pre_master_secret).decode()}")

        if not state.remote_random:
            logger.error("__setup_cipher_suite: remote_random is missing")
            raise ValueError("Flight 4 not found remote random")

        logger.debug(f"__setup_cipher_suite: remote_random={binascii.hexlify(state.remote_random).decode()}")
        logger.debug(f"__setup_cipher_suite: local_random={binascii.hexlify(state.local_random.marshal_fixed()).decode()}")

        # Compute master secret - use Extended Master Secret (RFC 7627) if negotiated
        if state.use_extended_master_secret and session_hash_for_ems is not None:
            # Extended Master Secret: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)
            # session_hash is Hash(handshake messages from ClientHello through ClientKeyExchange)
            session_hash_digest = hashlib.sha256(session_hash_for_ems).digest()
            logger.info("__setup_cipher_suite: Using Extended Master Secret (RFC 7627)")
            logger.debug(f"__setup_cipher_suite: session_hash_for_ems length={len(session_hash_for_ems)}")
            logger.debug(f"__setup_cipher_suite: session_hash_digest={session_hash_digest.hex()}")
            state.master_secret = prf_extended_master_secret(
                pre_master_secret,
                session_hash_digest,
                hashlib.sha256,
            )
        else:
            # Standard master secret: master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
            logger.info("__setup_cipher_suite: Using standard master secret")
            state.master_secret = prf_master_secret(
                pre_master_secret,
                state.remote_random,
                state.local_random.marshal_fixed(),
            )

        logger.debug(f"__setup_cipher_suite: master_secret={binascii.hexlify(state.master_secret).decode()}")

        state.pending_cipher_suite.start(
            state.master_secret,
            state.remote_random,
            state.local_random.marshal_fixed(),
            False,
        )

        logger.info("__setup_cipher_suite: cipher suite started, signaling ready")
        # Signal that cipher suite is ready for decryption
        state.cipher_suite_ready.set()
        logger.info("__setup_cipher_suite: cipher_suite_ready event set")

    def __validate_client_certificate(
        self,
        state: State,
        certificate: Certificate,
        certificate_verify: CertificateVerify,
    ):
        client_certificate_sign = state.cache.pull_and_merge(
            [
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ClientHello,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ServerHello,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Certificate,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.KeyServerExchange,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.CertificateRequest,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ServerHelloDone,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Certificate,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ClientKeyExchange,
                    epoch=0,
                    is_remote=True,
                ),
            ]
        )

        if not state.remote_random:
            raise ValueError(
                "Flight 4 remote random must be at client validation stage"
            )

        if not (
            certificate_verify.signature_hash_algorithm
            == SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
        ):
            raise ValueError(
                f"Flight 4 support only a secp256r1(prime256p1), current curve {state.local_keypair.curve}"
            )

        if not certificate.certificates:
            raise ValueError("Flight 4 must contain a certificates")

        if not certificate_verify.signature:
            raise ValueError("Flight 4 must contain a certificate signature")

        try:
            print("Flight 4 fingerprint", binascii.hexlify(client_certificate_sign))
            # client_certificate_sign = bytes(0x01)
            # verified = verify_certificate_signature(
            #     client_certificate_sign,
            #     certificate_verify.signature,
            #     hashlib.sha256,
            #     certificate.certificates,
            # )
            # print("Is client cert verified??", verified)
        except Exception as e:
            print("Client cert invalid with err", e)

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        print("[Flight4] parse: STARTED, waiting for ClientKeyExchange...")
        logger.info("parse: Flight 4 starting, waiting for ClientKeyExchange...")

        # Step 1: Wait for ClientKeyExchange (required) - Certificate and CertificateVerify are optional
        # Following the Rust implementation which marks Certificate and CertificateVerify as optional
        await state.cache.once(
            [
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ClientKeyExchange,
                    epoch=0,
                    is_remote=True,
                ),
            ]
        )
        print("[Flight4] parse: received ClientKeyExchange from cache")
        logger.info("parse: received ClientKeyExchange from cache")

        # Step 2: Get client key exchange and IMMEDIATELY setup cipher suite
        # This MUST happen before ChangeCipherSpec is processed so pending_cipher_suite is ready
        client_key_exchange_bytes = state.cache.pull(
            ClientKeyExchange,
            HandshakeCacheKey(
                message_type=HandshakeMessageType.ClientKeyExchange,
                epoch=0,
                is_remote=True,
            ),
        )
        logger.debug(f"parse: client_key_exchange_bytes length={len(client_key_exchange_bytes)}")

        client_key_exchange = Handshake.unmarshal(client_key_exchange_bytes)
        if not isinstance(client_key_exchange.message, ClientKeyExchange):
            logger.error(f"parse: expected ClientKeyExchange but got {type(client_key_exchange.message)}")
            raise ValueError("Not a client key exchange")

        # For Extended Master Secret (RFC 7627), compute session hash from
        # handshake messages: ClientHello through ClientKeyExchange
        session_hash_for_ems: bytes | None = None
        if state.use_extended_master_secret:
            logger.info("parse: computing session hash for Extended Master Secret")
            session_hash_for_ems = state.cache.pull_and_merge(
                [
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.ClientHello,
                        epoch=0,
                        is_remote=True,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.ServerHello,
                        epoch=0,
                        is_remote=False,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.Certificate,
                        epoch=0,
                        is_remote=False,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.KeyServerExchange,
                        epoch=0,
                        is_remote=False,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.CertificateRequest,
                        epoch=0,
                        is_remote=False,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.ServerHelloDone,
                        epoch=0,
                        is_remote=False,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.Certificate,
                        epoch=0,
                        is_remote=True,
                    ),
                    HandshakeCacheKey(
                        message_type=HandshakeMessageType.ClientKeyExchange,
                        epoch=0,
                        is_remote=True,
                    ),
                ]
            )
            logger.debug(f"parse: session_hash_for_ems length={len(session_hash_for_ems)}")

        logger.info("parse: calling __setup_cipher_suite to initialize encryption")
        # Initialize the cipher suite NOW, before encrypted messages arrive
        self.__setup_cipher_suite(state, client_key_exchange.message, session_hash_for_ems)
        logger.info("parse: cipher suite initialized, can now decrypt incoming messages")

        # Step 3: Now wait for the encrypted Finished message (epoch=1)
        # At this point, pending_cipher_suite is ready, so when ChangeCipherSpec
        # sets cipher_suite = pending_cipher_suite, decryption will work
        logger.info("parse: waiting for encrypted Finished message (epoch=1)...")
        await state.cache.once(
            [
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Finished,
                    epoch=1,
                    is_remote=True,
                ),
            ]
        )

        logger.info("parse: received Finished message, transitioning to Flight 6")

        return Flight.FLIGHT6

        # while True:
        #     # print("Flight 4 wait")
        #     message = await handshake_message_ch.get()
        #     # print("Flight 4 parse hello client hello", message)
        #
        #     match message.message_type:
        #         case HandshakeMessageType.ClientKeyExchange:
        #             if not isinstance(message, ClientKeyExchange):
        #                 raise ValueError("Flight 4 message must be a ClientKeyExchange")
        #
        #             verifying_key = VerifyingKey.from_der(message.pubkey)
        #
        #             state.pre_master_secret = (
        #                 Keypair.pre_master_secret_from_pub_and_priv_key(
        #                     verifying_key,
        #                     state.local_keypair.privateKey,
        #                 )
        #             )
        #
        #             print(
        #                 "Flight 4 pre master secret",
        #                 binascii.hexlify(state.pre_master_secret),
        #             )
        #
        #             if not state.remote_random:
        #                 raise ValueError("Flight 4 not found remote random")
        #
        #             state.master_secret = prf_master_secret(
        #                 state.pre_master_secret,
        #                 state.remote_random,
        #                 state.local_random.marshal_fixed(),
        #                 hashlib.sha256,
        #             )
        #
        #             print(
        #                 "Flight 4 master secret", binascii.hexlify(state.master_secret)
        #             )
        #
        #             if not state.pending_cipher_suite:
        #                 raise ValueError("Flight 4 require a pending cipher suite")
        #
        #             # print("Flight 4", binascii.hexlify(state.remote_random), binascii.hexlify(state.local_random.marshal_fixed()) )
        #
        #             state.pending_cipher_suite.start(
        #                 state.master_secret,
        #                 state.remote_random,
        #                 state.local_random.marshal_fixed(),
        #                 True,
        #             )
        #
        #             print("Flight 4 Success cipher suite")
        #
        #         case HandshakeMessageType.CertificateVerify:
        #             # TODO: cert verify
        #             # return Flight.FLIGHT6
        #             print("TODO: verify cert")
        #             if not state.pending_local_handshake_layers:
        #                 raise ValueError("Not found pending handshake layers")
        #
        #             for layer in state.pending_local_handshake_layers:
        #                 print("Pending layer", layer.content)
        #
        #         case HandshakeMessageType.Finished:
        #             print("Finished")
        #             return Flight.FLIGHT6
        #
        #         case _:
        #             pass
