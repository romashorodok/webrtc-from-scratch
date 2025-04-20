import asyncio
import binascii
import hashlib
from typing import Callable

from OpenSSL import crypto
from ecdsa import NIST256p, SigningKey, VerifyingKey

from webrtc.dtls.dtls_cipher_suite import (
    Keypair,
    ecdh_value_key_message,
    generate_server_signature,
    prf_master_secret,
    verify_certificate_signature,
)
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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import native


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

        signature = state.local_certificate._keypair.generate_server_signature(
            state.remote_random,
            state.local_random.marshal_fixed(),
        )
        curve = EllipticCurveGroup(state.local_certificate._keypair.curve_id())

        return [
            self.__msg.server_hello(
                state.local_random.marshal_fixed(), state.pending_cipher_suite
            ),
            self.__msg.certificate([state.local_certificate]),
            self.__msg.key_server_exchange(
                signature,
                curve,
                state.local_keypair.signature_hash_algorithm,
                state.local_certificate.pubkey_der,
                # keypair.publicKey.to_der(),
            ),
            self.__msg.certificate_request(
                [CertificateType.ECDSA], [state.local_keypair.signature_hash_algorithm]
            ),
            self.__msg.server_hello_done(),
        ]

    def __setup_cipher_suite(
        self, state: State, client_key_exchange: ClientKeyExchange
    ):
        # state.local_certificate.signkey

        # print("Flight 4 sign key", state.local_certificate.signkey)

        if not client_key_exchange.pubkey:
            raise ValueError("Not found pubkey")

        pre_master_secret = native.prf_pre_master_secret(
            client_key_exchange.pubkey, state.local_certificate._keypair
        )

        # pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
        #     ec.SECP256R1(), client_key_exchange.pubkey
        # )

        # pubkey = pubkey.public_bytes(
        #     serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        # )
        # pubkey = VerifyingKey.from_public_point(pubkey, curve=NIST256p)

        # private_key = state.local_certificate.signkey
        # private_key_bytes = private_key.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.TraditionalOpenSSL,
        #     encryption_algorithm=serialization.NoEncryption(),
        # )

        # private_key = SigningKey.from_pem(private_key_bytes)

        # pre_master_secret = private_key.exchange(ec.ECDH(), pubkey)

        # server_shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        # pre_master_secret = Keypair.pre_master_secret_from_pub_and_priv_key(
        #     pubkey,
        #     private_key,
        # )

        print("Flight 4 pre master secret", binascii.hexlify(pre_master_secret))

        if not state.remote_random:
            raise ValueError("Flight 4 not found remote random")
        #

        state.master_secret = native.prf_master_secret(
            pre_master_secret,
            state.remote_random,
            state.local_random.marshal_fixed(),
        )

        # state.master_secret = prf_master_secret(
        #     pre_master_secret,
        #     state.remote_random,
        #     state.local_random.marshal_fixed(),
        #     hashlib.sha256,
        # )

        print("Flight 4 master secret", binascii.hexlify(state.master_secret))
        #
        # if not state.pending_cipher_suite:
        #     raise ValueError("Flight 4 require a pending cipher suite")
        #
        # print("Flight 4", binascii.hexlify(state.remote_random), binascii.hexlify(state.local_random.marshal_fixed()) )
        #

        state.pending_cipher_suite.start(
            state.master_secret,
            state.remote_random,
            state.local_random.marshal_fixed(),
            False,
        )

        print("Flight 4 Success cipher suite")

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
        print("Flight 4 block??")
        await state.cache.once(
            [
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
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.CertificateVerify,
                    epoch=0,
                    is_remote=True,
                ),
                # HandshakeCacheKey(
                #     message_type=HandshakeMessageType.Finished,
                #     epoch=1,
                #     is_remote=True,
                # ),
            ]
        )
        print("Flight 4 block?? Recv all needed parts")

        # self.__validate_client_certificate(
        #     state,
        #     state.cache.pull(
        #         Certificate,
        #         HandshakeCacheKey(
        #             message_type=HandshakeMessageType.Certificate,
        #             epoch=0,
        #             is_remote=True,
        #         ),
        #     ),
        #     state.cache.pull(
        #         CertificateVerify,
        #         HandshakeCacheKey(
        #             message_type=HandshakeMessageType.CertificateVerify,
        #             epoch=0,
        #             is_remote=True,
        #         ),
        #     ),
        # )

        client_key_exchange_bytes = state.cache.pull(
            ClientKeyExchange,
            HandshakeCacheKey(
                message_type=HandshakeMessageType.ClientKeyExchange,
                epoch=0,
                is_remote=True,
            ),
        )
        client_key_exchange = Handshake.unmarshal(client_key_exchange_bytes)
        if not isinstance(client_key_exchange.message, ClientKeyExchange):
            raise ValueError("Not a client key exchange")

        self.__setup_cipher_suite(state, client_key_exchange.message)

        await state.cache.once(
            [
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Finished,
                    epoch=1,
                    is_remote=True,
                ),
            ]
        )

        print("All done transition to flight 6")

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
