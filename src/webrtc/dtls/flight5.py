import asyncio
import binascii
import hashlib
from typing import Callable

from ecdsa import VerifyingKey

from webrtc.dtls.dtls_cipher_suite import (
    Keypair,
    ecdh_value_key_message,
    prf_master_secret,
    verify_certificate_signature,
)
from webrtc.dtls.dtls_record import (
    Handshake,
    HandshakeHeader,
    HandshakeMessageType,
    KeyServerExchange,
    Message,
    RecordLayer,
    SignatureHashAlgorithm,
)
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight5(FlightTransition):
    __msg = DEFAULT_FACTORY

    def __initialize_cipher_suite(
        self,
        state: State,
        key_server_exchange: KeyServerExchange,
        handshake_messages_merged: bytes,
    ):
        if not state.pending_cipher_suite:
            raise ValueError("Flight5 cipher suite must be defined")

        if not state.pre_master_secret:
            raise ValueError("Flight5 pre master secret must be defined")

        if not state.remote_random:
            raise ValueError("Flight5 must know remote random")

        if (
            not key_server_exchange.pubkey
            or not key_server_exchange.named_curve
            or not key_server_exchange.signature
        ):
            raise ValueError(
                "Flight5 KeyServerExchange must have a pubkey, named_curve and signature  defined"
            )

        hash_func: Callable | None = None
        match key_server_exchange.signature_hash_algorithm:
            case SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256:
                hash_func = hashlib.sha256
            case _:
                raise ValueError(
                    "Unsupported cipher suite in key_server_exchange.signature_hash_algorithm"
                )

        print(
            "Flight 5 pre master secret",
            binascii.hexlify(state.pre_master_secret),
        )

        state.master_secret = prf_master_secret(
            state.pre_master_secret,
            state.local_random.marshal_fixed(),
            state.remote_random,
            hashlib.sha256,
        )

        print("Flight 5 master secret", binascii.hexlify(state.master_secret))

        # TODO: By default it expect a certificate auth type, ref it
        if not state.remote_peer_certificates:
            raise ValueError("Fligh5 not found remote peer certificates")

        expected_ecdh_secret_message = ecdh_value_key_message(
            state.local_random.marshal_fixed(),
            state.remote_random,
            key_server_exchange.pubkey,
            key_server_exchange.named_curve,
        )
        # print(
        #     "Expected client expected_ecdh_secret_message",
        #     binascii.hexlify(expected_ecdh_secret_message),
        # )

        verified = verify_certificate_signature(
            expected_ecdh_secret_message,
            key_server_exchange.signature,
            hash_func,
            state.remote_peer_certificates,
        )
        if not verified:
            raise ValueError("Invalid certificate signature")

        print("Certificate verified success ???", verified)

        state.pending_cipher_suite.start(
            state.master_secret,
            state.local_random.marshal_fixed(),
            state.remote_random,
            False,
        )

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        if not state.pending_remote_handshake_messages:
            raise ValueError("Flight5 not found pending messages")

        if not state.remote_random:
            raise ValueError("Flight5 not found remote random")

        # print("flight 5 messages", state.pending_remote_handshake_messages)

        merged = bytes()
        seq_pred = state.handshake_sequence_number

        # print("pending messages", state.pending_remote_handshake_messages)

        key_server_exchange: KeyServerExchange | None = None
        result = list[RecordLayer]()
        for message in state.pending_remote_handshake_messages:
            match message.message_type:
                case HandshakeMessageType.KeyServerExchange:
                    if not isinstance(message, KeyServerExchange):
                        raise ValueError("Require KeyServerExchange to be present")
                    key_server_exchange = message
                case _:
                    pass

            try:
                reconstructed = Handshake(
                    header=HandshakeHeader(
                        message_sequence=seq_pred,
                        handshake_type=message.message_type,
                        fragment_offset=0,
                    ),
                    message=message,
                )

                seq_pred += 1
                merged += reconstructed.marshal()
            except Exception as e:
                print("Flight 5 error", e)

        if not key_server_exchange:
            raise ValueError(
                "Require KeyServerExchange to be present for cipher suite init"
            )

        try:
            self.__initialize_cipher_suite(state, key_server_exchange, merged)
        except Exception as e:
            print("Flight5 Unable init cipher suite", e)
            raise e

        # certificate = Certificate(bytes())
        # state.local_certificate = create_self_signed_cert_with_ecdsa(
        #     state.local_keypair
        # )
        # certificate.certificates = [state.local_certificate]

        layer_certificate = self.__msg.certificate([state.local_certificate])
        if isinstance(layer_certificate.content, Handshake):
            layer_certificate.content.header.message_sequence = seq_pred

        result.append(layer_certificate)
        seq_pred += 1
        merged += layer_certificate.content.marshal()

        # print("merged data", merged)
        # print("remote state", binascii.hexlify(state.remote_random))

        layer_client_key_exchange = self.__msg.client_key_exchange(
            state.local_keypair.publicKey.to_der()
        )
        if isinstance(layer_client_key_exchange.content, Handshake):
            layer_client_key_exchange.content.header.message_sequence = seq_pred

        result.append(layer_client_key_exchange)
        seq_pred += 1
        merged += layer_client_key_exchange.content.marshal()

        # TODO: Why client side separate a pubkey and signature of the cert ?
        # KeyServerExchange sends pubkey and signature in one layer
        # certificate_verify = CertificateVerify(bytes())

        # TODO: Don't hard code, get from the key_server_exchange message
        # TODO: get values from local key pair
        # certificate_verify.signature_hash_algorithm = (
        #     SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
        # )

        # TODO: Check cache if this types of handshake message already sent merge before into merged and sign it with predicted merged data
        # ClientHello
        # ServerHello
        # Certificate
        # ServerKeyExchange
        # CertificateRequest
        # ServerHelloDone
        # Certificate
        # ClientKeyExchange

        # certificate_verify.signature = state.local_keypair.sign(merged)
        layer_certificate_verify_signature = self.__msg.certificate_verify(
            state.local_keypair.sign(merged),
            state.local_keypair.signature_hash_algorithm,
        )
        if isinstance(layer_certificate_verify_signature.content, Handshake):
            layer_certificate_verify_signature.content.header.message_sequence = (
                seq_pred
            )

        # RecordLayer(
        #     header=RecordHeader(
        #         content_type=ContentType.HANDSHAKE,
        #         version=DTLSVersion.V1_2,
        #         epoch=0,
        #         sequence_number=state.local_sequence_number,
        #     ),
        #     content=Handshake(
        #         header=HandshakeHeader(
        #             handshake_type=HandshakeMessageType.CertificateVerify,
        #             message_sequence=seq_pred,
        #             fragment_offset=0,
        #         ),
        #         message=certificate_verify,
        #     ),
        # )

        result.append(layer_certificate_verify_signature)
        seq_pred += 1
        merged += layer_certificate_verify_signature.content.marshal()

        # TODO: This not a handshake
        layer_change_cipher_spec = self.__msg.change_cipher_spec()
        # RecordLayer(
        #     header=RecordHeader(
        #         content_type=ContentType.CHANGE_CIPHER_SPEC,
        #         version=DTLSVersion.V1_2,
        #         epoch=0,
        #         sequence_number=state.local_sequence_number,
        #     ),
        #     content=ChangeCipherSpec(),
        # )
        result.append(layer_change_cipher_spec)
        # seq_pred += 1
        # merged += layer_change_cipher_spec.content.marshal()

        if not state.master_secret:
            raise ValueError("Flight 5 master_secret must be defined by cuite")

        # if not state.local_verify:
        #     state.local_verify = verify_data_client(state.master_secret, merged)
        # print(state.local_verify, len(state.local_verify))

        layer_finished = self.__msg.finished()
        if isinstance(layer_finished.content, Handshake):
            layer_finished.content.header.message_sequence = seq_pred

        # RecordLayer(
        #     header=RecordHeader(
        #         content_type=ContentType.HANDSHAKE,
        #         version=DTLSVersion.V1_2,
        #         epoch=1,
        #         sequence_number=state.local_sequence_number,
        #     ),
        #     content=Handshake(
        #         header=HandshakeHeader(
        #             handshake_type=HandshakeMessageType.Finished,
        #             message_sequence=seq_pred,
        #             fragment_offset=0,
        #         ),
        #         message=Finished(bytes()),
        #     ),
        # )
        # layer_finished.encrypt = True

        result.append(layer_finished)
        # return result
        return [
            layer_client_key_exchange,
            layer_change_cipher_spec,
            layer_finished,
        ]
        return

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        await asyncio.sleep(2)
        return Flight.FLIGHT5
