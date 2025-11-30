import asyncio
import binascii
import hashlib
from typing import Callable

from webrtc.dtls.prf import prf_master_secret, prf_extended_master_secret
from webrtc.dtls.dtls_cipher_suite import verify_data_client
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
from webrtc.dtls.flight_state import Flight, FlightTransition, HandshakeCacheKey, State


class Flight5(FlightTransition):
    __msg = DEFAULT_FACTORY

    def __initialize_cipher_suite(
        self,
        state: State,
        key_server_exchange: KeyServerExchange,
        session_hash_for_ems: bytes | None = None,
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

        # Compute master secret - use Extended Master Secret (RFC 7627) if negotiated
        if state.use_extended_master_secret and session_hash_for_ems is not None:
            # Extended Master Secret: master_secret = PRF(pre_master_secret, "extended master secret", session_hash)
            # session_hash is Hash(handshake messages from ClientHello through ClientKeyExchange)
            session_hash_digest = hashlib.sha256(session_hash_for_ems).digest()
            print(f"Flight 5: Using Extended Master Secret (RFC 7627)")
            print(f"Flight 5: session_hash_for_ems length={len(session_hash_for_ems)}")
            print(f"Flight 5: session_hash_digest={session_hash_digest.hex()}")
            state.master_secret = prf_extended_master_secret(
                state.pre_master_secret,
                session_hash_digest,
                hashlib.sha256,
            )
        else:
            # Standard master secret: master_secret = PRF(pre_master_secret, "master secret", client_random + server_random)
            print(f"Flight 5: Using standard master secret")
            state.master_secret = prf_master_secret(
                state.pre_master_secret,
                state.local_random.marshal_fixed(),
                state.remote_random,
                hashlib.sha256,
            )

        print("Flight 5 master secret", binascii.hexlify(state.master_secret))

        # TODO: Certificate signature verification should be done via Rust
        # For now, skip verification (server certificate is trusted)
        # if not state.remote_peer_certificates:
        #     raise ValueError("Flight5 not found remote peer certificates")
        print("Flight 5: Certificate verification skipped (TODO: implement via Rust)")

        state.pending_cipher_suite.start(
            state.master_secret,
            state.local_random.marshal_fixed(),
            state.remote_random,
            True,  # We are the client, so use client_write_key for encryption
        )

        # Signal that cipher suite is ready for decryption
        state.cipher_suite_ready.set()
        print("Flight 5 cipher suite started")

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        # if not state.pending_remote_handshake_messages:
        #     raise ValueError("Flight5 not found pending messages")

        if not state.remote_random:
            raise ValueError("Flight5 not found remote random")

        # print("flight 5 messages", state.pending_remote_handshake_messages)

        cache_fingerprint = bytes()

        # print("pending messages", state.pending_remote_handshake_messages)

        key_server_exchange_bytes = state.cache.pull(
            KeyServerExchange,
            HandshakeCacheKey(
                message_type=HandshakeMessageType.KeyServerExchange,
                epoch=0,
                is_remote=True,
            ),
        )

        # Unmarshal the bytes to get the actual KeyServerExchange object
        key_server_exchange_handshake = Handshake.unmarshal(key_server_exchange_bytes)
        if not isinstance(key_server_exchange_handshake.message, KeyServerExchange):
            raise ValueError("Flight5: Expected KeyServerExchange message")
        key_server_exchange = key_server_exchange_handshake.message

        result = list[RecordLayer]()

        print("Flight 5 block???")

        # Debug: Print each cached message's msg_seq
        for key in [
            HandshakeCacheKey(message_type=HandshakeMessageType.ClientHello, epoch=0, is_remote=False),
            HandshakeCacheKey(message_type=HandshakeMessageType.ServerHello, epoch=0, is_remote=True),
            HandshakeCacheKey(message_type=HandshakeMessageType.Certificate, epoch=0, is_remote=True),
            HandshakeCacheKey(message_type=HandshakeMessageType.KeyServerExchange, epoch=0, is_remote=True),
            HandshakeCacheKey(message_type=HandshakeMessageType.CertificateRequest, epoch=0, is_remote=True),
            HandshakeCacheKey(message_type=HandshakeMessageType.ServerHelloDone, epoch=0, is_remote=True),
        ]:
            try:
                data = state.cache._cache.get(key)
                if data:
                    # msg_seq is at bytes 4-5 of handshake header
                    msg_seq = int.from_bytes(data[4:6], 'big')
                    print(f"Flight5: cache {key.message_type.name} msg_seq={msg_seq}")
            except Exception as e:
                print(f"Flight5: cache error for {key.message_type.name}: {e}")

        cache_fingerprint = state.cache.pull_and_merge(
            [
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ClientHello,
                    epoch=0,
                    is_remote=False,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ServerHello,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Certificate,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.KeyServerExchange,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.CertificateRequest,
                    epoch=0,
                    is_remote=True,
                ),
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.ServerHelloDone,
                    epoch=0,
                    is_remote=True,
                ),
            ]
        )

        # seq_pred += 6

        # for message in state.pending_remote_handshake_messages:
        #     print("client layer", HandshakeMessageType(message.message_type))
        #     match message.message_type:
        #         case HandshakeMessageType.KeyServerExchange:
        #             if not isinstance(message, KeyServerExchange):
        #                 raise ValueError("Require KeyServerExchange to be present")
        #             key_server_exchange = message
        #         case _:
        #             pass
        #
        #     try:
        #         reconstructed = Handshake(
        #             header=HandshakeHeader(
        #                 message_sequence=seq_pred,
        #                 handshake_type=message.message_type,
        #                 fragment_offset=0,
        #             ),
        #             message=message,
        #         )
        #
        #         seq_pred += 1
        #         merged += reconstructed.marshal()
        #     except Exception as e:
        #         print("Flight 5 error", e)

        # if not key_server_exchange:
        #     raise ValueError(
        #         "Require KeyServerExchange to be present for cipher suite init"
        #     )

        # Get the next message sequence that will be assigned by FSM.prepare()
        # We need to set msg_seq BEFORE marshaling to fingerprint so the hash matches
        next_msg_seq = state.handshake_send_sequence

        # Create client Certificate first
        layer_certificate = self.__msg.certificate([state.local_certificate])
        if isinstance(layer_certificate.content, Handshake):
            layer_certificate.content.header.message_sequence = next_msg_seq
            print(f"Flight5: client Certificate using msg_seq={next_msg_seq}")
            next_msg_seq += 1

        result.append(layer_certificate)
        # Use content.marshal() to get only the handshake body, not the full record
        cert_bytes = layer_certificate.content.marshal()
        cert_msg_seq = int.from_bytes(cert_bytes[4:6], 'big')
        print(f"Flight5: client Certificate marshaled msg_seq={cert_msg_seq}")
        cache_fingerprint += cert_bytes

        # Create ClientKeyExchange
        layer_client_key_exchange = self.__msg.client_key_exchange(
            state.local_keypair.publicKey.to_der()
        )
        if isinstance(layer_client_key_exchange.content, Handshake):
            layer_client_key_exchange.content.header.message_sequence = next_msg_seq
            next_msg_seq += 1

        result.append(layer_client_key_exchange)
        # Use content.marshal() to get only the handshake body, not the full record
        client_key_exchange_bytes = layer_client_key_exchange.content.marshal()
        cache_fingerprint += client_key_exchange_bytes

        # For Extended Master Secret (RFC 7627), the session_hash is computed over
        # handshake messages from ClientHello through ClientKeyExchange (inclusive)
        # This is: cache_fingerprint at this point
        session_hash_for_ems = cache_fingerprint if state.use_extended_master_secret else None

        # NOW initialize cipher suite - with session_hash for EMS if negotiated
        try:
            self.__initialize_cipher_suite(
                state, key_server_exchange, session_hash_for_ems
            )
        except Exception as e:
            print("Flight5 Unable init cipher suite", e)
            raise e

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

        print("Flight 5 fingerprint", binascii.hexlify(cache_fingerprint))
        # Sign the handshake fingerprint using the certificate's private key
        signature = state.local_certificate.sign(cache_fingerprint)
        layer_certificate_verify_signature = self.__msg.certificate_verify(
            signature,
            SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256,
        )
        if isinstance(layer_certificate_verify_signature.content, Handshake):
            layer_certificate_verify_signature.content.header.message_sequence = next_msg_seq
            next_msg_seq += 1

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
        cache_fingerprint += layer_certificate_verify_signature.content.marshal()

        # ChangeCipherSpec is not a handshake message, don't include in fingerprint
        layer_change_cipher_spec = self.__msg.change_cipher_spec()
        result.append(layer_change_cipher_spec)

        if not state.master_secret:
            raise ValueError("Flight 5 master_secret must be defined by cipher suite")

        print(f"Flight 5: fingerprint for verify_data ({len(cache_fingerprint)} bytes): {binascii.hexlify(cache_fingerprint[:100]).decode()}...")

        # Compute client verify_data for Finished message
        # This is PRF(master_secret, "client finished", Hash(handshake_messages))[0..11]
        verifying_data = verify_data_client(state.master_secret, cache_fingerprint)
        print(f"Flight 5: client verifying_data: {binascii.hexlify(verifying_data).decode()}")

        layer_finished = self.__msg.finished(verifying_data)
        if isinstance(layer_finished.content, Handshake):
            layer_finished.content.header.message_sequence = next_msg_seq

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
        print("result done")
        return result

        # return [
        #     layer_client_key_exchange,
        #     layer_change_cipher_spec,
        #     layer_finished,
        # ]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight | None:
        # Wait for server's Finished message (encrypted, epoch=1)
        # After receiving this, the DTLS handshake is complete for the client
        while True:
            message = await handshake_message_ch.get()
            print(f"Flight 5: Received message type {message.message_type}")

            if message.message_type == HandshakeMessageType.Finished:
                print("Flight 5: Handshake complete (client side)")
                # Return None to signal handshake completion
                return None

            # Non-Finished messages are likely retransmissions from the server
            # (ServerHello, Certificate, etc. from Flight 4)
            # Drain them and signal FSM to retransmit our Flight 5
            print(f"Flight 5: Expected Finished but got {message.message_type} - draining retransmitted messages")

            # Check if there are more messages in the queue to drain
            while not handshake_message_ch.empty():
                try:
                    extra_msg = handshake_message_ch.get_nowait()
                    print(f"Flight 5: Drained retransmitted message type {extra_msg.message_type}")
                    if extra_msg.message_type == HandshakeMessageType.Finished:
                        print("Flight 5: Found Finished in queue - handshake complete")
                        return None
                except asyncio.QueueEmpty:
                    break

            # Return same flight to trigger retransmission
            return Flight.FLIGHT5
