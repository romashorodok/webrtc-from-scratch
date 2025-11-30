import asyncio
import binascii

from webrtc.dtls.dtls_cipher_suite import (
    prf_verify_data,
    verify_data_client,
    verify_data_server,
)
from webrtc.dtls.dtls_record import (
    Certificate,
    ChangeCipherSpec,
    ContentType,
    Finished,
    Handshake,
    HandshakeMessageType,
    Message,
    RecordHeader,
    RecordLayer,
)
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.flight_state import Flight, FlightTransition, HandshakeCacheKey, State


server_verifying_data = [
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
    HandshakeCacheKey(
        message_type=HandshakeMessageType.CertificateVerify,
        epoch=0,
        is_remote=True,
    ),
    HandshakeCacheKey(
        message_type=HandshakeMessageType.Finished,
        epoch=1,
        is_remote=True,
    ),
]


class Flight6(FlightTransition):
    __msg = DEFAULT_FACTORY

    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        if not state.master_secret:
            raise ValueError("Master secret required")

        try:
            # Debug: Check what's in the cache
            print("[Flight6] generate: checking cache for server verify_data computation")
            print(f"[Flight6] cache has {len(state.cache._items)} items total")
            for key in server_verifying_data:
                try:
                    data = state.cache._cache.get(key)
                    # Find the item to show message_sequence
                    item_seq = None
                    for item in state.cache._items:
                        if item.message_type == key.message_type and item.epoch == key.epoch and item.is_remote == key.is_remote:
                            item_seq = item.message_sequence
                    print(f"[Flight6] cache key {key}: {'present' if data else 'MISSING'} ({len(data) if data else 0} bytes, msg_seq={item_seq})")
                except:
                    print(f"[Flight6] cache key {key}: MISSING")

            verify = state.cache.pull_and_merge(server_verifying_data)

            print(f"[Flight6] verify data for server finished: {len(verify)} bytes")
            print(f"[Flight6] verify data hex (first 100): {binascii.hexlify(verify[:100]).decode()}...")
            print(f"[Flight6] verify data hex (last 50): {binascii.hexlify(verify[-50:]).decode()}")

            # Show SHA256 hash of all handshake messages
            import hashlib
            verify_hash = hashlib.sha256(verify).digest()
            print(f"[Flight6] SHA256 of handshake messages: {binascii.hexlify(verify_hash).decode()}")

            # Use Python PRF implementation instead of native
            verifying_data = verify_data_server(state.master_secret, verify)
            print(f"[Flight6] server verifying_data: {binascii.hexlify(verifying_data).decode()}")
        except Exception as e:
            print(f"[Flight6] generate error: {e}")
            import traceback
            traceback.print_exc()
            return

        finished = self.__msg.finished(verifying_data)

        return [self.__msg.change_cipher_spec(), finished]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        """
        Verify client Finished message.

        The client Finished message contains verify_data which is:
        PRF(master_secret, "client finished", Hash(handshake_messages))[0..11]

        We compute the expected value and compare it to the received value.

        Note: Flight 4 already received and cached the Finished message.
        We just need to verify it here.
        """
        if not state.master_secret:
            raise ValueError("Master secret required to verify client Finished")

        # Get the handshake messages for client verify_data computation
        # Client verify_data uses messages up to but NOT including client Finished
        client_verify_cache_keys = [
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
            HandshakeCacheKey(
                message_type=HandshakeMessageType.CertificateVerify,
                epoch=0,
                is_remote=True,
            ),
        ]

        try:
            handshake_messages = state.cache.pull_and_merge(client_verify_cache_keys)

            # Get the client Finished message from cache
            finished_bytes = state.cache.pull(
                Finished,
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Finished,
                    epoch=1,
                    is_remote=True,
                ),
            )

            # Parse the Finished message - skip the handshake header (12 bytes)
            # Handshake header: type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3) = 12 bytes
            finished = Handshake.unmarshal(finished_bytes)
            if not isinstance(finished.message, Finished):
                print(f"Flight 6 parse: expected Finished in cache, got {type(finished.message)}")
                return Flight.FLIGHT6

            # Compute expected client verify_data using Python PRF
            expected_verify_data = verify_data_client(state.master_secret, handshake_messages)

            print(f"Flight 6 parse: received verify_data: {binascii.hexlify(finished.message.verify_data)}")
            print(f"Flight 6 parse: expected verify_data: {binascii.hexlify(expected_verify_data)}")

            # Compare received vs expected
            if finished.message.verify_data != expected_verify_data:
                print("Flight 6 parse: Client Finished verify_data MISMATCH!")
                # TODO: Send decrypt_error alert
                return Flight.FLIGHT6

            print("Flight 6 parse: Client Finished verified successfully!")
            return Flight.FLIGHT6

        except Exception as e:
            print(f"Flight 6 parse error: {e}")
            import traceback
            traceback.print_exc()
            return Flight.FLIGHT6
