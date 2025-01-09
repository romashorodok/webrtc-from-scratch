import asyncio

from ecdsa.util import binascii

from webrtc.dtls.dtls_cipher_suite import prf_verify_data, verify_data_server
from webrtc.dtls.dtls_record import (
    Certificate,
    HandshakeMessageType,
    Message,
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
            verify = state.cache.pull_and_merge(server_verifying_data)

            certificate = state.cache.pull_record(
                Certificate,
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Certificate,
                    epoch=0,
                    is_remote=True,
                ),
            )
            print(certificate.header)

            print("Flight 6 verify data", binascii.hexlify(verify))
            verifying_data = verify_data_server(state.master_secret, verify)
            print("Flight 6 verifying data", binascii.hexlify(verifying_data))
        except Exception as e:
            print("FLight 6 error", e)
            return

        finished = self.__msg.finished(verifying_data)

        return [self.__msg.change_cipher_spec(), finished]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight: ...
