import asyncio
import time

from ecdsa.util import binascii

import native
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
            verify = state.cache.pull_and_merge(server_verifying_data)

            certificate = state.cache.pull(
                Certificate,
                HandshakeCacheKey(
                    message_type=HandshakeMessageType.Certificate,
                    epoch=0,
                    is_remote=True,
                ),
            )

            print("Flight 6 verify data", binascii.hexlify(verify))
            verifying_data = native.prf_verify_data_server(state.master_secret, verify)
            # verifying_data = verify_data_server(state.master_secret, verify)
            print("Flight 6 verifying data", binascii.hexlify(verifying_data))
        except Exception as e:
            print("FLight 6 error", e)
            return

        finished = self.__msg.finished(verifying_data)

        return [self.__msg.change_cipher_spec(), finished]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        ...
        # cache_result = state.cache.pull(
        #     Finished,
        #     HandshakeCacheKey(
        #         message_type=HandshakeMessageType.Finished,
        #         epoch=1,
        #         is_remote=True,
        #     ),
        # )
        # print("Finish has data??", cache_result.encrypted_payload)
        #
        # await asyncio.sleep(5)
        #
        # if not state.master_secret:
        #     raise ValueError("Master secret required")
        #
        # try:
        #     verify = state.cache.pull_and_merge(server_verifying_data)
        #
        #     certificate = state.cache.pull(
        #         Certificate,
        #         HandshakeCacheKey(
        #             message_type=HandshakeMessageType.Certificate,
        #             epoch=0,
        #             is_remote=True,
        #         ),
        #     )
        #     # print(certificate.header)
        #
        #     print("Flight 6 verify data", binascii.hexlify(verify))
        #     # verifying_data = native.prf_verify_data_server(state.master_secret, verify)
        #     verifying_data = native.prf_verify_data_server(state.master_secret, verify)
        #     print("Flight 6 verifying data", binascii.hexlify(verifying_data))
        # except Exception as e:
        #     print("FLight 6 error", e)
        #     return Flight.FLIGHT6
        #
        # finished = self.__msg.finished(verifying_data)
        #
        # pending_record_layers = [self.__msg.change_cipher_spec(), finished]
        #
        # message_sequence = 1
        # for record in pending_record_layers:
        #     record.header.sequence_number += state.handshake_sequence_number
        #     state.handshake_sequence_number += 1
        #
        #     if (
        #         record.header.content_type == ContentType.HANDSHAKE
        #         or record.header.content_type == ContentType.CHANGE_CIPHER_SPEC
        #     ):
        #         if not isinstance(record.content, Handshake) or not isinstance(
        #             record.content, ChangeCipherSpec
        #         ):
        #             continue
        #
        #         record.content.header.message_sequence = message_sequence
        #
        # send_batch = bytes()
        # MAX_MTU = 1280
        #
        # for layer in pending_record_layers:
        #     try:
        #         data = layer.marshal()
        #
        #         if layer.encrypt:
        #             if not state.pending_cipher_suite:
        #                 raise ValueError(
        #                     "layer data must be encrypted but cipher suite undefined"
        #                 )
        #
        #             print("Send seq number", layer.header.sequence_number)
        #
        #             data = state.pending_cipher_suite.encrypt(layer)
        #             if not data:
        #                 raise ValueError("None data after encrypt,")
        #
        #         if len(data) > MAX_MTU and len(send_batch) > MAX_MTU:
        #             raise ValueError(
        #                 "layer data has too much bytes. Message must be fragmented"
        #             )
        #
        #         send_batch += data
        #
        #     except Exception as e:
        #         # TODO: backoff
        #         print("Unable send packet. Err:", e, "layer", layer)
        #         await asyncio.sleep(10)
        #
        # await state.remote.sendto(send_batch)
        #
        # await asyncio.sleep(2)
        # return Flight.FLIGHT6
