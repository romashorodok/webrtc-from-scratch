import abc
import asyncio

from enum import IntEnum

from asn1crypto import x509

from webrtc.dtls.dtls_cipher_suite import (
    CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    Keypair,
    CipherSuite,
    create_self_signed_cert_with_ecdsa,
)
from webrtc.dtls.dtls_record import Message, RecordLayer
from webrtc.dtls.dtls_typing import EllipticCurveGroup, Random

#                     [RFC6347 Section-4.2.4]
#                      +-----------+
#                +---> | PREPARING | <--------------------+
#                |     +-----------+                      |
#                |           |                            |
#                |           | Buffer next flight         |
#                |           |                            |
#                |          \|/                           |
#                |     +-----------+                      |
#                |     |  SENDING  |<------------------+  | Send
#                |     +-----------+                   |  | HelloRequest
#        Receive |           |                         |  |
#           next |           | Send flight             |  | or
#         flight |  +--------+                         |  |
#                |  |        | Set retransmit timer    |  | Receive
#                |  |       \|/                        |  | HelloRequest
#                |  |  +-----------+                   |  | Send
#                +--)--|  WAITING  |-------------------+  | ClientHello
#                |  |  +-----------+   Timer expires   |  |
#                |  |         |                        |  |
#                |  |         +------------------------+  |
#        Receive |  | Send           Read retransmit      |
#           last |  | last                                |
#         flight |  | flight                              |
#                |  |                                     |
#               \|/\|/                                    |
#            +-----------+                                |
#            | FINISHED  | -------------------------------+
#            +-----------+
#                 |  /|\
#                 |   |
#                 +---+
#              Read retransmit
#           Retransmit last flight


class Flight(IntEnum):
    FLIGHT0 = 0
    FLIGHT1 = 1
    FLIGHT2 = 2
    FLIGHT3 = 3
    FLIGHT4 = 4
    FLIGHT4B = 5
    FLIGHT5 = 6
    FLIGHT5B = 7
    FLIGHT6 = 8


_DEFAULT_CURVE = EllipticCurveGroup.SECP256R1


class State:
    def __init__(self) -> None:
        self.local_random = Random()
        self.remote_random: bytes | None = None

        self.local_keypair: Keypair = Keypair.generate_P256()
        self.local_certificate: x509.Certificate = create_self_signed_cert_with_ecdsa(
            self.local_keypair
        )

        __cooike_random = Random(20, 20)
        __cooike_random.populate()
        self.cookie = __cooike_random.marshal_fixed()

        self.elliptic_curve: EllipticCurveGroup = _DEFAULT_CURVE

        self.remote_peer_certificates: list[x509.Certificate] | None = None

        self.pending_cipher_suite: CipherSuite = (
            CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
        )
        self.cipher_suite: CipherSuite | None = None

        self.pre_master_secret: bytes | None = None
        self.master_secret: bytes | None = None

        self.pending_remote_handshake_messages: list[Message] | None = None

        self.handshake_sequence_number = 0


# DTLS messages are grouped into a series of message flights, according
# to the diagrams below.  Although each flight of messages may consist
# of a number of messages, they should be viewed as monolithic for the
# purpose of timeout and retransmission.
# https://tools.ietf.org/html/rfc4347#section-4.2.4
#
# Message flights for full handshake:
#
# Client                                          Server
# ------                                          ------
#                                     Waiting                 Flight 0
#
# ClientHello             -------->                           Flight 1
#
#                         <-------    HelloVerifyRequest      Flight 2
#
# ClientHello              -------->                           Flight 3
#
#                                            ServerHello    \
#                                           Certificate*     \
#                                     ServerKeyExchange*      Flight 4
#                                    CertificateRequest*     /
#                         <--------      ServerHelloDone    /
#
# Certificate*                                              \
# ClientKeyExchange                                          \
# CertificateVerify*                                          Flight 5
# [ChangeCipherSpec]                                         /
# Finished                -------->                         /
#
#                                     [ChangeCipherSpec]    \ Flight 6
#                         <--------             Finished    /
#
# Message flights for session-resuming handshake (no cookie exchange):
#
# Client                                          Server
# ------                                          ------
#                                     Waiting                 Flight 0
#
# ClientHello             -------->                           Flight 1
#
#                                            ServerHello    \
#                                     [ChangeCipherSpec]      Flight 4b
#                         <--------             Finished    /
#
# [ChangeCipherSpec]                                        \ Flight 5b
# Finished                -------->                         /
#
#                                     [ChangeCipherSpec]    \ Flight 6
#                         <--------             Finished    /


class FlightTransition(abc.ABC):
    @abc.abstractmethod
    def generate(self, state: State) -> list[RecordLayer] | None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        raise NotImplementedError()
