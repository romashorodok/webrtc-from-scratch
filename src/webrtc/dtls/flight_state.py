import abc
import asyncio

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol, TypeVar

from asn1crypto import x509

from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import (
    CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuiteNative,
    Keypair,
    CipherSuite,
    create_self_signed_cert_with_ecdsa,
)
from webrtc.dtls.dtls_record import (
    Handshake,
    HandshakeMessageType,
    Message,
    RecordLayer,
)
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


_HANDSHAKE_CACHE_MESSAGE_T = TypeVar(
    name="_HANDSHAKE_CACHE_MESSAGE_T", bound=Message, infer_variance=True
)


@dataclass(frozen=True)
class HandshakeCacheKey:
    message_type: HandshakeMessageType
    epoch: int
    is_remote: bool


class HandshakeCache:
    def __init__(self) -> None:
        self._cache = dict[HandshakeCacheKey, bytes]()

        self.__subscribers = list[tuple[list[HandshakeCacheKey], asyncio.Event]]()

    def __emit_ready_at_once(self):
        to_remove = []
        for cache_keys, event in self.__subscribers:
            # needed_keys = set(cache_keys)  # Convert to a set for faster lookup
            # present_keys = set(self._cache.keys())

            # all_needed_keys_present = needed_keys.issubset(present_keys)
            # print("all keys in???", self._cache)
            # print("present keys", present_keys)

            if all(key in self._cache for key in cache_keys):
                event.set()
                to_remove.append((cache_keys, event))

        for item in to_remove:
            self.__subscribers.remove(item)

    async def once(self, cache_keys: list[HandshakeCacheKey]):
        event = asyncio.Event()
        self.__subscribers.append((cache_keys, event))
        self.__emit_ready_at_once()
        await event.wait()

    def put_and_notify_once(
        self,
        is_client: bool,
        epoch: int,
        message_type: HandshakeMessageType,
        message: bytes,
    ):
        key = HandshakeCacheKey(
            message_type=message_type,
            epoch=epoch,
            is_remote=is_client,
        )
        self._cache[key] = message
        self.__emit_ready_at_once()
        # print("Put flight state", self.__subscribers)

    def pull_and_merge(self, cache_keys: list[HandshakeCacheKey]) -> bytes:
        merged = bytes()

        for key in cache_keys:
            message = self._cache.get(key)
            if not message:
                raise ValueError(
                    f"unable pull_and_merge required handshake cache record {key}"
                )
            merged += message

        return merged

    def pull(
        self,
        typ: type[_HANDSHAKE_CACHE_MESSAGE_T],
        cache_key: HandshakeCacheKey,
    ) -> bytes:
        message = self._cache.get(cache_key)

        if not message:
            raise ValueError(f"unable pull required cache_key {typ}")

        return message


class DTLSRemote(Protocol):
    async def sendto(self, data: bytes): ...


class State:
    def __init__(
        self, remote: DTLSRemote, certificate: Certificate, keypair: Keypair
    ) -> None:
        self.remote = remote

        self.local_random = Random()
        self.local_random.populate()

        self.remote_random: bytes | None = None

        # self.local_keypair: Keypair = Keypair.generate_P256()
        # self.local_keypair: Keypair = certificate.keypair
        self.local_certificate: Certificate = certificate
        self.local_keypair: Keypair = keypair

        # self.local_keypair: Keypair = Keypair.generate_P256()
        # self.local_certificate: x509.Certificate = create_self_signed_cert_with_ecdsa(
        #     self.local_keypair
        # )

        __cooike_random = Random(20, 20)
        __cooike_random.populate()
        self.cookie = __cooike_random.marshal_fixed()

        self.elliptic_curve: EllipticCurveGroup = _DEFAULT_CURVE

        self.remote_peer_certificates: list[x509.Certificate] | None = None

        self.pending_cipher_suite: CipherSuite = CipherSuiteNative()
        # self.pending_cipher_suite: CipherSuite = (
        #     CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
        # )

        self.cipher_suite: CipherSuite | None = None

        self.pre_master_secret: bytes | None = None
        self.master_secret: bytes | None = None

        # self.pending_local_handshake_layers: list[RecordLayer] | None = None
        # self.pending_remote_handshake_messages: list[Message] | None = None

        self.handshake_sequence_number = 0

        self.cache = HandshakeCache()


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
