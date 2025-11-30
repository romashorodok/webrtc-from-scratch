import abc
import asyncio
import logging

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Protocol, TypeVar

logger = logging.getLogger("webrtc.dtls.flight_state")

from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import (
    CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    Keypair,
    CipherSuite,
)
from webrtc.dtls.dtls_record import (
    Handshake,
    HandshakeMessageType,
    Message,
    RecordLayer,
)
from webrtc.dtls.dtls_typing import EllipticCurveGroup, Random
from webrtc.dtls.prf import SRTPKeyingMaterial, get_srtp_keying_material

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
    """Key for looking up cached handshake messages (without message_sequence)."""
    message_type: HandshakeMessageType
    epoch: int
    is_remote: bool

    def __str__(self) -> str:
        return f"CacheKey({self.message_type.name}, epoch={self.epoch}, remote={self.is_remote})"


@dataclass
class HandshakeCacheItem:
    """Cache item storing handshake message with sequence number (like Rust)."""
    message_type: HandshakeMessageType
    epoch: int
    is_remote: bool
    message_sequence: int
    data: bytes


class HandshakeCache:
    """
    Handshake message cache matching Rust implementation behavior.

    Stores multiple messages with same (type, epoch, is_remote) but different
    message_sequence. When pulling, returns the one with highest message_sequence.
    This handles retransmissions correctly (e.g., ClientHello without cookie vs with cookie).
    """

    def __init__(self) -> None:
        # Store as list of items (like Rust) to handle multiple message_sequences
        self._items: list[HandshakeCacheItem] = []
        # Quick lookup dict: key -> highest message_sequence item
        self._cache: dict[HandshakeCacheKey, bytes] = {}

        self.__subscribers: list[tuple[list[HandshakeCacheKey], asyncio.Event]] = []

    def __emit_ready_at_once(self):
        to_remove = []
        for cache_keys, event in self.__subscribers:
            if all(key in self._cache for key in cache_keys):
                event.set()
                to_remove.append((cache_keys, event))

        for item in to_remove:
            self.__subscribers.remove(item)

    async def once(self, cache_keys: list[HandshakeCacheKey]):
        logger.info(f"cache.once: waiting for keys={[str(k) for k in cache_keys]}")
        event = asyncio.Event()
        self.__subscribers.append((cache_keys, event))
        self.__emit_ready_at_once()
        await event.wait()
        logger.info(f"cache.once: all keys received!")

    def put_and_notify_once(
        self,
        is_client: bool,
        epoch: int,
        message_type: HandshakeMessageType,
        message: bytes,
        message_sequence: int = 0,
    ):
        """
        Cache a handshake message.

        Like Rust, we store multiple items and when pulling we return the one
        with the highest message_sequence for a given (type, epoch, is_remote).
        """
        logger.info(f"cache.put_and_notify_once: message_type={message_type}, epoch={epoch}, is_remote={is_client}, msg_seq={message_sequence}, length={len(message)}")

        # Check if we already have this exact message_sequence (avoid duplicates)
        for item in self._items:
            if (item.message_type == message_type and
                item.epoch == epoch and
                item.is_remote == is_client and
                item.message_sequence == message_sequence):
                # Already have this message, skip
                return

        # Add to items list
        self._items.append(HandshakeCacheItem(
            message_type=message_type,
            epoch=epoch,
            is_remote=is_client,
            message_sequence=message_sequence,
            data=message,
        ))

        # Update quick lookup cache with highest message_sequence
        key = HandshakeCacheKey(
            message_type=message_type,
            epoch=epoch,
            is_remote=is_client,
        )

        # Find the item with highest message_sequence for this key
        best_item: HandshakeCacheItem | None = None
        for item in self._items:
            if (item.message_type == message_type and
                item.epoch == epoch and
                item.is_remote == is_client):
                if best_item is None or item.message_sequence > best_item.message_sequence:
                    best_item = item

        if best_item:
            self._cache[key] = best_item.data

        self.__emit_ready_at_once()

    def pull_and_merge(self, cache_keys: list[HandshakeCacheKey]) -> bytes:
        """
        Pull messages matching the keys and merge them in order.

        For each key, returns the message with the highest message_sequence
        (matching Rust behavior for handling retransmissions).
        """
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
        self, remote: DTLSRemote, certificate: Certificate, keypair: Keypair, is_server: bool = True
    ) -> None:
        self.remote = remote
        self.is_server = is_server

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

        self.remote_peer_certificates: list[Any] | None = None

        # Use Python cipher suite implementation
        self.pending_cipher_suite: CipherSuite = (
            CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
        )

        self.cipher_suite: CipherSuite | None = None

        self.pre_master_secret: bytes | None = None
        self.master_secret: bytes | None = None

        # Event to signal when cipher suite is initialized (pending_cipher_suite.start() called)
        self.cipher_suite_ready = asyncio.Event()

        # self.pending_local_handshake_layers: list[RecordLayer] | None = None
        # self.pending_remote_handshake_messages: list[Message] | None = None

        self.handshake_sequence_number = 0
        # Track message_sequence for outgoing handshake messages (continuous across flights)
        self.handshake_send_sequence = 0

        self.cache = HandshakeCache()

    def get_srtp_keying_material(self) -> SRTPKeyingMaterial:
        """
        Get SRTP keying material after DTLS handshake completion.

        This derives SRTP keys using the TLS exporter mechanism with
        the "EXTRACTOR-dtls_srtp" label per RFC 5764.

        Returns:
            SRTPKeyingMaterial: Contains client/server write keys (16 bytes each)
                               and client/server write salts (14 bytes each)

        Raises:
            ValueError: If master_secret or remote_random not set (handshake incomplete)
        """
        if not self.master_secret:
            raise ValueError("Master secret not available - handshake incomplete")
        if not self.remote_random:
            raise ValueError("Remote random not available - handshake incomplete")

        # Determine client_random and server_random based on our role
        # local_random is OUR random, remote_random is PEER's random
        if self.is_server:
            # We are server: local=server_random, remote=client_random
            client_random = self.remote_random
            server_random = self.local_random.marshal_fixed()
        else:
            # We are client: local=client_random, remote=server_random
            client_random = self.local_random.marshal_fixed()
            server_random = self.remote_random

        return get_srtp_keying_material(
            master_secret=self.master_secret,
            client_random=client_random,
            server_random=server_random,
        )


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
