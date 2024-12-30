# import asyncio
# import binascii
# from dataclasses import dataclass
from enum import Enum, IntEnum
# import hashlib
from typing import Any, Protocol, Self
# from typing import Tuple, Callable, Optional
# import hmac
# import math
# import struct
# import os
# from datetime import datetime, time, UTC, timedelta


# from asn1crypto.core import ValueMap
# from ecdsa.der import encode_length
# import six


# from OpenSSL import SSL
# from pylibsrtp import Policy, Session

from webrtc import ice
# from webrtc.ice import net

# from Crypto.Cipher import AES

# from asn1crypto import pem, x509, keys, algos
# from ecdsa import Ed25519, SigningKey, VerifyingKey, NIST256p
# from ecdsa.ecdh import ECDH


# from webrtc.ice.stun import utils as byteops
# from webrtc.dtls.gcm import prf_generate_encryption_keys, GCMCipherRecordLayer


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


class ICETransportDTLS(Protocol):
    def get_ice_role(self) -> ice.AgentRole: ...
    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None: ...
    async def bind(self, transport: ice.CandidatePairTransport): ...

    # def get_ice_pair_transports(self) -> list[ice.CandidatePairTransport]: ...


class RTPReaderProtocol(Protocol):
    async def recv_rtp_bytes(self) -> bytes: ...


_ECDSA_SIGN = bytes(64)

KEY_EXCHANGE_ALGORITHM_ECDHE = 1 << 2


class AUTHENTICATION_TYPE(IntEnum):
    Certificate = 1
    PreSharedKey = 2


class Marshallable(Protocol):
    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


# @dataclass
# class EncryptionKeys:
#     master_secret: bytes
#     client_mac_key: bytes
#     server_mac_key: bytes
#     client_write_key: bytes
#     server_write_key: bytes
#     client_write_iv: bytes
#     server_write_iv: bytes


class HandshakeState(IntEnum):
    Errored = 0
    Preparing = 1
    Sending = 2
    Waiting = 3
    Finished = 4


# NAMED_CURVE_TYPE = 0x03

# @dataclass
# class PullCacheOption:
#     message_type: HandshakeMessageType
#     epoch: int
#     is_client: bool
#     optional: bool
#
#
# @dataclass(frozen=True)
# class HandshakeCacheKey:
#     message_type: HandshakeMessageType
#     epoch: int


# class State:
#     INITIAL_EPOCH = 0
#     DEFAULT_CURVE: EllipticCurveGroup = EllipticCurveGroup.SECP256R1
#
#     def __init__(self) -> None:
#         self.local_epoch = self.remote_epoch = 0
#         self.local_random = Random()
#         self.remote_random: bytes | None = None
#
#         self.local_sequence_number = 0
#         self.handshake_sequence_number = 0
#
#         self.local_keypair: Keypair = Keypair.generate_P256()
#         self.local_certificate: x509.Certificate | None = None
#
#         self.cooike_random = Random(20, 20)
#         self.cooike_random.populate()
#         self.cookie = self.cooike_random.marshal_fixed()
#
#         self.pre_master_secret: bytes | None = None
#         self.master_secret: bytes | None = None
#         self.srtp_protection_profile: SRTPProtectionProfile | None = None
#         self.elliptic_curve: EllipticCurveGroup | None = None
#         self.remote_peer_certificates: list[x509.Certificate] | None = None
#
#         self.pending_remote_handshake_messages: list[Message] | None = None
#
#         self.pending_cipher_suite: CipherSuite | None = None
#         self.cipher_suite: CipherSuite | None = None
#
#         self.local_verify: bytes | None = None
#
#         # self.client_cache_messages = dict[HandshakeCacheKey, Message]()
#         # self.server_cache_messages = dict[HandshakeCacheKey, Message]()
#
#     # def push_cache(self, message: Message): ...
#
#     # def pull_cache(self, options: list[PullCacheOption]) -> list[Message] | None:
#     #     pass


# class FlightTransition(Protocol):
#     def generate(self, state: State) -> list[RecordLayer] | None: ...
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight: ...


# --- Server side flights


# class Flight0:
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         state.elliptic_curve = state.DEFAULT_CURVE
#
#         state.local_epoch = 0
#         state.remote_epoch = 0
#         state.local_random.populate()
#
#         state.local_keypair = Keypair.generate_P256()
#
#         state.remote_random = None
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         client_hello = await handshake_message_ch.get()
#         if not isinstance(client_hello, ClientHello):
#             print("Flight 0 must receive a client hello.")
#             return Flight.FLIGHT0
#
#         if not state.remote_random and client_hello.random:
#             state.remote_random = client_hello.random
#         elif not state.remote_random:
#             print("Flight 0 client hello must contain a random.")
#             return Flight.FLIGHT0
#
#         return Flight.FLIGHT2
#
#
# class Flight2:
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         state.handshake_sequence_number = 0
#         hello_verify_request = HelloVerifyRequest(bytes())
#         hello_verify_request.version = DTLSVersion.V1_2
#         hello_verify_request.cookie = state.cookie
#
#         return [
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_0,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.HelloVerifyRequest,
#                         message_sequence=0,
#                         fragment_offset=0,
#                     ),
#                     hello_verify_request,
#                 ),
#             ),
#         ]
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         # print("flight 2 wait")
#         client_hello = await handshake_message_ch.get()
#         # print("flight 2 after wait")
#         if not isinstance(client_hello, ClientHello):
#             print(
#                 "Flight 1 must receive a client hello after a HelloVerifyRequest. Reset state to Flight 0"
#             )
#             return Flight.FLIGHT0
#
#         if not client_hello.cookie:
#             print("Flight 0 client hello must contain a cookie.")
#             return Flight.FLIGHT0
#
#         if state.cookie != client_hello.cookie:
#             print("Flight 0 must contain a same remote and local cookie")
#             return Flight.FLIGHT0
#
#         return Flight.FLIGHT4
#
#
# class Flight4:
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         if not state.remote_random:
#             raise ValueError("Not found remote random")
#
#         # signature = state.local_keypair.generate_server_signature(
#         #     state.remote_random, state.local_random.marshal_fixed()
#         # )
#         # print("Generated signature", signature)
#
#         # key_server_exchange = KeyServerExchange(bytes())
#         # key_server_exchange.named_curve = state.local_keypair.curve
#         # # TODO: Don't hard code
#         # key_server_exchange.signature_hash_algorithm = (
#         #     SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
#         # )
#         # key_server_exchange.pubkey = state.local_keypair.publicKey.to_der()
#         # key_server_exchange.signature = signature
#
#         certificate_request = CertificateRequest(bytes())
#         certificate_request.certificate_types = [CertificateType.ECDSA]
#         certificate_request.signature_hash_algorithms = [
#             SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256,
#             SignatureHashAlgorithm.ED25519,
#         ]
#
#         # server_hello = ServerHello(bytes())
#         # server_hello.version = DTLSVersion.V1_2
#         # server_hello.random = state.local_random.marshal_fixed()
#
#         # TODO: Don't hard code
#         # server_hello.cipher_suite = (
#         #     CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#         # )
#         # server_hello.compression_method = CompressionMethod.Null
#         state.pending_cipher_suite = (
#             CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
#         )
#
#         use_srtp = UseSRTP(bytes())
#         use_srtp.srtp_protection_profiles = [
#             SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
#         ]
#         ec_point_formats = EcPointFormats(bytes())
#         ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]
#
#         server_hello.extensions = [
#             RegonitiationInfo(bytes()),
#             ExtendedMasterSecret(bytes()),
#             use_srtp,
#             ec_point_formats,
#         ]
#
#         certificate = Certificate(bytes())
#         state.local_certificate = create_self_signed_cert_with_ecdsa(
#             state.local_keypair
#         )
#         certificate.certificates = [state.local_certificate]
#
#         return [
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_0,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.ServerHello,
#                         message_sequence=1,
#                         fragment_offset=0,
#                     ),
#                     server_hello,
#                 ),
#             ),
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_0,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.Certificate,
#                         message_sequence=2,
#                         fragment_offset=0,
#                     ),
#                     certificate,
#                 ),
#             ),
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_2,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.KeyServerExchange,
#                         message_sequence=3,
#                         fragment_offset=0,
#                     ),
#                     key_server_exchange,
#                 ),
#             ),
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_2,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.CertificateRequest,
#                         message_sequence=4,
#                         fragment_offset=0,
#                     ),
#                     certificate_request,
#                 ),
#             ),
#             RecordLayer(
#                 RecordHeader(
#                     ContentType.HANDSHAKE,
#                     DTLSVersion.V1_2,
#                     state.local_epoch,
#                     state.local_sequence_number,
#                 ),
#                 Handshake(
#                     HandshakeHeader(
#                         handshake_type=HandshakeMessageType.ServerHelloDone,
#                         message_sequence=5,
#                         fragment_offset=0,
#                     ),
#                     ServerHelloDone(bytes()),
#                 ),
#             ),
#         ]
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         while True:
#             # print("Flight 4 wait")
#             message = await handshake_message_ch.get()
#             # print("Flight 4 parse hello client hello", message)
#
#             match message.message_type:
#                 case HandshakeMessageType.ClientKeyExchange:
#                     if not isinstance(message, ClientKeyExchange):
#                         raise ValueError("Flight 4 message must be a ClientKeyExchange")
#
#                     verifying_key = VerifyingKey.from_der(message.pubkey)
#
#                     state.pre_master_secret = (
#                         Keypair.pre_master_secret_from_pub_and_priv_key(
#                             verifying_key,
#                             state.local_keypair.privateKey,
#                         )
#                     )
#                     print(
#                         "Flight 4 pre master secret",
#                         binascii.hexlify(state.pre_master_secret),
#                     )
#
#                     # print("after pre master secret??")
#
#                     if not state.remote_random:
#                         raise ValueError("Flight 4 not found remote random")
#
#                     state.master_secret = prf_master_secret(
#                         state.pre_master_secret,
#                         state.local_random.marshal_fixed(),
#                         state.remote_random,
#                         hashlib.sha256,
#                     )
#
#                     if not state.pending_cipher_suite:
#                         raise ValueError("Flight 4 require a pending cipher suite")
#
#                     # print("Flight 4", binascii.hexlify(state.remote_random), binascii.hexlify(state.local_random.marshal_fixed()) )
#
#                     state.pending_cipher_suite.start(
#                         state.master_secret,
#                         state.local_random.marshal_fixed(),
#                         state.remote_random,
#                         False,
#                     )
#
#                     # print("Success cipher suite")
#
#                 case HandshakeMessageType.CertificateVerify:
#                     return Flight.FLIGHT5
#                 case _:
#                     pass
#
#
# class Flight6:
#     def generate(self, state: State) -> list[RecordLayer] | None: ...
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight: ...
#
#
# def client_hello_factory(state: State) -> RecordLayer:
#     client_hello = ClientHello(bytes())
#     client_hello.version = DTLSVersion.V1_0
#     client_hello.random = state.local_random.marshal_fixed()
#     client_hello.cipher_suites = [CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
#     if state.cookie:
#         client_hello.cookie = state.cookie
#
#     client_hello.compression_methods = [CompressionMethod.Null]
#
#     supported_groups = SupportedGroups(bytes())
#     supported_groups.supported_groups = [
#         # EllipticCurveGroup.X25519,
#         EllipticCurveGroup.SECP256R1,
#     ]
#
#     extended_master_secret = ExtendedMasterSecret(bytes())
#
#     signature_hash_algorithm = SignatureAlgorithms(bytes())
#     signature_hash_algorithm.signature_hash_algorithms = [
#         SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256,
#     ]
#
#     use_srtp = UseSRTP(bytes())
#     use_srtp.srtp_protection_profiles = [
#         SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
#         SRTPProtectionProfile.SRTP_AEAD_AES_256_GCM,
#         SRTPProtectionProfile.SRTP_AEAD_AES_128_GCM,
#     ]
#
#     ec_point_formats = EcPointFormats(bytes())
#     ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]
#
#     regonitiation_info = RegonitiationInfo(bytes())
#
#     client_hello.extensions = [
#         supported_groups,
#         extended_master_secret,
#         signature_hash_algorithm,
#         use_srtp,
#         ec_point_formats,
#         regonitiation_info,
#     ]
#
#     return RecordLayer(
#         RecordHeader(
#             ContentType.HANDSHAKE,
#             DTLSVersion.V1_0,
#             0,
#             0,
#         ),
#         Handshake(
#             HandshakeHeader(
#                 handshake_type=HandshakeMessageType.ClientHello,
#                 message_sequence=1,
#                 fragment_offset=0,
#             ),
#             client_hello,
#         ),
#     )
#
#
# class Flight1:
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         state.elliptic_curve = state.DEFAULT_CURVE
#
#         state.local_epoch = 0
#         state.remote_epoch = 0
#         state.local_random.populate()
#         state.remote_random = None
#         state.pending_cipher_suite = None
#
#         state.local_keypair = Keypair.generate_P256()
#
#         return [
#             client_hello_factory(state),
#         ]
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         handshake_messages = list[Message]()
#         while True:
#             # TODO: timeout and make a fallback to flight 1
#             message = await handshake_message_ch.get()
#             handshake_messages.append(message)
#
#             match message.message_type:
#                 case HandshakeMessageType.HelloVerifyRequest:
#                     if not message.cookie:
#                         print("Flight 1 Server must return a cookie")
#                         return Flight.FLIGHT1
#
#                     state.cookie = message.cookie
#                     return Flight.FLIGHT3
#                 case HandshakeMessageType.ServerHelloDone:
#                     if not message.cookie:
#                         print("Flight 1 Server must return a cookie")
#                         return Flight.FLIGHT1
#
#                     state.cookie = message.cookie
#                     state.pending_remote_handshake_messages = handshake_messages
#                     return Flight.FLIGHT5
#                 case _:
#                     pass
#
#
# class Flight3:
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         return [client_hello_factory(state)]
#
#     def __handle_server_key_exchange(self, state: State, message: KeyServerExchange):
#         # match message.named_curve:
#         # case EllipticCurveGroup.SECP256R1:
#         # state.local_keypair = Keypair.generate_P256()
#
#         # NOTE: This library not support generate a pre shared key with ECDH for X25519 curve
#         # case EllipticCurveGroup.X25519:
#         #     state.local_keypair = Keypair.generate_X25519()
#         # case _:
#         #     raise ValueError(
#         #         f"Unsupported {message.named_curve} curve unable create pre master secret"
#         #     )
#
#         # TODO: Is it must use a pub key instead of ?
#         state.pre_master_secret = state.local_keypair.generate_shared_key()
#         print(
#             "Flight 3 Shared pre master secret",
#             binascii.hexlify(state.pre_master_secret),
#             len(state.pre_master_secret),
#         )
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         handshake_messages = list[Message]()
#         while True:
#             # TODO: timeout and make a fallback to flight 1
#             print("Flight 3 wait")
#             message = await handshake_message_ch.get()
#             handshake_messages.append(message)
#
#             match message.message_type:
#                 case HandshakeMessageType.KeyServerExchange:
#                     if not isinstance(message, KeyServerExchange):
#                         raise ValueError(
#                             "Flight 3 message must be a instance of KeyServerExchange"
#                         )
#                     if (
#                         not message.named_curve
#                         and state.local_keypair.curve != message.named_curve
#                     ):
#                         raise ValueError("Flight 3 message key server must be defined")
#
#                     try:
#                         self.__handle_server_key_exchange(state, message)
#                     except Exception as e:
#                         print("Unable generate pre shared master key", e)
#
#                 case HandshakeMessageType.Certificate:
#                     if not isinstance(message, Certificate):
#                         raise ValueError(
#                             "Flight 3 message must be a instance of Certificate"
#                         )
#                     if not message.certificates:
#                         raise ValueError(
#                             "Flight3 not found required remote certificates"
#                         )
#
#                     state.remote_peer_certificates = message.certificates
#
#                 case HandshakeMessageType.ServerHello:
#                     if not isinstance(message, ServerHello):
#                         raise ValueError(
#                             "Flight 3 message must be a instance of ServerHello"
#                         )
#
#                     if not message.cipher_suite:
#                         raise ValueError("Flight 3 message must contain cipher suite")
#
#                     cipher_suite_cls = CIPHER_SUITES_CLASSES.get(message.cipher_suite)
#                     if not cipher_suite_cls:
#                         raise ValueError(
#                             f"Flight 3 not found cipher suite {message.cipher_suite}"
#                         )
#
#                     state.remote_random = message.random
#                     state.pending_cipher_suite = cipher_suite_cls()
#
#                 case HandshakeMessageType.ServerHelloDone:
#                     state.pending_remote_handshake_messages = handshake_messages
#                     print("Flight 3 done")
#                     return Flight.FLIGHT5
#                 case _:
#                     pass
#
#
# # Client and Server use mutual authentication by default
#
# # The Finished message is the first encrypted message sent by the client. The process involves:
# #
# # Generating the message hash (MAC) of all previous handshake messages.
# # Encrypting the hash with the session key derived from the shared secret (ServerKeyExchange - pubkey).
# # Sending the encrypted Finished message to the server.
#
# MASTER_SECRET_LABEL = b"master secret"
#
#
# def prf_master_secret(
#     pre_master_secret: bytes,
#     client_random: bytes,
#     server_random: bytes,
#     hash_func: Callable,
# ) -> bytes:
#     seed = MASTER_SECRET_LABEL + client_random + server_random
#     return p_hash(pre_master_secret, seed, 48, hash_func)
#
#
# class Flight5:
#     def __initialize_cipher_suite(
#         self,
#         state: State,
#         key_server_exchange: KeyServerExchange,
#         handshake_messages_merged: bytes,
#     ):
#         if not state.pending_cipher_suite:
#             raise ValueError("Flight5 cipher suite must be defined")
#
#         if not state.pre_master_secret:
#             raise ValueError("Flight5 pre master secret must be initialized")
#         if not state.remote_random:
#             raise ValueError("Flight5 must know remote random")
#
#         if (
#             not key_server_exchange.pubkey
#             or not key_server_exchange.named_curve
#             or not key_server_exchange.signature
#         ):
#             raise ValueError(
#                 "Flight5 KeyServerExchange must have a pubkey, named_curve and signature  defined"
#             )
#
#         hash_func: Callable | None = None
#         match key_server_exchange.signature_hash_algorithm:
#             case SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256:
#                 hash_func = hashlib.sha256
#             case _:
#                 raise ValueError(
#                     "Unsupported cipher suite in key_server_exchange.signature_hash_algorithm"
#                 )
#
#         state.master_secret = prf_master_secret(
#             state.pre_master_secret,
#             state.local_random.marshal_fixed(),
#             state.remote_random,
#             hash_func,
#         )
#
#         # TODO: By default it expect a certificate auth type, ref it
#         if not state.remote_peer_certificates:
#             raise ValueError("Fligh5 not found remote peer certificates")
#
#         expected_ecdh_secret_message = ecdh_value_key_message(
#             state.local_random.marshal_fixed(),
#             state.remote_random,
#             key_server_exchange.pubkey,
#             key_server_exchange.named_curve,
#         )
#         # print(
#         #     "Expected client expected_ecdh_secret_message",
#         #     binascii.hexlify(expected_ecdh_secret_message),
#         # )
#
#         verified = verify_certificate_signature(
#             expected_ecdh_secret_message,
#             key_server_exchange.signature,
#             hash_func,
#             state.remote_peer_certificates,
#         )
#         if not verified:
#             raise ValueError("Invalid certificate signature")
#
#         print("Certificate verified success ???", verified)
#
#         # TODO: verify remote_peer_certificates from CAs/PKI or on server itself by RPC
#         # TODO: verify connection. What should I do ? def verify_connection(state: State ): ...
#
#         # print("Flight 5", binascii.hexlify(state.remote_random), binascii.hexlify(state.local_random.marshal_fixed()) )
#         state.pending_cipher_suite.start(
#             state.master_secret,
#             state.local_random.marshal_fixed(),
#             state.remote_random,
#             True,
#         )
#
#     def generate(self, state: State) -> list[RecordLayer] | None:
#         if not state.pending_remote_handshake_messages:
#             raise ValueError("Flight5 not found pending messages")
#
#         if not state.remote_random:
#             raise ValueError("Flight5 not found remote random")
#
#         # print("flight 5 messages", state.pending_remote_handshake_messages)
#
#         merged = bytes()
#         seq_pred = state.handshake_sequence_number
#
#         # print("pending messages", state.pending_remote_handshake_messages)
#
#         key_server_exchange: KeyServerExchange | None = None
#         result = list[RecordLayer]()
#         for message in state.pending_remote_handshake_messages:
#             match message.message_type:
#                 case HandshakeMessageType.KeyServerExchange:
#                     if not isinstance(message, KeyServerExchange):
#                         raise ValueError("Require KeyServerExchange to be present")
#                     key_server_exchange = message
#                 case _:
#                     pass
#
#             try:
#                 reconstructed = Handshake(
#                     header=HandshakeHeader(
#                         message_sequence=seq_pred,
#                         handshake_type=message.message_type,
#                         fragment_offset=0,
#                     ),
#                     message=message,
#                 )
#
#                 seq_pred += 1
#                 merged += reconstructed.marshal()
#             except Exception as e:
#                 print("Flight 5 error", e)
#
#         if not key_server_exchange:
#             raise ValueError(
#                 "Require KeyServerExchange to be present for cipher suite init"
#             )
#
#         try:
#             self.__initialize_cipher_suite(state, key_server_exchange, merged)
#         except Exception as e:
#             print("Flight5 Unable init cipher suite", e)
#             raise e
#
#         certificate = Certificate(bytes())
#         state.local_certificate = create_self_signed_cert_with_ecdsa(
#             state.local_keypair
#         )
#         certificate.certificates = [state.local_certificate]
#         layer_certificate = RecordLayer(
#             header=RecordHeader(
#                 content_type=ContentType.HANDSHAKE,
#                 version=DTLSVersion.V1_2,
#                 epoch=0,
#                 sequence_number=state.local_sequence_number,
#             ),
#             content=Handshake(
#                 header=HandshakeHeader(
#                     handshake_type=HandshakeMessageType.Certificate,
#                     message_sequence=seq_pred,
#                     fragment_offset=0,
#                 ),
#                 message=certificate,
#             ),
#         )
#         result.append(layer_certificate)
#         seq_pred += 1
#         merged += layer_certificate.content.marshal()
#
#         # print("merged data", merged)
#         # print("remote state", binascii.hexlify(state.remote_random))
#
#         client_key_exchange = ClientKeyExchange(bytes())
#         client_key_exchange.pubkey = state.local_keypair.publicKey.to_der()
#         layer_client_key_exchange = RecordLayer(
#             header=RecordHeader(
#                 content_type=ContentType.HANDSHAKE,
#                 version=DTLSVersion.V1_2,
#                 epoch=0,
#                 sequence_number=seq_pred,
#             ),
#             content=Handshake(
#                 header=HandshakeHeader(
#                     handshake_type=HandshakeMessageType.ClientKeyExchange,
#                     message_sequence=seq_pred,
#                     fragment_offset=0,
#                 ),
#                 message=client_key_exchange,
#             ),
#         )
#         result.append(layer_client_key_exchange)
#         seq_pred += 1
#         merged += layer_client_key_exchange.content.marshal()
#
#         # TODO: Why client side separate a pubkey and signature of the cert ?
#         # KeyServerExchange sends pubkey and signature in one layer
#         certificate_verify = CertificateVerify(bytes())
#
#         # TODO: Don't hard code, get from the key_server_exchange message
#         # TODO: get values from local key pair
#         certificate_verify.signature_hash_algorithm = (
#             SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
#         )
#
#         # TODO: Check cache if this types of handshake message already sent merge before into merged and sign it with predicted merged data
#         # ClientHello
#         # ServerHello
#         # Certificate
#         # ServerKeyExchange
#         # CertificateRequest
#         # ServerHelloDone
#         # Certificate
#         # ClientKeyExchange
#
#         certificate_verify.signature = state.local_keypair.sign(merged)
#         layer_certificate_verify_signature = RecordLayer(
#             header=RecordHeader(
#                 content_type=ContentType.HANDSHAKE,
#                 version=DTLSVersion.V1_2,
#                 epoch=0,
#                 sequence_number=state.local_sequence_number,
#             ),
#             content=Handshake(
#                 header=HandshakeHeader(
#                     handshake_type=HandshakeMessageType.CertificateVerify,
#                     message_sequence=seq_pred,
#                     fragment_offset=0,
#                 ),
#                 message=certificate_verify,
#             ),
#         )
#         result.append(layer_certificate_verify_signature)
#         seq_pred += 1
#         merged += layer_certificate_verify_signature.content.marshal()
#
#         # TODO: This not a handshake
#         layer_change_cipher_spec = RecordLayer(
#             header=RecordHeader(
#                 content_type=ContentType.CHANGE_CIPHER_SPEC,
#                 version=DTLSVersion.V1_2,
#                 epoch=0,
#                 sequence_number=state.local_sequence_number,
#             ),
#             content=ChangeCipherSpec(),
#         )
#         result.append(layer_change_cipher_spec)
#         # seq_pred += 1
#         # merged += layer_change_cipher_spec.content.marshal()
#
#         if not state.master_secret:
#             raise ValueError("Flight 5 master_secret must be defined by cuite")
#
#         if not state.local_verify:
#             state.local_verify = verify_data_client(state.master_secret, merged)
#
#         print(state.local_verify, len(state.local_verify))
#
#         layer_finished = RecordLayer(
#             header=RecordHeader(
#                 content_type=ContentType.HANDSHAKE,
#                 version=DTLSVersion.V1_2,
#                 epoch=1,
#                 sequence_number=state.local_sequence_number,
#             ),
#             content=Handshake(
#                 header=HandshakeHeader(
#                     handshake_type=HandshakeMessageType.Finished,
#                     message_sequence=seq_pred,
#                     fragment_offset=0,
#                 ),
#                 message=Finished(bytes()),
#             ),
#         )
#         layer_finished.encrypt = True
#         result.append(layer_finished)
#         # return result
#         return [
#             layer_client_key_exchange,
#             layer_change_cipher_spec,
#             layer_finished,
#         ]
#
#     async def parse(
#         self, state: State, handshake_message_ch: asyncio.Queue[Message]
#     ) -> Flight:
#         #                 [ChangeCipherSpec] \ Flight 6
#         # <--------             Finished     /
#         await asyncio.sleep(2)
#         return Flight.FLIGHT5
#
#
# # --- Client side flights
#
# FLIGHT_TRANSITIONS: dict[Flight, FlightTransition] = {
#     Flight.FLIGHT0: Flight0(),
#     Flight.FLIGHT2: Flight2(),
#     Flight.FLIGHT4: Flight4(),
#     Flight.FLIGHT6: Flight6(),
#     # # Client side
#     Flight.FLIGHT1: Flight1(),
#     Flight.FLIGHT3: Flight3(),
#     Flight.FLIGHT5: Flight5(),
# }
#
#
# class DTLSRemote(Protocol):
#     async def sendto(self, data: bytes): ...
#
#
# MAX_MTU = 1280
#
#
# class FSM:
#     def __init__(
#         self,
#         remote: DTLSRemote,
#         handshake_messages_chan: asyncio.Queue[Message],
#         flight: Flight = Flight.FLIGHT0,
#     ) -> None:
#         self.remote = remote
#         self.handshake_message_chan = handshake_messages_chan
#
#         self.state = State()
#
#         self.handshake_state_transition = asyncio.Queue[HandshakeState]()
#         self.handshake_state_transition_lock = asyncio.Lock()
#
#         self.handshake_state: HandshakeState = HandshakeState.Preparing
#         self.flight: Flight = flight
#
#         self.pending_record_layers: list[RecordLayer] | None = None
#
#     async def dispatch(self):
#         async with self.handshake_state_transition_lock:
#             await self.handshake_state_transition.put(self.handshake_state)
#
#     async def run(self):
#         while True:
#             next_state = await self.handshake_state_transition.get()
#
#             async with self.handshake_state_transition_lock:
#                 while True:
#                     if self.handshake_state_transition.empty() and not next_state:
#                         print("Handshake state transition done")
#                         break
#
#                     handshake_state = (
#                         next_state or await self.handshake_state_transition.get()
#                     )
#                     # print("after next_state lock", next_state)
#                     if next_state:
#                         next_state = None
#
#                     match handshake_state:
#                         case HandshakeState.Preparing:
#                             await self.handshake_state_transition.put(
#                                 await self.prepare(),
#                             )
#                         case HandshakeState.Sending:
#                             await self.handshake_state_transition.put(
#                                 await self.send(),
#                             )
#                         case HandshakeState.Waiting:
#                             await self.handshake_state_transition.put(
#                                 await self.wait(),
#                             )
#                         case _:
#                             break
#
#     async def prepare(self) -> HandshakeState:
#         # print("Prepare state", self.flight)
#         flight = FLIGHT_TRANSITIONS.get(self.flight)
#         if not flight:
#             # TODO: DTLS alerting
#             return HandshakeState.Errored
#
#         try:
#             self.pending_record_layers = flight.generate(self.state)
#         except Exception as e:
#             print("FSM catch:", e)
#             raise e
#
#         epoch = self.state.INITIAL_EPOCH
#         next_epoch = epoch
#         if self.pending_record_layers:
#             for record in self.pending_record_layers:
#                 record.header.epoch += epoch
#
#                 if record.header.epoch > next_epoch:
#                     next_epoch = record.header.epoch
#
#                 if record.header.content_type == ContentType.HANDSHAKE:
#                     record.header.sequence_number = self.state.handshake_sequence_number
#                     self.state.handshake_sequence_number += 1
#
#         if epoch != next_epoch:
#             self.state.local_epoch = next_epoch
#
#         return HandshakeState.Sending
#
#     async def send(self) -> HandshakeState:
#         # print("Send state", self.flight, "pending", self.pending_record_layers)
#         # print("Send state", self.flight)
#         if not self.pending_record_layers:
#             return HandshakeState.Waiting
#
#         # TODO: message batch
#         for layer in self.pending_record_layers:
#             try:
#                 data = layer.marshal()
#
#                 if layer.encrypt:
#                     if not self.state.pending_cipher_suite:
#                         raise ValueError(
#                             "layer data must be encrypted but cipher suite undefined"
#                         )
#
#                     data = self.state.pending_cipher_suite.encrypt(layer, data)
#                     if not data:
#                         raise ValueError("None data after encrypt,")
#
#                 if len(data) > MAX_MTU:
#                     raise ValueError(
#                         "layer data has too much bytes. Message must be fragmented"
#                     )
#
#                 await self.remote.sendto(data)
#             except Exception as e:
#                 # TODO: backoff
#                 print("Unable send inconsistent packet. Err:", e, "layer", layer)
#                 await asyncio.sleep(10)
#                 return HandshakeState.Sending
#
#         return HandshakeState.Waiting
#
#     async def wait(self) -> HandshakeState:
#         flight = FLIGHT_TRANSITIONS.get(self.flight)
#         if not flight:
#             return HandshakeState.Errored
#         # print("wait transition", flight)
#
#         # TODO: On client side I must wait and buffer from ServerHello until ServerHelloDone
#         # TODO: This waiting must support also a batch send
#         # TODO: When wait a messages make a timeout and fallback to the flight of DTLS role
#         try:
#             self.flight = await flight.parse(self.state, self.handshake_message_chan)
#         except Exception as e:
#             print(f"transition Flight{flight} error", e)
#
#         return HandshakeState.Preparing
#
#     async def finish(self) -> HandshakeState: ...
#
#
# # TODO: Validate epoch
# # TODO: Anti-replay protection
# # TODO: Decrypt
# class DTLSConn:
#     def __init__(
#         self,
#         remote: DTLSRemote,
#         layer_chan: asyncio.Queue[RecordLayer],
#         flight: Flight = Flight.FLIGHT0,
#     ) -> None:
#         self.record_layer_chan = layer_chan
#
#         self.handshake_message_chan = asyncio.Queue[Message]()
#         self.fsm = FSM(remote, self.handshake_message_chan, flight)
#         self.recv_lock = asyncio.Lock()
#
#     def __handle_encrypted_message(
#         self, layer: RecordLayer, message: EncryptedHandshakeMessage
#     ):
#         if not self.fsm.state.cipher_suite:
#             return
#
#         cipher_suite = self.fsm.state.cipher_suite
#
#         if result := cipher_suite.decrypt(layer.header, message.encrypted_payload):
#             # print("message before decrypt", binascii.hexlify(message.encrypted_payload))
#             # print("Got decrypted message result", result)
#             # record = RecordLayer.unmarshal(result)
#             # print("Recv record", record)
#             return
#
#         # print("Unable decrypt message", layer, message)
#
#     async def handle_inbound_record_layers(self):
#         fsm_runnable = asyncio.create_task(self.fsm.run())
#
#         try:
#             while True:
#                 record_layer = await self.record_layer_chan.get()
#                 # print("recv record", record_layer)
#
#                 match record_layer.header.content_type:
#                     case ContentType.CHANGE_CIPHER_SPEC:
#                         if not self.fsm.state.cipher_suite:
#                             self.fsm.state.cipher_suite = (
#                                 self.fsm.state.pending_cipher_suite
#                             )
#
#                     case ContentType.HANDSHAKE:
#                         # if isinstance(record_layer.content, EncryptedHandshakeMessage):
#                         #     await self.__handle_encrypted_message(
#                         #         record_layer, record_layer.content
#                         #     )
#                         #     continue
#
#                         if record_layer.header.epoch > 0:
#                             if isinstance(
#                                 record_layer.content, EncryptedHandshakeMessage
#                             ):
#                                 self.__handle_encrypted_message(
#                                     record_layer, record_layer.content
#                                 )
#                                 continue
#
#                         if isinstance(record_layer.content, Handshake):
#                             await self.handshake_message_chan.put(
#                                 record_layer.content.message,
#                             )
#
#                         # elif isinstance(
#                         #     record_layer.content, EncryptedHandshakeMessage
#                         # ):
#                         #     await self.__handle_encrypted_message(
#                         #         record_layer, record_layer.content
#                         #     )
#
#                         # await self.fsm.dispatch()
#                     case _:
#                         print(
#                             "Unhandled record type of",
#                             record_layer.header.content_type,
#                         )
#
#         except Exception as e:
#             print("DTLS handle inbound record layers err", e)
#         finally:
#             fsm_runnable.cancel()


class DTLSTransport:
    def __init__(self, transport: ICETransportDTLS, certificate: Any) -> None:
        self.__transport = transport

        self.__dtls_role: DTLSRole = DTLSRole.Auto
        self.__certificate = certificate
        # self.__media_fingerprints = list[dtls.Fingerprint]()

        self.__rx_srtp: None = None
        self.__tx_srtp: None = None

    async def bind(self, transport: ice.CandidatePairTransport):
        await self.__transport.bind(transport)

    def ice_transport(self) -> ICETransportDTLS:
        return self.__transport

    async def do_handshake_for(
        self,
        ssl: Any,
        transport: ice.CandidatePairTransport,
        media_fingerprints: list[Any],
    ):
        print("Start candidate handshake")
        __encrypted = False
        # while not __encrypted:
        #     try:
        #         ssl.do_handshake()
        #     except SSL.WantReadError:
        #         try:
        #             print("Wait for dtls??")
        #             dtls_pkt = await transport.recv_dtls()
        #             ssl.bio_write(dtls_pkt.data)
        #             try:
        #                 data = ssl.recv(1500)
        #                 if data:
        #                     print(f"Received data: {data}")
        #             except SSL.ZeroReturnError as e:
        #                 print("Zero return", e)
        #             except SSL.Error as e:
        #                 print("SSL error", e)
        #
        #             flight = ssl.bio_read(1500)
        #             if flight:
        #                 transport.sendto(flight)
        #                 print(f"Sent flight data: {flight}")
        #         except SSL.WantReadError:
        #             pass
        #     else:
        #         __encrypted = True

        x509 = ssl.get_peer_certificate()
        if x509 is None:
            print("Unable get x509 remotecandidate")
            return

        # remote_fingerprint = certificate_digest(x509)
        # remote_fingerprint_valid = False
        # for f in media_fingerprints:
        #     print("media", f.value.lower(), "remote", remote_fingerprint.lower())
        #     if f.value.lower() == remote_fingerprint.lower():
        #         remote_fingerprint_valid = True
        #         break

        # if not remote_fingerprint_valid:
        #     print("Invalid fingerprint not matched remote and media fingerprint")
        #     return
        #
        # openssl_profile = ssl.get_selected_srtp_profile()
        # negotiated_profile: SRTPProtectionProfile
        #
        # for srtp_profile in SRTP_PROFILES:
        #     if srtp_profile.openssl_profile == openssl_profile:
        #         print(
        #             "DTLS handshake negotiated with",
        #             srtp_profile.openssl_profile.decode(),
        #         )
        #         negotiated_profile = srtp_profile
        #         break
        # else:
        #     print("x DTLS handshake failed (no SRTP profile negotiated)")
        #     return
        #
        # view = ssl.export_keying_material(
        #     b"EXTRACTOR-dtls_srtp",
        #     2 * (negotiated_profile.key_length + negotiated_profile.salt_length),
        # )
        #
        # if self.__dtls_role == DTLSRole.Server:
        #     srtp_tx_key = negotiated_profile.get_key_and_salt(view, 1)
        #     srtp_rx_key = negotiated_profile.get_key_and_salt(view, 0)
        # else:
        #     srtp_tx_key = srtp_profile.get_key_and_salt(view, 0)
        #     srtp_rx_key = srtp_profile.get_key_and_salt(view, 1)
        #
        # rx_policy = Policy(
        #     key=srtp_rx_key,
        #     ssrc_type=Policy.SSRC_ANY_INBOUND,
        #     srtp_profile=srtp_profile.libsrtp_profile,
        # )
        # rx_policy.allow_repeat_tx = True
        # rx_policy.window_size = 1024
        # self.__rx_srtp = Session(rx_policy)
        #
        # tx_policy = Policy(
        #     key=srtp_tx_key,
        #     ssrc_type=Policy.SSRC_ANY_OUTBOUND,
        #     srtp_profile=srtp_profile.libsrtp_profile,
        # )
        # tx_policy.allow_repeat_tx = True
        # tx_policy.window_size = 1024
        # self.__tx_srtp = Session(tx_policy)
        # print("Handshake completed??")

    async def start(self, media_fingerprints: list[Any]):
        # assert len(remote_fingerprints)
        print("Handshake start")

        transport = self.ice_transport()

        match transport.get_ice_role():
            case ice.AgentRole.Controlling:
                self.__dtls_role = DTLSRole.Server
            case ice.AgentRole.Controlled:
                self.__dtls_role = DTLSRole.Client

        print("Start DTLS role", self.__dtls_role)

        pair = await self.__transport.get_ice_pair_transport()
        if not pair:
            raise ValueError("Not found ice pair transport for dtls")

        # ctx = self.__certificate.create_ssl_context(SRTP_PROFILES)
        # ssl = SSL.Connection(ctx)

        # match self.__dtls_role:
        #     case DTLSRole.Server:
        #         ssl.set_accept_state()
        #     case DTLSRole.Client:
        #         ssl.set_connect_state()
        #
        # asyncio.ensure_future(self.do_handshake_for(ssl, pair, media_fingerprints))

    def write_rtcp_bytes(self, data: bytes) -> int:
        # if not ice.net.is_rtcp(pkt.data):
        #     return 0
        #
        # if not self._tx_srtp:
        #     return 0
        # data = self._tx_srtp.protect_rtcp(pkt.data)
        # return len(data)
        print("TODO: Handle rtcp")
        return 0

    async def write_rtp_bytes(self, data: bytes) -> int:
        if not self.__tx_srtp:
            return 0

        transport = await self.__transport.get_ice_pair_transport()
        if not transport:
            return 0

        data = self.__tx_srtp.protect(data)
        transport.sendto(data)

        return len(data)

    async def read_rtp_bytes(self) -> tuple[bytes, int]:
        if not self.__rx_srtp:
            return bytes(), 0

        transport = await self.__transport.get_ice_pair_transport()
        if not transport:
            return bytes(), 0

        pkt = transport.recv_rtp_sync()
        data = self.__rx_srtp.unprotect(pkt.data)

        return data, len(data)
