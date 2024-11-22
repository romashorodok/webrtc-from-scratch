import asyncio
import binascii
from dataclasses import dataclass
from enum import Enum, IntEnum
import hashlib
from typing import Any, Protocol, Self
from typing import Tuple, Callable, Optional
import hmac
import math
import struct
import os
from datetime import datetime, time

import six


# from OpenSSL import SSL
# from pylibsrtp import Policy, Session

from webrtc import ice
from webrtc.ice import net

from Crypto.Cipher import AES

from webrtc.ice.stun import utils as byteops


# from .certificate import (
#     SRTPProtectionProfile,
#     certificate_digest,
#     Certificate,
#     Fingerprint,
#     SRTP_PROFILES,
# )


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


class ContentType(IntEnum):
    """
    ContentType represents the IANA Registered ContentTypes.
    https://tools.ietf.org/html/rfc4346#section-6.2.1
    """

    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    CONNECTION_ID = 0x19


class DTLSVersion(IntEnum):
    V1_0 = 0xFEFF
    V1_2 = 0xFEFD


def unpack_version(data: bytes) -> DTLSVersion:
    version = DTLSVersion(byteops.unpack_unsigned_short(data))
    if version == DTLSVersion.V1_0:
        print("Catch DTLS 1.0 version. May not support it!")
    elif version == DTLSVersion.V1_2:
        pass
    else:
        raise ValueError(
            f"Unsupported DTLS version: {hex(version)}. DTLS 1.2 (0xFEFD) required."
        )
    return version


class CompressionMethod(IntEnum):
    Null = 0


class HandshakeMessageType(IntEnum):
    HelloRequest = 0
    ClientHello = 1
    ServerHello = 2
    HelloVerifyRequest = 3
    Certificate = 11
    KeyServerExchange = 12
    CertificateRequest = 13
    ServerHelloDone = 14
    CertificateVerify = 15
    ClientKeyExchange = 16
    ChangeCipherSpec = 20  # Finished


class Marshallable(Protocol):
    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


@dataclass
class Extension:
    extension_type: int
    length: int
    data: bytes


class SupportedGroups(Extension):
    extension_type = 0x0A


class ExtendedMasterSecret(Extension):
    extension_type = 0x17


class SignatureAlgorithms(Extension):
    extension_type = 0x0D


class UseSRTP(Extension):
    extension_type = 0x0E


class EcPointFormats(Extension):
    extension_type = 0x0B


class RegonitiationInfo(Extension):
    extension_type = 0xFF01


EXTENSION_CLASSES = {
    SupportedGroups.extension_type: SupportedGroups,
    ExtendedMasterSecret.extension_type: ExtendedMasterSecret,
    SignatureAlgorithms.extension_type: SignatureAlgorithms,
    UseSRTP.extension_type: UseSRTP,
    EcPointFormats.extension_type: EcPointFormats,
    RegonitiationInfo.extension_type: RegonitiationInfo,
}


class ExtensionList:
    @staticmethod
    def unmarshal(data: bytes) -> list[Extension]:
        if len(data) == 0 or len(data) < 2:
            return list()

        extensions_length = byteops.unpack_unsigned_short(data[0:2])
        if len(data) - 2 != extensions_length:
            raise ValueError("extensions violation or length mismatch")
        print("extensions_length", extensions_length)

        extensions = data[2 : 2 + extensions_length]

        result = list[Extension]()
        offset = 0

        while offset < len(extensions):
            ext_type = int.from_bytes(extensions[offset : offset + 2], "big")
            ext_length = int.from_bytes(extensions[offset + 2 : offset + 4], "big")

            ext_data = extensions[offset + 4 : offset + 4 + ext_length]
            if len(ext_data) != ext_length:
                raise ValueError("Extension length mismatch")

            result.append(
                Extension(
                    extension_type=ext_type,
                    length=ext_length,
                    data=ext_data,
                )
            )

            offset += 4 + ext_length

        print("extension result", len(result))

        return result


class Random:
    # Random value that is used in ClientHello and ServerHello
    # https://tools.ietf.org/html/rfc4346#section-7.4.1.2

    RANDOM_BYTES_LENGTH = 28
    RANDOM_LENGTH = RANDOM_BYTES_LENGTH + 4

    def __init__(self):
        self.gmt_unix_time = datetime.now()
        self.random_bytes = bytearray(self.RANDOM_BYTES_LENGTH)

    def marshal_fixed(self):
        out = bytearray(self.RANDOM_LENGTH)

        # Pack the GMT Unix time (big-endian, 4 bytes)
        unix_time = int(self.gmt_unix_time.timestamp())

        out[0] = (unix_time >> 24) & 0xFF  # Most significant byte
        out[1] = (unix_time >> 16) & 0xFF
        out[2] = (unix_time >> 8) & 0xFF
        out[3] = unix_time & 0xFF  # Least significant byte

        out[4:] = self.random_bytes
        return bytes(out)

    def unmarshal_fixed(self, data: bytes):
        if len(data) != self.RANDOM_LENGTH:
            raise ValueError(f"Data must be {self.RANDOM_LENGTH} bytes long")

        unix_time = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        self.gmt_unix_time = datetime.fromtimestamp(unix_time)
        self.random_bytes = bytearray(data[4:])

    def populate(self):
        self.gmt_unix_time = datetime.now()
        self.random_bytes = os.urandom(self.RANDOM_BYTES_LENGTH)


class Message:
    message_type: HandshakeMessageType


class ClientHello(Message):
    message_type = HandshakeMessageType.ClientHello

    random = Random()

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        if len(data) < 2 + cls.random.RANDOM_LENGTH:
            raise ValueError("Invalid client hello message format")

        version = unpack_version(data[0:2])
        print(version)

        random = data[2 : 2 + cls.random.RANDOM_LENGTH]
        print(binascii.hexlify(random))

        curr_offset = 2 + cls.random.RANDOM_LENGTH

        if len(data) <= curr_offset:
            raise ValueError("insufficient data for SessionID length")

        session_id_length = int.from_bytes(
            data[curr_offset : curr_offset + 1], byteorder="big"
        )
        curr_offset += 1

        if len(data) <= curr_offset + session_id_length:
            raise ValueError("insufficient data for SessionID")

        session_id = data[curr_offset : curr_offset + session_id_length]
        curr_offset += len(session_id)
        curr_offset += 1
        print("session_id", session_id)

        if len(data) < curr_offset:
            raise ValueError("insufficient data for cookie")

        cookie_length = int.from_bytes(data[curr_offset:curr_offset], byteorder="big")

        cookie = data[curr_offset : curr_offset + cookie_length]
        print("cookie", cookie)
        curr_offset += len(cookie)

        if len(data) <= curr_offset:
            raise ValueError("insufficient data for cipher suites")

        cipher_suie_length = int.from_bytes(
            data[curr_offset : curr_offset + 2], byteorder="big"
        )
        curr_offset += 2

        cipher_suites = data[curr_offset : curr_offset + cipher_suie_length]

        # One suite == 2 bytes
        cipher_suites_count = len(cipher_suites) // 2

        # TODO: Add cipher suites enum
        rtrn = list[int]()

        # TODO: marshal cipher suites
        for i in range(cipher_suites_count):
            if len(cipher_suites) < (i * 2 + 2):
                raise ValueError("Buffer too small for cipher suites decoding")

            rtrn.append(int.from_bytes(cipher_suites[(i * 2) : (i * 2) + 2], "big"))

        curr_offset += len(cipher_suites)

        compression_methods_count = int.from_bytes(data[curr_offset : curr_offset + 1])
        curr_offset += 1

        compression_methods = data[
            curr_offset : curr_offset + compression_methods_count
        ]

        cmpn = list[CompressionMethod]()

        # TODO: compression_method encodings
        for i in range(compression_methods_count):
            if len(compression_methods) <= i:
                raise ValueError("Buffer too small for compression methods decoding")

            cmpn.append(
                CompressionMethod(int.from_bytes(compression_methods[i : i + 1]))
            )

        curr_offset += len(cmpn)

        extensions = ExtensionList.unmarshal(data[curr_offset:])

        print(extensions)

        return cls()


class HelloVerifyRequest(Message):
    message_type = HandshakeMessageType.HelloVerifyRequest

    def __init__(self, version: DTLSVersion, cookie_length: int, cookie: bytes) -> None:
        self.version = version
        self.cookie_length = cookie_length
        self.cookie = cookie

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        if len(data) < 2:
            raise ValueError("Invalid hello verify request message format")

        version = unpack_version(data[0:2])
        curr_offset = 2

        if len(data) < curr_offset:
            raise ValueError("insufficient data for cookie")

        cookie_length = int.from_bytes(data[curr_offset : curr_offset + 1], "big")
        curr_offset += 1

        cookie = data[curr_offset : curr_offset + cookie_length]

        return cls(version, cookie_length, cookie)


class ServerHello(Message):
    message_type = HandshakeMessageType.ServerHello

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class Certificate(Message):
    message_type = HandshakeMessageType.Certificate

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class KeyServerExchange(Message):
    message_type = HandshakeMessageType.KeyServerExchange

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class CertificateRequest(Message):
    message_type = HandshakeMessageType.CertificateRequest

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class ServerHelloDone(Message):
    message_type = HandshakeMessageType.ServerHelloDone

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class ClientKeyExchange(Message):
    message_type = HandshakeMessageType.ClientKeyExchange

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class CertificateVerify(Message):
    message_type = HandshakeMessageType.CertificateVerify

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class ChangeCipherSpec(Message):
    message_type = HandshakeMessageType.ChangeCipherSpec

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


MESSAGE_CLASSES: dict[HandshakeMessageType, type[Marshallable]] = {
    ClientHello.message_type: ClientHello,
    HelloVerifyRequest.message_type: HelloVerifyRequest,
    ServerHello.message_type: ServerHello,
    Certificate.message_type: Certificate,
    KeyServerExchange.message_type: KeyServerExchange,
    CertificateRequest.message_type: CertificateRequest,
    ServerHelloDone.message_type: ServerHelloDone,
    ClientKeyExchange.message_type: ClientKeyExchange,
    CertificateVerify.message_type: CertificateVerify,
    ChangeCipherSpec.message_type: ChangeCipherSpec,
}


@dataclass
class HandshakeHeader:
    handshake_type: HandshakeMessageType
    length: int
    message_sequence: int
    fragment_offset: int
    fragment_length: int


class Handshake:
    """
    Header is the static first 12 bytes of each RecordLayer
    of type Handshake. These fields allow us to support message loss, reordering, and
    message fragmentation,

    https://tools.ietf.org/html/rfc6347#section-4.2.2

    """

    HEADER_LENGHT = 12

    def __init__(self, header: HandshakeHeader, message: Marshallable) -> None:
        self.header = header
        self.message = message

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        header = HandshakeHeader(
            handshake_type=HandshakeMessageType(data[0]),
            length=byteops.unpack_unsigned_24(data[1:4]),
            message_sequence=byteops.unpack_unsigned_short(data[4:6]),
            fragment_offset=byteops.unpack_unsigned_24(data[6:9]),
            fragment_length=byteops.unpack_unsigned_24(data[9:12]),
        )
        data = data[12:]

        message_cls = MESSAGE_CLASSES.get(header.handshake_type)
        if not message_cls:
            raise ValueError("Not found message class")

        message = message_cls.unmarshal(data)

        return cls(header, message)


@dataclass
class RecordHeader:
    content_type: ContentType
    version: DTLSVersion
    epoch: int
    sequence_number: int
    length: int


class RecordLayer:
    """
    The record layer can carry four types of content:

    1. Handshake messages—used for algorithm negotiation and key establishment.
    2. ChangeCipherSpec messages—really part of the handshake but technically a separate kind of message.
    3. Alert messages—used to signal that errors have occurred
    4. Application layer data

    The DTLS record layer is extremely similar to that of TLS 1.1.  The
    only change is the inclusion of an explicit sequence number in the
    record.  This sequence number allows the recipient to correctly
    verify the TLS MAC.

    https://tools.ietf.org/html/rfc4347#section-4.1
    """

    FIXED_HEADER_SIZE = 13

    def __init__(self, header: RecordHeader, payload: bytes) -> None:
        self.header = header
        self.payload = payload

    def marshal(self) -> bytes:
        header_bytes = bytearray()

        header_bytes.append(self.header.content_type.value)
        header_bytes.extend(self.header.version.value.to_bytes(2, byteorder="big"))
        header_bytes.extend(self.header.epoch.to_bytes(2, byteorder="big"))
        header_bytes.extend(self.header.sequence_number.to_bytes(6, byteorder="big"))
        header_bytes.extend(self.header.length.to_bytes(2, byteorder="big"))

        return bytes(header_bytes) + self.payload

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        if len(data) < cls.FIXED_HEADER_SIZE:
            raise ValueError("DTLS record is too small")

        header = data[: cls.FIXED_HEADER_SIZE]
        content_type = ContentType(header[0])

        if content_type == ContentType.CONNECTION_ID:
            raise ValueError("Unsupported connection id")

        version = unpack_version(data[1:3])

        epoch = byteops.unpack_unsigned_short(header[3:5])

        sequence_number = byteops.unpack_unsigned_64(
            bytearray(8)[2:]  # Convert uint48 into uint64
            + data[5:11]
        )

        length = byteops.unpack_unsigned_short(data[11:13])

        data = data[13:]

        header = RecordHeader(content_type, version, epoch, sequence_number, length)

        return cls(header, data)


class GaloisCounterMode:
    """
    https://datatracker.ietf.org/doc/html/rfc5288
    https://en.wikipedia.org/wiki/Galois/Counter_Mode
    """

    def __init__(
        self,
        local_key: bytes,
        local_write_iv: bytes,
        remote_key: bytes,
        remote_write_iv: bytes,
    ) -> None:
        self._local_gcm = AES.new(local_key, AES.MODE_GCM, local_write_iv)
        self._remote_gcm = AES.new(remote_key, AES.MODE_GCM, remote_write_iv)

        self.local_write_iv = local_write_iv
        self.remote_write_iv = remote_write_iv

    def encrypt(self, pkt: RecordLayer, raw: bytes) -> bytes | None: ...

    def decrypt(self, h: RecordHeader, raw: bytes) -> bytes | None: ...


class EncryptionKeys:
    def __init__(
        self,
        master_secret: bytes,
        client_mac_key: bytes,
        server_mac_key: bytes,
        client_write_key: bytes,
        server_write_key: bytes,
        client_write_iv: bytes,
        server_write_iv: bytes,
    ):
        self.master_secret = master_secret
        self.client_mac_key = client_mac_key
        self.server_mac_key = server_mac_key
        self.client_write_key = client_write_key
        self.server_write_key = server_write_key
        self.client_write_iv = client_write_iv
        self.server_write_iv = server_write_iv


def p_hash(
    secret: bytes,
    seed: bytes,
    requested_length: int,
    hash_func: Callable,
) -> bytes:
    """
    PHash is PRF is the SHA-256 hash function is used for all cipher suites
    defined in this TLS 1.2 document and in TLS documents published prior to this
    document when TLS 1.2 is negotiated.  New cipher suites MUST explicitly
    specify a PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
    stronger standard hash function.

       P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                              HMAC_hash(secret, A(2) + seed) +
                              HMAC_hash(secret, A(3) + seed) + ...

    A() is defined as:

       A(0) = seed
       A(i) = HMAC_hash(secret, A(i-1))

    P_hash can be iterated as many times as necessary to produce the
    required quantity of data.  For example, if P_SHA256 is being used to
    create 80 bytes of data, it will have to be iterated three times
    (through A(3)), creating 96 bytes of output data; the last 16 bytes
    of the final iteration will then be discarded, leaving 80 bytes of
    output data.

    https://tools.ietf.org/html/rfc4346w
    """

    def hmac_hash(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hash_func).digest()

    last_round = seed
    out = bytearray()

    iterations = math.ceil(requested_length / hash_func().digest_size)

    for _ in range(iterations):
        last_round = hmac_hash(secret, last_round)

        with_secret = hmac_hash(secret, last_round + seed)

        out.extend(with_secret)

    return bytes(out[:requested_length])


def prf_generate_encryption_keys(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    mac_len: int,
    key_len: int,
    iv_len: int,
) -> EncryptionKeys | None:
    try:
        key_expansion_label = b"key expansion"
        seed = key_expansion_label + server_random + client_random

        key_material = p_hash(
            master_secret,
            seed,
            (2 * mac_len) + (2 * key_len) + (2 * iv_len),
            hashlib.sha256,
        )

        client_mac_key = key_material[:mac_len]
        key_material = key_material[mac_len:]

        server_mac_key = key_material[:mac_len]
        key_material = key_material[mac_len:]

        client_write_key = key_material[:key_len]
        key_material = key_material[key_len:]

        server_write_key = key_material[:key_len]
        key_material = key_material[key_len:]

        client_write_iv = key_material[:iv_len]
        key_material = key_material[iv_len:]

        server_write_iv = key_material[:iv_len]

        encryption_keys = EncryptionKeys(
            master_secret=master_secret,
            client_mac_key=client_mac_key,
            server_mac_key=server_mac_key,
            client_write_key=client_write_key,
            server_write_key=server_write_key,
            client_write_iv=client_write_iv,
            server_write_iv=server_write_iv,
        )
        return encryption_keys

    except Exception:
        return None


class CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    __PRF_MAC_LEN = 0
    __PRF_KEY_LEN = 16
    __PRF_IV_LEN = 4

    def __init__(self) -> None:
        self.id = 0xC02B
        self.gcm: GaloisCounterMode | None = None

    def start(
        self,
        master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        client: bool,
    ):
        keys = prf_generate_encryption_keys(
            master_secret,
            client_random,
            server_random,
            self.__PRF_MAC_LEN,
            self.__PRF_KEY_LEN,
            self.__PRF_IV_LEN,
        )
        if not keys:
            raise ValueError("Unable generate prf encryption keys")

        if client:
            gcm = GaloisCounterMode(
                keys.client_write_key,
                keys.client_write_iv,
                keys.server_write_key,
                keys.server_write_iv,
            )
        else:
            gcm = GaloisCounterMode(
                keys.server_write_key,
                keys.server_write_iv,
                keys.client_write_key,
                keys.client_write_iv,
            )

        self.gcm = gcm

    def encrypt(self, pkt: RecordLayer, raw: bytes) -> bytes | None:
        if not self.gcm:
            raise ValueError("Unable encrypt start gcm first")
        return self.gcm.encrypt(pkt, raw)

    def decrypt(self, h: RecordHeader, raw: bytes) -> bytes | None:
        if not self.gcm:
            raise ValueError("Unable decrypt start gcm first")
        return self.gcm.decrypt(h, raw)

    def certificate_type_sign(self) -> bytes:
        return _ECDSA_SIGN

    def key_exchange_algorithm(self) -> int:
        return KEY_EXCHANGE_ALGORITHM_ECDHE

    def is_elliptic_curve_cryptography(self) -> bool:
        return True

    def authentication_type(self) -> AUTHENTICATION_TYPE:
        return AUTHENTICATION_TYPE.Certificate

    def __str__(self) -> str:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"


class CipherSuite(Protocol):
    pass


class DTLSConn:
    def __init__(self) -> None:
        self.__cipher_suites = list[CipherSuite]()


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
