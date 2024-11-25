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
from datetime import datetime, time, UTC, timedelta


import six


# from OpenSSL import SSL
# from pylibsrtp import Policy, Session

from webrtc import ice
from webrtc.ice import net

from Crypto.Cipher import AES

from asn1crypto import pem, x509, keys, algos
from ecdsa import Ed25519, SigningKey, SECP256k1, SECP128r1, VerifyingKey, NIST256p


from webrtc.ice.stun import utils as byteops


# from .certificate import (
#     SRTPProtectionProfile,
#     certificate_digest,
#     Certificate,
#     Fingerprint,
#     SRTP_PROFILES,
# )


def generate_ecdsa_keys():
    sk = SigningKey.generate(curve=NIST256p)

    pk = sk.get_verifying_key()
    if not isinstance(pk, VerifyingKey):
        raise ValueError("test")

    public_key_uncompressed = b"\x04" + pk.to_string()
    return (
        sk,
        public_key_uncompressed,
    )


def create_self_signed_cert_with_ecdsa():
    sk, public_key_der = generate_ecdsa_keys()

    ecdomain_params = keys.ECDomainParameters(("named", "secp256r1"))

    ec_point_bit_string = keys.ECPointBitString(public_key_der)

    if public_key_der[0] != 0x04:
        raise ValueError("Public key is not in uncompressed format")

    public_key_info = keys.PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "1.2.840.10045.2.1",
                "parameters": ecdomain_params,
            },
            "public_key": ec_point_bit_string,
        }
    )

    subject = x509.Name.build(
        {
            "common_name": "My Self-Signed ECDSA Cert",
            "country_name": "US",
            "organization_name": "Example Org",
        }
    )

    issuer = subject

    not_before = x509.Time({"utc_time": datetime.now(UTC)})
    not_after = x509.Time({"utc_time": datetime.now(UTC) + timedelta(days=365)})

    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(os.urandom(16), "big"),
            "signature": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "issuer": issuer,
            "validity": x509.Validity(
                {"not_before": not_before, "not_after": not_after}
            ),
            "subject": subject,
            "subject_public_key_info": public_key_info,
        }
    )

    signature = sk.sign(tbs_certificate.dump())

    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "sha256_ecdsa"}
            ),
            "signature_value": signature,
        }
    )

    return certificate


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


def is_dtls_record_layer(data: bytes) -> bool:
    try:
        ContentType(int.from_bytes(data[0:1], "big"))
        return True
    except Exception:
        return False


class DTLSVersion(IntEnum):
    V1_0 = 0xFEFF
    V1_2 = 0xFEFD


class CipherSuiteID(IntEnum):
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F

    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030

    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014

    TLS_PSK_WITH_AES_128_CCM = 0xC0A4
    TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8
    TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9
    TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8
    TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE

    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037

    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035


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


class EllipticCurveGroup(IntEnum):
    X25519 = 0x001D
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018


class SignatureHashAlgorithm(IntEnum):
    ECDSA_SECP256R1_SHA256 = 0x0403
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PKCS1_SHA256 = 0x0401
    ECDSA_SECP384R1_SHA384 = 0x0503
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PSS_RSAE_SHA512 = 0x0806
    RSA_PKCS1_SHA512 = 0x0601
    RSA_PKCS1_SHA1 = 0x0201


class SRTPProtectionProfile(IntEnum):
    SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
    SRTP_AEAD_AES_256_GCM = 0x0008
    SRTP_AEAD_AES_128_GCM = 0x0007


class EllipticCurvePointFormat(IntEnum):
    UNCOMPRESSED = 0x00


class Marshallable(Protocol):
    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class MessageBuffer:
    def __init__(self, data: bytes) -> None:
        self.offset: int = 0
        self.data = data

    @property
    def length(self) -> int:
        return len(self.data)

    def read_bytes(self, length: int) -> bytes:
        if len(self.data) < self.offset + length:
            raise ValueError("Buffer too small for read operation")

        value = self.data[self.offset : self.offset + length]

        self.offset += len(value)

        return value

    def next_uint8(self) -> int:
        return int.from_bytes(self.read_bytes(1), "big")

    def next_uint16(self):
        return byteops.unpack_unsigned_short(self.read_bytes(2))


class Extension:
    extension_type: int

    def __init__(self, data: bytes) -> None:
        self.buf = MessageBuffer(data)

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class SupportedGroups(Extension):
    extension_type = 0x0A

    supported_groups: list[EllipticCurveGroup] | None = None

    def marshal(self) -> bytes:
        if not self.supported_groups or len(self.supported_groups) == 0:
            raise ValueError("supported groups must not be nullable")

        result = bytes()
        for supported_group in self.supported_groups:
            result += byteops.pack_unsigned_short(supported_group)

        return byteops.pack_unsigned_short(len(result)) + result

    def unmarshal_supported_groups(self) -> Self:
        supported_groups_list_length = self.buf.next_uint16()
        supported_groups_list_count = supported_groups_list_length >> 1

        result = list[EllipticCurveGroup]()
        for _ in range(supported_groups_list_count):
            try:
                result.append(EllipticCurveGroup(self.buf.next_uint16()))
            except Exception:
                pass

        self.supported_groups = result
        # print("supported groups", result)

        return self

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_supported_groups()
        return c


class ExtendedMasterSecret(Extension):
    extension_type = 0x17

    def marshal(self) -> bytes:
        return bytes()

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        return cls(data)


class SignatureAlgorithms(Extension):
    extension_type = 0x0D

    signature_hash_algorithms: list[SignatureHashAlgorithm] | None = None

    def marshal(self) -> bytes:
        if (
            not self.signature_hash_algorithms
            or len(self.signature_hash_algorithms) == 0
        ):
            raise ValueError("signature hash algorithms must not be nullable")

        result = bytes()
        for signature_hash_algorithm in self.signature_hash_algorithms:
            result += byteops.pack_unsigned_short(signature_hash_algorithm)

        return byteops.pack_unsigned_short(len(result)) + result

    def unmarshal_signature_hash_algorithms(self) -> Self:
        signature_hash_algorithms_length = self.buf.next_uint16()
        signature_hash_algorithms_count = signature_hash_algorithms_length >> 1

        result = list[SignatureHashAlgorithm]()
        try:
            for _ in range(signature_hash_algorithms_count):
                result.append(SignatureHashAlgorithm(self.buf.next_uint16()))
        except Exception:
            pass

        self.signature_hash_algorithms = result
        # print("signature hash algo:" ,len(self.signature_hash_algorithms), self.signature_hash_algorithms)

        return self

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_signature_hash_algorithms()
        return c


class UseSRTP(Extension):
    extension_type = 0x0E

    srtp_protection_profiles: list[SRTPProtectionProfile] | None = None

    def marshal(self) -> bytes:
        if not self.srtp_protection_profiles or len(self.srtp_protection_profiles) == 0:
            raise ValueError("srtp protection profiles must not be nullable")

        result = bytes()
        for srtp_protection_profile in self.srtp_protection_profiles:
            result += byteops.pack_unsigned_short(srtp_protection_profile)

        return (
            byteops.pack_unsigned_short(len(result))
            + result
            + byteops.pack_byte_int(0)  # MKI
        )

    def unmarshal_srtp_protection_profiles(self) -> Self:
        srtp_protection_profiles_length = self.buf.next_uint16()
        srtp_protection_profiles_count = srtp_protection_profiles_length >> 1

        result = list[SRTPProtectionProfile]()
        for _ in range(srtp_protection_profiles_count):
            try:
                result.append(SRTPProtectionProfile(self.buf.next_uint16()))
            except Exception:
                pass

        self.srtp_protection_profiles = result
        # print("srtp protection profiles", self.srtp_protection_profiles)

        return self

    def unmarshal_master_key_identifier(self) -> Self:
        mki_length = self.buf.next_uint8()
        _ = mki_length
        return self

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_srtp_protection_profiles()
        c.unmarshal_master_key_identifier()
        return c


class EcPointFormats(Extension):
    extension_type = 0x0B

    ec_point_formats: list[EllipticCurvePointFormat] | None = None

    def marshal(self) -> bytes:
        if not self.ec_point_formats or len(self.ec_point_formats) == 0:
            raise ValueError("ec point formats must not be nullable")

        result = bytes()
        for ec_point_format in self.ec_point_formats:
            result += byteops.pack_byte_int(ec_point_format)

        return byteops.pack_byte_int(len(result)) + result

    def unmarshal_ec_point_formats(self) -> Self:
        ec_point_formats_count = self.buf.next_uint8()

        result = list[EllipticCurvePointFormat]()
        for _ in range(ec_point_formats_count):
            try:
                result.append(EllipticCurvePointFormat(self.buf.next_uint8()))
            except Exception:
                pass

        self.ec_point_formats = result
        # print(self.ec_point_formats)

        return self

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_ec_point_formats()
        return c


class RegonitiationInfo(Extension):
    extension_type = 0xFF01

    def marshal(self) -> bytes:
        return byteops.pack_byte_int(0)

    def unmarshal_regonitiation_info(self) -> Self:
        self.buf.next_uint8()
        return self

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_regonitiation_info()
        return c


EXTENSION_CLASSES: dict[int, type[Extension]] = {
    SupportedGroups.extension_type: SupportedGroups,
    ExtendedMasterSecret.extension_type: ExtendedMasterSecret,
    SignatureAlgorithms.extension_type: SignatureAlgorithms,
    UseSRTP.extension_type: UseSRTP,
    EcPointFormats.extension_type: EcPointFormats,
    RegonitiationInfo.extension_type: RegonitiationInfo,
}


class Random:
    # Random value that is used in ClientHello and ServerHello
    # https://tools.ietf.org/html/rfc4346#section-7.4.1.2

    RANDOM_BYTES_LENGTH = 28
    RANDOM_LENGTH = RANDOM_BYTES_LENGTH + 4

    def __init__(
        self, random_bytes_length=RANDOM_BYTES_LENGTH, random_length=RANDOM_LENGTH
    ):
        self.gmt_unix_time = datetime.now()
        self.RANDOM_BYTES_LENGTH = random_bytes_length
        self.RANDOM_LENGTH = random_length
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

    __random_gen = Random()

    def __init__(self, data: bytes) -> None:
        self.buf = MessageBuffer(data)

        self.version: DTLSVersion | None = None
        self.random: bytes | None = None
        self.session_id: bytes | None = None
        self.cookie: bytes | None = None
        self.cipher_suites: list[CipherSuiteID] | None = None
        self.compression_methods: list[CompressionMethod] | None = None
        self.extensions: list[Extension] | None = None

        # ServerHello
        self.cipher_suite: CipherSuiteID | None = None
        self.compression_method: CompressionMethod | None = None

    def marshal_version(self) -> bytes:
        if not self.version:
            raise ValueError("Require a version specified")

        return byteops.pack_unsigned_short(self.version)

    def marshal_random(self) -> bytes:
        if not self.random:
            self.__random_gen.populate()
            self.random = self.__random_gen.marshal_fixed()

        return self.random

    def marshal_session_id(self) -> bytes:
        if not self.session_id or len(self.session_id):
            return byteops.pack_byte_int(0)

        return byteops.pack_byte_int(len(self.session_id)) + self.session_id

    def marshal_cookie(self) -> bytes:
        if not self.cookie or len(self.cookie) == 0:
            return byteops.pack_byte_int(0)

        return byteops.pack_byte_int(len(self.cookie)) + self.cookie

    def marshal_cipher_suites(self) -> bytes:
        if not self.cipher_suites or len(self.cipher_suites) == 0:
            raise ValueError("cipher suites must not be nullable")

        result = bytes()
        for suite_id in self.cipher_suites:
            result += byteops.pack_unsigned_short(suite_id)

        # print("cipher suites", len(result))

        return byteops.pack_unsigned_short(len(result)) + result

    def marshal_cipher_suite(self) -> bytes:
        if not self.cipher_suite:
            raise ValueError("cipher suite must not be a nullable")

        return byteops.pack_unsigned_short(self.cipher_suite)

    def marshal_compression_methods(self) -> bytes:
        if not self.compression_methods or len(self.compression_methods) == 0:
            raise ValueError("compression methods must not be nullable")

        result = bytes()
        for compression_method in self.compression_methods:
            result += byteops.pack_byte_int(compression_method)

        return byteops.pack_byte_int(len(result)) + result

    def marshal_compression_method(self) -> bytes:
        if self.compression_method is None:
            raise ValueError("compresssion method must not be a nullable")
        return byteops.pack_byte_int(self.compression_method)

    def marshal_extensions(self) -> bytes:
        if not self.extensions or len(self.extensions) == 0:
            raise ValueError("extensions must not be nullable")

        result = bytes()
        for extension in self.extensions:
            payload = extension.marshal()
            if not payload:
                result += byteops.pack_unsigned_short(
                    extension.extension_type
                ) + byteops.pack_unsigned_short(0)
                continue

            result += (
                byteops.pack_unsigned_short(extension.extension_type)
                + byteops.pack_unsigned_short(len(payload))
                + payload
            )

        return byteops.pack_unsigned_short(len(result)) + result

    def unmarshal_version(self) -> Self:
        self.version = DTLSVersion(self.buf.next_uint16())

        if self.version == DTLSVersion.V1_0:
            pass
            # print("Catch DTLS 1.0 version. May not support it!")
        elif self.version == DTLSVersion.V1_2:
            pass
        else:
            raise ValueError(
                f"Unsupported DTLS version: {hex(self.version)}. DTLS 1.2 (0xFEFD) required."
            )

        return self

    def unmarshal_random(self) -> Self:
        self.random = self.buf.read_bytes(self.__random_gen.RANDOM_LENGTH)
        # print("random", binascii.hexlify(self.random))
        return self

    def unmarshal_session_id(self) -> Self:
        session_id_length = self.buf.next_uint8()
        if self.buf.length < self.buf.offset + session_id_length:
            raise ValueError("insufficient data for session id")
        self.session_id = self.buf.read_bytes(session_id_length)
        # print("session_id_length", session_id_length)
        # print("session_id", self.session_id)
        return self

    def unmarshal_cookie(self) -> Self:
        cookie_length = self.buf.next_uint8()
        if self.buf.length < self.buf.offset + cookie_length:
            raise ValueError("insufficient data for cookie")
        self.cookie = self.buf.read_bytes(cookie_length)
        # print("cookie_length", cookie_length)
        # print("cookie", self.cookie)
        return self

    def unmarshal_cipher_suites(self) -> Self:
        cipher_suite_length = self.buf.next_uint16()
        if self.buf.length < self.buf.offset + cipher_suite_length:
            raise ValueError("insufficient data for cipher suite")

        # One suite == 2 bytes
        cipher_suites_count = cipher_suite_length // 2

        result = list[CipherSuiteID]()
        for _ in range(cipher_suites_count):
            try:
                result.append(CipherSuiteID(self.buf.next_uint16()))
            except Exception as e:
                print("not found cipher sute", e)
                pass

        self.cipher_suites = result
        # print("cipher_suites", self.cipher_suites)

        return self

    def unmarshal_cipher_suite(self) -> Self:
        try:
            self.cipher_suite = CipherSuiteID(self.buf.next_uint16())
        except Exception:
            pass

        return self

    def unmarshal_compression_methods(self) -> Self:
        compression_methods_count = self.buf.next_uint8()
        if self.buf.length < self.buf.offset + compression_methods_count:
            raise ValueError("insufficient data for compression methods")

        result = list[CompressionMethod]()
        for _ in range(compression_methods_count):
            try:
                result.append(CompressionMethod(self.buf.next_uint8()))
            except Exception:
                pass

        self.compression_methods = result

        return self

    def unmarshal_compression_method(self) -> Self:
        try:
            self.compression_method = CompressionMethod(self.buf.next_uint8())
        except Exception:
            pass
        return self

    def unmarshal_extensions(self) -> Self:
        extensions_length = self.buf.next_uint16()
        if self.buf.length < self.buf.offset + extensions_length:
            raise ValueError("insufficient data for extensions")

        extensions = self.buf.read_bytes(extensions_length)

        offset = 0
        result = list[Extension]()

        while offset < len(extensions):
            ext_type = int.from_bytes(extensions[offset : offset + 2], "big")
            ext_length = int.from_bytes(extensions[offset + 2 : offset + 4], "big")

            ext_data = extensions[offset + 4 : offset + 4 + ext_length]
            if len(ext_data) != ext_length:
                raise ValueError("Extension length mismatch")

            try:
                extension_cls = EXTENSION_CLASSES.get(ext_type)

                if not extension_cls:
                    raise ValueError("Not found extension class")

                result.append(
                    extension_cls.unmarshal(ext_data),
                )

            except Exception as e:
                print("Not found extension", ext_type, e)
                pass

            offset += 4 + ext_length

        self.extensions = result

        return self

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class ClientHello(Message):
    message_type = HandshakeMessageType.ClientHello

    def marshal(self) -> bytes:
        return bytes(
            self.marshal_version()
            + self.marshal_random()
            + self.marshal_session_id()
            + self.marshal_cookie()
            + self.marshal_cipher_suites()
            + self.marshal_compression_methods()
            + self.marshal_extensions()
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        i.unmarshal_version()
        i.unmarshal_random()
        i.unmarshal_session_id()
        i.unmarshal_cookie()
        i.unmarshal_cipher_suites()
        i.unmarshal_compression_methods()
        i.unmarshal_extensions()
        return i

    def __repr__(self) -> str:
        full_name = f"{self.__class__.__module__}.{self.__class__.__qualname__}"
        return f"<{full_name} object at {hex(id(self))} version={self.version}, random={self.random}, session_id={self.session_id}, cookie={self.cookie}, cipher_suites={self.cipher_suites}, compression_methods={self.compression_methods}, extensions={self.extensions}>"


class HelloVerifyRequest(Message):
    message_type = HandshakeMessageType.HelloVerifyRequest

    def marshal(self) -> bytes:
        return bytes(self.marshal_version() + self.marshal_cookie())

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        i.unmarshal_version()
        i.unmarshal_cookie()
        return i


class ServerHello(Message):
    message_type = HandshakeMessageType.ServerHello

    def marshal(self) -> bytes:
        return bytes(
            self.marshal_version()
            + self.marshal_random()
            + self.marshal_session_id()
            + self.marshal_cipher_suite()
            + self.marshal_compression_method()
            + self.marshal_extensions()
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        i.unmarshal_version()
        i.unmarshal_random()
        i.unmarshal_session_id()
        i.unmarshal_cipher_suite()
        i.unmarshal_compression_method()
        i.unmarshal_extensions()
        return i


class Certificate(Message):
    message_type = HandshakeMessageType.Certificate

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        # TODO: certificate
        ...


class KeyServerExchange(Message):
    message_type = HandshakeMessageType.KeyServerExchange

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        # TODO: EC Diffie-Hellman Server Params
        ...


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


MESSAGE_CLASSES: dict[HandshakeMessageType, type[Message]] = {
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
    message_sequence: int
    fragment_offset: int
    fragment_length: int = 0
    length: int = 0


class RecordContentType:
    content_type: ContentType

    def marshal(self) -> bytes: ...

    @classmethod
    def unmarshal(cls, data: bytes) -> Self: ...


class Handshake(RecordContentType):
    """
    Header is the static first 12 bytes of each RecordLayer
    of type Handshake. These fields allow us to support message loss, reordering, and
    message fragmentation,

    https://tools.ietf.org/html/rfc6347#section-4.2.2

    """

    content_type = ContentType.HANDSHAKE

    HEADER_LENGHT = 12

    def __init__(self, header: HandshakeHeader, message: Message) -> None:
        self.header = header
        self.message = message

    def marshal(self) -> bytes:
        payload = self.message.marshal()
        # print("handshake payload", len(payload))

        length = byteops.pack_unsigned_24(len(payload))
        message_sequence = byteops.pack_unsigned_short(self.header.message_sequence)
        fragment_offset = byteops.pack_unsigned_24(self.header.fragment_offset)
        fragment_length = byteops.pack_unsigned_24(len(payload))

        return bytes(
            byteops.pack_byte_int(self.message.message_type)
            + length
            + message_sequence
            + fragment_offset
            + fragment_length
            + payload
        )

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

    def __repr__(self) -> str:
        full_name = f"{self.__class__.__module__}.{self.__class__.__qualname__}"
        return f"<{full_name} object at {hex(id(self))} message={self.message}>"


CONTENT_TYPE_CLASSES: dict[ContentType, type[RecordContentType]] = {
    Handshake.content_type: Handshake,
}


@dataclass
class RecordHeader:
    content_type: ContentType
    version: DTLSVersion
    epoch: int
    sequence_number: int
    length: int = 0


def unpack_version(data: bytes) -> DTLSVersion:
    version = DTLSVersion(byteops.unpack_unsigned_short(data))
    if version == DTLSVersion.V1_0:
        pass
        # print("Catch DTLS 1.0 version. May not support it!")
    elif version == DTLSVersion.V1_2:
        pass
    else:
        raise ValueError(
            f"Unsupported DTLS version: {hex(version)}. DTLS 1.2 (0xFEFD) required."
        )
    return version


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

    def __init__(self, header: RecordHeader, content: RecordContentType) -> None:
        self.header = header
        self.content = content

    def marshal(self) -> bytes:
        payload = self.content.marshal()
        # print("handshake", len(payload))
        return bytes(
            byteops.pack_byte_int(self.content.content_type)
            + byteops.pack_unsigned_short(self.header.version)
            + byteops.pack_unsigned_short(self.header.epoch)
            + self.header.sequence_number.to_bytes(6, byteorder="big")
            + byteops.pack_unsigned_short(len(payload))
            + payload
        )

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

        try:
            content_cls = CONTENT_TYPE_CLASSES.get(content_type)
            if not content_cls:
                raise ValueError("Unsupported content type")
            content = content_cls.unmarshal(data)
        except Exception as e:
            raise e

        # print(content)

        return cls(header, content)


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


class HandshakeState(IntEnum):
    Errored = 0
    Preparing = 1
    Sending = 2
    Waiting = 3
    Finished = 4


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


# @dataclass(frozen=True)
# class StateTransition:
#     FROM: Flight
#     TO: Flight

# flight_transitions: dict[StateTransition, FlightTransitionHandler] = {
#     StateTransition(Flight.FLIGHT0, Flight.FLIGHT1): lambda: print("test"),
#     StateTransition(Flight.FLIGHT1, Flight.FLIGHT2): lambda: print("test1"),
# }


class State:
    INITIAL_EPOCH = 0
    DEFAULT_CURVE: EllipticCurveGroup = EllipticCurveGroup.X25519

    def __init__(self) -> None:
        self.local_epoch = self.remote_epoch = 0
        self.local_random = Random()
        self.remote_random = Random()
        self.local_sequence_number = 0
        self.handshake_sequence_number = 0

        self.cooike_random = Random(20, 20)
        self.cooike_random.populate()
        self.cookie = self.cooike_random.marshal_fixed()

        self.master_secret: bytes | None = None
        self.srtp_protection_profile: SRTPProtectionProfile | None = None
        self.elliptic_curve: EllipticCurveGroup | None = None


class FlightTransition(Protocol):
    def generate(self, state: State) -> list[RecordLayer] | None: ...

    def parse(self, state: State) -> Flight: ...


class Flight0:
    def generate(self, state: State) -> list[RecordLayer] | None:
        state.elliptic_curve = state.DEFAULT_CURVE
        state.local_epoch = 0
        state.remote_epoch = 0
        state.local_random.populate()

    def parse(self, state: State) -> Flight:
        return Flight.FLIGHT2


class Flight2:
    def generate(self, state: State) -> list[RecordLayer] | None:
        state.handshake_sequence_number = 0
        hello_verify_request = HelloVerifyRequest(bytes())
        hello_verify_request.version = DTLSVersion.V1_2
        hello_verify_request.cookie = state.cookie

        return [
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_0,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.HelloVerifyRequest,
                        message_sequence=0,
                        fragment_offset=0,
                    ),
                    hello_verify_request,
                ),
            ),
        ]

    def parse(self, state: State) -> Flight:
        return Flight.FLIGHT4


class Flight4:
    def generate(self, state: State) -> list[RecordLayer] | None:
        server_hello = ServerHello(bytes())
        server_hello.version = DTLSVersion.V1_2

        # TODO: Don't hard code
        server_hello.cipher_suite = (
            CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        )
        server_hello.compression_method = CompressionMethod.Null

        use_srtp = UseSRTP(bytes())
        use_srtp.srtp_protection_profiles = [
            SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        ]
        ec_point_formats = EcPointFormats(bytes())
        ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]
        server_hello.extensions = [
            RegonitiationInfo(bytes()),
            ExtendedMasterSecret(bytes()),
            use_srtp,
            ec_point_formats,
        ]

        return [
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_0,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.ServerHello,
                        message_sequence=1,
                        fragment_offset=0,
                    ),
                    server_hello,
                ),
            ),
        ]

    def parse(self, state: State) -> Flight:
        return Flight.FLIGHT5


FLIGHT_TRANSITIONS: dict[Flight, FlightTransition] = {
    Flight.FLIGHT0: Flight0(),
    Flight.FLIGHT2: Flight2(),
    Flight.FLIGHT4: Flight4(),
}


class DTLSRemote(Protocol):
    def sendto(self, data: bytes): ...


class FSM:
    def __init__(
        self,
        remote: DTLSRemote,
        handshake_messages_chan: asyncio.Queue[Message],
    ) -> None:
        self.remote = remote
        self.handshake_message_chan = handshake_messages_chan

        self.state = State()

        self.handshake_state_transition = asyncio.Queue[HandshakeState]()
        self.handshake_state_transition_lock = asyncio.Lock()

        self.handshake_state: HandshakeState = HandshakeState.Preparing
        self.flight = Flight.FLIGHT0

        self.pending_record_layers: list[RecordLayer] | None = None

    async def dispatch(self):
        async with self.handshake_state_transition_lock:
            await self.handshake_state_transition.put(self.handshake_state)

    async def run(self):
        while True:
            # TODO: message sequence support ??
            handshake_message = await self.handshake_message_chan.get()

            async with self.handshake_state_transition_lock:
                while True:
                    if self.handshake_state_transition.empty():
                        print("Handshake state transition done")
                        break

                    handshake_state = await self.handshake_state_transition.get()

                    match handshake_state:
                        case HandshakeState.Preparing:
                            await self.handshake_state_transition.put(
                                await self.prepare(),
                            )
                        case HandshakeState.Sending:
                            await self.handshake_state_transition.put(
                                await self.send(),
                            )
                        case HandshakeState.Waiting:
                            await self.handshake_state_transition.put(
                                await self.wait(),
                            )
                        case _:
                            continue

    async def prepare(self) -> HandshakeState:
        print("Prepare state", self.flight)
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            # TODO: DTLS alerting
            return HandshakeState.Errored

        self.pending_record_layers = flight.generate(self.state)
        epoch = self.state.INITIAL_EPOCH
        next_epoch = epoch
        if self.pending_record_layers:
            for record in self.pending_record_layers:
                record.header.epoch += epoch

                if record.header.epoch > next_epoch:
                    next_epoch = record.header.epoch

                if record.header.content_type == ContentType.HANDSHAKE:
                    record.header.sequence_number = self.state.handshake_sequence_number
                    self.state.handshake_sequence_number += 1

        if epoch != next_epoch:
            self.state.local_epoch = next_epoch

        return HandshakeState.Sending

    async def send(self) -> HandshakeState:
        print("Send state", self.flight, "pending", self.pending_record_layers)
        if not self.pending_record_layers:
            return HandshakeState.Waiting

        for layer in self.pending_record_layers:
            try:
                self.remote.sendto(layer.marshal())
            except Exception as e:
                # TODO: backoff
                print("Unable send inconsistent packet. Err:", e, "layer", layer)
                await asyncio.sleep(1)
                return HandshakeState.Sending

        return HandshakeState.Waiting

    async def wait(self) -> HandshakeState:
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            return HandshakeState.Errored

        next_flight = flight.parse(self.state)
        self.flight = next_flight

        return HandshakeState.Preparing

    async def finish(self) -> HandshakeState: ...


# TODO: Validate epoch
# TODO: Anti-replay protection
# TODO: Decrypt
class DTLSConn:
    def __init__(
        self,
        remote: DTLSRemote,
        layer_chan: asyncio.Queue[RecordLayer],
    ) -> None:
        # self.__cipher_suites = list[CipherSuite]()

        self.record_layer_chan = layer_chan

        self.handshake_message_chan = asyncio.Queue[Message]()
        self.fsm = FSM(remote, self.handshake_message_chan)

    async def handle_inbound_record_layers(self):
        fsm_runnable = asyncio.create_task(self.fsm.run())

        try:
            while True:
                record_layer = await self.record_layer_chan.get()

                match record_layer.header.content_type:
                    case ContentType.HANDSHAKE:
                        if not isinstance(record_layer.content, Handshake):
                            print(
                                "DTLS layer not is instance of Message",
                                record_layer.content,
                            )
                            continue

                        await self.handshake_message_chan.put(
                            record_layer.content.message,
                        )
                        await self.fsm.dispatch()
                    case _:
                        print(
                            "Unhandled record type of", record_layer.header.content_type
                        )

        except Exception as e:
            print("DTLS handle inbound record layers err", e)
        finally:
            fsm_runnable.cancel()


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
