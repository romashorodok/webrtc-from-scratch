import asyncio
import binascii
from dataclasses import dataclass
from enum import Enum, IntEnum
import hashlib
from typing import Any, Coroutine, Protocol, Self
from typing import Tuple, Callable, Optional
import hmac
import math
import struct
import os
from datetime import datetime, time, UTC, timedelta


from asn1crypto.core import ValueMap
from ecdsa.der import encode_length
import six


# from OpenSSL import SSL
# from pylibsrtp import Policy, Session

from webrtc import ice
from webrtc.ice import net

from Crypto.Cipher import AES

from asn1crypto import pem, x509, keys, algos
from ecdsa import Ed25519, SigningKey, VerifyingKey, NIST256p
from ecdsa.ecdh import ECDH


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


class EllipticCurveGroup(IntEnum):
    X25519 = 0x001D
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018


@dataclass
class Keypair:
    privateKey: SigningKey
    publicKey: VerifyingKey
    curve: EllipticCurveGroup

    @classmethod
    def generate_X25519(cls) -> Self:
        pkey = SigningKey.generate(curve=Ed25519, hashfunc=hashlib.sha256)
        pubkey = pkey.get_verifying_key()
        if not isinstance(pubkey, VerifyingKey):
            raise ValueError("Unable generate X25519 Keypair")
        return cls(
            pkey,
            pubkey,
            EllipticCurveGroup.X25519,
        )

    @classmethod
    def generate_P256(cls) -> Self:
        pkey = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
        pubkey = pkey.get_verifying_key()
        if not isinstance(pubkey, VerifyingKey):
            raise ValueError("Unable generate SECP256R1 Keypair")
        return cls(
            pkey,
            pubkey,
            EllipticCurveGroup.SECP256R1,
        )

    def __ecdh_params(self) -> bytes:
        server_ecdh_params = bytearray(4)
        server_ecdh_params[0] = NAMED_CURVE_TYPE
        server_ecdh_params[1:3] = byteops.pack_unsigned_short(self.curve)
        server_ecdh_params[3:4] = byteops.pack_byte_int(len(self.publicKey.to_der()))
        return server_ecdh_params

    def generate_server_signature(
        self, remote_random: bytes, local_random: bytes
    ) -> bytes:
        ecdh_params = self.__ecdh_params()
        msg = bytes(
            remote_random + local_random + ecdh_params + self.publicKey.to_der()
        )
        print("Expected server expected_ecdh_secret_message", binascii.hexlify(msg))
        print(
            "Expected server expected_ecdh_secret_message digest",
            binascii.hexlify(hashlib.sha256(msg).digest()),
        )

        result = self.privateKey.sign(msg, hashfunc=hashlib.sha256)
        return result

    # NOTE: Must be a len(bytes(...)) == 32
    def generate_shared_key(self) -> bytes:
        """
        Need for creating a pre master secret
        """
        ecdh = ECDH(
            curve=self.privateKey.curve,
            private_key=self.privateKey,
            public_key=self.publicKey,
        )
        return ecdh.generate_sharedsecret_bytes()

    def sign(self, data: bytes) -> bytes:
        # TODO: pass hash func as arg
        return self.privateKey.sign(data, hashfunc=hashlib.sha256)

    @staticmethod
    def pre_master_secret_from_pub_and_priv_key(
        pubkey: VerifyingKey,
        privkey: SigningKey,
    ) -> bytes:
        ecdh = ECDH(
            curve=privkey.curve,
            private_key=privkey,
            public_key=pubkey,
        )
        return ecdh.generate_sharedsecret_bytes()


def create_self_signed_cert_with_ecdsa(keypair: Keypair):
    sk = keypair.privateKey

    public_key_der = b"\x04" + keypair.publicKey.to_string()

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

    UNSPECIFIED = 0
    # RFC types:
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
    Finished = 20


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
    ED25519 = 0x0807


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

    certificates: list[x509.Certificate] | None = None

    def marshal_certificates(self) -> bytes:
        if not self.certificates:
            raise ValueError("Require certificate to be specified")

        result = bytes()
        for cert in self.certificates:
            cert_der = cert.dump()
            if not isinstance(cert_der, bytes):
                raise ValueError("Unable transform certificate to DER bytes")

            result += byteops.pack_unsigned_24(len(cert_der)) + cert_der

        return result

    def marshal(self) -> bytes:
        certificates = self.marshal_certificates()
        return bytes(
            byteops.pack_unsigned_24(len(certificates)) + certificates,
        )

    def unmarshal_certificates(self):
        certificates_length = byteops.unpack_unsigned_24(self.buf.read_bytes(3))

        if self.buf.length < self.buf.offset + certificates_length:
            raise ValueError("Insufficient data for certificates")

        result = list[x509.Certificate]()
        remaining_length = certificates_length
        while remaining_length > 0:
            if remaining_length < 3:
                raise ValueError("Malformed certificate data")

            # Read the length of the current certificate (3 bytes)
            cert_length = byteops.unpack_unsigned_24(self.buf.read_bytes(3))
            remaining_length -= 3

            if remaining_length < cert_length:
                raise ValueError("Insufficient data for certificate content")

            certificate = self.buf.read_bytes(cert_length)
            remaining_length -= cert_length

            certificate = x509.Certificate.load(certificate)
            result.append(certificate)

        self.certificates = result

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.unmarshal_certificates()
        return c


class KeyServerExchange(Message):
    message_type = HandshakeMessageType.KeyServerExchange

    named_curve: EllipticCurveGroup | None = None
    signature_hash_algorithm: SignatureHashAlgorithm | None = None
    pubkey: bytes | None = None
    signature: bytes | None = None

    def marshal(self) -> bytes:
        named_curve_type = byteops.pack_byte_int(NAMED_CURVE_TYPE)
        if not self.named_curve:
            raise ValueError("KeyServerExchange require a named curve")
        named_curve = byteops.pack_unsigned_short(self.named_curve)
        if not self.pubkey:
            raise ValueError("KeyServerExchange require a pubkey")
        pubkey_length = byteops.pack_byte_int(len(self.pubkey))
        if not self.signature_hash_algorithm:
            raise ValueError("KeyServerExchange require a signature_hash_algorithm")
        if not self.signature:
            raise ValueError("KeyServerExchange require a signature")
        signature_length = byteops.pack_unsigned_short(len(self.signature))
        return bytes(
            named_curve_type
            + named_curve
            + pubkey_length
            + self.pubkey
            + byteops.pack_unsigned_short(self.signature_hash_algorithm)
            + signature_length
            + self.signature
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        c = cls(data)
        c.buf.read_bytes(1)

        c.named_curve = EllipticCurveGroup(c.buf.next_uint16())
        pubkey_length = int.from_bytes(c.buf.read_bytes(1), "big")
        c.pubkey = c.buf.read_bytes(pubkey_length)
        c.signature_hash_algorithm = SignatureHashAlgorithm(c.buf.next_uint16())
        print("Unmarshal signature hash algo", c.signature_hash_algorithm)
        signature_length = c.buf.next_uint16()
        c.signature = c.buf.read_bytes(signature_length)

        return c


class CertificateType(IntEnum):
    RSA = 0x01
    ECDSA = 0x40


class CertificateRequest(Message):
    message_type = HandshakeMessageType.CertificateRequest

    certificate_types: list[CertificateType] | None = None
    signature_hash_algorithms: list[SignatureHashAlgorithm] | None = None

    def marshal(self) -> bytes:
        if not self.certificate_types:
            raise ValueError("CertificateRequest require certificate signs")
        certificate_types = bytes()
        for certificate_type in self.certificate_types:
            certificate_types += byteops.pack_byte_int(certificate_type)

        if not self.signature_hash_algorithms:
            raise ValueError("CertificateRequest require signature hash algorithms")

        signature_hash_algorithms = bytes()
        for signature_hash_algorithm in self.signature_hash_algorithms:
            signature_hash_algorithms += byteops.pack_unsigned_short(
                signature_hash_algorithm
            )
        signature_hash_algorithms_count = byteops.pack_unsigned_short(
            len(signature_hash_algorithms)
        )

        distinguished_names_lenght = byteops.pack_unsigned_short(0)

        return bytes(
            byteops.pack_byte_int(len(certificate_types))
            + certificate_types
            + signature_hash_algorithms_count
            + signature_hash_algorithms
            + distinguished_names_lenght
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        certificate_types_count = i.buf.next_uint8()
        certificate_types = list[CertificateType]()
        for _ in range(certificate_types_count):
            certificate_types.append(CertificateType(i.buf.next_uint8()))

        signature_hash_algorithms_count = i.buf.next_uint16() >> 1

        signature_hash_algorithms = list[SignatureHashAlgorithm]()
        for _ in range(signature_hash_algorithms_count):
            signature_hash_algorithms.append(
                SignatureHashAlgorithm(i.buf.next_uint16())
            )

        i.buf.next_uint8()  # distinguished_names_lenght

        i.certificate_types = certificate_types
        i.signature_hash_algorithms = signature_hash_algorithms

        return i


class ServerHelloDone(Message):
    message_type = HandshakeMessageType.ServerHelloDone

    def marshal(self) -> bytes:
        return bytes()

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        return cls(data)


class ClientKeyExchange(Message):
    message_type = HandshakeMessageType.ClientKeyExchange

    pubkey: bytes | None = None

    def marshal(self) -> bytes:
        if not self.pubkey:
            raise ValueError("ClientKeyExchange require pubkey")

        pubkey_length = byteops.pack_byte_int(len(self.pubkey))
        return pubkey_length + self.pubkey

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        pubkey_length = int.from_bytes(i.buf.read_bytes(1), "big")
        i.pubkey = i.buf.read_bytes(pubkey_length)
        return i


class CertificateVerify(Message):
    message_type = HandshakeMessageType.CertificateVerify

    signature_hash_algorithm: SignatureHashAlgorithm | None = None
    signature: bytes | None = None

    def marshal(self) -> bytes:
        if not self.signature_hash_algorithm:
            raise ValueError("CertificateVerify require a signature_hash_algorithm")
        if not self.signature:
            raise ValueError("CertificateVerify require a signature")
        signature_length = byteops.pack_unsigned_short(len(self.signature))
        return bytes(
            byteops.pack_unsigned_short(self.signature_hash_algorithm)
            + signature_length
            + self.signature
        )

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        i = cls(data)
        i.signature_hash_algorithm = SignatureHashAlgorithm(i.buf.next_uint16())
        signature_length = i.buf.next_uint16()
        i.signature = i.buf.read_bytes(signature_length)
        return i


class Finished(Message):
    message_type = HandshakeMessageType.Finished

    def __init__(self, data: bytes) -> None:
        self.encrypted_payload = data

    def marshal(self) -> bytes:
        return self.encrypted_payload

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        return cls(data)


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
    Finished.message_type: Finished,
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


class ChangeCipherSpec(RecordContentType):
    content_type = ContentType.CHANGE_CIPHER_SPEC

    def marshal(self) -> bytes:
        return bytes(0x01)

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        # if len(data) != 1 or not data[0] == 0x01:
        #     raise ValueError("Change Cipher spec must be a 1 byte")
        return cls()


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


class EncryptedHandshakeMessage(RecordContentType):
    content_type = ContentType.UNSPECIFIED

    def __init__(self, data: bytes) -> None:
        self.encrypted_payload = data

    def marshal(self) -> bytes:
        return self.encrypted_payload

    @classmethod
    def unmarshal(cls, data: bytes) -> Self:
        return cls(data)


CONTENT_TYPE_CLASSES: dict[ContentType, type[RecordContentType]] = {
    Handshake.content_type: Handshake,
    ChangeCipherSpec.content_type: ChangeCipherSpec,
}


@dataclass
class RecordHeader:
    content_type: ContentType
    version: DTLSVersion
    epoch: int
    sequence_number: int
    length: int = 0

    def header_size(self) -> int:
        return 13


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

    encrypt: bool = False

    def __init__(self, header: RecordHeader, content: RecordContentType) -> None:
        self.header = header
        self.content = content

    def header_size(self) -> int:
        # TODO: self.FIXED_HEADER_SIZE + connection_id
        return self.FIXED_HEADER_SIZE

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

        if epoch > 0:
            return cls(header, EncryptedHandshakeMessage(data))

        try:
            content_cls = CONTENT_TYPE_CLASSES.get(content_type)
            if not content_cls:
                raise ValueError("Unsupported content type")
            content = content_cls.unmarshal(data)
        except Exception as e:
            raise e

        return cls(header, content)


def generate_aead_additional_data(header: RecordHeader, payload_len: int) -> bytes:
    data = bytearray(13)

    sequence_number = header.sequence_number & 0xFFFFFFFFFFFF  # Mask to 48 bits
    data[0] = (sequence_number >> 40) & 0xFF
    data[1] = (sequence_number >> 32) & 0xFF
    data[2] = (sequence_number >> 24) & 0xFF
    data[3] = (sequence_number >> 16) & 0xFF
    data[4] = (sequence_number >> 8) & 0xFF
    data[5] = sequence_number & 0xFF

    # Epoch: 16-bit integer
    data[6] = (header.epoch >> 8) & 0xFF
    data[7] = header.epoch & 0xFF

    # ContentType: 1 byte
    data[8] = header.content_type

    # Version (Major and Minor): 2 bytes
    data[9:10] = byteops.pack_unsigned_short(header.version)

    # Payload Length: 16-bit integer
    data[11] = (payload_len >> 8) & 0xFF
    data[12] = payload_len & 0xFF

    return data


def encrypt_with_aes_gcm(
    key: bytes, nonce: bytes, payload: bytes, additional_data: bytes
) -> bytes:
    """
    Encrypts the payload using AES-GCM with the given key, nonce, and additional data.

    :param key: Encryption key (16, 24, or 32 bytes for AES-128, AES-192, AES-256)
    :param nonce: Unique nonce for AES-GCM (recommended length is 12 bytes)
    :param payload: The data to encrypt
    :param additional_data: Associated additional data (AAD) for integrity verification
    :return: Encrypted payload concatenated with the authentication tag
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(additional_data)
    encrypted_payload, tag = cipher.encrypt_and_digest(payload)
    return encrypted_payload + tag


def decrypt_with_aes_gcm(
    key: bytes, nonce: bytes, encrypted_payload: bytes, additional_data: bytes
) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(additional_data)
    # ciphertext, tag = (
    #     encrypted_payload[:-16],
    #     encrypted_payload[-16:],
    # )
    # return cipher.decrypt_and_verify(ciphertext, tag)
    return cipher.decrypt(encrypted_payload)


class GCM:
    """
    https://datatracker.ietf.org/doc/html/rfc5288
    https://en.wikipedia.org/wiki/Galois/Counter_Mode
    """

    GCM_NONCE_LENGTH = 12
    GCM_TAG_LENGTH = 16

    def __init__(
        self,
        local_key: bytes,
        local_write_iv: bytes,
        remote_key: bytes,
        remote_write_iv: bytes,
    ) -> None:
        # self._local_gcm = AES.new(local_key, AES.MODE_GCM, local_write_iv)
        # self._remote_gcm = AES.new(remote_key, AES.MODE_GCM, remote_write_iv)

        self.local_key = local_key
        self.remote_key = remote_key
        self.local_write_iv = local_write_iv
        self.remote_write_iv = remote_write_iv

    def encrypt(self, pkt: RecordLayer, raw: bytes) -> bytes | None:
        payload = raw[pkt.header_size() :]
        raw = raw[: pkt.header_size()]

        nonce = bytearray(self.GCM_NONCE_LENGTH)
        nonce[:4] = self.local_write_iv[:4]
        nonce[4:] = os.urandom(self.GCM_NONCE_LENGTH - 4)

        additional_data = generate_aead_additional_data(pkt.header, len(payload))

        encrypted = encrypt_with_aes_gcm(
            self.local_key, nonce, payload, additional_data
        )

        total_length = len(raw) + len(nonce[4:]) + len(encrypted)
        result = bytearray(total_length)
        result[0 : len(raw)] = raw
        result[len(raw) : len(raw) + len(nonce[4:])] = nonce[4:]
        result[len(raw) + len(nonce[4:]) :] = encrypted

        result[pkt.header_size() - 2 : pkt.header_size()] = byteops.pack_unsigned_short(
            total_length - pkt.header_size()
        )

        return result

    def decrypt(self, h: RecordHeader, raw: bytes) -> bytes | None:
        nonce = bytearray(self.GCM_NONCE_LENGTH)
        nonce[:4] = self.remote_write_iv[:4]
        nonce += raw[h.header_size() : h.header_size() + 8]

        out = raw[h.header_size() + 8 :]

        additional_data = generate_aead_additional_data(
            h, len(out) - self.GCM_TAG_LENGTH
        )

        decrypted = decrypt_with_aes_gcm(self.remote_key, nonce, out, additional_data)

        return raw[: h.header_size()] + decrypted


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
        self.gcm: GCM | None = None

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
            gcm = GCM(
                keys.client_write_key,
                keys.client_write_iv,
                keys.server_write_key,
                keys.server_write_iv,
            )
        else:
            gcm = GCM(
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
            print("Unable decrypt start gcm first")
            return
            # raise ValueError("Unable decrypt start gcm first")

        return self.gcm.decrypt(h, raw)


class CipherSuite(Protocol):
    def start(
        self,
        master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        client: bool,
    ): ...

    def encrypt(self, pkt: RecordLayer, raw: bytes) -> bytes | None: ...

    def decrypt(self, h: RecordHeader, raw: bytes) -> bytes | None: ...


CIPHER_SUITES_CLASSES: dict[CipherSuiteID, type[CipherSuite]] = {
    CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}


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


NAMED_CURVE_TYPE = 0x03


# TODO: Same as Keypair.generate_signature
def ecdh_value_key_message(
    client_random: bytes,
    server_random: bytes,
    pubkey: bytes,
    named_curve: EllipticCurveGroup,
) -> bytes:
    ecdh_params = bytearray(4)
    ecdh_params[0] = NAMED_CURVE_TYPE
    ecdh_params[1:3] = byteops.pack_unsigned_short(named_curve)
    ecdh_params[3:4] = byteops.pack_byte_int(len(pubkey))
    return bytes(client_random + server_random + ecdh_params + pubkey)


def verify_certificate_signature(
    ecdh_shared_secret_message: bytes,
    signature: bytes,
    hash_func: Callable,
    certificates: list[x509.Certificate],
) -> bool:
    """
    Why Certificates + ECDH:
    - ECDH alone provides confidentiality:
        * It ensures that a shared secret can be computed securely without transmitting private keys.
    - Certificates add authentication:
        * They ensure that the public key used in the ECDH process belongs to the intended entity (e.g., the server in a TLS session).
        * They prevent MITM attacks by binding the public key to the server’s identity.
    """
    if hash_func is not hashlib.sha256:
        raise ValueError("verify_certificate_signature support only sha256")

    for certificate in certificates:
        pubkey: x509.PublicKeyInfo = certificate.public_key
        verifying_key = VerifyingKey.from_der(pubkey.dump())
        digest = hashlib.sha256(ecdh_shared_secret_message).digest()
        if verified := verifying_key.verify_digest(signature, digest):
            return verified

    return False


@dataclass
class PullCacheOption:
    message_type: HandshakeMessageType
    epoch: int
    is_client: bool
    optional: bool


@dataclass(frozen=True)
class HandshakeCacheKey:
    message_type: HandshakeMessageType
    epoch: int


class State:
    INITIAL_EPOCH = 0
    DEFAULT_CURVE: EllipticCurveGroup = EllipticCurveGroup.SECP256R1

    def __init__(self) -> None:
        self.local_epoch = self.remote_epoch = 0
        self.local_random = Random()
        self.remote_random: bytes | None = None
        self.local_sequence_number = 0
        self.handshake_sequence_number = 0

        self.local_keypair: Keypair = Keypair.generate_P256()
        self.local_certificate: x509.Certificate | None = None

        self.cooike_random = Random(20, 20)
        self.cooike_random.populate()
        self.cookie = self.cooike_random.marshal_fixed()

        self.pre_master_secret: bytes | None = None
        self.master_secret: bytes | None = None
        self.srtp_protection_profile: SRTPProtectionProfile | None = None
        self.elliptic_curve: EllipticCurveGroup | None = None
        self.remote_peer_certificates: list[x509.Certificate] | None = None

        self.pending_remote_handshake_messages: list[Message] | None = None

        self.pending_cipher_suite: CipherSuite | None = None
        self.cipher_suite: CipherSuite | None = None

        self.local_verify: bytes | None = None

        self.client_cache_messages = dict[HandshakeCacheKey, Message]()
        self.server_cache_messages = dict[HandshakeCacheKey, Message]()

    def push_cache(self, message: Message): ...

    def pull_cache(self, options: list[PullCacheOption]) -> list[Message] | None:
        pass


class FlightTransition(Protocol):
    def generate(self, state: State) -> list[RecordLayer] | None: ...

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight: ...


VERIFY_DATA_CLIENT_LABEL = b"client finished"
VERIFY_DATA_SERVER_LABEL = b"server finished"


def prf_verify_data(master_secret: bytes, handshake_bodies: bytes, label: bytes):
    # TODO: dynamic hashfunc
    digest = hashlib.sha256(handshake_bodies).digest()
    seed = label + digest
    return p_hash(master_secret, seed, 12, hashlib.sha256)


def verify_data_client(master_secret: bytes, handshake_bodies: bytes):
    return prf_verify_data(master_secret, handshake_bodies, VERIFY_DATA_CLIENT_LABEL)


def verify_data_server(master_secret: bytes, handshake_bodies: bytes):
    return prf_verify_data(master_secret, handshake_bodies, VERIFY_DATA_SERVER_LABEL)


# --- Server side flights


class Flight0:
    def generate(self, state: State) -> list[RecordLayer] | None:
        state.elliptic_curve = state.DEFAULT_CURVE

        state.local_epoch = 0
        state.remote_epoch = 0
        state.local_random.populate()

        state.local_keypair = Keypair.generate_P256()

        state.remote_random = None

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        client_hello = await handshake_message_ch.get()
        if not isinstance(client_hello, ClientHello):
            print("Flight 0 must receive a client hello.")
            return Flight.FLIGHT0

        if not state.remote_random and client_hello.random:
            state.remote_random = client_hello.random
        elif not state.remote_random:
            print("Flight 0 client hello must contain a random.")
            return Flight.FLIGHT0

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

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        print("flight 2 wait")
        client_hello = await handshake_message_ch.get()
        print("flight 2 after wait")
        if not isinstance(client_hello, ClientHello):
            print(
                "Flight 1 must receive a client hello after a HelloVerifyRequest. Reset state to Flight 0"
            )
            return Flight.FLIGHT0

        if not client_hello.cookie:
            print("Flight 0 client hello must contain a cookie.")
            return Flight.FLIGHT0

        if state.cookie != client_hello.cookie:
            print("Flight 0 must contain a same remote and local cookie")
            return Flight.FLIGHT0

        return Flight.FLIGHT4


class Flight4:
    def generate(self, state: State) -> list[RecordLayer] | None:
        if not state.remote_random:
            raise ValueError("Not found remote random")

        signature = state.local_keypair.generate_server_signature(
            state.remote_random, state.local_random.marshal_fixed()
        )
        # print("Generated signature", signature)

        key_server_exchange = KeyServerExchange(bytes())
        key_server_exchange.named_curve = state.local_keypair.curve
        # TODO: Don't hard code
        key_server_exchange.signature_hash_algorithm = (
            SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
        )
        key_server_exchange.pubkey = state.local_keypair.publicKey.to_der()
        key_server_exchange.signature = signature

        certificate_request = CertificateRequest(bytes())
        certificate_request.certificate_types = [CertificateType.ECDSA]
        certificate_request.signature_hash_algorithms = [
            SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256,
            SignatureHashAlgorithm.ED25519,
        ]

        server_hello = ServerHello(bytes())
        server_hello.version = DTLSVersion.V1_2
        server_hello.random = state.local_random.marshal_fixed()

        # TODO: Don't hard code
        server_hello.cipher_suite = (
            CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        )
        server_hello.compression_method = CompressionMethod.Null
        state.pending_cipher_suite = (
            CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
        )

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

        certificate = Certificate(bytes())
        state.local_certificate = create_self_signed_cert_with_ecdsa(
            state.local_keypair
        )
        certificate.certificates = [state.local_certificate]

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
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_0,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.Certificate,
                        message_sequence=2,
                        fragment_offset=0,
                    ),
                    certificate,
                ),
            ),
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_2,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.KeyServerExchange,
                        message_sequence=3,
                        fragment_offset=0,
                    ),
                    key_server_exchange,
                ),
            ),
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_2,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.CertificateRequest,
                        message_sequence=4,
                        fragment_offset=0,
                    ),
                    certificate_request,
                ),
            ),
            RecordLayer(
                RecordHeader(
                    ContentType.HANDSHAKE,
                    DTLSVersion.V1_2,
                    state.local_epoch,
                    state.local_sequence_number,
                ),
                Handshake(
                    HandshakeHeader(
                        handshake_type=HandshakeMessageType.ServerHelloDone,
                        message_sequence=5,
                        fragment_offset=0,
                    ),
                    ServerHelloDone(bytes()),
                ),
            ),
        ]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        while True:
            print("Flight 4 wait")
            message = await handshake_message_ch.get()
            print("Flight 4 parse hello client hello", message)

            match message.message_type:
                case HandshakeMessageType.ClientKeyExchange:
                    if not isinstance(message, ClientKeyExchange):
                        raise ValueError("Flight 4 message must be a ClientKeyExchange")

                    verifying_key = VerifyingKey.from_der(message.pubkey)

                    state.pre_master_secret = (
                        Keypair.pre_master_secret_from_pub_and_priv_key(
                            verifying_key,
                            state.local_keypair.privateKey,
                        )
                    )
                    print("after pre master secret??")

                    if not state.remote_random:
                        raise ValueError("Flight 4 not found remote random")

                    state.master_secret = prf_master_secret(
                        state.pre_master_secret,
                        state.local_random.marshal_fixed(),
                        state.remote_random,
                        hashlib.sha256,
                    )

                    if not state.pending_cipher_suite:
                        raise ValueError("Flight 4 require a pending cipher suite")

                    state.pending_cipher_suite.start(
                        state.master_secret,
                        state.local_random.marshal_fixed(),
                        state.remote_random,
                        False,
                    )

                    print("Success cipher suite")

                case HandshakeMessageType.CertificateVerify:
                    return Flight.FLIGHT6
                case _:
                    pass


class Flight6:
    def generate(self, state: State) -> list[RecordLayer] | None: ...

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight: ...


def client_hello_factory(state: State) -> RecordLayer:
    client_hello = ClientHello(bytes())
    client_hello.version = DTLSVersion.V1_0
    client_hello.random = state.local_random.marshal_fixed()
    client_hello.cipher_suites = [CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
    if state.cookie:
        client_hello.cookie = state.cookie

    client_hello.compression_methods = [CompressionMethod.Null]

    supported_groups = SupportedGroups(bytes())
    supported_groups.supported_groups = [
        # EllipticCurveGroup.X25519,
        EllipticCurveGroup.SECP256R1,
    ]

    extended_master_secret = ExtendedMasterSecret(bytes())

    signature_hash_algorithm = SignatureAlgorithms(bytes())
    signature_hash_algorithm.signature_hash_algorithms = [
        SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256,
    ]

    use_srtp = UseSRTP(bytes())
    use_srtp.srtp_protection_profiles = [
        SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        SRTPProtectionProfile.SRTP_AEAD_AES_256_GCM,
        SRTPProtectionProfile.SRTP_AEAD_AES_128_GCM,
    ]

    ec_point_formats = EcPointFormats(bytes())
    ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]

    regonitiation_info = RegonitiationInfo(bytes())

    client_hello.extensions = [
        supported_groups,
        extended_master_secret,
        signature_hash_algorithm,
        use_srtp,
        ec_point_formats,
        regonitiation_info,
    ]

    return RecordLayer(
        RecordHeader(
            ContentType.HANDSHAKE,
            DTLSVersion.V1_0,
            0,
            0,
        ),
        Handshake(
            HandshakeHeader(
                handshake_type=HandshakeMessageType.ClientHello,
                message_sequence=1,
                fragment_offset=0,
            ),
            client_hello,
        ),
    )


class Flight1:
    def generate(self, state: State) -> list[RecordLayer] | None:
        state.elliptic_curve = state.DEFAULT_CURVE

        state.local_epoch = 0
        state.remote_epoch = 0
        state.local_random.populate()
        state.remote_random = None
        state.pending_cipher_suite = None

        state.local_keypair = Keypair.generate_P256()

        return [
            client_hello_factory(state),
        ]

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        handshake_messages = list[Message]()
        while True:
            # TODO: timeout and make a fallback to flight 1
            message = await handshake_message_ch.get()
            handshake_messages.append(message)

            match message.message_type:
                case HandshakeMessageType.HelloVerifyRequest:
                    if not message.cookie:
                        print("Flight 1 Server must return a cookie")
                        return Flight.FLIGHT1

                    state.cookie = message.cookie
                    return Flight.FLIGHT3
                case HandshakeMessageType.ServerHelloDone:
                    if not message.cookie:
                        print("Flight 1 Server must return a cookie")
                        return Flight.FLIGHT1

                    state.cookie = message.cookie
                    state.pending_remote_handshake_messages = handshake_messages
                    return Flight.FLIGHT5
                case _:
                    pass


class Flight3:
    def generate(self, state: State) -> list[RecordLayer] | None:
        return [client_hello_factory(state)]

    def __handle_server_key_exchange(self, state: State, message: KeyServerExchange):
        # match message.named_curve:
        # case EllipticCurveGroup.SECP256R1:
        # state.local_keypair = Keypair.generate_P256()

        # NOTE: This library not support generate a pre shared key with ECDH for X25519 curve
        # case EllipticCurveGroup.X25519:
        #     state.local_keypair = Keypair.generate_X25519()
        # case _:
        #     raise ValueError(
        #         f"Unsupported {message.named_curve} curve unable create pre master secret"
        #     )

        # TODO: Is it must use a pub key instead of ?
        state.pre_master_secret = state.local_keypair.generate_shared_key()
        print(
            "Shared pre master secret",
            state.pre_master_secret,
            len(state.pre_master_secret),
        )

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        handshake_messages = list[Message]()
        while True:
            # TODO: timeout and make a fallback to flight 1
            print("Flight 3 wait")
            message = await handshake_message_ch.get()
            handshake_messages.append(message)

            match message.message_type:
                case HandshakeMessageType.KeyServerExchange:
                    if not isinstance(message, KeyServerExchange):
                        raise ValueError(
                            "Flight 3 message must be a instance of KeyServerExchange"
                        )
                    if (
                        not message.named_curve
                        and state.local_keypair.curve != message.named_curve
                    ):
                        raise ValueError("Flight 3 message key server must be defined")

                    try:
                        self.__handle_server_key_exchange(state, message)
                    except Exception as e:
                        print("Unable generate pre shared master key", e)

                case HandshakeMessageType.Certificate:
                    if not isinstance(message, Certificate):
                        raise ValueError(
                            "Flight 3 message must be a instance of Certificate"
                        )
                    if not message.certificates:
                        raise ValueError(
                            "Flight3 not found required remote certificates"
                        )

                    state.remote_peer_certificates = message.certificates

                case HandshakeMessageType.ServerHello:
                    if not isinstance(message, ServerHello):
                        raise ValueError(
                            "Flight 3 message must be a instance of ServerHello"
                        )

                    if not message.cipher_suite:
                        raise ValueError("Flight 3 message must contain cipher suite")

                    cipher_suite_cls = CIPHER_SUITES_CLASSES.get(message.cipher_suite)
                    if not cipher_suite_cls:
                        raise ValueError(
                            f"Flight 3 not found cipher suite {message.cipher_suite}"
                        )

                    state.remote_random = message.random
                    state.pending_cipher_suite = cipher_suite_cls()

                case HandshakeMessageType.ServerHelloDone:
                    state.pending_remote_handshake_messages = handshake_messages
                    print("Flight 3 done")
                    return Flight.FLIGHT5
                case _:
                    pass


# Client and Server use mutual authentication by default

# The Finished message is the first encrypted message sent by the client. The process involves:
#
# Generating the message hash (MAC) of all previous handshake messages.
# Encrypting the hash with the session key derived from the shared secret (ServerKeyExchange - pubkey).
# Sending the encrypted Finished message to the server.

MASTER_SECRET_LABEL = b"master secret"


def prf_master_secret(
    pre_master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    hash_func: Callable,
) -> bytes:
    seed = MASTER_SECRET_LABEL + client_random + server_random
    return p_hash(pre_master_secret, seed, 48, hash_func)


class Flight5:
    def __initialize_cipher_suite(
        self,
        state: State,
        key_server_exchange: KeyServerExchange,
        handshake_messages_merged: bytes,
    ):
        if not state.pending_cipher_suite:
            raise ValueError("Flight5 cipher suite must be defined")

        if not state.pre_master_secret:
            raise ValueError("Flight5 pre master secret must be initialized")
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

        state.master_secret = prf_master_secret(
            state.pre_master_secret,
            state.local_random.marshal_fixed(),
            state.remote_random,
            hash_func,
        )

        # TODO: By default it expect a certificate auth type, ref it
        if not state.remote_peer_certificates:
            raise ValueError("Fligh5 not found remote peer certificates")

        expected_ecdh_secret_message = ecdh_value_key_message(
            state.local_random.marshal_fixed(),
            state.remote_random,
            key_server_exchange.pubkey,
            key_server_exchange.named_curve,
        )
        print(
            "Expected client expected_ecdh_secret_message",
            binascii.hexlify(expected_ecdh_secret_message),
        )

        verified = verify_certificate_signature(
            expected_ecdh_secret_message,
            key_server_exchange.signature,
            hash_func,
            state.remote_peer_certificates,
        )
        if not verified:
            raise ValueError("Invalid certificate signature")

        print("Certificate verified success ???", verified)

        # TODO: verify remote_peer_certificates from CAs/PKI or on server itself by RPC
        # TODO: verify connection. What should I do ? def verify_connection(state: State ): ...
        state.pending_cipher_suite.start(
            state.master_secret,
            state.local_random.marshal_fixed(),
            state.remote_random,
            True,
        )

    def generate(self, state: State) -> list[RecordLayer] | None:
        if not state.pending_remote_handshake_messages:
            raise ValueError("Flight5 not found pending messages")

        if not state.remote_random:
            raise ValueError("Flight5 not found remote random")

        print("flight 5 messages", state.pending_remote_handshake_messages)

        merged = bytes()
        seq_pred = state.handshake_sequence_number

        print("pending messages", state.pending_remote_handshake_messages)

        key_server_exchange: KeyServerExchange | None = None
        result = list[RecordLayer]()
        for message in state.pending_remote_handshake_messages:
            match message.message_type:
                case HandshakeMessageType.KeyServerExchange:
                    if not isinstance(message, KeyServerExchange):
                        raise ValueError("Require KeyServerExchange to be present")
                    key_server_exchange = message
                case _:
                    pass

            try:
                reconstructed = Handshake(
                    header=HandshakeHeader(
                        message_sequence=seq_pred,
                        handshake_type=message.message_type,
                        fragment_offset=0,
                    ),
                    message=message,
                )

                seq_pred += 1
                merged += reconstructed.marshal()
            except Exception as e:
                print("Flight 5 error", e)

        if not key_server_exchange:
            raise ValueError(
                "Require KeyServerExchange to be present for cipher suite init"
            )

        try:
            self.__initialize_cipher_suite(state, key_server_exchange, merged)
        except Exception as e:
            print("Flight5 Unable init cipher suite", e)
            raise e

        certificate = Certificate(bytes())
        state.local_certificate = create_self_signed_cert_with_ecdsa(
            state.local_keypair
        )
        certificate.certificates = [state.local_certificate]
        layer_certificate = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.HANDSHAKE,
                version=DTLSVersion.V1_2,
                epoch=state.local_epoch,
                sequence_number=state.local_sequence_number,
            ),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.Certificate,
                    message_sequence=seq_pred,
                    fragment_offset=0,
                ),
                message=certificate,
            ),
        )
        result.append(layer_certificate)
        seq_pred += 1
        merged += layer_certificate.content.marshal()

        # print("merged data", merged)
        # print("remote state", binascii.hexlify(state.remote_random))

        client_key_exchange = ClientKeyExchange(bytes())
        client_key_exchange.pubkey = state.local_keypair.publicKey.to_der()
        layer_client_key_exchange = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.HANDSHAKE,
                version=DTLSVersion.V1_2,
                epoch=state.local_epoch,
                sequence_number=seq_pred,
            ),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.ClientKeyExchange,
                    message_sequence=seq_pred,
                    fragment_offset=0,
                ),
                message=client_key_exchange,
            ),
        )
        result.append(layer_client_key_exchange)
        seq_pred += 1
        merged += layer_client_key_exchange.content.marshal()

        # TODO: Why client side separate a pubkey and signature of the cert ?
        # KeyServerExchange sends pubkey and signature in one layer
        certificate_verify = CertificateVerify(bytes())

        # TODO: Don't hard code, get from the key_server_exchange message
        # TODO: get values from local key pair
        certificate_verify.signature_hash_algorithm = (
            SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
        )

        # TODO: Check cache if this types of handshake message already sent merge before into merged and sign it with predicted merged data
        # ClientHello
        # ServerHello
        # Certificate
        # ServerKeyExchange
        # CertificateRequest
        # ServerHelloDone
        # Certificate
        # ClientKeyExchange

        certificate_verify.signature = state.local_keypair.sign(merged)
        layer_certificate_verify_signature = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.HANDSHAKE,
                version=DTLSVersion.V1_2,
                epoch=state.local_epoch,
                sequence_number=state.local_sequence_number,
            ),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.CertificateVerify,
                    message_sequence=seq_pred,
                    fragment_offset=0,
                ),
                message=certificate_verify,
            ),
        )
        result.append(layer_certificate_verify_signature)
        seq_pred += 1
        merged += layer_certificate_verify_signature.content.marshal()

        # TODO: This not a handshake
        layer_change_cipher_spec = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.CHANGE_CIPHER_SPEC,
                version=DTLSVersion.V1_2,
                epoch=state.local_epoch,
                sequence_number=state.local_sequence_number,
            ),
            content=ChangeCipherSpec(),
        )
        result.append(layer_change_cipher_spec)
        # seq_pred += 1
        # merged += layer_change_cipher_spec.content.marshal()

        if not state.master_secret:
            raise ValueError("Flight 5 master_secret must be defined by cuite")

        if not state.local_verify:
            state.local_verify = verify_data_client(state.master_secret, merged)

        print(state.local_verify, len(state.local_verify))

        layer_finished = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.HANDSHAKE,
                version=DTLSVersion.V1_2,
                epoch=1,
                sequence_number=state.local_sequence_number,
            ),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.Finished,
                    message_sequence=seq_pred,
                    fragment_offset=0,
                ),
                message=Finished(bytes()),
            ),
        )
        layer_finished.encrypt = True
        result.append(layer_finished)

        return result

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        #                 [ChangeCipherSpec] \ Flight 6
        # <--------             Finished     /
        ...


# --- Client side flights

FLIGHT_TRANSITIONS: dict[Flight, FlightTransition] = {
    Flight.FLIGHT0: Flight0(),
    Flight.FLIGHT2: Flight2(),
    Flight.FLIGHT4: Flight4(),
    Flight.FLIGHT6: Flight6(),
    # # Client side
    Flight.FLIGHT1: Flight1(),
    Flight.FLIGHT3: Flight3(),
    Flight.FLIGHT5: Flight5(),
}


class DTLSRemote(Protocol):
    async def sendto(self, data: bytes): ...


MAX_MTU = 1280


class FSM:
    def __init__(
        self,
        remote: DTLSRemote,
        handshake_messages_chan: asyncio.Queue[Message],
        flight: Flight = Flight.FLIGHT0,
    ) -> None:
        self.remote = remote
        self.handshake_message_chan = handshake_messages_chan

        self.state = State()

        self.handshake_state_transition = asyncio.Queue[HandshakeState]()
        self.handshake_state_transition_lock = asyncio.Lock()

        self.handshake_state: HandshakeState = HandshakeState.Preparing
        self.flight: Flight = flight

        self.pending_record_layers: list[RecordLayer] | None = None

    async def dispatch(self):
        async with self.handshake_state_transition_lock:
            await self.handshake_state_transition.put(self.handshake_state)

    async def run(self):
        while True:
            next_state = await self.handshake_state_transition.get()

            async with self.handshake_state_transition_lock:
                while True:
                    if self.handshake_state_transition.empty() and not next_state:
                        print("Handshake state transition done")
                        break

                    handshake_state = (
                        next_state or await self.handshake_state_transition.get()
                    )
                    # print("after next_state lock", next_state)
                    if next_state:
                        next_state = None

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
                            break

    async def prepare(self) -> HandshakeState:
        print("Prepare state", self.flight)
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            # TODO: DTLS alerting
            return HandshakeState.Errored

        try:
            self.pending_record_layers = flight.generate(self.state)
        except Exception as e:
            print("FSM catch:", e)
            raise e

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
        # print("Send state", self.flight, "pending", self.pending_record_layers)
        print("Send state", self.flight)
        if not self.pending_record_layers:
            return HandshakeState.Waiting

        # TODO: message batch
        for layer in self.pending_record_layers:
            try:
                data = layer.marshal()

                if layer.encrypt:
                    if not self.state.pending_cipher_suite:
                        raise ValueError(
                            "layer data must be encrypted but cipher suite undefined"
                        )

                    data = self.state.pending_cipher_suite.encrypt(layer, data)
                    if not data:
                        raise ValueError("None data after encrypt,")

                if len(data) > MAX_MTU:
                    raise ValueError(
                        "layer data has too much bytes. Message must be fragmented"
                    )

                await self.remote.sendto(data)
            except Exception as e:
                # TODO: backoff
                print("Unable send inconsistent packet. Err:", e, "layer", layer)
                await asyncio.sleep(10)
                return HandshakeState.Sending

        return HandshakeState.Waiting

    async def wait(self) -> HandshakeState:
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            return HandshakeState.Errored
        print("wait transition", flight)

        # TODO: On client side I must wait and buffer from ServerHello until ServerHelloDone
        # TODO: This waiting must support also a batch send
        # TODO: When wait a messages make a timeout and fallback to the flight of DTLS role
        try:
            self.flight = await flight.parse(self.state, self.handshake_message_chan)
        except Exception as e:
            print(f"transition Flight{flight} error", e)

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
        flight: Flight = Flight.FLIGHT0,
    ) -> None:
        self.record_layer_chan = layer_chan

        self.handshake_message_chan = asyncio.Queue[Message]()
        self.fsm = FSM(remote, self.handshake_message_chan, flight)
        self.recv_lock = asyncio.Lock()

    def __handle_encrypted_message(
        self, layer: RecordLayer, message: EncryptedHandshakeMessage
    ):
        if not self.fsm.state.cipher_suite:
            return

        cipher_suite = self.fsm.state.cipher_suite

        if result := cipher_suite.decrypt(layer.header, message.encrypted_payload):
            print("Got decrypted message result", result)
            record = RecordLayer.unmarshal(result)
            print("Recv record", record)
            return

        print("Unable decrypt message", layer, message)

    async def handle_inbound_record_layers(self):
        fsm_runnable = asyncio.create_task(self.fsm.run())

        try:
            while True:
                record_layer = await self.record_layer_chan.get()
                print("recv record", record_layer)

                match record_layer.header.content_type:
                    case ContentType.CHANGE_CIPHER_SPEC:
                        self.fsm.state.cipher_suite = (
                            self.fsm.state.pending_cipher_suite
                        )

                    case ContentType.HANDSHAKE:
                        # if isinstance(record_layer.content, EncryptedHandshakeMessage):
                        #     await self.__handle_encrypted_message(
                        #         record_layer, record_layer.content
                        #     )
                        #     continue

                        if record_layer.header.epoch > 0:
                            if isinstance(
                                record_layer.content, EncryptedHandshakeMessage
                            ):
                                self.__handle_encrypted_message(
                                    record_layer, record_layer.content
                                )
                                continue

                        if isinstance(record_layer.content, Handshake):
                            await self.handshake_message_chan.put(
                                record_layer.content.message,
                            )

                        # elif isinstance(
                        #     record_layer.content, EncryptedHandshakeMessage
                        # ):
                        #     await self.__handle_encrypted_message(
                        #         record_layer, record_layer.content
                        #     )

                        # await self.fsm.dispatch()
                    case _:
                        print(
                            "Unhandled record type of",
                            record_layer.header.content_type,
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
