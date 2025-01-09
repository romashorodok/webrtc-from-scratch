import binascii
from dataclasses import dataclass
from enum import IntEnum

from typing import Self


from asn1crypto import x509

from webrtc.dtls.dtls_typing import (
    NAMED_CURVE_TYPE,
    CipherSuiteID,
    EllipticCurveGroup,
    Random,
)

from webrtc.ice.stun import utils as byteops
from webrtc.dtls.certificate import Certificate as CertificateDTLS


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


class SRTPProtectionProfile(IntEnum):
    SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
    SRTP_AEAD_AES_256_GCM = 0x0008
    SRTP_AEAD_AES_128_GCM = 0x0007


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


class EllipticCurvePointFormat(IntEnum):
    UNCOMPRESSED = 0x00


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


class CompressionMethod(IntEnum):
    Null = 0


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

    certificates: list[CertificateDTLS] | None = None

    def marshal_certificates(self) -> bytes:
        if not self.certificates:
            raise ValueError("Require certificate to be specified")

        result = bytes()
        for cert in self.certificates:
            cert_der = cert.der
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

        result = list[CertificateDTLS]()
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

            result.append(CertificateDTLS.from_bytes(certificate))

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
            byteops.pack_byte_int(self.header.content_type or self.content.content_type)
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
        # print("content type", header[0])
        content_type = ContentType(header[0])

        if content_type == ContentType.CONNECTION_ID:
            raise ValueError("Unsupported connection id")

        version = unpack_version(data[1:3])

        epoch = byteops.unpack_unsigned_short(header[3:5])

        sequence_number = byteops.unpack_unsigned_64(data[5:11])

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

    @classmethod
    def unmarshal_and_rest(cls, data: bytes) -> tuple[bytes, Self]:
        if len(data) < cls.FIXED_HEADER_SIZE:
            raise ValueError("DTLS record is too small")

        length = byteops.unpack_unsigned_short(data[11:13])

        layer = cls.unmarshal(data)

        rest = data[cls.FIXED_HEADER_SIZE + length :]

        return (rest, layer)


class RecordLayerBatch:
    def __init__(self, data: bytes) -> None:
        self.__data = data

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> RecordLayer:
        if not self.__data:
            raise StopIteration()

        data, layer = RecordLayer.unmarshal_and_rest(self.__data)
        self.__data = data
        return layer
