import abc

from asn1crypto import x509

from webrtc.dtls.dtls_record import (
    Certificate,
    CertificateRequest,
    CertificateType,
    CertificateVerify,
    ChangeCipherSpec,
    ClientHello,
    ClientKeyExchange,
    CompressionMethod,
    ContentType,
    DTLSVersion,
    EcPointFormats,
    EllipticCurvePointFormat,
    ExtendedMasterSecret,
    Finished,
    HelloVerifyRequest,
    KeyServerExchange,
    RecordHeader,
    RecordLayer,
    Handshake,
    HandshakeHeader,
    HandshakeMessageType,
    RegonitiationInfo,
    SRTPProtectionProfile,
    ServerHello,
    ServerHelloDone,
    SignatureAlgorithms,
    SignatureHashAlgorithm,
    SupportedGroups,
    UseSRTP,
)
from webrtc.dtls.dtls_cipher_suite import CipherSuite
from webrtc.dtls.certificate import Certificate as CertificateDTLS
from webrtc.dtls.dtls_typing import CipherSuiteID, EllipticCurveGroup


class RecordFactory(abc.ABC):
    # --- Server side DTLS Records ---
    @abc.abstractmethod
    def hello_verify_request(self, cookie: bytes) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def server_hello(self, random: bytes, cipher_suite: CipherSuite) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def certificate(self, certificates: list[CertificateDTLS]) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def key_server_exchange(
        self,
        signature: bytes,
        signature_named_curve: EllipticCurveGroup,
        signature_hash_algorithm: SignatureHashAlgorithm,
        pubkey: bytes,
    ) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def certificate_request(
        self,
        certificate_types: list[CertificateType],
        signature_hash_algorithms: list[SignatureHashAlgorithm],
    ) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def server_hello_done(self) -> RecordLayer:
        raise NotImplementedError()

    # --- Server side DTLS Records End ---

    # --- Client side DTLS Records ---

    @abc.abstractmethod
    def client_hello(
        self,
        random: bytes,
        cookie: bytes | None,
        cipher_suites: list[CipherSuiteID],
        elliptic_curves: list[EllipticCurveGroup],
        signature_hash_algorithms: list[SignatureHashAlgorithm],
    ) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def client_key_exchange(
        self,
        pubkey: bytes,
    ) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def certificate_verify(
        self, signature: bytes, signature_hash_algorithm: SignatureHashAlgorithm
    ) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def change_cipher_spec(self) -> RecordLayer:
        raise NotImplementedError()

    @abc.abstractmethod
    def finished(self, verifying_data: bytes) -> RecordLayer:
        raise NotImplementedError()

    # --- Client side DTLS Records End ---


class FlightRecordFactory(RecordFactory):
    def hello_verify_request(self, cookie: bytes) -> RecordLayer:
        hello_verify_request = HelloVerifyRequest(bytes())
        hello_verify_request.version = DTLSVersion.V1_2
        hello_verify_request.cookie = cookie
        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_0, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.HelloVerifyRequest,
                    message_sequence=0,
                    fragment_offset=0,
                ),
                hello_verify_request,
            ),
        )

    def server_hello(
        self,
        random: bytes,
        cipher_suite: CipherSuite,
    ) -> RecordLayer:
        server_hello = ServerHello(bytes())
        server_hello.version = DTLSVersion.V1_2
        server_hello.compression_method = CompressionMethod.Null

        server_hello.random = random
        server_hello.cipher_suite = cipher_suite.cipher_suite_id()

        use_srtp = UseSRTP(bytes())
        use_srtp.srtp_protection_profiles = [
            SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
            # SRTPProtectionProfile.SRTP_AEAD_AES_256_GCM,
            # SRTPProtectionProfile.SRTP_AEAD_AES_128_GCM,
        ]

        ec_point_formats = EcPointFormats(bytes())
        ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]

        server_hello.extensions = [
            # RegonitiationInfo(bytes()),
            # ExtendedMasterSecret(bytes()),
            # use_srtp,
            ec_point_formats,
        ]

        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.ServerHello,
                    message_sequence=0,
                    fragment_offset=0,
                ),
                server_hello,
            ),
        )

    def certificate(self, certificates: list[CertificateDTLS]) -> RecordLayer:
        certificate = Certificate(bytes())
        certificate.certificates = certificates
        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_0, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.Certificate,
                    message_sequence=0,
                    fragment_offset=0,
                ),
                certificate,
            ),
        )

    def key_server_exchange(
        self,
        signature: bytes,
        signature_named_curve: EllipticCurveGroup,
        signature_hash_algorithm: SignatureHashAlgorithm,
        pubkey: bytes,
    ) -> RecordLayer:
        key_server_exchange = KeyServerExchange(bytes())
        key_server_exchange.signature = signature
        key_server_exchange.named_curve = signature_named_curve
        key_server_exchange.signature_hash_algorithm = signature_hash_algorithm
        key_server_exchange.pubkey = pubkey
        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.KeyServerExchange,
                    message_sequence=3,
                    fragment_offset=0,
                ),
                key_server_exchange,
            ),
        )

    def certificate_request(
        self,
        certificate_types: list[CertificateType] = [],
        signature_hash_algorithms: list[SignatureHashAlgorithm] = [],
    ) -> RecordLayer:
        certificate_request = CertificateRequest(bytes())
        certificate_request.certificate_types = certificate_types
        certificate_request.signature_hash_algorithms = signature_hash_algorithms
        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.CertificateRequest,
                    message_sequence=4,
                    fragment_offset=0,
                ),
                certificate_request,
            ),
        )

    def server_hello_done(self) -> RecordLayer:
        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.ServerHelloDone,
                    message_sequence=5,
                    fragment_offset=0,
                ),
                ServerHelloDone(bytes()),
            ),
        )

    def client_hello(
        self,
        random: bytes,
        cookie: bytes | None,
        cipher_suites: list[CipherSuiteID],
        elliptic_curves: list[EllipticCurveGroup],
        signature_hash_algorithms: list[SignatureHashAlgorithm],
    ) -> RecordLayer:
        client_hello = ClientHello(bytes())
        client_hello.version = DTLSVersion.V1_0
        client_hello.compression_methods = [CompressionMethod.Null]

        client_hello.random = random
        client_hello.cipher_suites = cipher_suites

        if cookie:
            client_hello.cookie = cookie

        supported_groups = SupportedGroups(bytes())
        supported_groups.supported_groups = elliptic_curves

        _signature_hash_algorithms = SignatureAlgorithms(bytes())
        _signature_hash_algorithms.signature_hash_algorithms = signature_hash_algorithms

        use_srtp = UseSRTP(bytes())
        use_srtp.srtp_protection_profiles = [
            SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80,
            SRTPProtectionProfile.SRTP_AEAD_AES_256_GCM,
            SRTPProtectionProfile.SRTP_AEAD_AES_128_GCM,
        ]

        ec_point_formats = EcPointFormats(bytes())
        ec_point_formats.ec_point_formats = [EllipticCurvePointFormat.UNCOMPRESSED]

        client_hello.extensions = [
            supported_groups,
            ExtendedMasterSecret(bytes()),
            _signature_hash_algorithms,
            use_srtp,
            ec_point_formats,
            RegonitiationInfo(bytes()),
        ]

        return RecordLayer(
            RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_0, 0, 0),
            Handshake(
                HandshakeHeader(
                    handshake_type=HandshakeMessageType.ClientHello,
                    message_sequence=1,
                    fragment_offset=0,
                ),
                client_hello,
            ),
        )

    def client_key_exchange(self, pubkey: bytes) -> RecordLayer:
        client_key_exchange = ClientKeyExchange(bytes())
        client_key_exchange.pubkey = pubkey
        return RecordLayer(
            header=RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.ClientKeyExchange,
                    message_sequence=0,
                    fragment_offset=0,
                ),
                message=client_key_exchange,
            ),
        )

    def certificate_verify(
        self, signature: bytes, signature_hash_algorithm: SignatureHashAlgorithm
    ) -> RecordLayer:
        certificate_verify = CertificateVerify(bytes())
        certificate_verify.signature_hash_algorithm = signature_hash_algorithm
        certificate_verify.signature = signature
        return RecordLayer(
            header=RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 0, 0),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.CertificateVerify,
                    message_sequence=0,
                    fragment_offset=0,
                ),
                message=certificate_verify,
            ),
        )

    def change_cipher_spec(self) -> RecordLayer:
        return RecordLayer(
            header=RecordHeader(ContentType.CHANGE_CIPHER_SPEC, DTLSVersion.V1_2, 0, 0),
            content=ChangeCipherSpec(),
        )

    def finished(self, verifying_data: bytes) -> RecordLayer:
        layer = RecordLayer(
            header=RecordHeader(ContentType.HANDSHAKE, DTLSVersion.V1_2, 1, 0),
            content=Handshake(
                header=HandshakeHeader(HandshakeMessageType.Finished, 0, 0),
                message=Finished(verifying_data),
            ),
        )
        layer.encrypt = True
        return layer


DEFAULT_FACTORY: RecordFactory = FlightRecordFactory()
