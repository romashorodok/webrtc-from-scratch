import binascii
import hashlib
import logging

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Self

# Structured logging for crypto operations
logger = logging.getLogger("webrtc.dtls.cipher_suite")

from webrtc.dtls.dtls_record import (
    EllipticCurvePointFormat,
    RecordHeader,
    RecordLayer,
    SignatureHashAlgorithm,
)
from webrtc.dtls.dtls_typing import NAMED_CURVE_TYPE, CipherSuiteID, EllipticCurveGroup
from webrtc.dtls.gcm import (
    generate_aead_additional_data,
    p_hash,
    prf_generate_encryption_keys,
)

from webrtc.ice.stun import utils as byteops
from webrtc_rs import AesGcmCipher, ECDHKeyPair


@dataclass
class Keypair:
    """
    ECDH Keypair using Rust ECDHKeyPair for cryptographic operations.
    """
    _rust_keypair: ECDHKeyPair = field(repr=False)
    curve: EllipticCurveGroup
    signature_hash_algorithm: SignatureHashAlgorithm = (
        SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
    )

    @property
    def publicKey(self) -> Any:
        """For compatibility - returns self to access public_key_bytes()"""
        return self

    def to_der(self) -> bytes:
        """Get public key in DER format (uncompressed point for P-256)"""
        return self._rust_keypair.public_key_bytes()

    def public_key_bytes(self) -> bytes:
        """Get public key bytes"""
        return self._rust_keypair.public_key_bytes()

    @classmethod
    def generate_X25519(cls) -> Self:
        rust_kp = ECDHKeyPair("X25519")
        return cls(
            _rust_keypair=rust_kp,
            curve=EllipticCurveGroup.X25519,
        )

    @classmethod
    def generate_P256(cls) -> Self:
        rust_kp = ECDHKeyPair("P-256")
        return cls(
            _rust_keypair=rust_kp,
            curve=EllipticCurveGroup.SECP256R1,
        )

    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """Compute ECDH shared secret (pre-master secret)"""
        return self._rust_keypair.compute_shared_secret(peer_public)

    def sign(self, data: bytes) -> bytes:
        """Sign data - currently a placeholder, signing handled by Rust Certificate"""
        # TODO: Implement signing via Rust if needed
        raise NotImplementedError("Signing should be done via Rust Certificate")


def __ecdh_params(curve: EllipticCurveGroup, pubkey: bytes) -> bytes:
    server_ecdh_params = byteops.pack_byte_int(NAMED_CURVE_TYPE)
    server_ecdh_params += byteops.pack_unsigned_short(curve)
    server_ecdh_params += byteops.pack_byte_int(len(pubkey))
    return server_ecdh_params


def generate_server_signature(
    client_random: bytes,
    server_random: bytes,
    public_key: bytes,
    named_curve: EllipticCurveGroup,
    # private_key: SigningKey,
) -> bytes:
    ecdh_params = __ecdh_params(named_curve, public_key)
    msg = bytes(client_random + server_random + ecdh_params + public_key)
    return msg
    # msg = hashlib.sha256(msg).digest()
    # return private_key.sign_digest(msg)
    # return private_key.sign(msg, hashfunc=hashlib.sha256)


def create_self_signed_cert_with_ecdsa(keypair: Keypair):
    """
    Create self-signed certificate.

    NOTE: Certificate generation is handled by Rust webrtc_rs.Certificate.
    This function is kept for API compatibility but should not be used.
    """
    raise NotImplementedError("Certificate generation should be done via Rust webrtc_rs.Certificate")


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
    certificates: list[Any],
) -> bool:
    """
    Verify certificate signature.

    NOTE: This is client-side functionality. Certificate verification
    should be handled by Rust when implemented.
    """
    # TODO: Implement via Rust certificate verification
    raise NotImplementedError("Certificate verification should be done via Rust")


class CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    """
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.

    Uses Rust AesGcmCipher for AES-128-GCM encryption/decryption.
    """
    __PRF_MAC_LEN = 0
    __PRF_KEY_LEN = 16
    __PRF_IV_LEN = 4

    def __init__(self) -> None:
        self.gcm: AesGcmCipher | None = None
        self._is_client: bool = False

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

        self._is_client = client

        # Use Rust AesGcmCipher - it handles local/remote key assignment internally
        self.gcm = AesGcmCipher(
            keys.client_write_key,
            keys.client_write_iv,
            keys.server_write_key,
            keys.server_write_iv,
            client,
        )

    def encrypt(self, pkt: RecordLayer) -> bytes:
        if not self.gcm:
            raise ValueError("Unable encrypt start gcm first")

        # Use Rust cipher to encrypt
        pkt_bytes = pkt.marshal()
        return self.gcm.encrypt(
            pkt.header.content_type,
            pkt.header.epoch,
            pkt.header.sequence_number,
            pkt_bytes[pkt.header_size():],  # payload only
        )

    def decrypt(self, pkt: RecordLayer, raw: bytes) -> bytes:
        if not self.gcm:
            raise ValueError("Unable decrypt start gcm first")

        # Use Rust cipher to decrypt - pass the full raw record
        return self.gcm.decrypt(raw)

    def cipher_suite_id(self) -> CipherSuiteID:
        return CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256


class CipherSuite_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
    """
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 cipher suite.

    Uses RSA for authentication (vs ECDSA) but same ECDHE key exchange
    and AES-128-GCM encryption.

    NOTE: This is a stub for browser compatibility. RSA certificate
    signing is not yet implemented in Rust bindings.
    """
    __PRF_MAC_LEN = 0
    __PRF_KEY_LEN = 16
    __PRF_IV_LEN = 4

    def __init__(self) -> None:
        self.gcm: AesGcmCipher | None = None
        self._is_client: bool = False

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

        self._is_client = client

        # Use Rust AesGcmCipher - same as ECDSA version
        self.gcm = AesGcmCipher(
            keys.client_write_key,
            keys.client_write_iv,
            keys.server_write_key,
            keys.server_write_iv,
            client,
        )

    def encrypt(self, pkt: RecordLayer) -> bytes:
        if not self.gcm:
            raise ValueError("Unable encrypt start gcm first")

        pkt_bytes = pkt.marshal()
        return self.gcm.encrypt(
            pkt.header.content_type,
            pkt.header.epoch,
            pkt.header.sequence_number,
            pkt_bytes[pkt.header_size():],
        )

    def decrypt(self, pkt: RecordLayer, raw: bytes) -> bytes:
        if not self.gcm:
            raise ValueError("Unable decrypt start gcm first")

        return self.gcm.decrypt(raw)

    def cipher_suite_id(self) -> CipherSuiteID:
        return CipherSuiteID.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256


class CipherSuite(Protocol):
    def start(
        self,
        master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        client: bool,
    ): ...

    def encrypt(self, pkt: RecordLayer) -> bytes: ...

    def decrypt(self, pkt: RecordLayer, raw: bytes) -> bytes: ...

    def cipher_suite_id(self) -> CipherSuiteID: ...


# Registry of supported cipher suites
CIPHER_SUITES_CLASSES: dict[CipherSuiteID, type[CipherSuite]] = {
    CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuiteID.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}


# Preferred cipher suite order for negotiation (server preference)
CIPHER_SUITE_PREFERENCE: list[CipherSuiteID] = [
    CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  # Prefer ECDSA
    CipherSuiteID.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    # Fallback to RSA
]


def select_cipher_suite(client_suites: list[CipherSuiteID]) -> CipherSuiteID | None:
    """
    Select the best cipher suite based on server preference and client support.

    Args:
        client_suites: List of cipher suites offered by the client

    Returns:
        The selected cipher suite ID, or None if no common suite found
    """
    for suite in CIPHER_SUITE_PREFERENCE:
        if suite in client_suites and suite in CIPHER_SUITES_CLASSES:
            return suite
    return None


VERIFY_DATA_CLIENT_LABEL = b"client finished"
VERIFY_DATA_SERVER_LABEL = b"server finished"


def prf_verify_data(master_secret: bytes, handshake_bodies: bytes, label: bytes):
    # TODO: dynamic hashfunc
    digest = hashlib.sha256(handshake_bodies).digest()
    seed = label + digest
    print(f"[prf_verify_data] label={label}, digest={digest.hex()}")
    print(f"[prf_verify_data] master_secret_len={len(master_secret)}, handshake_bodies_len={len(handshake_bodies)}")
    result = p_hash(master_secret, seed, 12, hashlib.sha256)
    print(f"[prf_verify_data] result={result.hex()}")
    return result


def verify_data_client(master_secret: bytes, handshake_bodies: bytes):
    return prf_verify_data(master_secret, handshake_bodies, VERIFY_DATA_CLIENT_LABEL)


def verify_data_server(master_secret: bytes, handshake_bodies: bytes):
    return prf_verify_data(master_secret, handshake_bodies, VERIFY_DATA_SERVER_LABEL)


# Client and Server use mutual authentication by default

# The Finished message is the first encrypted message sent by the client. The process involves:
#
# Generating the message hash (MAC) of all previous handshake messages.
# Encrypting the hash with the session key derived from the shared secret (ServerKeyExchange - pubkey).
# Sending the encrypted Finished message to the server.

MASTER_SECRET_LABEL = b"master secret"


def prf(key: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=48,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(key)


def prf_master_secret(
    pre_master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    hash_func: Callable,
) -> bytes:
    seed = MASTER_SECRET_LABEL + client_random + server_random
    return p_hash(pre_master_secret, seed, 48, hash_func)
    # return prf(pre_master_secret, seed)
