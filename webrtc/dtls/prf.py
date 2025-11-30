"""
TLS 1.2 PRF (Pseudo-Random Function) Implementation

Implements the PRF using HMAC-SHA256 as specified in RFC 5246.
This is used for key derivation in DTLS 1.2 handshakes.

References:
- RFC 5246 Section 5 (TLS 1.2 PRF)
- RFC 6347 Section 4.1 (DTLS extensions)
"""

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Callable


# PRF Labels as specified in RFCs
LABEL_MASTER_SECRET = b"master secret"
LABEL_EXTENDED_MASTER_SECRET = b"extended master secret"
LABEL_KEY_EXPANSION = b"key expansion"
LABEL_CLIENT_FINISHED = b"client finished"
LABEL_SERVER_FINISHED = b"server finished"
LABEL_DTLS_SRTP = b"EXTRACTOR-dtls_srtp"

# Constants
MASTER_SECRET_LENGTH = 48
VERIFY_DATA_LENGTH = 12
SRTP_KEY_LENGTH = 16
SRTP_SALT_LENGTH = 14


def p_hash(
    secret: bytes,
    seed: bytes,
    requested_length: int,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    P_hash as defined in RFC 5246 Section 5.

    PRF(secret, label, seed) = P_<hash>(secret, label + seed)

    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                           HMAC_hash(secret, A(2) + seed) +
                           HMAC_hash(secret, A(3) + seed) + ...

    Where A() is defined as:
        A(0) = seed
        A(i) = HMAC_hash(secret, A(i-1))

    Args:
        secret: The secret value (pre-master or master secret)
        seed: Seed data (typically label + random values)
        requested_length: Desired output length in bytes
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: PRF output of specified length
    """
    def hmac_hash(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hash_func).digest()

    a = seed  # A(0) = seed
    result = bytearray()

    digest_size = hash_func().digest_size
    iterations = math.ceil(requested_length / digest_size)

    for _ in range(iterations):
        a = hmac_hash(secret, a)  # A(i) = HMAC_hash(secret, A(i-1))
        result.extend(hmac_hash(secret, a + seed))

    return bytes(result[:requested_length])


def prf(
    secret: bytes,
    label: bytes,
    seed: bytes,
    length: int,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    TLS 1.2 PRF function.

    PRF(secret, label, seed) = P_SHA256(secret, label + seed)

    Args:
        secret: The secret value
        label: ASCII label (e.g., b"master secret")
        seed: Seed data (typically random values)
        length: Desired output length in bytes
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: PRF output of specified length
    """
    return p_hash(secret, label + seed, length, hash_func)


def prf_master_secret(
    pre_master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    Derive 48-byte master secret from pre-master secret.

    master_secret = PRF(pre_master_secret, "master secret",
                       ClientHello.random + ServerHello.random)[0..47]

    Args:
        pre_master_secret: Shared secret from ECDH (32 bytes for P-256/X25519)
        client_random: ClientHello.random (32 bytes)
        server_random: ServerHello.random (32 bytes)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: 48-byte master secret
    """
    seed = client_random + server_random
    return p_hash(pre_master_secret, LABEL_MASTER_SECRET + seed, MASTER_SECRET_LENGTH, hash_func)


def prf_extended_master_secret(
    pre_master_secret: bytes,
    session_hash: bytes,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    Derive 48-byte extended master secret (RFC 7627).

    extended_master_secret = PRF(pre_master_secret, "extended master secret",
                                 session_hash)[0..47]

    Args:
        pre_master_secret: Shared secret from ECDH (32 bytes)
        session_hash: SHA-256 of handshake messages up to and including ClientKeyExchange
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: 48-byte extended master secret
    """
    return p_hash(pre_master_secret, LABEL_EXTENDED_MASTER_SECRET + session_hash, MASTER_SECRET_LENGTH, hash_func)


@dataclass
class EncryptionKeys:
    """Container for derived encryption keys."""
    master_secret: bytes        # 48 bytes
    client_mac_key: bytes       # 0 bytes for AEAD
    server_mac_key: bytes       # 0 bytes for AEAD
    client_write_key: bytes     # 16 bytes for AES-128
    server_write_key: bytes     # 16 bytes for AES-128
    client_write_iv: bytes      # 4 bytes for GCM implicit IV
    server_write_iv: bytes      # 4 bytes for GCM implicit IV


def prf_key_expansion(
    master_secret: bytes,
    server_random: bytes,
    client_random: bytes,
    mac_key_length: int = 0,
    key_length: int = 16,
    iv_length: int = 4,
    hash_func: Callable = hashlib.sha256,
) -> EncryptionKeys:
    """
    Derive encryption keys from master secret using TLS 1.2 PRF.

    key_block = PRF(master_secret, "key expansion",
                   server_random + client_random)

    The key_block is partitioned as:
        client_write_MAC_key[mac_key_length]
        server_write_MAC_key[mac_key_length]
        client_write_key[key_length]
        server_write_key[key_length]
        client_write_IV[iv_length]
        server_write_IV[iv_length]

    Note: For AEAD ciphers like AES-GCM, mac_key_length is 0.

    Args:
        master_secret: 48-byte master secret
        server_random: ServerHello.random (32 bytes)
        client_random: ClientHello.random (32 bytes)
        mac_key_length: MAC key length (0 for AEAD ciphers)
        key_length: Encryption key length (16 for AES-128)
        iv_length: Implicit IV length (4 for GCM)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        EncryptionKeys: Derived key material
    """
    # Note: key expansion uses server_random + client_random (opposite order from master_secret)
    seed = server_random + client_random
    total_length = (2 * mac_key_length) + (2 * key_length) + (2 * iv_length)

    key_block = p_hash(master_secret, LABEL_KEY_EXPANSION + seed, total_length, hash_func)

    offset = 0

    client_mac_key = key_block[offset:offset + mac_key_length]
    offset += mac_key_length

    server_mac_key = key_block[offset:offset + mac_key_length]
    offset += mac_key_length

    client_write_key = key_block[offset:offset + key_length]
    offset += key_length

    server_write_key = key_block[offset:offset + key_length]
    offset += key_length

    client_write_iv = key_block[offset:offset + iv_length]
    offset += iv_length

    server_write_iv = key_block[offset:offset + iv_length]

    return EncryptionKeys(
        master_secret=master_secret,
        client_mac_key=client_mac_key,
        server_mac_key=server_mac_key,
        client_write_key=client_write_key,
        server_write_key=server_write_key,
        client_write_iv=client_write_iv,
        server_write_iv=server_write_iv,
    )


def prf_verify_data_client(
    master_secret: bytes,
    handshake_messages: bytes,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    Compute client Finished verify_data.

    verify_data = PRF(master_secret, "client finished",
                     Hash(handshake_messages))[0..11]

    Args:
        master_secret: 48-byte master secret
        handshake_messages: Concatenated raw handshake message bytes
                           (from ClientHello up to and including
                            CertificateVerify, excluding ChangeCipherSpec)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: 12-byte verify_data
    """
    digest = hash_func(handshake_messages).digest()
    return p_hash(master_secret, LABEL_CLIENT_FINISHED + digest, VERIFY_DATA_LENGTH, hash_func)


def prf_verify_data_server(
    master_secret: bytes,
    handshake_messages: bytes,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    Compute server Finished verify_data.

    verify_data = PRF(master_secret, "server finished",
                     Hash(handshake_messages))[0..11]

    Args:
        master_secret: 48-byte master secret
        handshake_messages: Concatenated raw handshake message bytes
                           (from ClientHello up to and including client Finished)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: 12-byte verify_data
    """
    digest = hash_func(handshake_messages).digest()
    return p_hash(master_secret, LABEL_SERVER_FINISHED + digest, VERIFY_DATA_LENGTH, hash_func)


@dataclass
class SRTPKeyingMaterial:
    """Container for SRTP key derivation output."""
    client_write_key: bytes     # 16 bytes
    server_write_key: bytes     # 16 bytes
    client_write_salt: bytes    # 14 bytes
    server_write_salt: bytes    # 14 bytes

    @classmethod
    def from_exported_material(cls, material: bytes) -> "SRTPKeyingMaterial":
        """
        Parse SRTP keying material from exported bytes.

        Format: client_key (16) || server_key (16) || client_salt (14) || server_salt (14)
        Total: 60 bytes

        Args:
            material: 60-byte exported keying material

        Returns:
            SRTPKeyingMaterial: Parsed keys and salts
        """
        if len(material) != 60:
            raise ValueError(f"Expected 60 bytes, got {len(material)}")

        return cls(
            client_write_key=material[0:16],
            server_write_key=material[16:32],
            client_write_salt=material[32:46],
            server_write_salt=material[46:60],
        )


def prf_export_keying_material(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    label: bytes = LABEL_DTLS_SRTP,
    length: int = 60,
    hash_func: Callable = hashlib.sha256,
) -> bytes:
    """
    Export keying material for external use (e.g., SRTP).

    exported = PRF(master_secret, label, client_random + server_random, length)

    For SRTP (RFC 5764), the label is "EXTRACTOR-dtls_srtp" and length is 60 bytes:
    - client_write_SRTP_master_key (16)
    - server_write_SRTP_master_key (16)
    - client_write_SRTP_master_salt (14)
    - server_write_SRTP_master_salt (14)

    Args:
        master_secret: 48-byte master secret
        client_random: ClientHello.random (32 bytes)
        server_random: ServerHello.random (32 bytes)
        label: Application-specific label (default: DTLS-SRTP)
        length: Desired output length (default: 60 for SRTP)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        bytes: Exported keying material
    """
    seed = client_random + server_random
    return p_hash(master_secret, label + seed, length, hash_func)


def get_srtp_keying_material(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    hash_func: Callable = hashlib.sha256,
) -> SRTPKeyingMaterial:
    """
    Get SRTP keying material after DTLS handshake completion.

    Convenience function that exports and parses SRTP keys.

    Args:
        master_secret: 48-byte master secret
        client_random: ClientHello.random (32 bytes)
        server_random: ServerHello.random (32 bytes)
        hash_func: Hash function to use (default: SHA-256)

    Returns:
        SRTPKeyingMaterial: Parsed SRTP keys and salts
    """
    exported = prf_export_keying_material(
        master_secret, client_random, server_random,
        LABEL_DTLS_SRTP, 60, hash_func
    )
    return SRTPKeyingMaterial.from_exported_material(exported)
