"""
DTLS GCM utilities and key derivation.

AES-GCM encryption/decryption is handled by Rust native implementation (webrtc_rs.AesGcmCipher).
This module provides:
- AAD (Additional Authenticated Data) generation
- PRF-based key expansion
- Helper constants
"""

import hmac
import math
import hashlib

from dataclasses import dataclass
from typing import Callable

from webrtc.dtls.dtls_record import RecordHeader
from webrtc.ice.stun import utils as byteops


def generate_aead_additional_data(header: RecordHeader, payload_len: int) -> bytes:
    """
    Generate Additional Authenticated Data (AAD) for DTLS GCM.

    AAD format (13 bytes):
        epoch (2) || sequence_number (6) || content_type (1) || version (2) || length (2)

    This matches RFC 6347 and the Rust implementation in crypto/mod.rs.
    """
    data = bytearray(13)

    # Write 8-byte sequence_number first (positions 0-8)
    # We only want the lower 48 bits, but write as 64-bit and overwrite first 2 bytes
    sequence_number = header.sequence_number & 0xFFFFFFFFFFFF  # Mask to 48 bits
    data[0:8] = byteops.pack_unsigned_64(sequence_number)

    # Overwrite first 2 bytes with epoch (positions 0-2)
    # This gives us: epoch (2) || sequence_number[2:8] (6)
    data[0:2] = byteops.pack_unsigned_short(header.epoch)

    data[8] = header.content_type
    data[9:11] = byteops.pack_unsigned_short(header.version)
    data[11:13] = byteops.pack_unsigned_short(payload_len)

    return bytes(data)


@dataclass
class EncryptionKeys:
    master_secret: bytes
    client_mac_key: bytes
    server_mac_key: bytes
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes


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
) -> EncryptionKeys:
    """
    Derive encryption keys from master secret using TLS 1.2 PRF.

    Uses p_hash (HMAC-SHA256 based PRF) as per RFC 5246, NOT HKDF.

    key_block = PRF(master_secret, "key expansion", server_random + client_random)

    Note: Key expansion uses server_random + client_random (opposite order from master_secret).
    """
    key_expansion_label = b"key expansion"
    # Note: server_random comes FIRST in key expansion (opposite of master_secret derivation)
    seed = key_expansion_label + server_random + client_random

    total_key_material_len = (2 * mac_len) + (2 * key_len) + (2 * iv_len)

    # Use correct TLS 1.2 PRF (p_hash with HMAC-SHA256), NOT HKDF
    key_material = p_hash(
        master_secret,
        seed,
        total_key_material_len,
        hashlib.sha256,
    )

    offset = 0

    client_mac_key = key_material[offset:offset + mac_len]
    offset += mac_len

    server_mac_key = key_material[offset:offset + mac_len]
    offset += mac_len

    client_write_key = key_material[offset:offset + key_len]
    offset += key_len

    server_write_key = key_material[offset:offset + key_len]
    offset += key_len

    client_write_iv = key_material[offset:offset + iv_len]
    offset += iv_len

    server_write_iv = key_material[offset:offset + iv_len]

    return EncryptionKeys(
        master_secret=master_secret,
        client_mac_key=client_mac_key,
        server_mac_key=server_mac_key,
        client_write_key=client_write_key,
        server_write_key=server_write_key,
        client_write_iv=client_write_iv,
        server_write_iv=server_write_iv,
    )


# GCM constants
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16
