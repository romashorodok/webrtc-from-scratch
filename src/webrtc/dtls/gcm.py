import binascii
import os
import hmac
import math
import hashlib

from dataclasses import dataclass
from typing import Callable
from Crypto.Cipher import AES

from webrtc.dtls.dtls_record import Finished, RecordHeader, RecordLayer
from webrtc.ice.stun import utils as byteops

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


def generate_aead_additional_data(header: RecordHeader, payload_len: int) -> bytes:
    data = bytearray(13)

    sequence_number = header.sequence_number & 0xFFFFFFFFFFFF  # Mask to 48 bits
    data[0:8] = byteops.pack_unsigned_64(sequence_number)
    data[6:8] = byteops.pack_unsigned_short(header.epoch)
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
    key_expansion_label = b"key expansion"
    seed = key_expansion_label + server_random + client_random

    total_key_material_len = (2 * mac_len) + (2 * key_len) + (2 * iv_len)
    hkdf = HKDF(
        algorithm=SHA256(),
        length=total_key_material_len,
        salt=None,
        info=seed,
        backend=default_backend(),
    )
    key_material = hkdf.derive(master_secret)

    # key_material = p_hash(
    #     master_secret,
    #     seed,
    #     (2 * mac_len) + (2 * key_len) + (2 * iv_len),
    #     hashlib.sha256,
    # )
    # print("key meterial", binascii.hexlify(key_material))

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

    return EncryptionKeys(
        master_secret=master_secret,
        client_mac_key=client_mac_key,
        server_mac_key=server_mac_key,
        client_write_key=client_write_key,
        server_write_key=server_write_key,
        client_write_iv=client_write_iv,
        server_write_iv=server_write_iv,
    )


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
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, additional_data)
    return ciphertext

    # cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # # additional_data = bytes(0x01)
    # cipher.update(additional_data)
    # encrypted_payload, tag = cipher.encrypt_and_digest(payload)
    # # print("ecnrypt aead", binascii.hexlify(additional_data))
    # # print("encrypt tag", binascii.hexlify(tag))
    # # print("encrypt payload", binascii.hexlify(encrypted_payload))
    # return encrypted_payload + tag


def decrypt_with_aes_gcm(
    key: bytes, nonce: bytes, ciphertext: bytes, additional_data: bytes
) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, additional_data)
    # cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    # # additional_data = bytes(0x01)
    # cipher.update(additional_data)
    #
    # print("decrypted aead", binascii.hexlify(additional_data))
    # # print("decrypted tag", binascii.hexlify(tag))
    # print("decrypted payload", binascii.hexlify(ciphertext))
    # # result = cipher.decrypt_and_verify(ciphertext, tag)
    #
    # result = cipher.decrypt(ciphertext)
    # # tag = result[-16:]
    #
    # # cipher.verify(tag)
    # # result = cipher.decrypt_and_verify(ciphertext, tag)
    # # result = result[-16:]
    #
    # print("dec", binascii.hexlify(result), "tag")
    #
    # return result


GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16


class GCMCipherBytes:
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
        self.local_key = local_key
        self.remote_key = remote_key
        self.local_write_iv = local_write_iv
        self.remote_write_iv = remote_write_iv

    def encrypt(self, aead_data: bytes, payload: bytes) -> tuple[bytes, bytes]:
        nonce = self.local_write_iv[:4] + os.urandom(GCM_NONCE_LENGTH - 4)
        print(
            "encrypt local_key:",
            binascii.hexlify(self.local_key),
            "remote_key:",
            binascii.hexlify(self.remote_key),
        )
        print(
            "encrypt local_key_iv:",
            binascii.hexlify(self.local_write_iv),
            "remote_key_iv:",
            binascii.hexlify(self.remote_write_iv),
        )
        print("encrypt nonce", binascii.hexlify(nonce))

        return nonce, encrypt_with_aes_gcm(self.local_key, nonce, payload, aead_data)

    def decrypt(self, aead_data: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        print("dec nonce", binascii.hexlify(nonce))
        print(
            "dec remote_write_iv",
            binascii.hexlify(self.remote_write_iv),
            "local_write_iv",
            binascii.hexlify(self.local_write_iv),
        )
        print(
            "dec remote_key",
            binascii.hexlify(self.remote_key),
            "local_key",
            binascii.hexlify(self.local_key),
        )
        print()

        return decrypt_with_aes_gcm(
            self.remote_key,
            nonce,
            ciphertext,
            aead_data,
        )


class GCMCipherRecordLayer:
    def __init__(
        self,
        local_key: bytes,
        local_write_iv: bytes,
        remote_key: bytes,
        remote_write_iv: bytes,
    ) -> None:
        self.__gcm_bytes = GCMCipherBytes(
            local_key,
            local_write_iv,
            remote_key,
            remote_write_iv,
        )

    def encrypt(self, pkt: RecordLayer) -> bytes:
        """
        Marshal a DTLS Layer and change payload with a nonce and encoded payload

        :return Encrypted DTLS Record Layer:
            | Header | Nonce | Encoded Payload | Tag |
        """
        pkt_bytes = pkt.marshal()

        pkt_header_len = pkt.header_size()
        payload = pkt_bytes[pkt_header_len:]

        nonce, encrypted = self.__gcm_bytes.encrypt(
            generate_aead_additional_data(pkt.header, len(payload)),
            payload,
        )

        nonce_len = len(nonce[4:])
        pkt_enc_len = pkt_header_len + nonce_len + len(encrypted)
        pkt_enc = bytearray(pkt_enc_len)

        pkt_enc[:pkt_header_len] = pkt_bytes[:pkt_header_len]

        nonce_offset = pkt_header_len + nonce_len
        pkt_enc[pkt_header_len:nonce_offset] = nonce[4:]

        pkt_enc[nonce_offset:] = encrypted

        layer_header_length_offset = pkt_header_len - 2
        pkt_enc[layer_header_length_offset:pkt_header_len] = (
            byteops.pack_unsigned_short(
                pkt_enc_len - pkt_header_len,
            )
        )

        print("enc aead len", len(payload))

        return bytes(pkt_enc)

    def decrypt(self, pkt: RecordLayer) -> bytes:
        """
        :param encoded_payload - DTLS encoded message:
           | Header | Nonce | Encoded Payload | Tag |
        """
        pkt_bytes = pkt.marshal()
        pkt_header_len = pkt.header_size()
        payload = pkt_bytes[pkt_header_len:]

        nonce = self.__gcm_bytes.remote_write_iv[:4] + payload[4:GCM_NONCE_LENGTH]

        payload = payload[:GCM_NONCE_LENGTH]

        print(pkt)
        print("header content typ", pkt.header.content_type)
        print("dec", binascii.hexlify(pkt_bytes))

        aead_data = generate_aead_additional_data(
            pkt.header, len(payload) - GCM_TAG_LENGTH
        )

        # ciphertext = payload[GCM_NONCE_LENGTH:]

        # ciphertext = encoded_payload[0 : len(encoded_payload) - GCM_TAG_LENGTH]
        #
        print(
            "dec remote_iv",
            self.__gcm_bytes.remote_write_iv[:4],
            "cipher text",
            # len(ciphertext[0:GCM_NONCE_LENGTH]),
        )

        #
        # nonce = bytearray(GCM_NONCE_LENGTH)
        # nonce[0:4] = self.__gcm_bytes.remote_write_iv[:4]
        # nonce[4:GCM_NONCE_LENGTH] = encoded_payload[0:8]
        # nonce = bytes(nonce)
        #
        # ciphertext = ciphertext[GCM_NONCE_LENGTH:]
        #
        # aead_data = generate_aead_additional_data(header, len(ciphertext))
        # print("decrypt aead len", len(ciphertext))

        return self.__gcm_bytes.decrypt(
            aead_data,
            nonce,
            payload,
        )
