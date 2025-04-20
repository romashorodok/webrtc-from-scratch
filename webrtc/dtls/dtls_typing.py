from datetime import datetime
from enum import IntEnum
import os


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


class EllipticCurveGroup(IntEnum):
    X25519 = 0x001D
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018


NAMED_CURVE_TYPE = 0x03
