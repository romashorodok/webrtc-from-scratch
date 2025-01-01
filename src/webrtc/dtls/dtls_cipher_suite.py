import binascii
import hashlib
import os

from dataclasses import dataclass
from typing import Callable, Protocol, Self
from datetime import datetime, UTC, timedelta

from ecdsa import Ed25519, SigningKey, VerifyingKey, NIST256p
from ecdsa.ecdh import ECDH
from asn1crypto import x509, keys, algos
from ecdsa.util import sha256

from webrtc.dtls.dtls_record import (
    EllipticCurvePointFormat,
    RecordHeader,
    RecordLayer,
    SignatureHashAlgorithm,
)
from webrtc.dtls.dtls_typing import NAMED_CURVE_TYPE, CipherSuiteID, EllipticCurveGroup
from webrtc.dtls.gcm import GCMCipherRecordLayer, p_hash, prf_generate_encryption_keys

from webrtc.ice.stun import utils as byteops


@dataclass
class Keypair:
    privateKey: SigningKey
    publicKey: VerifyingKey
    curve: EllipticCurveGroup
    signature_hash_algorithm: SignatureHashAlgorithm = (
        SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256
    )

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

    # def __ecdh_params(self) -> bytes:
    #     # server_ecdh_params = bytearray(4)
    #     # server_ecdh_params[0] = NAMED_CURVE_TYPE
    #     # server_ecdh_params[1:3] = byteops.pack_unsigned_short(self.curve)
    #     # server_ecdh_params[3:4] = byteops.pack_byte_int(len(self.publicKey.to_der()))
    #     server_ecdh_params = byteops.pack_byte_int(NAMED_CURVE_TYPE)
    #     server_ecdh_params += byteops.pack_unsigned_short(self.curve)
    #     server_ecdh_params += byteops.pack_byte_int(len(self.publicKey.to_der()))
    #     return server_ecdh_params

    # def generate_server_signature(
    #     self, remote_random: bytes, local_random: bytes, private_key: SigningKey
    # ) -> bytes:
    #     ecdh_params = self.__ecdh_params()
    #     msg = bytes(
    #         remote_random + local_random + ecdh_params + self.publicKey.to_der()
    #     )
    #     # print("Expected server expected_ecdh_secret_message", binascii.hexlify(msg))
    #     # print(
    #     #     "Expected server expected_ecdh_secret_message digest",
    #     #     binascii.hexlify(hashlib.sha256(msg).digest()),
    #     # )
    #
    #     # msg = hashlib.sha256(msg).digest()
    #
    #     result = private_key.sign(msg, hashfunc=hashlib.sha256)
    #     return result

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
    sk = keypair.privateKey

    public_key_der = keypair.publicKey.to_der()

    ecdomain_params = keys.ECDomainParameters(("named", "secp256r1"))

    ec_point_bit_string = keys.ECPointBitString(public_key_der)

    # if public_key_der[0] != 0x04:
    #     raise ValueError("Public key is not in uncompressed format")

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
            "common_name": "WebRTC",
            # "country_name": "US",
            # "organization_name": "Example Org",
        },
        True,
    )

    issuer = subject

    not_before = x509.Time({"utc_time": datetime.now(UTC)})
    not_after = x509.Time({"utc_time": datetime.now(UTC) + timedelta(days=30)})

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

    # signature = sk.sign(tbs_certificate.dump(), hashfunc=hashlib.sha256)
    signature = sk.sign_digest(hashlib.sha256(tbs_certificate.dump()).digest())
    # signature = sk.sign(tbs_certificate.dump(), hashfunc=hashlib.sha256)

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


class CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
    __PRF_MAC_LEN = 0
    __PRF_KEY_LEN = 16
    __PRF_IV_LEN = 4

    def __init__(self) -> None:
        self.gcm: GCMCipherRecordLayer | None = None

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

        # print("Master Secret:", binascii.hexlify(master_secret))
        # print("Client Random:", binascii.hexlify(client_random))
        # print("Server Random:", binascii.hexlify(server_random))
        # print("Generated Keys:", keys)
        # print("is client", client)

        if client:
            gcm = GCMCipherRecordLayer(
                keys.client_write_key,
                keys.client_write_iv,
                keys.server_write_key,
                keys.server_write_iv,
            )
        else:
            gcm = GCMCipherRecordLayer(
                keys.server_write_key,
                keys.server_write_iv,
                keys.client_write_key,
                keys.client_write_iv,
            )

        self.gcm = gcm

    def encrypt(self, pkt: RecordLayer) -> bytes:
        if not self.gcm:
            raise ValueError("Unable encrypt start gcm first")

        return self.gcm.encrypt(pkt)

    def decrypt(self, header: RecordHeader, payload: bytes) -> bytes:
        if not self.gcm:
            raise ValueError("Unable decrypt start gcm first")
        return self.gcm.decrypt(header, payload)

    def cipher_suite_id(self) -> CipherSuiteID:
        return CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256


class CipherSuite(Protocol):
    def start(
        self,
        master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        client: bool,
    ): ...

    def encrypt(self, pkt: RecordLayer) -> bytes: ...

    def decrypt(self, header: RecordHeader, payload: bytes) -> bytes: ...

    def cipher_suite_id(self) -> CipherSuiteID: ...


CIPHER_SUITES_CLASSES: dict[CipherSuiteID, type[CipherSuite]] = {
    CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}


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
