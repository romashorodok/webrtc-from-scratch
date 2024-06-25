from dataclasses import dataclass
import datetime
import binascii
import os

from typing import Type, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL, crypto


def certificate_digest(x509: crypto.X509) -> str:
    return x509.digest("SHA256").decode("ascii")


def generate_certificate(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(
                x509.NameOID.COMMON_NAME,
                binascii.hexlify(os.urandom(16)).decode("ascii"),
            )
        ]
    )
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    return builder.sign(key, hashes.SHA256(), default_backend())


CERTIFICATE_T = TypeVar("CERTIFICATE_T", bound="Certificate")


@dataclass
class Fingerprint:
    algorithm: str
    value: str


class Certificate:
    def __init__(self, key: crypto.PKey, cert: crypto.X509) -> None:
        self._key = key
        self._cert = cert

    @property
    def expires(self) -> datetime.datetime:
        return self._cert.to_cryptography().not_valid_after_utc

    def get_fingerprints(self) -> list[Fingerprint]:
        return [
            Fingerprint(
                algorithm="sha-256",
                value=certificate_digest(self._cert),
            )
        ]

    @classmethod
    def generate_certificate(cls: Type[CERTIFICATE_T]) -> CERTIFICATE_T:
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        private_key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_bytes)

        cert = generate_certificate(key)

        return cls(
            key=pkey,
            cert=crypto.X509.from_cryptography(cert),
        )

    def _create_ssl_context(
        self,
    ) -> SSL.Context:
        ctx = SSL.Context(SSL.DTLS_METHOD)
        ctx.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda *args: True
        )
        ctx.use_certificate(self._cert)
        ctx.use_privatekey(self._key)
        ctx.set_cipher_list(
            b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA"
        )
        return ctx
