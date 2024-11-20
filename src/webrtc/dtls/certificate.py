from dataclasses import dataclass
import datetime
import binascii
import os

from typing import Type, TypeVar

# from cryptography import x509
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import serialization
# from OpenSSL import SSL, crypto

# TODO: remove this lib
# from pylibsrtp import Policy, Error


# def certificate_digest(x509: crypto.X509) -> str:
#     return x509.digest("SHA256").decode("ascii")
#
#
# def generate_certificate(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
#     name = x509.Name(
#         [
#             x509.NameAttribute(
#                 x509.NameOID.COMMON_NAME,
#                 binascii.hexlify(os.urandom(16)).decode("ascii"),
#             )
#         ]
#     )
#     now = datetime.datetime.now(tz=datetime.timezone.utc)
#     builder = (
#         x509.CertificateBuilder()
#         .subject_name(name)
#         .issuer_name(name)
#         .public_key(key.public_key())
#         .serial_number(x509.random_serial_number())
#         .not_valid_before(now - datetime.timedelta(days=1))
#         .not_valid_after(now + datetime.timedelta(days=30))
#     )
#     return builder.sign(key, hashes.SHA256(), default_backend())
#
#
# CERTIFICATE_T = TypeVar("CERTIFICATE_T", bound="Certificate")
#
#
@dataclass
class Fingerprint:
    algorithm: str
    value: str
#
#
# @dataclass(frozen=True)
# class SRTPProtectionProfile:
#     libsrtp_profile: int
#     openssl_profile: bytes
#     key_length: int
#     salt_length: int
#
#     def get_key_and_salt(self, src, idx: int) -> bytes:
#         key_start = idx * self.key_length
#         salt_start = 2 * self.key_length + idx * self.salt_length
#         return (
#             src[key_start : key_start + self.key_length]
#             + src[salt_start : salt_start + self.salt_length]
#         )
#
#
# SRTP_AEAD_AES_256_GCM = SRTPProtectionProfile(
#     libsrtp_profile=Policy.SRTP_PROFILE_AEAD_AES_256_GCM,
#     openssl_profile=b"SRTP_AEAD_AES_256_GCM",
#     key_length=32,
#     salt_length=12,
# )
# SRTP_AEAD_AES_128_GCM = SRTPProtectionProfile(
#     libsrtp_profile=Policy.SRTP_PROFILE_AEAD_AES_128_GCM,
#     openssl_profile=b"SRTP_AEAD_AES_128_GCM",
#     key_length=16,
#     salt_length=12,
# )
# SRTP_AES128_CM_SHA1_80 = SRTPProtectionProfile(
#     libsrtp_profile=Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
#     openssl_profile=b"SRTP_AES128_CM_SHA1_80",
#     key_length=16,
#     salt_length=14,
# )
#
# SRTP_PROFILES: list[SRTPProtectionProfile] = []
# for srtp_profile in [
#     SRTP_AEAD_AES_256_GCM,
#     SRTP_AEAD_AES_128_GCM,
#     SRTP_AES128_CM_SHA1_80,
# ]:
#     try:
#         Policy(srtp_profile=srtp_profile.libsrtp_profile)
#     except Error:
#         pass
#     else:
#         SRTP_PROFILES.append(srtp_profile)
#
#
# class Certificate:
#     def __init__(self, key: crypto.PKey, cert: crypto.X509) -> None:
#         self._key = key
#         self._cert = cert
#
#     @property
#     def expires(self) -> datetime.datetime:
#         return self._cert.to_cryptography().not_valid_after_utc
#
#     def get_fingerprints(self) -> list[Fingerprint]:
#         return [
#             Fingerprint(
#                 algorithm="sha-256",
#                 value=certificate_digest(self._cert),
#             )
#         ]
#
#     @classmethod
#     def generate_certificate(cls: Type[CERTIFICATE_T]) -> CERTIFICATE_T:
#         key = ec.generate_private_key(ec.SECP256R1(), default_backend())
#
#         private_key_bytes = key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption(),
#         )
#         pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_bytes)
#
#         cert = generate_certificate(key)
#
#         return cls(
#             key=pkey,
#             cert=crypto.X509.from_cryptography(cert),
#         )
#
#     def create_ssl_context(
#         self,
#         srtp_profiles: list[SRTPProtectionProfile],
#     ) -> SSL.Context:
#         ctx = SSL.Context(SSL.DTLS_METHOD)
#         ctx.set_verify(
#             SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda *args: True
#         )
#         ctx.use_certificate(self._cert)
#         ctx.use_privatekey(self._key)
#         ctx.set_cipher_list(
#             b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA"
#         )
#         ctx.set_tlsext_use_srtp(b":".join(x.openssl_profile for x in srtp_profiles))
#
#         return ctx
