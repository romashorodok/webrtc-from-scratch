from dataclasses import dataclass
from typing import Self


@dataclass
class Fingerprint:
    algorithm: str
    value: str


class RemoteCertificate:
    """Simple certificate wrapper that stores raw DER bytes."""

    def __init__(self, der_bytes: bytes) -> None:
        self._der = der_bytes

    @property
    def der(self) -> bytes:
        return self._der

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(data)


class Certificate:
    """
    Certificate wrapper for DTLS.
    Uses Rust webrtc_rs.Certificate for actual certificate operations.
    """

    def __init__(self, rust_cert) -> None:
        """
        Args:
            rust_cert: webrtc_rs.Certificate instance from Rust
        """
        self._cert = rust_cert
        self._keypair = rust_cert  # The Rust certificate provides keypair methods

    @property
    def der(self) -> bytes:
        """Get certificate DER bytes."""
        return self._cert.certificate_der()

    @property
    def pubkey_der(self) -> bytes:
        """Get public key DER bytes."""
        return self._cert.pubkey_der()

    def get_fingerprints(self) -> list[Fingerprint]:
        """Get SHA-256 fingerprint of certificate."""
        return [
            Fingerprint(
                algorithm="sha-256",
                value=self._cert.certificate_fingerprint(),
            )
        ]

    def sign(self, data: bytes) -> bytes:
        """Sign data with the certificate's private key."""
        return self._cert.sign(data)
