class ECDHKeyPair:
    """ECDH key pair for DTLS key exchange.

    Supports P-256 (secp256r1) and X25519 curves.
    """
    def __init__(self, curve: str) -> None:
        """Create a new ECDH key pair.

        Args:
            curve: "P-256" or "X25519"
        """
        ...

    def public_key_bytes(self) -> bytes:
        """Get the public key bytes.

        For P-256: Returns uncompressed point (65 bytes, starts with 0x04)
        For X25519: Returns 32 bytes
        """
        ...

    def curve_name(self) -> str:
        """Get the curve name."""
        ...

    def compute_shared_secret(self, peer_public: bytes) -> bytes:
        """Compute the shared secret using peer's public key.

        Args:
            peer_public: Peer's public key bytes

        Returns:
            32-byte shared secret (pre-master secret for DTLS)
        """
        ...


class AesGcmCipher:
    """AES-128-GCM cipher for DTLS record encryption/decryption.

    Wraps the existing CryptoGcm implementation from webrtc_dtls.
    """
    def __init__(
        self,
        client_write_key: bytes,
        client_write_iv: bytes,
        server_write_key: bytes,
        server_write_iv: bytes,
        is_client: bool,
    ) -> None:
        """Create a new AES-128-GCM cipher from derived keys.

        Args:
            client_write_key: 16-byte client write key
            client_write_iv: 4-byte client write IV
            server_write_key: 16-byte server write key
            server_write_iv: 4-byte server write IV
            is_client: True if this is the client side
        """
        ...

    def encrypt(
        self,
        content_type: int,
        epoch: int,
        sequence_number: int,
        payload: bytes,
    ) -> bytes:
        """Encrypt a DTLS record.

        Args:
            content_type: DTLS content type (22=handshake, 23=application_data, 21=alert)
            epoch: DTLS epoch number
            sequence_number: Record sequence number within epoch
            payload: Plaintext payload to encrypt

        Returns:
            Complete encrypted DTLS record (header + explicit_nonce + ciphertext + tag)
        """
        ...

    def decrypt(self, record: bytes) -> bytes:
        """Decrypt a DTLS record.

        Args:
            record: Complete encrypted DTLS record bytes

        Returns:
            Decrypted record (header + plaintext payload)
        """
        ...

    def is_client(self) -> bool:
        """Check if this cipher is for client-side encryption."""
        ...


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Args:
        length: Number of random bytes to generate

    Returns:
        Random bytes
    """
    ...


class Av1Payloader:
    def __init__(self) -> None: ...
    def packetize(self, mtu: int, frame: bytes) -> list[bytes]: ...


class Certificate:
    def __init__(self) -> None: ...
    def certificate_fingerprint(self) -> str: ...

class DTLS:
    def __init__(
        self, client: bool, certificate: Certificate, threads: int = 4
    ) -> None: ...
    def do_handshake(self) -> None: ...
    async def enqueue_record(self, record: bytes): ...
    async def dequeue_record(self) -> bytes: ...
    async def handshake_success(self) -> None:
        """
        Mutex Guarded must be used after the do_handshake fn
        """
    ...

class Stream:
    def __init__(self) -> None: ...
    async def recv(self) -> bytes: ...
    async def recv_rtcp(self) -> bytes: ...

class SRTP:
    def __init__(self, is_rtp: bool, client: bool, dtls: DTLS) -> None: ...
    @staticmethod
    def from_keying_material(is_rtp: bool, tx_key: bytes, rx_key: bytes) -> "SRTP":
        """Create SRTP session from raw keying material.

        Args:
            is_rtp: True for RTP, False for RTCP
            tx_key: Local master key + salt (30 bytes for AES-128-CM-HMAC-SHA1-80)
            rx_key: Remote master key + salt (30 bytes for AES-128-CM-HMAC-SHA1-80)
        """
        ...
    async def write_pkt(self, pkt: bytes): ...
    async def read_pkt(self) -> bytes: ...
    async def ssrc_stream(self, ssrc: int) -> Stream: ...
    async def encrypt(self, pkt: bytes): ...
    async def encrypt_nonblock(self, pkt: bytes) -> bytes: ...
