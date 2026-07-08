from webrtc.dtls.dtls_record import (
    ClientHello,
    ContentType,
    DTLSVersion,
    Handshake,
    HandshakeFragment,
    HandshakeMessageType,
    RecordLayerBatch,
)
from webrtc.dtls.dtls_record import SignatureHashAlgorithm
from webrtc.dtls.dtls_record_factory import DEFAULT_FACTORY
from webrtc.dtls.dtls_typing import CipherSuiteID, EllipticCurveGroup
from webrtc.dtls.handshake_reconstructor import HandshakeReconstructor


def _record(content: bytes, sequence_number: int) -> bytes:
    return (
        bytes([ContentType.HANDSHAKE])
        + int(DTLSVersion.V1_2).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + sequence_number.to_bytes(6, "big")
        + len(content).to_bytes(2, "big")
        + content
    )


def _handshake_fragment(
    payload: bytes, offset: int, length: int, message_sequence: int = 1
) -> bytes:
    return (
        bytes([HandshakeMessageType.ClientHello])
        + length.to_bytes(3, "big")
        + message_sequence.to_bytes(2, "big")
        + offset.to_bytes(3, "big")
        + len(payload).to_bytes(3, "big")
        + payload
    )


def test_fragmented_client_hello_is_reassembled_before_parsing():
    client_hello = DEFAULT_FACTORY.client_hello(
        random=b"\x11" * 32,
        cookie=None,
        cipher_suites=[CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        elliptic_curves=[EllipticCurveGroup.X25519, EllipticCurveGroup.SECP256R1],
        signature_hash_algorithms=[SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256],
    )
    client_hello_payload = client_hello.content.message.marshal()
    split_at = 20

    first_raw = _record(
        _handshake_fragment(client_hello_payload[:split_at], 0, len(client_hello_payload)),
        0,
    )
    second_raw = _record(
        _handshake_fragment(
            client_hello_payload[split_at:], split_at, len(client_hello_payload)
        ),
        1,
    )

    first_record = next(iter(RecordLayerBatch(first_raw)))[0]
    assert isinstance(first_record.content, Handshake)
    assert isinstance(first_record.content.message, HandshakeFragment)

    reconstructor = HandshakeReconstructor()

    assert reconstructor.complete(first_record, first_raw) == []

    second_record = next(iter(RecordLayerBatch(second_raw)))[0]
    completed = reconstructor.complete(second_record, second_raw)

    assert len(completed) == 1
    complete_record, complete_raw = completed[0]
    assert complete_raw == complete_record.marshal()
    assert complete_record.header.content_type == ContentType.HANDSHAKE
    assert isinstance(complete_record.content, Handshake)
    assert isinstance(complete_record.content.message, ClientHello)
    assert complete_record.content.header.fragment_offset == 0
    assert complete_record.content.header.fragment_length == len(client_hello_payload)


def test_unfragmented_client_hello_passes_through_unchanged():
    client_hello = DEFAULT_FACTORY.client_hello(
        random=b"\x22" * 32,
        cookie=None,
        cipher_suites=[CipherSuiteID.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        elliptic_curves=[EllipticCurveGroup.X25519, EllipticCurveGroup.SECP256R1],
        signature_hash_algorithms=[SignatureHashAlgorithm.ECDSA_SECP256R1_SHA256],
    )
    raw = client_hello.marshal()
    record = next(iter(RecordLayerBatch(raw)))[0]

    completed = HandshakeReconstructor().complete(record, raw)

    assert completed == [(record, raw)]
