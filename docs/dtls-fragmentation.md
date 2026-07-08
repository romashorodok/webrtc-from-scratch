# DTLS Handshake Fragmentation

DTLS handshake messages can be larger than a single datagram. When that happens,
the peer sends multiple handshake fragments with the same handshake type, message
sequence, total message length, and different fragment offsets.

This matters for browser interop. Chrome can send a fragmented `ClientHello`
when the extensions make the message larger than the datagram budget. The DTLS
handshake parser must not parse a partial `ClientHello` as if it were complete.

## Responsibilities

`webrtc.dtls.dtls_record` owns DTLS record and handshake serialization:

- `RecordLayerBatch` splits a UDP datagram into DTLS records.
- `RecordLayer` parses one record.
- `Handshake` parses a complete handshake message.
- `HandshakeFragment` stores raw bytes for an incomplete handshake message.
- `HandshakeMultipleMessages` preserves each raw handshake item when multiple
  handshake messages are packed into one DTLS record.

`webrtc.dtls.handshake_reconstructor.HandshakeReconstructor` owns reassembly
state:

- Non-handshake records pass through unchanged.
- Encrypted handshake records, where `epoch > 0`, pass through unchanged.
- Epoch-0 complete handshake records pass through unchanged.
- Epoch-0 fragmented handshake records are buffered until all bytes are present.
- Once complete, fragments are emitted as one normal handshake record with
  `fragment_offset = 0` and `fragment_length = length`.

Keeping reconstruction out of `DTLSTransport` keeps the transport focused on
moving parsed records into the DTLS state machine. Keeping reconstruction out of
`Handshake` keeps message classes focused on parsing and marshaling one message.

## Fragment Key

Fragments are grouped by:

- DTLS content type
- DTLS epoch
- handshake type
- handshake message sequence
- full handshake message length

The fragment offset is not part of the key. It is the position of that fragment
inside the assembled handshake payload.

## Complete And Unfragmented Records

A handshake message is complete when:

```text
fragment_offset == 0
fragment_length == length
```

Complete records are returned exactly as they arrived. This includes normal
unfragmented records. No reconstruction or remarshal is done in that case, so
the original raw record remains available for the handshake transcript path.

## Fragmented Records

For fragmented messages, `Handshake.unmarshal()` returns a `HandshakeFragment`
instead of parsing the fragment body as a `ClientHello`, `ServerHello`, or other
handshake message. The reconstructor stores the fragment bytes by offset and
checks whether offsets form a contiguous payload from `0` to `length`.

When the final missing fragment arrives, the reconstructor builds a single
handshake record and parses it normally. The completed record is then safe to
feed into the DTLS handshake state machine.

## Current Limits

The reconstructor does not currently expire incomplete fragment sets. If packet
loss leaves a fragment set incomplete, that state remains until the
`HandshakeReconstructor` instance is discarded or a retransmission completes the
message.
