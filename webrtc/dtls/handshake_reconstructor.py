from webrtc.dtls.dtls_record import (
    ContentType,
    Handshake,
    HandshakeMessageType,
    HandshakeMultipleMessages,
    RecordLayer,
)


class HandshakeReconstructor:
    """Reassembles epoch-0 DTLS handshake fragments before handshake parsing.

    DTLS can split a large handshake message across multiple records. The record
    parser keeps partial messages as raw fragments; this class owns the state
    needed to combine those fragments into complete handshake records.
    """

    def __init__(self) -> None:
        self._fragments: dict[
            tuple[ContentType, int, HandshakeMessageType, int, int],
            dict[int, bytes],
        ] = {}

    def complete(
        self, record: RecordLayer, raw: bytes
    ) -> list[tuple[RecordLayer, bytes]]:
        """Return complete handshake records produced by this input record.

        Non-handshake, encrypted, and already-complete records pass through
        unchanged. Fragmented handshakes return an empty list until all bytes for
        the handshake message have arrived.
        """

        if record.header.content_type != ContentType.HANDSHAKE or record.header.epoch != 0:
            return [(record, raw)]

        if isinstance(record.content, HandshakeMultipleMessages):
            return self._complete_batch(record, raw)

        if isinstance(record.content, Handshake):
            return self._complete_single(record, raw)

        return [(record, raw)]

    def _complete_batch(
        self, record: RecordLayer, raw: bytes
    ) -> list[tuple[RecordLayer, bytes]]:
        if all(
            self._is_complete(handshake)
            for handshake, _ in record.content.handshake_messages
        ):
            return [(record, raw)]

        completed = list[tuple[RecordLayer, bytes]]()
        for handshake, handshake_raw in record.content.handshake_messages:
            if self._is_complete(handshake):
                completed.append(self._record_from_handshake_bytes(record, handshake_raw))
                continue

            if result := self._complete_fragmented(record, handshake):
                completed.append(result)

        return completed

    def _complete_single(
        self, record: RecordLayer, raw: bytes
    ) -> list[tuple[RecordLayer, bytes]]:
        if not isinstance(record.content, Handshake):
            return [(record, raw)]
        if self._is_complete(record.content):
            return [(record, raw)]

        completed = self._complete_fragmented(record, record.content)
        return [] if completed is None else [completed]

    def _complete_fragmented(
        self, record: RecordLayer, handshake: Handshake
    ) -> tuple[RecordLayer, bytes] | None:
        fragments = self._fragments.setdefault(self._key(record, handshake), {})
        fragments[handshake.header.fragment_offset] = handshake.message.marshal()

        payload = self._assemble(handshake, fragments)
        if payload is None:
            return None

        del self._fragments[self._key(record, handshake)]
        raw = self._record_bytes(record, handshake, payload)
        return RecordLayer.unmarshal(raw), raw

    def _record_from_handshake_bytes(
        self, record: RecordLayer, handshake_bytes: bytes
    ) -> tuple[RecordLayer, bytes]:
        raw = self._record_header_bytes(record, len(handshake_bytes)) + handshake_bytes
        return RecordLayer.unmarshal(raw), raw

    def _is_complete(self, handshake: Handshake) -> bool:
        header = handshake.header
        return header.fragment_offset == 0 and header.fragment_length == header.length

    def _key(
        self, record: RecordLayer, handshake: Handshake
    ) -> tuple[ContentType, int, HandshakeMessageType, int, int]:
        header = handshake.header
        return (
            record.header.content_type,
            record.header.epoch,
            header.handshake_type,
            header.message_sequence,
            header.length,
        )

    def _assemble(
        self, handshake: Handshake, fragments: dict[int, bytes]
    ) -> bytes | None:
        payload = bytearray()
        offset = 0

        for fragment_offset in sorted(fragments):
            if fragment_offset != offset:
                return None
            payload.extend(fragments[fragment_offset])
            offset += len(fragments[fragment_offset])
            if offset >= handshake.header.length:
                break

        return bytes(payload) if len(payload) == handshake.header.length else None

    def _record_bytes(
        self, record: RecordLayer, handshake: Handshake, payload: bytes
    ) -> bytes:
        handshake_bytes = self._handshake_bytes(handshake, payload)
        return self._record_header_bytes(record, len(handshake_bytes)) + handshake_bytes

    def _record_header_bytes(self, record: RecordLayer, length: int) -> bytes:
        return (
            bytes([record.header.content_type])
            + int(record.header.version).to_bytes(2, "big")
            + record.header.epoch.to_bytes(2, "big")
            + record.header.sequence_number.to_bytes(6, "big")
            + length.to_bytes(2, "big")
        )

    def _handshake_bytes(self, handshake: Handshake, payload: bytes) -> bytes:
        header = handshake.header
        return (
            bytes([header.handshake_type])
            + header.length.to_bytes(3, "big")
            + header.message_sequence.to_bytes(2, "big")
            + (0).to_bytes(3, "big")
            + header.length.to_bytes(3, "big")
            + payload
        )
