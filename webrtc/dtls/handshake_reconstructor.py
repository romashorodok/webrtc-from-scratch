from dataclasses import replace

from webrtc.dtls.dtls_record import (
    ContentType,
    Handshake,
    HandshakeFragment,
    HandshakeMessageType,
    HandshakeMultipleMessages,
    RecordHeader,
    RecordLayer,
)


class _RawHandshakeContent:
    content_type = ContentType.HANDSHAKE

    def __init__(self, data: bytes) -> None:
        self.data = data

    def marshal(self) -> bytes:
        return self.data


class HandshakeReconstructor:
    """Reassembles epoch-0 DTLS handshake fragments before handshake parsing.

    DTLS can split a large handshake message across multiple records. The record
    parser keeps partial messages as raw fragments; this class owns the state
    needed to combine those fragments into complete handshake records.
    """

    def __init__(self) -> None:
        self._fragments: dict[
            tuple[HandshakeMessageType, int, int],
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
        if self._is_complete(record.content):
            return [(record, raw)]

        completed = self._complete_fragmented(record, record.content)
        return [] if completed is None else [completed]

    def _complete_fragmented(
        self, record: RecordLayer, handshake: Handshake
    ) -> tuple[RecordLayer, bytes] | None:
        fragments = self._fragments.setdefault(self._key(handshake), {})
        fragments[handshake.header.fragment_offset] = handshake.message.marshal()

        payload = self._assemble(handshake, fragments)
        if payload is None:
            return None

        del self._fragments[self._key(handshake)]
        return self._record_from_handshake(
            record,
            Handshake(
                replace(
                    handshake.header,
                    fragment_offset=0,
                    fragment_length=handshake.header.length,
                ),
                HandshakeFragment(payload),
            ),
        )

    def _record_from_handshake(
        self, record: RecordLayer, handshake: Handshake
    ) -> tuple[RecordLayer, bytes]:
        return self._record_from_content(record, handshake)

    def _record_from_handshake_bytes(
        self, record: RecordLayer, handshake_bytes: bytes
    ) -> tuple[RecordLayer, bytes]:
        return self._record_from_content(record, _RawHandshakeContent(handshake_bytes))

    def _record_from_content(
        self, record: RecordLayer, content: Handshake | _RawHandshakeContent
    ) -> tuple[RecordLayer, bytes]:
        raw = RecordLayer(
            RecordHeader(
                content_type=record.header.content_type,
                version=record.header.version,
                epoch=record.header.epoch,
                sequence_number=record.header.sequence_number,
            ),
            content,
        ).marshal()
        return RecordLayer.unmarshal(raw), raw

    def _is_complete(self, handshake: Handshake) -> bool:
        header = handshake.header
        return header.fragment_offset == 0 and header.fragment_length == header.length

    def _key(self, handshake: Handshake) -> tuple[HandshakeMessageType, int, int]:
        header = handshake.header
        return (
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
