"""Contract and differential tests for the Stage 1 Kernel E candidate."""

from __future__ import annotations

import pytest

from webrtc.compiler.kernel_e import packetize_av1_frame


DEFAULT_ARGUMENTS = (b"\x32\x03\x01\x02\x03", 1200, 1, 2, 3, 4)


def _call(
    frame: bytes,
    fragmentation_limit: int = 1200,
    timestamp: int = 1,
    ssrc: int = 2,
    current_rtp_sequence: int = 3,
    current_twcc_sequence: int = 4,
) -> tuple[tuple[bytes, ...], int, int]:
    return packetize_av1_frame(
        frame,
        fragmentation_limit,
        timestamp,
        ssrc,
        current_rtp_sequence,
        current_twcc_sequence,
    )


def _obu(
    obu_type: int,
    payload: bytes = b"",
    *,
    extension: int | None = None,
    has_size: bool = True,
) -> bytes:
    """Build differential-test inputs; expected bytes remain fixed goldens."""
    header = obu_type << 3
    if extension is not None:
        header |= 0x04
    if has_size:
        header |= 0x02
    result = bytearray((header,))
    if extension is not None:
        result.append(extension)
    if has_size:
        size = len(payload)
        while size >= 0x80:
            result.append(0x80 | (size & 0x7F))
            size >>= 7
        result.append(size)
    result.extend(payload)
    return bytes(result)


def _payloads(packets: tuple[bytes, ...]) -> list[bytes]:
    return [packet[20:] for packet in packets]


def test_single_obu_complete_rtp_packet_golden() -> None:
    frame = bytes.fromhex("3209010203040506070809")

    packets, rtp_sequence, twcc_sequence = _call(
        frame,
        timestamp=0x01020304,
        ssrc=0xA0B0C0D0,
        current_rtp_sequence=0x1233,
        current_twcc_sequence=0xABCC,
    )

    assert packets == (
        bytes.fromhex(
            "90ad123401020304a0b0c0d0bede000141abcd00"
            "1030010203040506070809"
        ),
    )
    assert (rtp_sequence, twcc_sequence) == (0x1234, 0xABCD)


def test_multi_obu_fragmentation_complete_rtp_packets_golden() -> None:
    # Sequence header with two bytes, followed by a nine-byte frame OBU.
    frame = bytes.fromhex("0a0201023209010203040506070809")

    packets, rtp_sequence, twcc_sequence = _call(
        frame,
        fragmentation_limit=6,
        timestamp=0,
        ssrc=0xFFFFFFFF,
        current_rtp_sequence=0x00FE,
        current_twcc_sequence=0xFFFE,
    )

    assert packets == (
        bytes.fromhex(
            "902d00ff00000000ffffffffbede000141ffff00"
            "680308010230"
        ),
        bytes.fromhex(
            "902d010000000000ffffffffbede000141000000"
            "d00102030405"
        ),
        bytes.fromhex(
            "90ad010100000000ffffffffbede000141000100"
            "9006070809"
        ),
    )
    assert (rtp_sequence, twcc_sequence) == (0x0101, 0x0001)


def test_ignored_obu_types_are_absent_from_complete_packet_golden() -> None:
    frame = b"".join(
        (
            _obu(2),  # temporal delimiter
            _obu(5),  # metadata, retained
            _obu(8, b"\x01\x02\x03\x04\x05\x06"),  # tile list
            _obu(3, b"\x15\x16\x17"),  # frame header, retained
            _obu(15, b"padding"),  # padding
            _obu(4, b"\x1f\x20\x21\x22\x23\x24"),  # tile group
        )
    )

    packets, rtp_sequence, twcc_sequence = _call(
        frame,
        timestamp=0xFFFFFFFF,
        ssrc=0,
        current_rtp_sequence=0,
        current_twcc_sequence=0,
    )

    assert packets == (
        bytes.fromhex(
            "90ad0001ffffffff00000000bede000141000100"
            "3001280418151617201f2021222324"
        ),
    )
    assert (rtp_sequence, twcc_sequence) == (1, 1)


def test_minimum_fragmentation_limit_three_has_exact_payloads_and_order() -> None:
    frame = bytes.fromhex("3209010203040506070809")

    packets, rtp_sequence, twcc_sequence = _call(
        frame,
        fragmentation_limit=3,
        current_rtp_sequence=10,
        current_twcc_sequence=20,
    )

    assert _payloads(packets) == [
        bytes.fromhex(value)
        for value in ("503001", "d00203", "d00405", "d00607", "900809")
    ]
    assert [packet[1] for packet in packets] == [0x2D] * 4 + [0xAD]
    assert [int.from_bytes(packet[2:4], "big") for packet in packets] == [
        11,
        12,
        13,
        14,
        15,
    ]
    assert [int.from_bytes(packet[17:19], "big") for packet in packets] == [
        21,
        22,
        23,
        24,
        25,
    ]
    assert (rtp_sequence, twcc_sequence) == (15, 25)


@pytest.mark.parametrize(
    ("fragmentation_limit", "expected_payloads"),
    (
        (5, ("5030010203", "d004050607", "900809")),
        (6, ("503001020304", "900506070809")),
        (11, ("50300102030405060708", "9009")),
        (12, ("1030010203040506070809",)),
    ),
)
def test_fragmentation_boundary_golden_payloads(
    fragmentation_limit: int, expected_payloads: tuple[str, ...]
) -> None:
    frame = bytes.fromhex("3209010203040506070809")

    packets, _, _ = _call(frame, fragmentation_limit=fragmentation_limit)

    assert _payloads(packets) == [bytes.fromhex(value) for value in expected_payloads]
    assert all(len(packet) <= fragmentation_limit + 20 for packet in packets)


def test_nonfinal_128_byte_obu_uses_canonical_two_byte_leb128() -> None:
    frame = _obu(6, bytes(range(127))) + _obu(4)

    packets, _, _ = _call(frame, fragmentation_limit=255)

    assert len(packets) == 1
    assert packets[0][20:25] == bytes.fromhex("2080013000")
    assert packets[0][-1] == 0x20
    assert len(packets[0]) == 152


def test_rtp_and_twcc_roll_over_independently_without_reordering() -> None:
    frame = bytes.fromhex("3209010203040506070809")

    packets, rtp_sequence, twcc_sequence = _call(
        frame,
        fragmentation_limit=5,
        current_rtp_sequence=0xFFFE,
        current_twcc_sequence=0xFFFD,
    )

    assert [int.from_bytes(packet[2:4], "big") for packet in packets] == [
        0xFFFF,
        0,
        1,
    ]
    assert [int.from_bytes(packet[17:19], "big") for packet in packets] == [
        0xFFFE,
        0xFFFF,
        0,
    ]
    assert _payloads(packets) == [
        bytes.fromhex(value) for value in ("5030010203", "d004050607", "900809")
    ]
    assert (rtp_sequence, twcc_sequence) == (1, 0)


@pytest.mark.parametrize(
    "frame",
    (
        b"",
        _obu(2) + _obu(8, b"ignored") + _obu(15, b"ignored too"),
    ),
)
def test_empty_result_leaves_caller_state_unchanged(frame: bytes) -> None:
    assert _call(
        frame,
        current_rtp_sequence=0xFFFF,
        current_twcc_sequence=0xFFFF,
    ) == ((), 0xFFFF, 0xFFFF)


class _BytesSubclass(bytes):
    pass


class _IntSubclass(int):
    pass


@pytest.mark.parametrize("bad_frame", (bytearray(), memoryview(b""), "", None, _BytesSubclass()))
def test_frame_requires_concrete_bytes(bad_frame: object) -> None:
    with pytest.raises(TypeError, match=r"^frame must be bytes$"):
        packetize_av1_frame(bad_frame, 1200, 1, 2, 3, 4)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("argument_index", "argument_name"),
    (
        (1, "fragmentation_limit"),
        (2, "timestamp"),
        (3, "ssrc"),
        (4, "current_rtp_sequence"),
        (5, "current_twcc_sequence"),
    ),
)
@pytest.mark.parametrize("bad_value", (True, False, 1.0, "1", None, _IntSubclass(1)))
def test_integer_arguments_require_concrete_int(
    argument_index: int, argument_name: str, bad_value: object
) -> None:
    arguments = list(DEFAULT_ARGUMENTS)
    arguments[argument_index] = bad_value

    with pytest.raises(TypeError, match=rf"^{argument_name} must be int$"):
        packetize_av1_frame(*arguments)  # type: ignore[arg-type]


def test_all_types_are_validated_in_signature_order_before_ranges() -> None:
    with pytest.raises(TypeError, match=r"^frame must be bytes$"):
        packetize_av1_frame(bytearray(), False, "bad", None, 1.0, object())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"^timestamp must be int$"):
        packetize_av1_frame(b"", -1, "bad", None, 1.0, object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("argument_index", "argument_name", "bad_value", "low", "high"),
    (
        (1, "fragmentation_limit", 2, 3, 65_535),
        (1, "fragmentation_limit", 65_536, 3, 65_535),
        (2, "timestamp", -1, 0, 0xFFFFFFFF),
        (2, "timestamp", 0x1_0000_0000, 0, 0xFFFFFFFF),
        (3, "ssrc", -1, 0, 0xFFFFFFFF),
        (3, "ssrc", 0x1_0000_0000, 0, 0xFFFFFFFF),
        (4, "current_rtp_sequence", -1, 0, 0xFFFF),
        (4, "current_rtp_sequence", 0x1_0000, 0, 0xFFFF),
        (5, "current_twcc_sequence", -1, 0, 0xFFFF),
        (5, "current_twcc_sequence", 0x1_0000, 0, 0xFFFF),
    ),
)
def test_integer_ranges_have_exact_errors(
    argument_index: int,
    argument_name: str,
    bad_value: int,
    low: int,
    high: int,
) -> None:
    arguments = list(DEFAULT_ARGUMENTS)
    arguments[argument_index] = bad_value

    with pytest.raises(
        ValueError,
        match=rf"^{argument_name} must be in range {low}\.\.{high}$",
    ):
        packetize_av1_frame(*arguments)


def test_all_range_endpoints_are_accepted() -> None:
    assert packetize_av1_frame(b"", 3, 0, 0, 0, 0) == ((), 0, 0)
    assert packetize_av1_frame(
        b"", 65_535, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF
    ) == ((), 0xFFFF, 0xFFFF)


def test_oversized_frame_has_exact_error() -> None:
    with pytest.raises(
        ValueError, match=r"^frame must not exceed 16777216 bytes$"
    ):
        _call(b"\x00" * (16 * 1024 * 1024 + 1))


@pytest.mark.parametrize(
    ("frame", "message"),
    (
        (b"\x34", "truncated OBU extension header"),
        (b"\x32", "truncated OBU size"),
        (b"\x32\x80", "truncated OBU size"),
        (b"\x32\x80\x80\x80\x80", "truncated OBU size"),
        (b"\x32\x80\x80\x80\x80\x10", "OBU size exceeds 32-bit LEB128"),
        (b"\x32\xff\xff\xff\xff\x0f", "declared OBU size exceeds frame"),
        (b"\x32\x02\x01", "declared OBU size exceeds frame"),
    ),
)
def test_malformed_frames_have_exact_errors(frame: bytes, message: str) -> None:
    with pytest.raises(
        ValueError, match=rf"^malformed AV1 frame: {message}$"
    ):
        _call(frame)


def test_failures_are_transactional_and_do_not_create_hidden_state() -> None:
    valid_frame = bytes.fromhex("3203010203")
    before = _call(
        valid_frame,
        fragmentation_limit=3,
        current_rtp_sequence=0xFFFE,
        current_twcc_sequence=0xFFFF,
    )

    with pytest.raises(ValueError, match=r"^malformed AV1 frame:"):
        _call(
            b"\x32\x02\x01",
            fragmentation_limit=3,
            current_rtp_sequence=0xFFFE,
            current_twcc_sequence=0xFFFF,
        )

    assert _call(
        valid_frame,
        fragmentation_limit=3,
        current_rtp_sequence=0xFFFE,
        current_twcc_sequence=0xFFFF,
    ) == before


def test_result_is_deterministic_immutable_and_independently_owned() -> None:
    frame = bytes.fromhex("3209010203040506070809")

    first = _call(frame, fragmentation_limit=3)
    second = _call(frame, fragmentation_limit=3)

    assert first == second
    assert first is not second
    assert first[0] is not second[0]
    assert all(type(packet) is bytes for packet in first[0])
    assert all(left is not right for left, right in zip(first[0], second[0]))
    with pytest.raises(TypeError):
        first[0][0][0] = 0  # type: ignore[index]


def test_valid_av1_payloads_match_installed_rust_payloader() -> None:
    webrtc_rs = pytest.importorskip(
        "webrtc_rs", reason="optional webrtc_rs differential oracle unavailable"
    )
    av1_payloader = getattr(webrtc_rs, "Av1Payloader", None)
    if av1_payloader is None:
        pytest.skip("optional webrtc_rs.Av1Payloader differential oracle unavailable")

    frames = (
        _obu(6, bytes(range(1, 10))),
        _obu(6, bytes(range(1, 10)), has_size=False),
        _obu(6, bytes(range(1, 10)), extension=0x28),
        _obu(1, b"\x01\x02") + _obu(6, bytes(range(1, 10))),
        _obu(3, b"\x15", extension=0x28)
        + _obu(4, b"\x0b\x0c\x0d\x0e", extension=0x28),
        b"".join(_obu(obu_type, bytes((obu_type,))) for obu_type in (1, 5, 6, 4)),
        _obu(2) + _obu(5) + _obu(8, b"ignored") + _obu(3, b"\x15\x16"),
        _obu(6, bytes(range(200))),
    )

    for frame in frames:
        for fragmentation_limit in (3, 4, 5, 6, 8, 12, 127, 128, 129, 1200):
            packets, _, _ = _call(frame, fragmentation_limit=fragmentation_limit)
            expected = [
                bytes(payload)
                for payload in av1_payloader().packetize(fragmentation_limit, frame)
            ]
            assert _payloads(packets) == expected, (
                frame.hex(),
                fragmentation_limit,
            )


@pytest.mark.xfail(
    reason=(
        "installed Rust payloader encodes an OBU element length of 128 as "
        "noncanonical 81 80 02 while reserving only two bytes"
    ),
    strict=True,
)
def test_known_rust_differential_for_128_byte_nonfinal_obu() -> None:
    webrtc_rs = pytest.importorskip(
        "webrtc_rs", reason="optional webrtc_rs differential oracle unavailable"
    )
    av1_payloader = getattr(webrtc_rs, "Av1Payloader", None)
    if av1_payloader is None:
        pytest.skip("optional webrtc_rs.Av1Payloader differential oracle unavailable")
    frame = _obu(6, bytes(range(127))) + _obu(4)

    packets, _, _ = _call(frame, fragmentation_limit=255)
    rust_payloads = [bytes(value) for value in av1_payloader().packetize(255, frame)]

    assert _payloads(packets) == rust_payloads
