import io
from typing import Self
from dataclasses import dataclass

IVF_FILE_HEADER_SIGNATURE = "DKIF"
IVF_FILE_HEADER_SIZE = 32
IVF_FRAME_HEADER_SIZE = 12


@dataclass
class IVFFileHeader:
    signature: str
    version: int
    header_size: int
    four_cc: str
    width: int
    height: int
    timebase_denominator: int
    timebase_numerator: int
    num_frames: int
    unused: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        return cls(
            signature=data[:4].decode(),
            version=int.from_bytes(data[4:6], "little"),
            header_size=int.from_bytes(data[6:8], "little"),
            four_cc=data[8:12].decode(),
            width=int.from_bytes(data[12:14], "little"),
            height=int.from_bytes(data[14:16], "little"),
            timebase_denominator=int.from_bytes(data[16:20], "little"),
            timebase_numerator=int.from_bytes(data[20:24], "little"),
            num_frames=int.from_bytes(data[24:28], "little"),
            unused=int.from_bytes(data[28:32], "little"),
        )


@dataclass
class IVFFrameHeader:
    frame_size: int
    timestamp: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        return cls(
            frame_size=int.from_bytes(data[:4], "little"),
            timestamp=int.from_bytes(data[4:12], "little"),
        )


class IVFReader:
    def __init__(self, reader: io.BufferedReader) -> None:
        self._reader = reader
        self.read_succesfull_count = 0
        self.file_header = self._read_file_header()

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[bytes, IVFFrameHeader]:
        header = self._read_frame_header()
        if not header:
            raise StopIteration

        frame_payload = bytearray(header.frame_size)
        n = self._reader.readinto(frame_payload)
        if n == 0:
            raise StopIteration

        self.read_succesfull_count += n

        return frame_payload, header

    def _read_frame_header(self) -> IVFFrameHeader | None:
        data = bytearray(IVF_FRAME_HEADER_SIZE)
        n = self._reader.readinto(data)
        if n == 0:
            return

        self.read_succesfull_count += n
        return IVFFrameHeader.parse(data)

    def _read_file_header(self) -> IVFFileHeader:
        data = bytearray(IVF_FILE_HEADER_SIZE)
        n = self._reader.readinto(data)
        if n == 0:
            raise EOFError("EOF")

        if n != IVF_FILE_HEADER_SIZE:
            raise IOError(
                f"Failed to read ivf header Expected {IVF_FILE_HEADER_SIZE} bytes, got {n} bytes."
            )

        header = IVFFileHeader.parse(data)

        if header.signature != IVF_FILE_HEADER_SIGNATURE:
            raise IOError("Signature mismatch. Use IVF container")

        if header.version != 0:
            raise ValueError("Unsuported header version")

        self.read_succesfull_count += n

        return header
