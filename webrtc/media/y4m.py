import io
from dataclasses import dataclass
from enum import Enum
from typing import Self

_FRAME_MAGIC = b"FRAME"


@dataclass
class Ratio:
    """
    F30:1
    """

    numerator: int
    denominator: int

    @classmethod
    def parse(cls, value: bytes) -> Self:
        num, den = value.split(b":")
        return cls(int(num), int(den))


class Colorspace(Enum):
    # /// Grayscale only, 8-bit.
    Cmono = b"mono"
    # /// Grayscale only, 12-bit.
    Cmono12 = b"mono12"
    # /// 4:2:0 with coincident chroma planes, 8-bit.
    C420 = b"420"
    # /// 4:2:0 with coincident chroma planes, 10-bit.
    C420p10 = b"420p10"
    # /// 4:2:0 with coincident chroma planes, 12-bit.
    C420p12 = b"420p12"
    # /// 4:2:0 with biaxially-displaced chroma planes, 8-bit.
    C420jpeg = b"420jpeg"
    # /// 4:2:0 with coincident Cb and vertically-displaced Cr, 8-bit.
    C420paldv = b"420paldv"
    # /// 4:2:0 with vertically-displaced chroma planes, 8-bit.
    C420mpeg2 = b"420mpeg2"
    # /// 4:2:2, 8-bit.
    C422 = b"422"
    # /// 4:2:2, 10-bit.
    C422p10 = b"422p10"
    # /// 4:2:2, 12-bit.
    C422p12 = b"422p12"
    # /// 4:4:4, 8-bit.
    C444 = b"444"
    # /// 4:4:4, 10-bit.
    C444p10 = b"444p10"
    # /// 4:4:4, 12-bit.
    C444p12 = b"444p12"

    def get_bit_depth(self) -> int:
        match Colorspace(self.value):
            case (
                Colorspace.Cmono
                | Colorspace.C420
                | Colorspace.C422
                | Colorspace.C444
                | Colorspace.C420jpeg
                | Colorspace.C420paldv
                | Colorspace.C420mpeg2
            ):
                return 8
            case Colorspace.C420p10 | Colorspace.C422p10 | Colorspace.C444p10:
                return 10
            case (
                Colorspace.Cmono12
                | Colorspace.C420p12
                | Colorspace.C422p12
                | Colorspace.C444p12
            ):
                return 12

        raise ValueError("not found bit depth")

    def get_bytes_per_sample(self) -> int:
        if self.get_bit_depth() <= 8:
            return 1

        return 2


type YUV = tuple[int, int, int]


def get_plane_sizes(width: int, height: int, colorspace: Colorspace) -> YUV:
    y_plane_size = width * height * colorspace.get_bytes_per_sample()

    # TODO: // may be replaced with >>
    c420_chroma_size = (
        ((width + 1) // 2) * ((height + 1) // 2) * colorspace.get_bytes_per_sample()
    )
    c422_chroma_size = ((width + 1) // 2) * height * colorspace.get_bytes_per_sample()

    c420_sizes = (y_plane_size, c420_chroma_size, c420_chroma_size)
    c422_sizes = (y_plane_size, c422_chroma_size, c422_chroma_size)
    c444_sizes = (y_plane_size, y_plane_size, y_plane_size)

    match colorspace:
        case Colorspace.Cmono | Colorspace.Cmono12:
            return y_plane_size, 0, 0
        case (
            Colorspace.C420
            | Colorspace.C420p10
            | Colorspace.C420p12
            | Colorspace.C420jpeg
            | Colorspace.C420paldv
            | Colorspace.C420mpeg2
        ):
            return c420_sizes
        case Colorspace.C422 | Colorspace.C422p10 | Colorspace.C422p12:
            return c422_sizes
        case Colorspace.C444 | Colorspace.C444p10 | Colorspace.C444p12:
            return c444_sizes

    raise ValueError("not found plane size")


@dataclass
class Y4mFrame:
    """
    Y4m container has YUV color model.

    A YUV video frame:
        Y (Luma): Brightness or grayscale information.
        U (Cb, Chroma Blue): Blue projection of the chroma (color) component
        V (Cr, Chroma Red): Red projection of the chroma (color) component

    Luma plane = Y plane (grayscale/brightness)
    Chroma planes = U (Cb) and V (Cr) planes (color information)
    """

    frame: bytes
    planes: bytes | None


_BUFFER_SIZE = 1024 * 1024 * 1024  # 1GB


class Y4mDecoder:
    def __init__(self, reader: io.BufferedReader) -> None:
        self._reader = reader

        self.width = 0
        self.height = 0
        self.framerate: Ratio | None = None
        self.pixel_aspect: Ratio | None = None
        self.colorspace: Colorspace | None = None
        self.buf = bytearray(0)
        self.y_size = self.u_size = self.v_size = 0
        self.__read_params()

    def __read_params(self):
        """
        b'PEG2 W640 H480 F30:1 Ip A1:1 C420jpeg XYSCSS=420JPEG\n'
        """

        data = self._reader.readline()
        if len(data) < len(_FRAME_MAGIC) and not data.startswith(_FRAME_MAGIC):
            raise ValueError("")

        params = data[len(_FRAME_MAGIC) :].split(b" ")

        for param in params:
            name, value = param[:1], param[1:]
            match name:
                case b"W":
                    self.width = int(value)
                case b"H":
                    self.height = int(value)
                case b"F":
                    self.framerate = Ratio.parse(value)
                case b"A":
                    self.pixel_aspect = Ratio.parse(value)
                case b"C":
                    self.colorspace = Colorspace(value)

        if not self.colorspace:
            self.colorspace = Colorspace.C420

        if not self.width or not self.height:
            raise ValueError("y4m must have width and height")

        self.y_size, self.u_size, self.v_size = get_plane_sizes(
            self.width, self.height, self.colorspace
        )

        # 460800 bytes = 640×480 YUV 4:2:0 frame
        frame_size = self.y_size + self.u_size + self.v_size
        if frame_size > _BUFFER_SIZE:
            raise ValueError("Out of memory")

        self.buf = bytearray(frame_size)

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Y4mFrame:
        params_header = self._reader.readline()
        if not params_header:
            raise StopIteration("Invalid")
        nbytes = len(params_header)

        if nbytes < len(_FRAME_MAGIC) or not params_header.startswith(_FRAME_MAGIC):
            print("invalid header")
            raise StopIteration("invalid params header")

        planes: bytes | None = None
        start_params_offset = len(_FRAME_MAGIC)

        if nbytes - start_params_offset > 0:
            if _planes := bytes(params_header[start_params_offset:nbytes]):
                if _planes != b"\n":
                    planes = _planes

        nbytes = self._reader.readinto(self.buf)
        if not nbytes:
            raise StopIteration("EOF")

        return Y4mFrame(
            frame=bytes(
                self.buf[0 : self.y_size]
                + self.buf[self.y_size : self.y_size + self.u_size]
                + self.buf[self.y_size + self.u_size :]
            ),
            planes=planes,
        )
