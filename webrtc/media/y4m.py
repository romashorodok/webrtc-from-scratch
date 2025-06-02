import io
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Self

_FRAME_MAGIC = b"FRAME"
_FILE_MAGIC = b"YUV4MPEG2"


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
class Planes:
    # Y (Luma): Brightness or grayscale information.
    y: bytes
    # U (Cb, Chroma Blue): Blue projection of the chroma (color) component
    u: bytes
    # V (Cr, Chroma Red): Red projection of the chroma (color) component
    v: bytes


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

    planes: Planes
    raw_params: bytes | None


class ChromaSampling(IntEnum):
    # Cs420 = "4:2:0"
    # Cs422 = "4:2:2"
    # Cs444 = "4:4:4"
    # Cs400 = "Monochrome"
    Cs420 = 0
    Cs422 = auto()
    Cs444 = auto()
    Cs400 = auto()

    def get_decimation(self) -> tuple[int, int] | None:
        """
        Provides the amount to right shift the luma plane dimensions to get the
        chroma plane dimensions.
        Only values 0 or 1 are ever returned.
        The plane dimensions must also be rounded up to accommodate odd luma plane
        sizes.
        Cs400 returns None, as there are no chroma planes.
        """
        match self.value:
            case ChromaSampling.Cs420:
                return 1, 1
            case ChromaSampling.Cs422:
                return 1, 0
            case ChromaSampling.Cs444:
                return 0, 0
            case ChromaSampling.Cs400 | _:
                return None

    def get_chroma_dimensions(
        self, luma_width: int, luma_height: int
    ) -> tuple[int, int]:
        """
        Calculates the size of a chroma plane for this sampling type, given the luma plane dimensions.
        """
        decimation = self.get_decimation()
        if not decimation:
            return 0, 0
        ss_x, ss_y = decimation
        return (luma_width + ss_x) >> ss_x, (luma_height + ss_y) >> ss_y


class ChromaSamplePosition(IntEnum):
    # The source video transfer function must be signaled
    # outside the AV1 bitstream.
    Unknown = 0
    # Horizontally co-located with (0, 0) luma sample, vertically positioned
    # in the middle between two luma samples.
    Vertical = 1
    # Co-located with (0, 0) luma sample.
    Colocated = 2


def map_y4m_color_space(
    color_space: Colorspace,
) -> tuple[ChromaSampling, ChromaSamplePosition]:
    match color_space:
        case Colorspace.Cmono | Colorspace.Cmono12:
            return ChromaSampling.Cs400, ChromaSamplePosition.Unknown
        case Colorspace.C420jpeg | Colorspace.C420paldv:
            return ChromaSampling.Cs420, ChromaSamplePosition.Unknown
        case Colorspace.C420mpeg2:
            return ChromaSampling.Cs420, ChromaSamplePosition.Vertical
        case Colorspace.C420 | Colorspace.C420p10 | Colorspace.C420p12:
            return ChromaSampling.Cs420, ChromaSamplePosition.Colocated
        case Colorspace.C422 | Colorspace.C422p10 | Colorspace.C422p12:
            return ChromaSampling.Cs422, ChromaSamplePosition.Colocated
        case Colorspace.C444 | Colorspace.C444p10 | Colorspace.C444p12:
            return ChromaSampling.Cs444, ChromaSamplePosition.Colocated


@dataclass
class VideoDetails:
    width: int
    height: int
    sample_aspect_ratio: Ratio
    bit_depth: int
    chroma_sampling: ChromaSampling
    chroma_sample_position: ChromaSamplePosition
    time_base: Ratio


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
        self.bytes_per_sample: int = 0
        self.__read_params()

    def get_video_details(self) -> VideoDetails:
        aspect_ratio = self.pixel_aspect
        assert aspect_ratio, "unable get the aspect ratio"

        assert self.colorspace, "unable get the colorspace"
        chroma_sampling, chroma_sample_position = map_y4m_color_space(self.colorspace)

        assert self.framerate, "unable get the framerate"

        return VideoDetails(
            width=self.width,
            height=self.height,
            sample_aspect_ratio=Ratio(1, 1)
            if aspect_ratio.numerator == 0 and aspect_ratio.denominator == 0
            else aspect_ratio,
            bit_depth=self.colorspace.get_bit_depth(),
            chroma_sampling=chroma_sampling,
            chroma_sample_position=chroma_sample_position,
            time_base=self.framerate,
        )

    def __read_params(self):
        """
        b'PEG2 W640 H480 F30:1 Ip A1:1 C420jpeg XYSCSS=420JPEG\n'
        """

        data = self._reader.readline()
        if len(data) < len(_FILE_MAGIC) and not data.startswith(_FILE_MAGIC):
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

        self.bytes_per_sample = frame_size
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
            planes=Planes(
                y=bytes(self.buf[0 : self.y_size]),
                u=bytes(self.buf[self.y_size : self.y_size + self.u_size]),
                v=bytes(self.buf[self.y_size + self.v_size :]),
            ),
            raw_params=planes,
        )
