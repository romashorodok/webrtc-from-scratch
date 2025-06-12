import json
import asyncio
import os
from typing import Awaitable, Callable

import zmq
from zmq.asyncio import Context, Socket

from webrtc import media
from webrtc.media.y4m import Y4mFrame

yuv_channel = os.environ.get("YUV_CHANNEL", "ipc:///tmp/yuv.sock")
transport_channel = os.environ.get("TRANSPORT_CHANNEL", "ipc:///tmp/transport.sock")


class Encoder:
    def __init__(
        self,
    ) -> None:
        ctx = Context()

        self.__sock = ctx.socket(zmq.DEALER)
        self.__sock.setsockopt(zmq.IDENTITY, os.urandom(8))

        self.__yuv = ctx.socket(zmq.PUSH)
        self.nominated = asyncio.Event()
        self._running = True
        self.on_frame = asyncio.Queue(30)

        self._on_nominated: Callable[[Socket], Awaitable[None]] | None = None

    def on_nominated(
        self, cb: Callable[[Socket], Awaitable[None]] | Callable[[Socket], None]
    ):
        if asyncio.iscoroutinefunction(cb):
            self._on_nominated = cb
        else:

            async def wrapper(_sock: Socket):
                cb(self.__sock)

            self._on_nominated = wrapper

    async def recv_loop(self):
        self.__sock.connect(transport_channel)
        self.__yuv.connect(yuv_channel)
        await self.__sock.send_multipart([b"connect"])

        while self._running:
            try:
                payload = await asyncio.wait_for(
                    self.__sock.recv_multipart(), timeout=5
                )
                await self.__handler(payload)
            except asyncio.TimeoutError:
                print("[ZMQ] No data received in 5 seconds")
                asyncio.ensure_future(self.recv_loop())
                return
            except Exception as e:
                print(f"[Receiver] Error: {e}")
                await asyncio.sleep(0.5)

    async def __handler(self, payload: list[bytes]):
        match payload[0]:
            case b"nominated":
                self.nominated.set()
                if self._on_nominated:
                    await self._on_nominated(self.__sock)
            case b"connected":
                print("connected pair")
            case b"frame":
                await self.on_frame.put(payload[1])
            case _:
                pass

    async def send_frame(
        self,
        bytes_per_sample: int,
        width: int,
        chroma_width: int,
        y_plane: bytes,
        u_plane: bytes,
        v_plane: bytes,
    ):
        await self.__yuv.send_multipart(
            [
                bytes_per_sample.to_bytes(4, "big"),
                width.to_bytes(4, "big"),
                chroma_width.to_bytes(4, "big"),
                y_plane,
                u_plane,
                v_plane,
            ]
        )


async def reader(enc: Encoder):
    while True:
        frame = await enc.on_frame.get()
        print("on frame", frame)


def pre_read_y4m(file_path: str):
    with open(file_path, "rb") as file:
        n_frames = 0
        reader = media.Y4mDecoder(file)
        frames: list[Y4mFrame] = []
        for frame in reader:
            n_frames += 1
            frames.append(frame)
        return frames, reader


frames, y4m_reader = pre_read_y4m("output.y4m")
video_details = y4m_reader.get_video_details()


async def main():
    encoder = Encoder()
    asyncio.ensure_future(encoder.recv_loop())

    asyncio.ensure_future(reader(encoder))

    @encoder.on_nominated
    async def on_nominated(sock: Socket):
        await sock.send_multipart(
            [
                b"config",
                json.dumps(
                    {
                        "width": video_details.width,
                        "height": video_details.height,
                        "sample_aspect_ratio_num": video_details.sample_aspect_ratio.denominator,
                        "sample_aspect_ratio_den": video_details.sample_aspect_ratio.numerator,
                        "bit_depth": video_details.bit_depth,
                        "chroma_sampling": video_details.chroma_sampling,
                        "time_base_num": video_details.time_base.numerator,
                        "time_base_dem": video_details.time_base.denominator,
                    }
                ).encode(),
            ]
        )
        print("on nominated")

    frame_index = 0
    chroma_width, _ = video_details.chroma_sampling.get_chroma_dimensions(
        video_details.width,
        video_details.height,
    )

    while True:
        await encoder.nominated.wait()
        if frame_index >= len(frames):
            frame_index = 0

        frame = frames[frame_index]
        await encoder.send_frame(
            bytes_per_sample=1,
            width=video_details.width,
            chroma_width=chroma_width,
            y_plane=frame.planes.y,
            u_plane=frame.planes.u,
            v_plane=frame.planes.v,
        )
        frame_index += 1


asyncio.run(main())
