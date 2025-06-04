import json
import asyncio
import os
from typing import Awaitable, Callable

import zmq
from zmq.asyncio import Context, Socket

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

    async def send_frame(self, frame: bytes):
        await self.__yuv.send(frame)


async def reader(enc: Encoder):
    while True:
        frame = await enc.on_frame.get()
        print("on frame", frame)


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
                        "width": 0,
                        "height": 0,
                        "sample_aspect_ratio_num": 0,
                        "sample_aspect_ratio_den": 0,
                        "bit_depth": 0,
                        "chroma_sampling": 0,
                        "time_base_num": 0,
                        "time_base_dem": 0,
                    }
                ).encode(),
            ]
        )
        print("on nominated")

    while True:
        await encoder.nominated.wait()
        await asyncio.sleep(0.4)
        await encoder.send_frame(b"")


asyncio.run(main())
