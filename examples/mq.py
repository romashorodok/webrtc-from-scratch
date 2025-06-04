import asyncio
import os
from typing import Awaitable, Callable

import zmq
from zmq.asyncio import Context

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
        self._on_frame: Callable[[bytes], Awaitable[None]] | None = None

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
            case b"connected":
                print("connected pair")
            case b"frame":
                if self._on_frame:
                    await self._on_frame(payload[1])
            case _:
                pass

    async def send_frame(self, frame: bytes):
        await self.__yuv.send(frame)

    def on_frame(
        self, cb: Callable[[bytes], Awaitable[None]] | Callable[[bytes], None]
    ):
        if asyncio.iscoroutinefunction(cb):
            self._on_frame = cb
        else:

            async def wrapper(frame: bytes):
                cb(frame)

            self._on_frame = wrapper


async def main():
    encoder = Encoder()
    asyncio.ensure_future(encoder.recv_loop())

    @encoder.on_frame
    def on_new_frame(frame: bytes):
        print("on frame")

    while True:
        await encoder.nominated.wait()

        await encoder.send_frame(b"")


asyncio.run(main())
