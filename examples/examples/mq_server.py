import asyncio
import json
import os
from typing import Awaitable, Callable

import zmq
from zmq.asyncio import Context, Socket


yuv_channel = os.environ.get("YUV_CHANNEL", "ipc:///tmp/yuv.sock")
transport_channel = os.environ.get("TRANSPORT_CHANNEL", "ipc:///tmp/transport.sock")


class LocalEncoder:
    def __init__(self) -> None:
        ctx = Context()

        self.__sock = ctx.socket(zmq.ROUTER)
        pass
