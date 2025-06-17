import argparse
import asyncio
from concurrent.futures import ProcessPoolExecutor
import importlib
from multiprocessing import Process
from multiprocessing.shared_memory import SharedMemory
import os
from time import sleep

import uvicorn
from watchfiles import DefaultFilter, run_process

from webrtc import media


# filename = "output.y4m"
filename = "test.y4m"
with open(filename, "rb") as file:
    y4m_reader = media.Y4mDecoder(file)

PROCESSING_WORKERS = 2


def encoder_process():
    while True:
        sleep(2)
        print("worker")


async def run_server(module: str, app: str):
    mod = importlib.import_module(module)

    application = getattr(mod, app)
    config = uvicorn.Config(application, port=9000, loop="asyncio", interface="asgi3")
    server = uvicorn.Server(config)
    await server.serve()


def server_routine(module: str, app: str):
    loop = asyncio.new_event_loop()

    executor = ProcessPoolExecutor(max_workers=PROCESSING_WORKERS)
    shared_memory_slots = [
        SharedMemory(create=True, size=y4m_reader.buffer_bytes_size)
        for _ in range(PROCESSING_WORKERS)
    ]

    p = Process(target=encoder_process, name="encoder")
    try:
        p.start()
        loop.run_until_complete(run_server(module, app))
    finally:
        executor.shutdown(wait=True, cancel_futures=True)

        p.terminate()
        p.join()

        for shm in shared_memory_slots:
            shm.close()
            shm.unlink()

        print("collected resources")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebRTC server")

    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="examples_ws:app",
        help="the ASGI application as <module>:<attribute>",
    )

    args = parser.parse_args()

    module_str, app_str = args.app.split(":", maxsplit=1)

    print("Watching for changes in ../packages and ../webrtc")

    ROOT = os.path.dirname(__file__)

    run_process(
        f"{ROOT}/../packages",
        f"{ROOT}/../webrtc",
        f"{ROOT}/examples",
        target=server_routine,
        args=(module_str, app_str),
        watch_filter=DefaultFilter(
            ignore_dirs=["target", "__pycache__"],
            # ignore_entity_patterns=[r".*\.so$", r".*\.dll$"],
        ),
    )
