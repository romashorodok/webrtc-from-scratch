import argparse
import asyncio
import importlib
import os

import uvicorn
from watchfiles import DefaultFilter, run_process


async def run_server(module: str, app: str):
    mod = importlib.import_module(module)
    application = getattr(mod, app)

    config = uvicorn.Config(application, port=9000, loop="asyncio")
    server = uvicorn.Server(config)
    await server.serve()


def server_routine(module: str, app: str):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(run_server(module, app))


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
