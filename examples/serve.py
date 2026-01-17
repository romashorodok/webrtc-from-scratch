import argparse
import asyncio
import importlib
import os

import uvicorn
from watchfiles import DefaultFilter, run_process


async def run_server(module: str, app: str, port: int = 9000):
    mod = importlib.import_module(module)

    # process_bench = getattr(mod, "process_bench")

    # await process_bench()

    application = getattr(mod, app)
    config = uvicorn.Config(application, port=port, loop="asyncio")
    server = uvicorn.Server(config)
    await server.serve()


def server_routine(module: str, app: str, port: int = 9000):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(run_server(module, app, port))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebRTC server")

    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="examples_ws:app",
        help="the ASGI application as <module>:<attribute>",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="port to run the server on (default: 9000)",
    )

    args = parser.parse_args()

    module_str, app_str = args.app.split(":", maxsplit=1)

    print(f"Watching for changes in ../packages and ../webrtc")
    print(f"Starting server on port {args.port}")

    ROOT = os.path.dirname(__file__)

    run_process(
        f"{ROOT}/../packages",
        f"{ROOT}/../webrtc",
        f"{ROOT}/examples",
        target=server_routine,
        args=(module_str, app_str, args.port),
        watch_filter=DefaultFilter(
            ignore_dirs=["target", "__pycache__"],
            # ignore_entity_patterns=[r".*\.so$", r".*\.dll$"],
        ),
    )
