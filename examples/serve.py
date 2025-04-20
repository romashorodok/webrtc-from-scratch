import argparse
import asyncio
import importlib

import uvicorn
from watchfiles import DefaultFilter, awatch

current_server_task = None
server: uvicorn.Server | None = None


async def run_server(module: str, app: str):
    mod = importlib.import_module(module)
    application = getattr(mod, app)

    config = uvicorn.Config(application, port=9000, loop="asyncio")
    global server
    server = uvicorn.Server(config)
    await server.serve()


async def main(module: str, app: str):
    global current_server_task

    print("🔍 Watching for changes in ../packages and ../webrtc")

    current_server_task = asyncio.create_task(run_server(module, app))

    async for _ in awatch(
        "../packages",
        "../webrtc",
        watch_filter=DefaultFilter(
            ignore_dirs=["target", "__pycache__"],
            # ignore_entity_patterns=[r".*\.so$", r".*\.dll$"],
        ),
    ):
        print("Change detected, reloading server...")

        if current_server_task:
            try:
                current_server_task.cancel()
            except asyncio.CancelledError:
                print("Server task cancelled cleanly")

        if server:
            await server.shutdown()

        current_server_task = asyncio.create_task(run_server(module, app))


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
    asyncio.run(main(module_str, app_str))
