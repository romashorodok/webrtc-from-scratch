import argparse
import asyncio
import importlib
import logging
import os
from functools import partial

from webrtc import event_loop

logger = logging.getLogger("webrtc.server")


async def run_server(module: str, app: str, port: int = 9000) -> None:
    import uvicorn

    mod = importlib.import_module(module)

    # process_bench = getattr(mod, "process_bench")

    # await process_bench()

    application = getattr(mod, app)
    config = uvicorn.Config(application, port=port, loop="asyncio")
    server = uvicorn.Server(config)
    await server.serve()


def server_loop_factory(
    *,
    packet_workers: int = 0,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
    require_native: bool = False,
    force_asyncio: bool = False,
):
    return event_loop.new_event_loop(
        packet_workers=packet_workers,
        packet_queue_capacity=packet_queue_capacity,
        receive_packet_budget=receive_packet_budget,
        receive_time_budget_us=receive_time_budget_us,
        require_native=require_native,
        force_asyncio=force_asyncio,
    )


def server_routine(
    module: str,
    app: str,
    port: int = 9000,
    packet_workers: int = 0,
    packet_queue_capacity: int = 2048,
    receive_packet_budget: int = 32,
    receive_time_budget_us: int = 100,
    require_native: bool = False,
    force_asyncio: bool = False,
) -> None:
    factory = partial(
        server_loop_factory,
        packet_workers=packet_workers,
        packet_queue_capacity=packet_queue_capacity,
        receive_packet_budget=receive_packet_budget,
        receive_time_budget_us=receive_time_budget_us,
        require_native=require_native,
        force_asyncio=force_asyncio,
    )
    with asyncio.Runner(loop_factory=factory) as runner:
        # Runner constructs and owns the selected loop, including async-generator
        # and default-executor shutdown. No global event-loop policy is changed.
        loop = runner.get_loop()
        mode = event_loop.event_loop_mode()
        reason = event_loop.event_loop_selection_reason()
        print(
            "WebRTC event loop "
            f"mode={mode} type={type(loop).__module__}.{type(loop).__name__} "
            f"({reason})",
            flush=True,
        )
        logger.info(
            "WebRTC server event loop mode=%s (%s)",
            mode,
            reason,
        )
        runner.run(run_server(module, app, port))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebRTC server")

    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="examples_ws:app",
        help="the ASGI application as <module>:<attribute>",
    )
    parser.add_argument("--packet-workers", type=int, default=0)
    parser.add_argument("--packet-queue-capacity", type=int, default=2048)
    parser.add_argument("--receive-packet-budget", type=int, default=32)
    parser.add_argument("--receive-time-budget-us", type=int, default=100)
    loop_mode = parser.add_mutually_exclusive_group()
    loop_mode.add_argument(
        "--require-native-event-loop",
        action="store_true",
        help="fail startup unless a production-compatible native loop is available",
    )
    loop_mode.add_argument(
        "--force-asyncio-event-loop",
        action="store_true",
        help="always use stock asyncio even if a native artifact is compatible",
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

    from watchfiles import DefaultFilter, run_process

    run_process(
        f"{ROOT}/../packages",
        f"{ROOT}/../webrtc",
        f"{ROOT}/examples",
        target=server_routine,
        args=(
            module_str,
            app_str,
            args.port,
            args.packet_workers,
            args.packet_queue_capacity,
            args.receive_packet_budget,
            args.receive_time_budget_us,
            args.require_native_event_loop,
            args.force_asyncio_event_loop,
        ),
        watch_filter=DefaultFilter(
            ignore_dirs=["target", "__pycache__"],
            # ignore_entity_patterns=[r".*\.so$", r".*\.dll$"],
        ),
    )
