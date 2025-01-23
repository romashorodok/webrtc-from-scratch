import argparse
import importlib
import os

import uvicorn
import watchfiles


def main(module: str, app: str):
    mod = importlib.import_module(module)
    application = getattr(mod, app)

    uvicorn.run(application, port=8080)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebRTC server")

    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="examples.examples_ws:app",
        help="the ASGI application as <module>:<attribute>",
    )

    parser.add_argument(
        "webrtc_src",
        type=str,
        nargs="?",
        default="../../src/webrtc/",
        help="the source code of webrtc lib",
    )

    parser.add_argument(
        "native_src",
        type=str,
        nargs="?",
        default="../../src/native/",
        help="the source code of native lib",
    )

    args = parser.parse_args()

    module_str, app_str = args.app.split(":", maxsplit=1)

    ROOT = os.path.dirname(__file__)

    webrtc_src_path = f"{ROOT}/{os.path.dirname(args.webrtc_src)}"
    native_src_path = f"{ROOT}/{os.path.dirname(args.native_src)}"

    watchfiles.run_process(
        webrtc_src_path, native_src_path, target=main, args=(module_str, app_str)
    )
