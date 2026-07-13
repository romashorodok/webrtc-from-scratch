"""Static gate for context-sensitive worker-method application typing.

Run with: pyright tests/typecheck/worker_contract.py
"""

from typing import Awaitable, assert_type

from webrtc.performance import ObservedComponent, async_worker_method, worker


class Codec(ObservedComponent):
    @worker
    def decode(self, packet: bytes) -> bytes:
        return packet


decode_in_runtime = async_worker_method(Codec().decode)
assert_type(decode_in_runtime(b"packet"), Awaitable[bytes])


async def application() -> bytes:
    # The application view is awaitable; using it as bytes without awaiting is
    # rejected by the static checker.
    return await decode_in_runtime(b"packet")
