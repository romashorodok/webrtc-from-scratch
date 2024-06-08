import asyncio
import logging
import threading
from typing import override, Any

logging.basicConfig(level=logging.DEBUG)

# While a Task running in event loop -- no other Task can run on same thread
# When inside a task exec await, the running task is suspended
# When task is suspended event loop exec next task

# To make a coroutine from a different OS thread, must be used run_coroutine_threadsafe()
# It return concurrent.futures.Future


class UDPMux(asyncio.DatagramProtocol):
    @override
    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        self._transport = transport

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        message = data.decode()
        print(f"Received message: {message} from {addr}")

        # You can send a response if needed
        response = f"Received your message: {message}"
        self._transport.sendto(response.encode(), addr)

        return super().datagram_received(data, addr)


async def coro_func():
    corot = asyncio.sleep(1, 1)
    print("coro_func")
    return await corot


loop = asyncio.new_event_loop()


def start_loop(loop: asyncio.AbstractEventLoop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


t = threading.Thread(target=start_loop, args=(loop,))
t.start()


if __name__ == "__main__":
    # In terms coro_func is scheduled task on the event loop
    future = asyncio.run_coroutine_threadsafe(coro_func(), loop)

    print("Run test")
    result = future.result()

    loop.call_soon_threadsafe(loop.stop)
    t.join()

    # async def main():
    #     loop = asyncio.get_running_loop()
    #
    #     transport, protocol = await loop.create_datagram_endpoint(
    #         UDPMux, local_addr=("127.0.0.1", 9999)
    #     )
    #
    #     try:
    #         await asyncio.sleep(3600)  # Run for 1 hour
    #     finally:
    #         transport.close()
    #         loop.call_soon_threadsafe(loop.stop)
    #
    # asyncio.run(main())
