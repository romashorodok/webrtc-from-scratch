import asyncio
import logging
import threading
import signal
import functools

import ice

logging.basicConfig(level=logging.DEBUG)

# While a Task running in event loop -- no other Task can run on same thread
# When inside a task exec await, the running task is suspended
# When task is suspended event loop exec next task

# To make a coroutine from a different OS thread, must be used run_coroutine_threadsafe()
# It return concurrent.futures.Future


async def coro_func() -> int:
    corot = asyncio.sleep(1, 1)
    print("coro_func")
    return await corot


def start_loop(loop: asyncio.AbstractEventLoop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


# https://stackoverflow.com/questions/5815675/what-is-sock-dgram-and-sock-stream


async def start_agent():
    agent_params = ice.AgentOptions(
        True,
        [ice.CandidateType.Host],
    )
    agent = ice.Agent(agent_params)
    agent.gather_candidates()

    try:
        await asyncio.sleep(3600)
    finally:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(loop.stop)

    print(agent)


async def main():
    loop = asyncio.new_event_loop()

    def ask_exit(signame, loop):
        print("got signal %s: exit" % signame)
        loop.stop()

    for signame in {"SIGINT", "SIGTERM"}:
        loop.add_signal_handler(
            getattr(signal, signame), functools.partial(ask_exit, signame, loop)
        )

    t = threading.Thread(target=start_loop, args=(loop,))
    t.start()

    # In terms coro_func is scheduled task on the event loop
    future = asyncio.run_coroutine_threadsafe(coro_func(), loop)

    # def create_udp_endpoint():
    #     return loop.create_datagram_endpoint(UDPMux, local_addr=("127.0.0.1", 9999))

    # Schedule the creation of the UDP endpoint on the new event loop
    # transport, protocol = await asyncio.wrap_future(
    #     asyncio.run_coroutine_threadsafe(create_udp_endpoint(), loop)
    # )

    # _ = protocol

    print("Run test")
    result = future.result()

    print("Result of feature", result)

    try:
        await asyncio.sleep(3600)
    finally:
        # transport.close()
        loop.call_soon_threadsafe(loop.stop)
        t.join()


if __name__ == "__main__":
    asyncio.run(start_agent())
