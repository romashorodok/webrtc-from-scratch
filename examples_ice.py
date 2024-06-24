import socket
import asyncio
import logging


import ice
from ice import net

logging.basicConfig(level=logging.DEBUG)


interfaces = net.interface_factory(
    net.InterfaceProvider.PSUTIL,
    [
        socket.AF_INET,
    ],
    True,
)


async def start_agent():
    agent_params = ice.AgentOptions(True, [ice.CandidateType.Host], interfaces)
    agent = ice.Agent(agent_params)
    agent.gather_candidates()

    try:
        await asyncio.sleep(3600)
    finally:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    asyncio.run(start_agent())
