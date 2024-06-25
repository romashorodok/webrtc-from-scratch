import socket
import asyncio
import logging


import ice
from ice import net
from ice.net.udp_mux import MultiUDPMux

logging.basicConfig(level=logging.DEBUG)


interfaces = net.interface_factory(
    net.InterfaceProvider.PSUTIL,
    [
        socket.AF_INET,
    ],
    False,
)

if len(interfaces) <= 0:
    interfaces = net.interface_factory(
        net.InterfaceProvider.PSUTIL,
        [
            socket.AF_INET,
        ],
        True,
    )


async def start_agent():
    loop = asyncio.get_event_loop()

    controlling_udp = MultiUDPMux(interfaces, loop)
    await controlling_udp.accept(9999)

    controlled_udp = MultiUDPMux(interfaces, loop)
    await controlled_udp.accept(0)

    controlling_agent = ice.Agent(
        ice.AgentOptions([ice.CandidateType.Host], controlling_udp, interfaces)
    )
    controlled_agent = ice.Agent(
        ice.AgentOptions([ice.CandidateType.Host], controlled_udp, interfaces)
    )

    controlling_creds = controlling_agent.get_local_credentials()
    controlled_creds = controlled_agent.get_local_credentials()

    controlling_agent.set_remote_credentials(controlled_creds[0], controlled_creds[1])
    controlled_agent.set_remote_credentials(controlling_creds[0], controlling_creds[1])

    controlling_agent.set_on_candidate(
        lambda candidate: controlled_agent.add_remote_candidate(candidate.to_ice_str())
    )
    controlled_agent.set_on_candidate(
        lambda candidate: controlling_agent.add_remote_candidate(candidate.to_ice_str())
    )

    await controlling_agent.gather_candidates()
    await controlled_agent.gather_candidates()

    controlled_agent.accept(controlling_creds[0], controlling_creds[1])

    # Controlling agent must start connection
    # Also, in webrtc context that agent must mutate state
    controlling_agent.dial(controlled_creds[0], controlled_creds[1])

    # first = controlling_agent._local_candidates[NetworkType.UDP][0]
    # second = controlling_agent._local_candidates[NetworkType.UDP][1]
    # print("is same ??", first == second)

    try:
        await asyncio.sleep(3600)
    finally:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    asyncio.run(start_agent())
