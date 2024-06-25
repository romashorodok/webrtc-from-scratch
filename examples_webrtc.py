import asyncio
import peer_connection


async def main():
    pc = peer_connection.PeerConnection()
    await pc.gatherer.gather()
    pc.add_transceiver_from_kind(
        peer_connection.RTPCodecKind.Video,
        peer_connection.RTPTransceiverDirection.Sendrecv,
    )
    pc.add_transceiver_from_kind(
        peer_connection.RTPCodecKind.Audio,
        peer_connection.RTPTransceiverDirection.Sendrecv,
    )

    desc = await pc.create_offer()
    if not desc:
        return
    result = desc.marshal()
    print(str(result))


asyncio.run(main())
