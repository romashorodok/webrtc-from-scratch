import asyncio
import peer_connection


test_answer = """v=0
o=mozilla...THIS_IS_SDPARTA-99.0 2413216437558734132 0 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 06:95:5B:5C:44:9D:DE:9D:AF:1A:97:01:AD:3B:64:01:5D:2B:8B:DB:30:78:B5:92:91:A2:90:B1:E9:84:8C:41
a=group:BUNDLE 0
a=ice-options:trickle
a=msid-semantic:WMS *
m=video 9 UDP/TLS/RTP/SAVPF 96 97 106 107 108 109 98 99
c=IN IP4 0.0.0.0
a=recvonly
a=fmtp:106 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1
a=fmtp:108 profile-level-id=42e01f;level-asymmetry-allowed=1
a=fmtp:96 max-fs=12288;max-fr=60
a=fmtp:97 apt=96
a=fmtp:107 apt=106
a=fmtp:109 apt=108
a=fmtp:98 max-fs=12288;max-fr=60
a=fmtp:99 apt=98
a=ice-pwd:82f54ed224ad0cc92998a1618f4001d4
a=ice-ufrag:4a74bb97
a=mid:0
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 goog-remb
a=rtcp-fb:106 nack
a=rtcp-fb:106 nack pli
a=rtcp-fb:106 ccm fir
a=rtcp-fb:106 goog-remb
a=rtcp-fb:108 nack
a=rtcp-fb:108 nack pli
a=rtcp-fb:108 ccm fir
a=rtcp-fb:108 goog-remb
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 goog-remb
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtpmap:97 rtx/90000
a=rtpmap:106 H264/90000
a=rtpmap:107 rtx/90000
a=rtpmap:108 H264/90000
a=rtpmap:109 rtx/90000
a=rtpmap:98 VP9/90000
a=rtpmap:99 rtx/90000
a=setup:active
a=ssrc:752126633 cname:{49f5b574-99f2-493c-9c7c-d5a25a6f6685}
"""


async def main():
    pc = peer_connection.PeerConnection()
    await pc.add_transceiver_from_kind(
        peer_connection.RTPCodecKind.Video,
        peer_connection.RTPTransceiverDirection.Sendrecv,
    )
    # await pc.add_transceiver_from_kind(
    #     peer_connection.RTPCodecKind.Video,
    #     peer_connection.RTPTransceiverDirection.Sendrecv,
    # )
    await pc.gatherer.gather()
    pc.gatherer.agent.dial()
    desc = await pc.create_offer()
    if not desc:
        return
    await pc.set_local_description(peer_connection.SessionDescriptionType.Offer, desc)
    raw = desc.marshal()
    print("offer", raw)

    # raw = raw.decode()

    pc1 = peer_connection.PeerConnection()
    await pc1.add_transceiver_from_kind(
        peer_connection.RTPCodecKind.Audio,
        peer_connection.RTPTransceiverDirection.Sendrecv,
    )
    await pc1.gatherer.gather()
    pc1.gatherer.agent.dial()
    desc = await pc1.create_offer()
    if not desc:
        return

    # raw = desc.marshal().decode()
    #
    # desc = peer_connection.SessionDescription.parse(raw)
    print("offer from remote", desc.marshal())

    await pc.set_remote_description(peer_connection.SessionDescriptionType.Answer, desc)


asyncio.run(main())
