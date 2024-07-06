def grouplines(sdp: str) -> tuple[list[str], list[list[str]]]:
    # Ensure the SDP data is a string (decode if it's a bytestring)
    if isinstance(sdp, bytes):
        sdp = sdp.decode()

    session = []
    media = []
    for line in sdp.splitlines():
        if line.startswith("m="):
            media.append([line])
        elif len(media):
            media[-1].append(line)
        else:
            session.append(line)
    return session, media

# Test the function with the provided SDP data
sdp_data = b'v=0\r\no=- 1012765056609774649 3929118917 IN IP4 0.0.0.0\r\ns=-\r\na=msid-semantic:WMS*\r\na=fingerprint:sha-256 C1:C3:5B:6B:90:A7:A6:DF:52:5C:91:62:47:EF:14:07:E5:25:42:5D:8E:B6:9F:28:E2:0F:6B:7B:EA:77:68:C6\r\na=extmap-allow-mixed\r\na=group:BUNDLE 1 2\r\nm=1 9/9 UDP/TLS/RTP/SAVPF 0 96\r\na=setup:passive\r\na=mid:1\r\na=sendrecv\r\na=ice-ufrag:HjqWfyihaLsn3VZ1\r\na=ice-pwd:nw7WShE0yIh9xGN6Y41bQtAiV7xtm4kk\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack pli\r\na=rtcp-fb:96 goog-remb \r\na=ssrc:3243394032 cname:bOgnhu8hUPGs1qhu\r\na=ssrc:3243394032 msid:bOgnhu8hUPGs1qhu sCHve6TxqOpnhVem\r\na=msid:bOgnhu8hUPGs1qhu sCHve6TxqOpnhVem\r\na=rid:bOgnhu8hUPGs1qhu send\r\na=sendrecv\r\na=fingerprint:sha-256 C1:C3:5B:6B:90:A7:A6:DF:52:5C:91:62:47:EF:14:07:E5:25:42:5D:8E:B6:9F:28:E2:0F:6B:7B:EA:77:68:C6\r\na=candidate:485737556 1 udp 2130706431 192.168.43.217 58363 typ host\r\na=candidate:485737556 2 udp 2130706430 192.168.43.217 58363 typ host\r\na=end-of-candidates\r\nm=2 9/9 UDP/TLS/RTP/SAVPF 0 111\r\na=setup:passive\r\na=mid:2\r\na=sendrecv\r\na=ice-ufrag:HjqWfyihaLsn3VZ1\r\na=ice-pwd:nw7WShE0yIh9xGN6Y41bQtAiV7xtm4kk\r\na=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=ssrc:3913659348 cname:r4ie8AYVETMusMQ4\r\na=ssrc:3913659348 msid:r4ie8AYVETMusMQ4 YjLrDMbbLLwUM470\r\na=msid:r4ie8AYVETMusMQ4 YjLrDMbbLLwUM470\r\na=rid:r4ie8AYVETMusMQ4 send\r\na=sendrecv\r\na=fingerprint:sha-256 C1:C3:5B:6B:90:A7:A6:DF:52:5C:91:62:47:EF:14:07:E5:25:42:5D:8E:B6:9F:28:E2:0F:6B:7B:EA:77:68:C6\r\n'

session, media = grouplines(sdp_data)
print(session)
print(media)

