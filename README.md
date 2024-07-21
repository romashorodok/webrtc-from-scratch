Proof of concept that a WebRTC backend can be implemented without too much code, large dependencies and coding/decoding of media.

### Features

- Established ICE and DTLS connection with a browser
- Sending/Receiving media in the Chrome browser
- Reading IVF container format with VP8 codec

## Architecture
![](./docs/architecture_sendrecv.png)

## Credits

### [pion/webrtc](https://github.com/pion/webrtc)
Pure Golang implementation of the WebRTC protocol with zero dependencies. It has a well-decoupled architecture, but the complex implementation sometimes makes it difficult to figure out what's going on due to the abstraction. However, it also reduces the amount of code required to understand and work with it.
Also has been battle-tested in [livekit/livekit](https://github.com/livekit/livekit.git)

### [aiortc/aiortc](https://github.com/aiortc/aiortc)
Python implementation of the WebRTC protocol. It requires dependencies like libvpx or H.264 and Opus codecs, as well as other C/C++ libraries. It has an easy and simple architecture, which only requires [reading this draft diagram](https://draft.ortc.org/#overview*). 
There are many things to learn about media that are not in the context of WebRTC.