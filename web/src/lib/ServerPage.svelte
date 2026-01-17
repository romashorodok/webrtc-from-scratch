<script lang="ts">
  /**
   * Server Page - Browser acts as WebRTC Server
   *
   * Flow:
   * 1. Browser connects to Python client (client.py)
   * 2. Browser creates offer and sends to Python
   * 3. Python sends answer back
   * 4. Browser receives video from Python
   *
   * Use with: make client (examples/client.py)
   */
  import { onMount, onDestroy } from "svelte";
  import { Signal } from "./Signal";

  const signal = new Signal();
  const pc = new RTCPeerConnection();

  let videoRef: HTMLVideoElement;
  let status = "Disconnected";

  onMount(async () => {
    // Add transceiver to receive video (recvonly)
    pc.addTransceiver("video", { direction: "recvonly" });

    pc.onicecandidate = (c) => {
      const candidate = c.candidate?.toJSON();
      if (!candidate) {
        return;
      }
      signal.send("trickle-ice", candidate);
      console.log("[Server] Sending ICE candidate", c);
    };

    pc.ontrack = (track) => {
      if (videoRef) {
        videoRef.srcObject = track.streams[0];
      }
      console.log("[Server] Got track", track);
      status = "Receiving video";
    };

    pc.onconnectionstatechange = () => {
      console.log("[Server] Connection state:", pc.connectionState);
      status = `Connection: ${pc.connectionState}`;
    };

    // Listen for answer from Python client
    signal.on("answer", async function (data) {
      console.log("[Server] Received answer from client", data);
      status = "Received answer, establishing connection...";

      const parsed = typeof data === "string" ? JSON.parse(data) : data;
      const session = new RTCSessionDescription({
        type: "answer",
        sdp: parsed.sdp,
      });

      await pc.setRemoteDescription(session);
      console.log("[Server] Remote description set");
      status = "Connection established, waiting for video...";
    });

    // Listen for ICE candidates from Python client
    signal.on("trickle-ice", async function (data) {
      const parsed = typeof data === "string" ? JSON.parse(data) : data;
      if (parsed.candidate) {
        console.log("[Server] Adding remote ICE candidate", parsed);
        await pc.addIceCandidate(new RTCIceCandidate(parsed));
      }
    });

    signal.connect();
    await signal.connectedLock.wait;
    status = "Connected to signaling server";
  });

  onDestroy(() => {
    signal.close();
    pc.close();
  });

  const createOffer = async () => {
    status = "Creating offer...";
    console.log("[Server] Creating offer");

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    console.log("[Server] Sending offer to Python client", offer);
    signal.send("offer", {
      type: "offer",
      sdp: offer.sdp,
    });

    status = "Offer sent, waiting for answer...";
  };
</script>

<div class="page">
  <h2>Server Mode</h2>
  <p class="description">Browser creates offer, Python client sends answer back.</p>
  <p class="status">Status: {status}</p>

  <video bind:this={videoRef} controls autoplay playsinline>
    <track kind="captions" />
  </video>

  <div class="controls">
    <button type="button" on:click={createOffer}>Create Offer</button>
  </div>
</div>

<style>
  .page {
    padding: 1rem;
  }

  .description {
    color: #666;
    font-size: 0.9rem;
  }

  .status {
    color: #007bff;
    font-weight: bold;
  }

  video {
    width: 100%;
    max-width: 640px;
    background: #000;
    margin: 1rem 0;
  }

  .controls {
    margin-top: 1rem;
  }

  button {
    padding: 0.5rem 1rem;
    font-size: 1rem;
    cursor: pointer;
  }
</style>
