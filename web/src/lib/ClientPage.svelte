<script lang="ts">
  /**
   * Client Page - Browser acts as WebRTC Client
   *
   * Flow:
   * 1. Browser connects to Python server (ws.py)
   * 2. Browser requests offer from Python
   * 3. Python sends offer, browser creates answer
   * 4. Browser receives video from Python
   *
   * Use with: make run (examples/ws.py)
   */
  import { onMount, onDestroy } from "svelte";
  import { Signal } from "./Signal";

  const signal = new Signal();
  const pc = new RTCPeerConnection();

  let videoRef: HTMLVideoElement;
  let status = "Disconnected";

  onMount(async () => {
    pc.onicecandidate = (c) => {
      const candidate = c.candidate?.toJSON();
      if (!candidate) {
        return;
      }
      signal.send("trickle-ice", candidate);
      console.log("[Client] Sending ICE candidate", c);
    };

    pc.ontrack = (track) => {
      if (videoRef) {
        videoRef.srcObject = track.streams[0];
      }
      console.log("[Client] Got track", track);
      status = "Receiving video";
    };

    pc.onconnectionstatechange = () => {
      console.log("[Client] Connection state:", pc.connectionState);
      status = `Connection: ${pc.connectionState}`;
    };

    // Listen for offer from Python server
    signal.on("offer", async function (desc) {
      console.log("[Client] Received offer from server", desc);
      status = "Received offer, creating answer...";

      const session = new RTCSessionDescription({
        type: "offer",
        sdp: desc,
      });

      await pc.setRemoteDescription(session);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      console.log("[Client] Sending answer", answer);
      signal.send("answer", answer);
      status = "Answer sent, waiting for connection...";
    });

    signal.connect();
    await signal.connectedLock.wait;
    status = "Connected to signaling server";

    // Request offer from Python server
    signal.send("offer", undefined);
    status = "Requested offer from server...";
  });

  onDestroy(() => {
    signal.close();
    pc.close();
  });

  const start = () => signal.send("negotiate", undefined);
</script>

<div class="page">
  <h2>Client Mode</h2>
  <p class="description">Browser receives offer from Python server, sends answer back.</p>
  <p class="status">Status: {status}</p>

  <video bind:this={videoRef} controls autoplay playsinline>
    <track kind="captions" />
  </video>

  <div class="controls">
    <button type="button" on:click={start}>Start/Negotiate</button>
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
