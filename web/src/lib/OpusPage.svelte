<script lang="ts">
  /**
   * Opus Audio Page - Bidirectional Audio with Sendrecv Transceiver
   *
   * Flow:
   * 1. Browser connects to Python Opus server (opus_ws.py on port 9001)
   * 2. Browser requests offer from Python
   * 3. Python sends offer with ONE audio m= line: sendrecv
   * 4. Browser adds microphone and creates answer
   * 5. Bidirectional audio flow established
   *
   * Use with: uvicorn examples.opus_ws:app --reload --port 9001
   */
  import { onMount, onDestroy } from "svelte";
  import { Signal } from "./Signal";

  // Use different port for Opus server
  const OPUS_SERVER_PORT = 9001;

  let signal: Signal;
  let pc: RTCPeerConnection;

  let audioRef: HTMLAudioElement;
  let status = "Disconnected";
  let isSendingAudio = false;
  let isReceivingAudio = false;
  let micStream: MediaStream | null = null;
  let statsInterval: number | null = null;
  let reconnectAttempt = 0;
  let isReconnecting = false;
  let shouldReconnect = true;

  // WebRTC Stats Logging
  const logStats = async () => {
    try {
      if (!pc || pc.connectionState === "closed") return;

      const stats = await pc.getStats();
      const outboundAudio: any[] = [];
      const inboundAudio: any[] = [];

      stats.forEach((report) => {
        if (report.type === "outbound-rtp" && report.kind === "audio") {
          outboundAudio.push(report);
        } else if (report.type === "inbound-rtp" && report.kind === "audio") {
          inboundAudio.push(report);
        }
      });

      if (outboundAudio.length > 0 || inboundAudio.length > 0) {
        console.log("=== WebRTC Stats ===");

        outboundAudio.forEach((report) => {
          console.log(`[BROWSER TX] SSRC=${report.ssrc}, packets=${report.packetsSent}, bytes=${report.bytesSent}, codec=${report.codecId}`);
        });

        inboundAudio.forEach((report) => {
          const lossRate = report.packetsLost / (report.packetsReceived + report.packetsLost) * 100;
          const concealRate = report.concealedSamples / report.totalSamplesReceived * 100;
          console.log(`[BROWSER RX] SSRC=${report.ssrc}, packets=${report.packetsReceived}, lost=${report.packetsLost} (${lossRate.toFixed(1)}%), concealed=${concealRate.toFixed(1)}%, jitter=${report.jitter}`);
        });
      }
    } catch (err) {
      // Ignore errors if connection not yet established
    }
  };

  const cleanup = () => {
    console.log("[Opus] Cleaning up connection");

    // Stop microphone tracks but keep the stream for reuse
    if (micStream && isSendingAudio) {
      console.log("[Opus] Pausing microphone (keeping for reconnect)");
      // Don't stop tracks, just mark as not sending
      isSendingAudio = false;
    }

    // Clear audio element
    isReceivingAudio = false;
    if (audioRef) {
      audioRef.srcObject = null;
    }

    // Close peer connection
    if (pc) {
      try {
        pc.close();
      } catch (err) {
        console.error("[Opus] Error closing peer connection:", err);
      }
    }
  };

  const setupConnection = async () => {
    console.log("[Opus] Setting up connection");

    // Create new peer connection
    pc = new RTCPeerConnection();

    pc.onicecandidate = (c) => {
      const candidate = c.candidate?.toJSON();
      if (!candidate) {
        return;
      }
      signal.send("trickle-ice", candidate);
      console.log("[Opus] Sending ICE candidate", candidate);
    };

    pc.ontrack = (event) => {
      console.log("[Opus] Got remote audio track", event);
      console.log("[Opus] Track kind:", event.track.kind);
      console.log("[Opus] Track ID:", event.track.id);
      console.log("[Opus] Transceiver direction:", event.transceiver?.direction);

      if (audioRef && event.streams[0]) {
        audioRef.srcObject = event.streams[0];
        isReceivingAudio = true;
        status = "Receiving audio - you should hear loopback!";
        console.log("[Opus] Audio element connected to remote stream");
      }
    };

    pc.onconnectionstatechange = () => {
      console.log("[Opus] Connection state:", pc.connectionState);
      status = `Connection: ${pc.connectionState}`;

      if (pc.connectionState === "connected") {
        status = "Connected - audio should be flowing";
        isReconnecting = false;
        reconnectAttempt = 0;
      } else if (pc.connectionState === "disconnected" || pc.connectionState === "failed") {
        console.log("[Opus] Connection lost, attempting to reconnect...");
        if (shouldReconnect && !isReconnecting) {
          attemptReconnect();
        }
      }
    };

    // Listen for offer from Python server
    signal.on("offer", async function (desc) {
      console.log("[Opus] Received offer from server");
      console.log("[Opus] Offer SDP:", desc);
      status = "Received offer, setting up audio...";

      // Set remote description (offer from server)
      const session = new RTCSessionDescription({
        type: "offer",
        sdp: desc,
      });
      await pc.setRemoteDescription(session);
      console.log("[Opus] Remote description set");

      // Get microphone for sending to server (reuse existing if available)
      try {
        if (!micStream) {
          micStream = await navigator.mediaDevices.getUserMedia({
            audio: {
              echoCancellation: false,
              noiseSuppression: false,
              autoGainControl: true,
            },
          });
          console.log("[Opus] Microphone captured, tracks:", micStream.getAudioTracks().length);
        } else {
          console.log("[Opus] Reusing existing microphone stream");
        }

        // Add microphone track to peer connection
        micStream.getAudioTracks().forEach((track) => {
          const sender = pc.addTrack(track, micStream!);
          console.log("[Opus] Added microphone track, sender:", sender);
        });

        isSendingAudio = true;
        status = "Microphone active, creating answer...";
      } catch (err) {
        console.error("[Opus] Failed to get microphone:", err);
        status = `Microphone error: ${err}`;
      }

      // Create answer
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      console.log("[Opus] Created answer");
      console.log("[Opus] Answer SDP:", answer.sdp);
      console.log("[Opus] Transceivers:", pc.getTransceivers().length);
      pc.getTransceivers().forEach((t, i) => {
        console.log(`  Transceiver ${i}: ${t.direction}, mid=${t.mid}`);
      });

      signal.send("answer", answer);
      status = "Answer sent, waiting for connection...";
    });
  };

  const attemptReconnect = async () => {
    if (isReconnecting) {
      console.log("[Opus] Reconnection already in progress");
      return;
    }

    isReconnecting = true;
    reconnectAttempt++;

    console.log(`[Opus] Attempting reconnection #${reconnectAttempt}`);
    status = `Reconnecting (attempt ${reconnectAttempt})...`;

    // Cleanup old connection
    cleanup();

    // Wait a bit before reconnecting (exponential backoff)
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), 10000);
    await new Promise(resolve => setTimeout(resolve, delay));

    if (!shouldReconnect) {
      console.log("[Opus] Reconnection cancelled");
      isReconnecting = false;
      return;
    }

    try {
      // Setup new connection
      await setupConnection();

      // Reconnect signal if needed
      if (signal.getConnectionState() !== "open") {
        signal.connect();
        await signal.connectedLock.wait;
      }

      status = "Reconnected to signaling server";
      console.log("[Opus] Requesting new offer from server");

      // Request new offer
      signal.send("offer", undefined);
      status = "Requested offer from server...";
    } catch (err) {
      console.error("[Opus] Reconnection failed:", err);
      status = `Reconnection failed: ${err}`;
      isReconnecting = false;

      // Try again if we haven't given up
      if (shouldReconnect && reconnectAttempt < 10) {
        setTimeout(() => attemptReconnect(), delay);
      }
    }
  };

  onMount(async () => {
    console.log("[Opus] Mounting component");

    // Start stats logging every 2 seconds
    statsInterval = window.setInterval(logStats, 2000);

    // Create signal connection
    signal = new Signal(OPUS_SERVER_PORT);

    // Listen for signal events
    signal.on("reconnecting", (data) => {
      console.log(`[Opus] Signal reconnecting (attempt ${data.attempt}, delay ${data.delay}ms)`);
      status = `Signal reconnecting (attempt ${data.attempt})...`;
    });

    signal.on("connected", () => {
      console.log("[Opus] Signal connected");
      if (isReconnecting) {
        // Request new offer after signal reconnects
        signal.send("offer", undefined);
      }
    });

    signal.on("disconnected", () => {
      console.log("[Opus] Signal disconnected");
      if (!isReconnecting) {
        status = "Signal disconnected";
      }
    });

    // Setup initial connection
    await setupConnection();

    signal.connect();
    await signal.connectedLock.wait;
    status = "Connected to signaling server";

    console.log("[Opus] Requesting offer from server");
    signal.send("offer", undefined);
    status = "Requested offer from server...";
  });

  onDestroy(() => {
    console.log("[Opus] Component destroying");
    shouldReconnect = false;
    isReconnecting = false;

    if (statsInterval !== null) {
      window.clearInterval(statsInterval);
      statsInterval = null;
    }

    stopMicrophone();

    if (signal) {
      signal.close();
    }

    if (pc) {
      pc.close();
    }
  });

  const stopMicrophone = () => {
    if (micStream) {
      micStream.getTracks().forEach((track) => track.stop());
      micStream = null;
      isSendingAudio = false;
      status = "Microphone stopped";
    }
  };

  const manualReconnect = () => {
    console.log("[Opus] Manual reconnect triggered");
    reconnectAttempt = 0;
    shouldReconnect = true;
    attemptReconnect();
  };
</script>

<div class="page">
  <h2>Opus Audio (Bidirectional - Sendrecv)</h2>
  <p class="description">
    Two-way audio using a single sendrecv transceiver: Browser sends microphone audio to server AND receives audio
    from server.
  </p>
  <p class="status" class:reconnecting={isReconnecting}>
    Status: {status}
    {#if isReconnecting}
      <span class="reconnect-indicator">🔄</span>
    {/if}
  </p>

  <div class="audio-indicators">
    <div class="indicator">
      <span class="dot" class:active={isSendingAudio}></span>
      Sending: {isSendingAudio ? "Active" : "Inactive"}
    </div>
    <div class="indicator">
      <span class="dot" class:active={isReceivingAudio}></span>
      Receiving: {isReceivingAudio ? "Active" : "Inactive"}
    </div>
    {#if isReconnecting}
      <div class="indicator reconnecting-status">
        <span class="dot reconnecting-dot"></span>
        Reconnecting (attempt {reconnectAttempt})
      </div>
    {/if}
  </div>

  <!-- Audio element for playback -->
  <div class="audio-container">
    <audio bind:this={audioRef} autoplay playsinline controls>
      <track kind="captions" />
    </audio>
  </div>

  <div class="controls">
    <button type="button" on:click={stopMicrophone} disabled={!isSendingAudio || isReconnecting}>
      Stop Microphone
    </button>
    <button type="button" on:click={manualReconnect} disabled={isReconnecting || (pc && pc.connectionState === "connected")}>
      Reconnect
    </button>
  </div>

  <div class="info">
    <p><strong>Note:</strong> Microphone will be requested automatically when connecting. You should hear your own voice echoed back with a small delay (loopback test).</p>
    <p><strong>Architecture:</strong> Server uses a single sendrecv transceiver for bidirectional audio (same as AV1 video example).</p>
    <p><strong>Auto-Reconnect:</strong> Connection will automatically attempt to reconnect if disconnected (up to 10 attempts with exponential backoff).</p>
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
    margin: 1rem 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .status.reconnecting {
    color: #ff9800;
  }

  .reconnect-indicator {
    display: inline-block;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  .audio-indicators {
    display: flex;
    gap: 2rem;
    margin: 1rem 0;
    padding: 1rem;
    background: #f5f5f5;
    border-radius: 8px;
  }

  .indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.95rem;
  }

  .dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #ccc;
    transition: background 0.3s;
  }

  .dot.active {
    background: #28a745;
    box-shadow: 0 0 8px #28a745;
    animation: pulse 2s infinite;
  }

  .reconnecting-dot {
    background: #ff9800 !important;
    box-shadow: 0 0 8px #ff9800;
    animation: pulse 1s infinite;
  }

  .reconnecting-status {
    color: #ff9800;
    font-weight: 600;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.6;
    }
  }

  .audio-container {
    margin: 1rem 0;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 8px;
    border: 1px solid #dee2e6;
  }

  audio {
    width: 100%;
    max-width: 400px;
  }

  .controls {
    margin-top: 1rem;
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  button {
    padding: 0.5rem 1rem;
    font-size: 1rem;
    cursor: pointer;
    border: 1px solid #ccc;
    background: #fff;
    border-radius: 4px;
    transition: all 0.2s;
  }

  button:hover:not(:disabled) {
    background: #f0f0f0;
    transform: translateY(-1px);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button:active:not(:disabled) {
    transform: translateY(0);
  }

  .info {
    margin-top: 1rem;
    padding: 1rem;
    background: #e7f3ff;
    border-left: 4px solid #007bff;
    border-radius: 4px;
  }

  .info p {
    margin: 0.5rem 0;
    font-size: 0.9rem;
    color: #004085;
  }
</style>
