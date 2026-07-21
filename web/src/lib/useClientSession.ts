import { useEffect, useRef, useState } from "react";
import { attachStream } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";

export function useClientSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const [status, setStatus] = useState("Disconnected");

  useEffect(() => {
    const signal = new Signal();
    const pc = new RTCPeerConnection();
    signalRef.current = signal;

    const unsubscribeOffer = signal.on("offer", async (desc) => {
      setStatus("Received offer, creating answer...");

      const session = normalizeRemoteDescription(desc, "offer");
      if (!session) {
        setStatus("Invalid offer payload");
        return;
      }

      await pc.setRemoteDescription(session);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      signal.send("answer", answer);
      setStatus("Answer sent, waiting for connection...");
    });

    const unsubscribeConnected = signal.on("connected", () => {
      setStatus("Connected to signaling server");
    });

    pc.onicecandidate = (event) => {
      const candidate = event.candidate?.toJSON();
      if (candidate) {
        signal.send("trickle-ice", candidate);
      }
    };

    pc.ontrack = (event) => {
      attachStream(videoRef.current, event.streams[0] ?? null);
      setStatus("Receiving video");
    };

    pc.onconnectionstatechange = () => {
      setStatus(`Connection: ${pc.connectionState}`);
    };

    signal.connect();
    void signal.connectedLock.wait.then(() => {
      setStatus("Connected to signaling server");
      signal.send("offer", undefined);
      setStatus("Requested offer from server...");
    });

    return () => {
      unsubscribeOffer();
      unsubscribeConnected();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
    };
  }, []);

  const startNegotiation = () => {
    signalRef.current?.send("negotiate", undefined);
    setStatus("Negotiation requested");
  };

  return {
    startNegotiation,
    status,
    videoRef,
  };
}
