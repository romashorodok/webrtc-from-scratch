import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";

export function useServerSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const [status, setStatus] = useState("Disconnected");

  useEffect(() => {
    const signal = new Signal();
    const pc = new RTCPeerConnection();
    signalRef.current = signal;
    pcRef.current = pc;

    pc.addTransceiver("video", { direction: "recvonly" });

    const unsubscribeAnswer = signal.on("answer", async (data) => {
      setStatus("Received answer, establishing connection...");

      const session = normalizeRemoteDescription(data, "answer");
      if (!session) {
        setStatus("Invalid answer payload");
        return;
      }

      await pc.setRemoteDescription(session);
      setStatus("Connection established, waiting for video...");
    });

    const unsubscribeIce = signal.on("trickle-ice", async (data) => {
      const candidate = parseJson<RTCIceCandidateInit>(data);
      if (candidate?.candidate) {
        await pc.addIceCandidate(new RTCIceCandidate(candidate));
      }
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
    });

    return () => {
      unsubscribeAnswer();
      unsubscribeIce();
      unsubscribeConnected();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
      signalRef.current = null;
      pcRef.current = null;
    };
  }, []);

  const createOffer = async () => {
    const signal = signalRef.current;
    const pc = pcRef.current;
    if (!signal || !pc) {
      return;
    }

    setStatus("Creating offer...");
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    signal.send("offer", {
      type: "offer",
      sdp: offer.sdp,
    });
    setStatus("Offer sent, waiting for answer...");
  };

  return {
    createOffer,
    status,
    videoRef,
  };
}
