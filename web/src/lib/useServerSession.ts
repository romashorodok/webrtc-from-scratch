import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { useTraceState } from "./useTraceState";

export function useServerSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const retentionRef = useRef(60);
  const [status, setStatus] = useState("Disconnected");
  const [successRetentionSeconds, setSuccessRetentionSeconds] = useState(60);
  const { enqueueTraceEvent, summaries, traces } = useTraceState();

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
    const unsubscribeTraceInit = signal.on("trace:init", (data) => {
      const payload = parseJson<{ success_retention_seconds?: number }>(data);
      if (typeof payload?.success_retention_seconds === "number") {
        retentionRef.current = payload.success_retention_seconds;
        setSuccessRetentionSeconds(payload.success_retention_seconds);
      }
      enqueueTraceEvent("trace:init", data);
    });
    const unsubscribeTraceUpdate = signal.on("trace:update", (data) => {
      enqueueTraceEvent("trace:update", data);
    });
    const unsubscribeTraceComplete = signal.on("trace:complete", (data) => {
      enqueueTraceEvent("trace:complete", data);
    });
    const unsubscribeTraceDelete = signal.on("trace:delete", (data) => {
      enqueueTraceEvent("trace:delete", data);
    });
    const unsubscribeTraceSummary = signal.on("trace:summary", (data) => {
      enqueueTraceEvent("trace:summary", data);
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
      signal.send("trace:configure", {
        success_retention_seconds: retentionRef.current,
      });
    });

    return () => {
      unsubscribeAnswer();
      unsubscribeIce();
      unsubscribeConnected();
      unsubscribeTraceInit();
      unsubscribeTraceUpdate();
      unsubscribeTraceComplete();
      unsubscribeTraceDelete();
      unsubscribeTraceSummary();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
      signalRef.current = null;
      pcRef.current = null;
    };
  }, [enqueueTraceEvent]);

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

  const clearCompletedTraces = () => {
    signalRef.current?.send("trace:delete", { scope: "completed" });
  };

  const clearFailedTraces = () => {
    signalRef.current?.send("trace:delete", { scope: "failed" });
  };

  const deleteTrace = (traceId: string) => {
    signalRef.current?.send("trace:delete", { trace_id: traceId });
  };

  const setTraceRetentionSeconds = (seconds: number) => {
    retentionRef.current = seconds;
    setSuccessRetentionSeconds(seconds);
    signalRef.current?.send("trace:configure", {
      success_retention_seconds: seconds,
    });
  };

  return {
    clearCompletedTraces,
    clearFailedTraces,
    createOffer,
    deleteTrace,
    setTraceRetentionSeconds,
    status,
    successRetentionSeconds,
    summaries,
    traces,
    videoRef,
  };
}
