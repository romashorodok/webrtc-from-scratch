import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { useTraceState } from "./useTraceState";

export function useClientSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const retentionRef = useRef(60);
  const [status, setStatus] = useState("Disconnected");
  const [successRetentionSeconds, setSuccessRetentionSeconds] = useState(60);
  const { enqueueTraceEvent, summaries, traces } = useTraceState();

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
      signal.send("offer", undefined);
      setStatus("Requested offer from server...");
    });

    return () => {
      unsubscribeOffer();
      unsubscribeConnected();
      unsubscribeTraceInit();
      unsubscribeTraceUpdate();
      unsubscribeTraceComplete();
      unsubscribeTraceDelete();
      unsubscribeTraceSummary();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
    };
  }, [enqueueTraceEvent]);

  const startNegotiation = () => {
    signalRef.current?.send("negotiate", undefined);
    setStatus("Negotiation requested");
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
    deleteTrace,
    setTraceRetentionSeconds,
    startNegotiation,
    status,
    successRetentionSeconds,
    summaries,
    traces,
    videoRef,
  };
}
