import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { useTraceState } from "./useTraceState";

export function useClientSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const [status, setStatus] = useState("Disconnected");
  const [toasts, setToasts] = useState<string[]>([]);
  const {
    enqueueTraceBatch,
    enqueueTraceSnapshot, enqueueTraceResyncRequired,
    machinesById, transitions, controlsById, groupsById, facetsById, capturesById,
    operationNamesById, diagnostics, topologyVersion, valueVersion,
  } = useTraceState((request) => signalRef.current?.send("trace:resync_request", request));

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
    const unsubscribeTraceBatch = signal.on("trace:batch", enqueueTraceBatch);
    const unsubscribeTraceSnapshot = signal.on("trace:snapshot", enqueueTraceSnapshot);
    const unsubscribeTraceResyncRequired = signal.on(
      "trace:resync_required", enqueueTraceResyncRequired,
    );
    const unsubscribeCaptureResult = signal.on("trace:capture_result", (data) => {
      const result = parseJson<{ success?: boolean; capture_id?: number; error?: string }>(data);
      setToasts((previous) => [...previous, result?.success
        ? `Diagnostic capture #${result.capture_id} authorized`
        : `Capture rejected: ${result?.error ?? "unknown error"}`]);
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
      unsubscribeTraceBatch();
      unsubscribeTraceSnapshot();
      unsubscribeTraceResyncRequired();
      unsubscribeCaptureResult();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
    };
  }, [
    enqueueTraceBatch,
    enqueueTraceSnapshot, enqueueTraceResyncRequired,
  ]);

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

  const deleteTask = (taskId: string) => {
    signalRef.current?.send("trace:delete", { task_id: taskId });
  };

  const requestTraceCapture = (request: Record<string, unknown>) => {
    signalRef.current?.send("trace:capture_request", request);
  };

  const dismissToast = (index: number) => {
    setToasts((previous) => previous.filter((_item, current) => current !== index));
  };

  return {
    clearCompletedTraces,
    clearFailedTraces,
    deleteTask,
    startNegotiation,
    status,
    toasts,
    dismissToast,
    requestTraceCapture,
    machinesById,
    transitions,
    controlsById,
    groupsById,
    facetsById,
    capturesById,
    operationNamesById,
    diagnostics,
    topologyVersion,
    valueVersion,
    videoRef,
  };
}
