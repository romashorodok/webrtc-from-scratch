import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { useTraceState } from "./useTraceState";

export function useServerSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const [status, setStatus] = useState("Disconnected");
  const [toasts, setToasts] = useState<string[]>([]);
  const {
    enqueueTraceBatch,
    enqueueTraceSnapshot, enqueueTraceResyncRequired, enqueueTraceTerminal,
    machinesById, entitiesById, transitions, controlsById, groupsById, facetsById, capturesById,
    operationNamesById, diagnostics, topologyVersion, valueVersion,
  } = useTraceState((request) => signalRef.current?.send("trace:resync_request", request));

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
    const unsubscribeTraceBatch = signal.on("trace:batch", enqueueTraceBatch);
    const unsubscribeTraceSnapshot = signal.on("trace:snapshot", enqueueTraceSnapshot);
    const unsubscribeTraceResyncRequired = signal.on(
      "trace:resync_required", enqueueTraceResyncRequired,
    );
    const unsubscribeTraceTerminal = signal.on("trace:terminal", enqueueTraceTerminal);
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
    });

    return () => {
      unsubscribeAnswer();
      unsubscribeIce();
      unsubscribeConnected();
      unsubscribeTraceBatch();
      unsubscribeTraceSnapshot();
      unsubscribeTraceResyncRequired();
      unsubscribeTraceTerminal();
      unsubscribeCaptureResult();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
      signalRef.current = null;
      pcRef.current = null;
    };
  }, [
    enqueueTraceBatch,
    enqueueTraceSnapshot, enqueueTraceResyncRequired, enqueueTraceTerminal,
  ]);

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
    createOffer,
    deleteTask,
    status,
    toasts,
    dismissToast,
    requestTraceCapture,
    machinesById,
    entitiesById,
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
