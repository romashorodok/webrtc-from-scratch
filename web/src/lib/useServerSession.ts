import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { traceDeleteFailureMessage, type TraceDeleteResultPayload } from "./toast";
import { useTraceState } from "./useTraceState";

type TraceBatchPayload = {
  events?: Array<{
    event?: unknown;
    data?: unknown;
  }>;
  trace?: unknown;
  traces?: unknown[];
};

export function useServerSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const [status, setStatus] = useState("Disconnected");
  const [toasts, setToasts] = useState<string[]>([]);
  const { enqueueTraceEvent, enqueueTraceEvents, performanceEvents, summaries, traces } = useTraceState();

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
    const unsubscribeTraceDeleteResult = signal.on("trace:delete_result", (data) => {
      const payload = parseJson<TraceDeleteResultPayload>(data);
      if (payload?.success === false) {
        setToasts((previous) => [...previous, traceDeleteFailureMessage(payload)]);
      }
      if (payload?.success === true) {
        const traceIds = payload.trace_ids ?? (payload.trace_id ? [payload.trace_id] : []);
        if (traceIds.length > 0) {
          enqueueTraceEvent("trace:delete", { trace_ids: traceIds });
        }
      }
      enqueueTraceEvent("trace:delete_result", data);
    });
    const unsubscribeTraceBatch = signal.on("trace:batch", (data) => {
      const payload = parseJson<TraceBatchPayload>(data);
      const batchEvents =
        payload?.events ??
        (payload?.trace || payload?.traces ? [{ event: "trace:update", data }] : []);
      const events = batchEvents
        .filter((event): event is { event: string; data: unknown } =>
          typeof event.event === "string",
        )
        .map((event) => {
          if (event.event === "trace:delete_result") {
            const payload = parseJson<TraceDeleteResultPayload>(event.data);
            if (payload?.success === false) {
              setToasts((previous) => [...previous, traceDeleteFailureMessage(payload)]);
            }
            if (payload?.success === true) {
              const traceIds = payload.trace_ids ?? (payload.trace_id ? [payload.trace_id] : []);
              if (traceIds.length > 0) {
                enqueueTraceEvent("trace:delete", { trace_ids: traceIds });
              }
            }
          }
          return { event: event.event, data: event.data };
        });
      enqueueTraceEvents(events);
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
      unsubscribeTraceInit();
      unsubscribeTraceUpdate();
      unsubscribeTraceComplete();
      unsubscribeTraceDelete();
      unsubscribeTraceDeleteResult();
      unsubscribeTraceBatch();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
      signalRef.current = null;
      pcRef.current = null;
    };
  }, [enqueueTraceEvent, enqueueTraceEvents]);

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

  const dismissToast = (index: number) => {
    setToasts((previous) => previous.filter((_item, current) => current !== index));
  };

  return {
    clearCompletedTraces,
    clearFailedTraces,
    createOffer,
    deleteTrace,
    status,
    toasts,
    dismissToast,
    performanceEvents,
    summaries,
    traces,
    videoRef,
  };
}
