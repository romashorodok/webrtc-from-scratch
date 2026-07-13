import { useEffect, useRef, useState } from "react";
import { attachStream, parseJson } from "./media";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";
import { traceDeleteFailureMessage, type TraceDeleteResultPayload } from "./toast";
import { traceEventsFromBatch, useTraceState } from "./useTraceState";

export function useClientSession() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const signalRef = useRef<Signal | null>(null);
  const [status, setStatus] = useState("Disconnected");
  const [toasts, setToasts] = useState<string[]>([]);
  const { enqueueTraceEvent, enqueueTraceEvents, performanceEvents, groups, summaries, tasks } = useTraceState();

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
      enqueueTraceEvent("trace:delete_result", data);
    });
    const unsubscribeTraceBatch = signal.on("trace:batch", (data) => {
      const events = traceEventsFromBatch(data)
        .map((event) => {
          if (event.event === "trace:delete_result") {
            const payload = parseJson<TraceDeleteResultPayload>(event.data);
            if (payload?.success === false) {
              setToasts((previous) => [...previous, traceDeleteFailureMessage(payload)]);
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
      unsubscribeTraceDeleteResult();
      unsubscribeTraceBatch();
      signal.close();
      pc.close();
      attachStream(videoRef.current, null);
    };
  }, [enqueueTraceEvent, enqueueTraceEvents]);

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
    performanceEvents,
    groups,
    summaries,
    tasks,
    videoRef,
  };
}
