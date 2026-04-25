import { useEffect, useMemo, useRef, useState } from "react";
import { type AudioSpectrogramHandle, type AudioSpectrumPayload } from "./AudioSpectrogram";
import { type CustomFilterConfig } from "./FilterSettings";
import { Signal } from "./Signal";
import { normalizeRemoteDescription } from "./sdp";

const OPUS_SERVER_PORT = 9001;

type FilterPresetInfo = {
  name: string;
  description: string;
};

function attachStream(
  element: HTMLAudioElement | null,
  stream: MediaStream | null,
) {
  if (!element) {
    return;
  }

  (element as HTMLAudioElement & { srcObject: MediaStream | null }).srcObject = stream;
}

function parseMaybeJson(value: unknown) {
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return value;
    }
  }

  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function useOpusSession() {
  const audioRef = useRef<HTMLAudioElement>(null);
  const spectrogramRef = useRef<AudioSpectrogramHandle | null>(null);
  const signalRef = useRef<Signal | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const micStreamRef = useRef<MediaStream | null>(null);
  const reconnectRef = useRef<(() => Promise<void>) | null>(null);
  const statsIntervalRef = useRef<number | null>(null);

  const [status, setStatus] = useState("Disconnected");
  const [isSendingAudio, setIsSendingAudio] = useState(false);
  const [isReceivingAudio, setIsReceivingAudio] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [audioFeatures, setAudioFeatures] = useState({
    rms: 0,
    zcr: 0,
    spectral_centroid: 0,
  });
  const [thresholdTriggered, setThresholdTriggered] = useState(false);
  const [filterPresets, setFilterPresets] = useState<Record<string, FilterPresetInfo>>({});
  const [currentFilter, setCurrentFilter] = useState("none");
  const [vadActive, setVadActive] = useState(false);
  const [playFiltered, setPlayFiltered] = useState(false);

  const filterPresetEntries = useMemo(
    () => Object.entries(filterPresets),
    [filterPresets],
  );
  const currentPresetDescription = filterPresets[currentFilter]?.description ?? "";

  useEffect(() => {
    const signal = new Signal(OPUS_SERVER_PORT);
    signalRef.current = signal;

    let shouldReconnect = true;
    let reconnecting = false;
    let reconnectCounter = 0;

    const cleanupPeerConnection = (preserveMic: boolean) => {
      const pc = pcRef.current;
      if (preserveMic && micStreamRef.current) {
        setIsSendingAudio(false);
      }

      setIsReceivingAudio(false);
      attachStream(audioRef.current, null);

      if (pc) {
        try {
          pc.close();
        } catch (error) {
          console.error("[Opus] Error closing peer connection:", error);
        }
        pcRef.current = null;
      }
    };

    const logStats = async () => {
      const pc = pcRef.current;
      if (!pc || pc.connectionState === "closed") {
        return;
      }

      try {
        const stats = await pc.getStats();
        const outboundAudio: RTCStatsReport[] = [];
        const inboundAudio: RTCStatsReport[] = [];

        stats.forEach((report) => {
          if (report.type === "outbound-rtp" && (report as RTCOutboundRtpStreamStats).kind === "audio") {
            outboundAudio.push(report);
          } else if (report.type === "inbound-rtp" && (report as RTCInboundRtpStreamStats).kind === "audio") {
            inboundAudio.push(report);
          }
        });

        if (outboundAudio.length > 0 || inboundAudio.length > 0) {
          console.log("=== WebRTC Stats ===");
          outboundAudio.forEach((report) => {
            const item = report as RTCOutboundRtpStreamStats;
            console.log(
              `[BROWSER TX] SSRC=${item.ssrc}, packets=${item.packetsSent}, bytes=${item.bytesSent}, codec=${item.codecId}`,
            );
          });

          inboundAudio.forEach((report) => {
            const item = report as RTCInboundRtpStreamStats;
            const lossRate =
              item.packetsLost && item.packetsReceived
                ? (item.packetsLost / (item.packetsReceived + item.packetsLost)) * 100
                : 0;
            const concealRate =
              item.concealedSamples && item.totalSamplesReceived
                ? (item.concealedSamples / item.totalSamplesReceived) * 100
                : 0;
            console.log(
              `[BROWSER RX] SSRC=${item.ssrc}, packets=${item.packetsReceived}, lost=${item.packetsLost} (${lossRate.toFixed(1)}%), concealed=${concealRate.toFixed(1)}%, jitter=${item.jitter}`,
            );
          });
        }
      } catch {
        // Ignore stats errors while the connection is not yet stable.
      }
    };

    const setupConnection = async () => {
      const pc = new RTCPeerConnection();
      pcRef.current = pc;

      pc.onicecandidate = (event) => {
        const candidate = event.candidate?.toJSON();
        if (candidate) {
          signal.send("trickle-ice", candidate);
        }
      };

      pc.ontrack = (event) => {
        const stream = event.streams[0] ?? null;
        if (stream) {
          attachStream(audioRef.current, stream);
          setIsReceivingAudio(true);
          setStatus("Receiving audio - you should hear loopback!");
        }
      };

      pc.onconnectionstatechange = () => {
        setStatus(`Connection: ${pc.connectionState}`);

        if (pc.connectionState === "connected") {
          reconnecting = false;
          reconnectCounter = 0;
          setIsReconnecting(false);
          setReconnectAttempt(0);
          setStatus("Connected - audio should be flowing");
        } else if (
          (pc.connectionState === "disconnected" || pc.connectionState === "failed") &&
          shouldReconnect &&
          !reconnecting
        ) {
          void reconnectRef.current?.();
        }
      };
    };

    const attemptReconnect = async () => {
      if (reconnecting) {
        return;
      }

      reconnecting = true;
      reconnectCounter += 1;
      setIsReconnecting(true);
      setReconnectAttempt(reconnectCounter);
      setStatus(`Reconnecting (attempt ${reconnectCounter})...`);

      cleanupPeerConnection(true);

      const delay = Math.min(1000 * 2 ** (reconnectCounter - 1), 10000);
      await new Promise((resolve) => window.setTimeout(resolve, delay));

      if (!shouldReconnect) {
        reconnecting = false;
        setIsReconnecting(false);
        return;
      }

      try {
        await setupConnection();

        if (signal.getConnectionState() !== "open") {
          signal.connect();
          await signal.connectedLock.wait;
        }

        signal.send("offer", undefined);
        signal.send("get_filter_presets", undefined);
        setStatus("Requested offer from server...");
      } catch (error) {
        console.error("[Opus] Reconnection failed:", error);
        setStatus(`Reconnection failed: ${String(error)}`);
        reconnecting = false;
        setIsReconnecting(false);

        if (shouldReconnect && reconnectCounter < 10) {
          window.setTimeout(() => {
            void attemptReconnect();
          }, delay);
        }
      }
    };

    reconnectRef.current = attemptReconnect;

    const unsubscribeOffer = signal.on("offer", async (desc) => {
      const pc = pcRef.current;
      if (!pc) {
        return;
      }

      setStatus("Received offer, setting up audio...");

      const session = normalizeRemoteDescription(desc, "offer");
      if (!session) {
        setStatus("Invalid offer payload");
        return;
      }

      await pc.setRemoteDescription(session);

      try {
        if (!micStreamRef.current) {
          micStreamRef.current = await navigator.mediaDevices.getUserMedia({
            audio: {
              echoCancellation: false,
              noiseSuppression: false,
              autoGainControl: true,
            },
          });
        }

        micStreamRef.current.getAudioTracks().forEach((track) => {
          pc.addTrack(track, micStreamRef.current!);
        });
        setIsSendingAudio(true);
        setStatus("Microphone active, creating answer...");
      } catch (error) {
        setStatus(`Microphone error: ${String(error)}`);
      }

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      signal.send("answer", answer);
      setStatus("Answer sent, waiting for connection...");
    });

    const unsubscribeSpectrum = signal.on("audio_spectrum", (data) => {
      const payload = parseMaybeJson(data);
      if (!isRecord(payload)) {
        return;
      }

      const spectrum = payload as AudioSpectrumPayload;
      spectrogramRef.current?.update(spectrum);
      setAudioFeatures(spectrum.features);
      if (typeof spectrum.features.is_voice === "boolean") {
        setVadActive(spectrum.features.is_voice);
      }
    });

    const unsubscribeThreshold = signal.on("audio_threshold", (data) => {
      const payload = parseMaybeJson(data);
      if (isRecord(payload) && "triggered" in payload) {
        setThresholdTriggered(Boolean(payload.triggered));
      }
    });

    const unsubscribePresets = signal.on("filter_presets", (data) => {
      const payload = parseMaybeJson(data);
      if (!isRecord(payload)) {
        return;
      }

      const presets = payload as Record<string, FilterPresetInfo>;
      setFilterPresets(presets);
      setCurrentFilter((prev) => {
        if (prev in presets) {
          return prev;
        }
        return "none" in presets ? "none" : prev;
      });
    });

    const unsubscribeConnected = signal.on("connected", () => {
      if (reconnecting) {
        signal.send("offer", undefined);
      }
    });

    const unsubscribeDisconnected = signal.on("disconnected", () => {
      if (!reconnecting) {
        setStatus("Signal disconnected");
      }
    });

    const unsubscribeReconnecting = signal.on("reconnecting", (data) => {
      const payload = parseMaybeJson(data);
      if (isRecord(payload)) {
        setStatus(`Signal reconnecting (attempt ${String(payload.attempt ?? 0)})...`);
      }
    });

    const unsubscribeError = signal.on("error", (error) => {
      console.error("[Opus] Signal error:", error);
    });

    void setupConnection();
    signal.connect();
    void signal.connectedLock.wait.then(() => {
      setStatus("Connected to signaling server");
      signal.send("offer", undefined);
      signal.send("get_filter_presets", undefined);
      setStatus("Requested offer from server...");
    });

    statsIntervalRef.current = window.setInterval(() => {
      void logStats();
    }, 2000);

    return () => {
      shouldReconnect = false;
      reconnecting = false;

      if (statsIntervalRef.current !== null) {
        window.clearInterval(statsIntervalRef.current);
        statsIntervalRef.current = null;
      }

      unsubscribeOffer();
      unsubscribeSpectrum();
      unsubscribeThreshold();
      unsubscribePresets();
      unsubscribeConnected();
      unsubscribeDisconnected();
      unsubscribeReconnecting();
      unsubscribeError();

      if (micStreamRef.current) {
        micStreamRef.current.getTracks().forEach((track) => track.stop());
        micStreamRef.current = null;
      }

      signal.close();
      cleanupPeerConnection(false);
    };
  }, []);

  const changeFilter = (preset: string) => {
    setCurrentFilter(preset);
    signalRef.current?.send("audio_config", JSON.stringify({ filter_preset: preset }));
  };

  const togglePlayFiltered = (next: boolean) => {
    setPlayFiltered(next);
    signalRef.current?.send("audio_config", JSON.stringify({ play_filtered: next }));
  };

  const applyCustomFilters = (config: CustomFilterConfig) => {
    signalRef.current?.send(
      "audio_config",
      JSON.stringify({ custom_filter_config: config }),
    );
  };

  const stopMicrophone = () => {
    if (micStreamRef.current) {
      micStreamRef.current.getTracks().forEach((track) => track.stop());
      micStreamRef.current = null;
      setIsSendingAudio(false);
      setStatus("Microphone stopped");
    }
  };

  const manualReconnect = () => {
    setReconnectAttempt(0);
    setIsReconnecting(true);
    void reconnectRef.current?.();
  };

  return {
    audioRef,
    spectrogramRef,
    status,
    isSendingAudio,
    isReceivingAudio,
    reconnectAttempt,
    isReconnecting,
    audioFeatures,
    thresholdTriggered,
    filterPresetEntries,
    currentFilter,
    currentPresetDescription,
    vadActive,
    playFiltered,
    changeFilter,
    togglePlayFiltered,
    applyCustomFilters,
    stopMicrophone,
    manualReconnect,
  };
}
