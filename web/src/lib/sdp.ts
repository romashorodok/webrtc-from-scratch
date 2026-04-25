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

export function normalizeRemoteDescription(
  value: unknown,
  fallbackType: RTCSdpType,
): RTCSessionDescriptionInit | null {
  const payload = parseMaybeJson(value);

  if (typeof payload === "string") {
    if (payload.length === 0) {
      return null;
    }

    return {
      type: fallbackType,
      sdp: payload,
    };
  }

  if (!isRecord(payload)) {
    return null;
  }

  const sdp = payload.sdp;
  if (typeof sdp !== "string" || sdp.length === 0) {
    return null;
  }

  return {
    type: typeof payload.type === "string" ? (payload.type as RTCSdpType) : fallbackType,
    sdp,
  };
}
