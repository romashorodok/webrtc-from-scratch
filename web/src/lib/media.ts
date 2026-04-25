export function attachStream(
  element: HTMLVideoElement | HTMLAudioElement | null,
  stream: MediaStream | null,
) {
  if (!element) {
    return;
  }

  (element as HTMLVideoElement & HTMLAudioElement & {
    srcObject: MediaStream | null;
  }).srcObject = stream;
}

export function parseJson<T>(value: unknown): T | null {
  if (typeof value !== "string") {
    return (value as T) ?? null;
  }

  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}
