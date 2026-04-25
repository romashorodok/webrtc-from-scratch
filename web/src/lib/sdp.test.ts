import { expect, test } from "bun:test";
import { normalizeRemoteDescription } from "./sdp";

test("normalizes raw SDP offers", () => {
  const session = normalizeRemoteDescription("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n", "offer");

  expect(session).toEqual({
    type: "offer",
    sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
  });
});

test("normalizes JSON-wrapped SDP offers", () => {
  const session = normalizeRemoteDescription(
    JSON.stringify({
      type: "offer",
      sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
    }),
    "offer",
  );

  expect(session).toEqual({
    type: "offer",
    sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
  });
});

test("rejects empty raw SDP payloads", () => {
  expect(normalizeRemoteDescription("", "offer")).toBeNull();
});

test("rejects offers without SDP", () => {
  expect(normalizeRemoteDescription(JSON.stringify({ type: "offer" }), "offer")).toBeNull();
  expect(normalizeRemoteDescription(JSON.stringify({ type: "offer", sdp: "" }), "offer")).toBeNull();
});

test("normalizes raw SDP answers", () => {
  const session = normalizeRemoteDescription("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n", "answer");

  expect(session).toEqual({
    type: "answer",
    sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
  });
});
