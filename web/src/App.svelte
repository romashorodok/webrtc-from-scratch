<script lang="ts">
  import { EventEmitter } from "events";
  import { onMount } from "svelte";

  export class Mutex {
    wait: Promise<void>;
    private _locks: number;

    constructor() {
      this.wait = Promise.resolve();
      this._locks = 0;
    }

    isLocked() {
      return this._locks > 0;
    }

    lock() {
      this._locks += 1;
      let unlockNext: () => void;
      const willLock = new Promise<void>(
        (resolve) =>
          (unlockNext = () => {
            this._locks -= 1;
            resolve();
          }),
      );
      const willUnlock = this.wait.then(() => unlockNext);
      this.wait = this.wait.then(() => willLock);
      return willUnlock;
    }
  }

  class Signal extends EventEmitter {
    ws?: WebSocket;

    connectedLock = new Mutex();
    connected: Promise<() => void>;

    constructor() {
      super();
      this.connected = this.connectedLock.lock();
    }

    connect() {
      this.ws = new WebSocket("ws://localhost:9000/ws");
      this.ws.onopen = async () => (await this.connected)();
      this.ws.onmessage = (evt) => {
        const { event = null, data = null } = JSON.parse(evt.data);
        if (!event) {
          return;
        }
        this.emit(event, data);
      };
    }

    close() {
      this.ws?.close();
    }

    send(event: string, data: any) {
      if (!this.ws) {
        console.log("start connection first");
        return;
      }
      this.ws.send(
        JSON.stringify({
          event,
          data: JSON.stringify({
            ...data,
          }),
        }),
      );
    }
  }

  const signal = new Signal();
  const pc = new RTCPeerConnection();

  onMount(async () => {
    const streams = await navigator.mediaDevices.getUserMedia({
      video: true,
    });
    const [track] = streams.getVideoTracks();
    pc.addTrack(track, streams);

    pc.onicecandidate = (c) => {
      const candidate = c.candidate?.toJSON();
      if (!candidate) {
        return;
      }

      signal.send("trickle-ice", candidate);
      console.log(c);
    };

    signal.on("offer", async function (desc) {
      console.log("offer", desc);
      const session = new RTCSessionDescription({
        type: "offer",
        sdp: desc,
      });

      await pc.setRemoteDescription(session);

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      console.log("answer", answer);
      signal.send("answer", answer);
    });

    signal.connect();
    await signal.connectedLock.wait;
    signal.send("offer", undefined);
  });

  const start = () => signal.send("negotiate", undefined);

  let videoRef: HTMLVideoElement;
  $: if (videoRef && pc) {
    pc.ontrack = (track) => {
      videoRef.srcObject = track.streams[0];
      console.log("Got receiver", track);
    };
  }
</script>

<main>
  <video bind:this={videoRef} controls autoplay>
    <track kind="captions" />
  </video>
  <div>
    <button type="button" on:click={start}>Start</button>
  </div>
</main>
