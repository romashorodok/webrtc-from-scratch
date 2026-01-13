import { EventEmitter } from "events";

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

export class Signal extends EventEmitter {
  ws?: WebSocket;
  port: number;

  connectedLock = new Mutex();
  connected: Promise<() => void>;

  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimeout?: number;
  private shouldReconnect = true;
  private isManualClose = false;

  constructor(port: number = 9000) {
    super();
    this.port = port;
    this.connected = this.connectedLock.lock();
  }

  connect() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      console.log("[Signal] Already connected");
      return;
    }

    console.log(`[Signal] Connecting to ws://localhost:${this.port}/ws (attempt ${this.reconnectAttempts + 1})`);
    this.ws = new WebSocket(`ws://localhost:${this.port}/ws`);

    this.ws.onopen = async () => {
      console.log("[Signal] WebSocket connected");
      this.reconnectAttempts = 0;
      this.emit("connected");
      (await this.connected)();
    };

    this.ws.onmessage = (evt) => {
      const { event = null, data = null } = JSON.parse(evt.data);
      if (!event) {
        return;
      }
      this.emit(event, data);
    };

    this.ws.onerror = (error) => {
      console.error("[Signal] WebSocket error:", error);
      this.emit("error", error);
    };

    this.ws.onclose = (event) => {
      console.log(`[Signal] WebSocket closed (code: ${event.code}, clean: ${event.wasClean})`);
      this.emit("disconnected");

      // Only attempt reconnection if not manually closed and under max attempts
      if (this.shouldReconnect && !this.isManualClose && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.scheduleReconnect();
      } else if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error("[Signal] Max reconnection attempts reached");
        this.emit("max-reconnect-reached");
      }
    };
  }

  private scheduleReconnect() {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, max 30s
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    console.log(`[Signal] Reconnecting in ${delay}ms...`);

    this.reconnectAttempts++;
    this.emit("reconnecting", { attempt: this.reconnectAttempts, delay });

    this.reconnectTimeout = window.setTimeout(() => {
      this.connect();
    }, delay);
  }

  close() {
    this.isManualClose = true;
    this.shouldReconnect = false;

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = undefined;
    }

    this.ws?.close();
  }

  send(event: string, data: any) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn("[Signal] Cannot send - not connected");
      return;
    }
    this.ws.send(
      JSON.stringify({
        event,
        data: typeof data === "string" ? data : JSON.stringify(data ?? {}),
      }),
    );
  }

  getConnectionState(): string {
    if (!this.ws) return "not-initialized";
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return "connecting";
      case WebSocket.OPEN:
        return "open";
      case WebSocket.CLOSING:
        return "closing";
      case WebSocket.CLOSED:
        return "closed";
      default:
        return "unknown";
    }
  }
}
