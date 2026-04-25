type Listener = (data: unknown) => void;

type Deferred<T> = {
  wait: Promise<T>;
  resolve: (value: T) => void;
};

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const wait = new Promise<T>((res) => {
    resolve = res;
  });
  return { wait, resolve };
}

export class Signal {
  ws?: WebSocket;
  port: number;

  connectedLock: Deferred<void>;

  private listeners = new Map<string, Set<Listener>>();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimeout?: number;
  private shouldReconnect = true;
  private isManualClose = false;

  constructor(port: number = 9000) {
    this.port = port;
    this.connectedLock = createDeferred<void>();
  }

  on(event: string, listener: Listener) {
    const listeners = this.listeners.get(event) ?? new Set<Listener>();
    listeners.add(listener);
    this.listeners.set(event, listeners);
    return () => this.off(event, listener);
  }

  off(event: string, listener: Listener) {
    const listeners = this.listeners.get(event);
    if (!listeners) {
      return;
    }

    listeners.delete(listener);
    if (listeners.size === 0) {
      this.listeners.delete(event);
    }
  }

  private emit(event: string, data?: unknown) {
    const listeners = this.listeners.get(event);
    if (!listeners) {
      return;
    }

    for (const listener of listeners) {
      try {
        listener(data);
      } catch (error) {
        console.error(`[Signal] Listener for "${event}" failed`, error);
      }
    }
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.connectedLock = createDeferred<void>();
    this.isManualClose = false;

    const url = `ws://localhost:${this.port}/ws`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.emit("connected");
      this.connectedLock.resolve();
    };

    this.ws.onmessage = (evt) => {
      try {
        const message = JSON.parse(String(evt.data)) as { event?: string; data?: unknown };
        if (!message.event) {
          return;
        }

        this.emit(message.event, message.data);
      } catch (error) {
        console.error("[Signal] Failed to parse message", error);
        this.emit("error", error);
      }
    };

    this.ws.onerror = (error) => {
      this.emit("error", error);
    };

    this.ws.onclose = (event) => {
      this.emit("disconnected", event);

      if (
        this.shouldReconnect &&
        !this.isManualClose &&
        this.reconnectAttempts < this.maxReconnectAttempts
      ) {
        this.scheduleReconnect();
      } else if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        this.emit("max-reconnect-reached");
      }
    };
  }

  private scheduleReconnect() {
    const delay = Math.min(1000 * 2 ** this.reconnectAttempts, 30000);
    this.reconnectAttempts += 1;
    this.emit("reconnecting", { attempt: this.reconnectAttempts, delay });

    this.reconnectTimeout = window.setTimeout(() => {
      this.connect();
    }, delay);
  }

  close() {
    this.isManualClose = true;
    this.shouldReconnect = false;

    if (this.reconnectTimeout) {
      window.clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = undefined;
    }

    if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
      this.ws.close();
    }
  }

  send(event: string, data: unknown) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return;
    }

    this.ws.send(
      JSON.stringify({
        event,
        data: typeof data === "string" ? data : JSON.stringify(data ?? {}),
      }),
    );
  }

  getConnectionState() {
    if (!this.ws) {
      return "not-initialized";
    }

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
