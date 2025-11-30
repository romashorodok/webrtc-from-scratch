# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Proof-of-concept WebRTC Media Server implementation demonstrating minimal code and dependency approach. Hybrid Rust/Python architecture with PyO3 FFI bindings.

**Status:** Heavy experimental. Working code on `old` branch.

## Build Commands

**Prerequisites:**
```bash
rustup default nightly
```

**Development (watch mode):**
```bash
# Terminal 1: Rust file watcher (auto-rebuilds on changes)
make watch

# Terminal 2: FastAPI server with hot reload (port 9000)
cd examples && make run
```

**Dependency sync:**
```bash
make sync  # uv sync --all-extras --dev --all-packages
```

**Web frontend:**
```bash
cd web && npm install && npm run dev
```

**Video generation (for testing):**
```bash
cd examples
make y4m           # Generate test Y4M video
make transcode     # Transcode MP4 to Y4M
make av1           # Encode Y4M to AV1
```

## Architecture

Three-layer hybrid Rust/Python system:

1. **Transport Layer (Rust - `packages/`):**
   - `webrtc_rs/` - Main PyO3 bindings, contains DTLS, RTP, RTCP, SRTP implementations
   - `eventloop/` - Tokio event loop integration
   - `rav1e/` - AV1 encoder wrapper

2. **Protocol Layer (Python - `webrtc/`):**
   - `ice/` - ICE agent with STUN protocol and UDP mux
   - `dtls/` - DTLS handshake coordination
   - `media/` - RTP/RTCP handling, payloaders (VP8, AV1), jitter buffer
   - `peer_connection.py` - Main PeerConnection implementation
   - `session_description.py` - SDP parsing/generation

3. **Application Layer:**
   - `examples/` - FastAPI WebSocket signaling server
   - `web/` - Svelte/TypeScript browser client

## Key Implementation Details

**PyO3 FFI Boundary:** Rust types exposed to Python via PyO3 classes (Certificate, DTLS, Av1Payloader, SRTP). Async communication uses Tokio mpsc channels.

**Event-Driven:** Uses custom `AsyncEventEmitter` for decoupled messaging between components.

**Media Pipeline:** Y4M input → PyTorch processing (motion detection) → rav1e AV1 encoding → RTP packetization → SRTP encryption → Browser

**Signaling:** Browser ↔ WebSocket ↔ FastAPI ↔ Python WebRTC ↔ Rust core

## Rust Workspace Structure

Root `Cargo.toml` defines workspace members. Each package under `packages/` builds as a Python extension module via maturin.

The `webrtc_rs` crate contains vendored protocol implementations:
- `dtls/` - Rewrite of Pion/dtls (Go → Rust)
- `rtp/`, `rtcp/`, `srtp/` - RTP stack
- `util/` - Virtual networking, marshaling utilities

## Active Technologies
- Python 3.11+ / Rust nightly (PyO3 bindings via maturin) (001-python-dtls-migration)
- N/A (stateless protocol) (001-python-dtls-migration)

## Recent Changes
- 001-python-dtls-migration: Added Python 3.11+ / Rust nightly (PyO3 bindings via maturin)
