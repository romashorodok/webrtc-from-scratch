# Compiled WebRTC asyncio Event Loop

`webrtc/compiler/event_loop.py` is the readable semantic authority for the
pinned CPython scheduling turn. The C17 compiler recognizes that reviewed AST
and emits `event_loop_native<EXT_SUFFIX>` with:

- a heap type derived from the host's `asyncio.SelectorEventLoop`;
- a native `_run_once` method fusing timer cleanup, timeout calculation,
  selector polling, timer promotion, and ready-snapshot draining;
- a native `new_event_loop()` factory;
- source, semantic, compiler, CPython-source, platform, and ABI metadata.

Build an artifact with:

```sh
.venv/bin/wrtc-pymeta-compiler \
  --source webrtc/compiler/event_loop.py \
  --output webrtc/compiler
```

Production code calls `webrtc.event_loop.new_event_loop()`. It discovers the
adjacent artifact, or the path in `WEBRTC_EVENT_LOOP_NATIVE`, and selects it
only after complete validation. Every absence or incompatibility falls directly
back to `asyncio.new_event_loop()`; the interpreted custom loop is only a test
oracle.

The isolated benchmark records paired stock/auto CPU, selector polls, wakeups,
allocations, throughput, and latency:

```sh
.venv/bin/python tests/performance/benchmark_event_loop.py \
  --pairs 7 --duration 5
```

No benchmark result is an adoption claim. Selection for deployment still
requires the plan's loop-core and end-to-end CPU thresholds, a paired
confidence bound favoring native, packet/workload parity, and no more than a
1 ms p99 latency regression.

The generic compiler remains version 0.3: its ordinary function backend still
uses transitional `Nv` aggregates. The event-loop path is deliberately bounded
to the reviewed class/source profile; it does not claim general native-class,
`try/finally`, or PyObject-method lowering for arbitrary Python modules.
