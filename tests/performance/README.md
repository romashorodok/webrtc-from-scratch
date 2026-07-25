# Kernel E reproducible benchmark

`benchmark_kernel_e.py` compares the ordinary Python execution of
`webrtc/compiler/kernel_e.py` with the native extension compiled from those
exact source bytes. Both modes call the same stable runtime dispatch API. The
controller builds the artifact once, validates its source metadata during
loading, and runs every measurement in a fresh Python process.

Run the declared baseline:

```sh
.venv/bin/python tests/performance/benchmark_kernel_e.py \
  --pairs 7 \
  --warmup 2 \
  --duration 5 \
  --fps 30 \
  --bitrate 2000000 \
  --peers 1 \
  --mtu 1200 \
  --output benchmark-results/kernel-e.json
```

Seven pairs produce fourteen isolated samples. Pair order alternates `AB`, `BA`,
where A is Python and B is `native-required`. Do not reduce `--pairs` for a
reported result.

End-to-end media measurements use a 30-second warmup followed by a 120-second
timed interval and at least five alternating AB/BA pairs. Those longer runs are
not interchangeable with this isolated-kernel harness.

The deterministic corpus contains five valid AV1 OBUs sized around the target
bitrate. The default network profile is an in-process deterministic null sink,
so OS and NIC variability does not obscure the packetizer comparison. A fixed
loss rate can be included with `--packet-loss-ppm`; packetization still occurs
before the deterministic sink drops a packet.

Each result records:

- process CPU and CPU microseconds per frame;
- frames and packets per second;
- event-loop p50/p95/p99/max scheduling lag;
- input and output byte volumes;
- the exact bytes materialized as independently owned packet results;
- a separate `tracemalloc` probe of retained allocation blocks, bytes, and
  peak traced memory;
- corpus, source, platform, interpreter, workload, and AB/BA order metadata.

The JSON includes the generated binary's SHA-256 and the extension's embedded
source hash, semantic hash, compiler version, and optimization mode. The
controller rejects a native sample whose embedded source hash differs from the
ordinary Python file used by the Python samples. When the controller builds an
artifact itself, its filesystem path is temporary; use the recorded hash to
identify it, or pass `--artifact` to benchmark a retained build.

Timing is performed without `tracemalloc` and with cyclic GC temporarily
disabled. The prior GC state is restored before the separate, bounded
allocation probe. `observable_output_copy_bytes` measures the mandatory public API
boundary materialization; it does not claim to count hidden intermediate
copies. Use Instruments Allocations or generated native instrumentation to
attribute those.

For comparable runs, keep the Python executable, power source, thermal state,
background load, frame rate, bitrate, peer count, MTU, and loss profile fixed.
Compare the raw paired samples, not only the aggregate medians. A result is
invalid if the controller reports workload parity failure.
