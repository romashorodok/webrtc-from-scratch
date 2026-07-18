# Stage 0 baseline and source inventory

Status: work item 0.1 started; repository revision is frozen; environment and
workload freeze have open fields.

## Reproducibility record

| Item | Recorded value | Status |
| --- | --- | --- |
| Reference repository | `romashorodok/webrtc-from-scratch` | Frozen |
| Reference branch | `ffi-working` (informational only) | Frozen |
| Reference commit | `8b85614672a1e51d8a464288db202cfc791a0d3d` | Frozen |
| Worktree state at inventory | research/plan files are uncommitted additions; no application change is attributed to Stage 0 | Frozen observation |
| Authoritative interpreter source | `https://github.com/romashorodok/cpython.git` | Frozen |
| CPython commit | `070700ed4d95c16855603cecab3f41f3b587f973` | Frozen |
| CPython commit date/subject | 2026-07-18, `Merge branch 'python:main' into main` | Frozen observation |
| CPython worktree state | modified `setup.sh`; untracked `tutorial/` | Frozen observation |
| CPython configuration | `--with-pydebug --enable-shared CC='ccache gcc'` | Frozen observation |
| CPython threading mode | regular/GIL build (`Py_GIL_DISABLED` is undefined) | Frozen observation |
| CPython executable | `../cpython/python.exe` | Provisional path |
| CPython executable usability | not loadable: expects `/usr/local/lib/libpython3.15d.dylib` | Open blocker |
| Developer Python | 3.13.13 regular build at `.venv/bin/python3` | Observation only; not an approved substitute |
| Developer host | macOS 13.7.8, Darwin 22.6.0, x86-64 | Observation only; not a primary target |
| Developer C compiler | Apple clang 14.0.3, target `x86_64-apple-darwin22.6.0` | Observation only |
| Developer CMake | 4.4.0 | Observation only |

The exact commits above were read from the local checkouts. The CPython
executable is not currently suitable for Stage 1 validation, and the CPython
worktree is dirty. Rebuilding or repairing it is outside Stage 0.

## Proposed native build contract

These values are concrete Stage 0 proposals and require review before they are
frozen:

| Setting | Proposed value |
| --- | --- |
| Minimum CMake | 3.25 |
| Generator | Ninja (single configuration) |
| C language standard | ISO C17, extensions disabled |
| Build directories | outside the source tree; one directory per target, compiler, build type, and sanitizer mode |
| Release build type | `Release`; project flags limited to warnings and reproducibility flags, with optimization selected by the CMake toolchain |
| Verification build type | `Debug` with compiler-supported ASan+UBSan, frame pointers retained |
| Network during configure/build | prohibited |
| CPython selection | explicit absolute path to the executable built from the pinned fork; no PATH discovery |
| Kernel linkage | no CPython headers or libraries |
| Recorded configure facts | CMake version, generator, compiler path/ID/version, target triple, build type, effective C flags, linker flags, and sanitizer set |

Exact release and sanitizer flags will be frozen per approved compiler. Flags
must not be copied between AppleClang, Clang, and GCC on the assumption that
they have identical meaning.

## Target matrix

| Priority | OS / architecture | Compiler | State |
| --- | --- | --- | --- |
| 1 | macOS arm64 | AppleClang; exact Xcode/SDK/compiler versions not yet supplied | Open |
| 1 | Linux x86-64 | GCC or Clang; distribution, libc, and exact compiler version not yet supplied | Open |
| documentation only | Windows x86-64 | MSVC ABI/loading implications only; no Stage 1 build promised | Provisional |

The observed macOS x86-64 machine does not satisfy either primary target. The
owners of the target environments must record OS image, kernel, libc/SDK, CPU,
available instruction sets, compiler binary and version, and CMake version.

## Selected source boundary

The sole candidate is Kernel E, frame-level AV1 RTP packet construction. The
observable operation begins with one encoded AV1 frame and explicit stream
state, and ends with an ordered collection of serialized RTP packet bytes plus
advanced sequence state. It excludes SRTP, socket I/O, scheduling, pacing,
tracing, callbacks, and session lookup.

The future compiler input must be one ordinary `.py` source region conforming
to `research/python_metalanguage_spec.md`. It must import and execute on the
pinned CPython without a compiler, native artifact, import hook, or native-only
intrinsic. Its Python body—not generated C, the paper ABI, or the handwritten C
oracle—is the maintained kernel and executable specification.

The current application-level composition is evidence from which that Python
source contract is derived:

1. `examples/examples/ws.py` calls `encoding._packetizer.packetize(frame,
   timestamp)`.
2. `webrtc/media/av1_payloader.py:Av1Packetizer.packetize` calls
   `webrtc_rs.Av1Payloader.packetize`, assigns RTP sequence numbers, timestamp,
   SSRC, payload type 45, payload bytes, and the final-packet marker.
3. `examples/examples/ws.py` assigns one transport-wide sequence number per
   packet.
4. `webrtc/media/rtp_packet.py:RtpPacket.serialize` and
   `webrtc/media/rtp_extensions.py:DEFAULT_EXT_MAP` serialize the RTP header,
   the transport-wide extension, and payload.

### Transitive source inventory

| Role | Source | Language | Notes |
| --- | --- | --- | --- |
| Application composition | `examples/examples/ws.py` | Python | Exact live order of packetize, TWCC assignment, serialize |
| Packetizer wrapper | `webrtc/media/av1_payloader.py` | Python | Payload type is hard-coded to 45; constructor `pt` is not used |
| RTP sequence state | `webrtc/media/packetizer.py:Sequencer` | Python | Increments before use; wraps with `& 0xffff` |
| RTP serialization | `webrtc/media/rtp_packet.py:RtpPacket.serialize` | Python | Uses network byte order; supports more features than Kernel E needs |
| Extension serialization | `webrtc/media/rtp_extensions.py` | Python | Default map enables TWCC as extension id 4 |
| AV1 Python entry point | `packages/webrtc_rs/src/lib.rs:Av1Payloader` | Rust/PyO3 | Converts Python frame to owned Rust bytes and results back to Python byte arrays |
| AV1 OBU parsing | `packages/webrtc_rs/rtp/src/codecs/av1/obu.rs` | Rust | Not a Python executable specification |
| AV1 fragmentation | `packages/webrtc_rs/rtp/src/codecs/av1/packetizer.rs` | Rust | Not a Python executable specification |
| AV1 payload construction | `packages/webrtc_rs/rtp/src/codecs/av1/mod.rs` | Rust | Wrapper currently unwraps errors |

There is no single source function implementing Kernel E and no pure-Python
AV1 fragmenter in this revision. This is a Stage 0 completion blocker: the
normative Python behavior cannot yet be exercised independently of the
existing Rust FFI.

The Rust fragmenter cannot remain a transitive dependency of a region reported
as compiled by the Python-independent backend. The future Python kernel must
express the accepted AV1 parsing, fragmentation, header construction, and
serialization behavior itself, using ordinary Python and pure-Python PyMeta
metadata where representation or effect facts are required.

## Existing fixtures and missing coverage

Existing AV1 packetization vectors live in
`packages/webrtc_rs/rtp/src/codecs/av1/av1_test.rs`. They exercise the Rust
fragmenter and are useful evidence, but they are not Python differential
vectors and do not cover the complete Kernel E boundary.

No repository tests were found for the combined Python path covering AV1
fragmentation, RTP sequence assignment, TWCC assignment, serialization, and
state advancement.

Missing fixture classes include:

- empty frame and empty parsed-OBU result;
- malformed/truncated OBU header, extension, and LEB128 length;
- minimum, typical, and maximum accepted frame sizes;
- fragmentation around every MTU/header boundary;
- RTP and TWCC rollover at 65535;
- timestamp endpoints at 0 and 2^32-1;
- marker and packet ordering for one and many packets;
- exact extension bytes and network byte order;
- output-capacity, overlap, and misalignment cases for the future boundary;
- proof that failure leaves all state in its specified condition.

## MTU observation

The live AV1 wrapper passes its configured `mtu` directly to the AV1 payloader.
With the configured value 1200, an AV1 RTP payload can therefore be 1200 bytes.
The Python serializer can then add 12 bytes of RTP header and, when TWCC is
present, 8 bytes of extension header/value. The resulting serialized packet
can be 1220 bytes. Stage 0 must decide whether 1200 means payload budget or
final packet budget. Changing this behavior is not authorized in Stage 0.

## Workload freeze (open)

The benchmark workload still needs exact values for AV1 input asset and hash,
encoder settings, resolution, frame rate, frame-count/duration, peer/browser
version, MTU interpretation, network topology, executor size, tracing/logging
configuration, warmup duration, measurement duration, and sample count/order.
Until those are supplied and reviewed, work item 0.1 is not complete.

## Owners and required decisions

| Decision/evidence | Owner | State |
| --- | --- | --- |
| Accept the CPython commit and provide a usable clean build | compiler project owner | Open |
| Freeze exact macOS arm64 toolchain | macOS environment owner | Open |
| Freeze exact Linux x86-64 toolchain | Linux environment owner | Open |
| Freeze workload and input hashes | benchmark owner | Open |
| Specify the ordinary Python Meta-Language kernel that replaces the Rust-only AV1 semantics | compiler project owner | Open |
| Decide whether MTU is payload or final-wire capacity | WebRTC behavior owner | Open |
