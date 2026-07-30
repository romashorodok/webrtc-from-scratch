# C17 Module Compiler Integration Contract

## Scope

This contract defines the process boundary between a C17
  `wrtc-pymeta-compiler-c` executable, its pinned CPython installation, generated
extension modules, and the Python runtime loader. Compiler version 0.3 performs
direct CPython AST traversal, reachable same-module call analysis, typed IR
lowering, and generation of private native helpers. Python source is never
embedded, compiled, evaluated, imported, or executed by a generated artifact.

## Current Implementation Status

The repository implements a bounded single-module compiler with Kernel E as
its acceptance module. The source remains the semantic authority and PyMeta is
compile-time metadata only:

| Area | Current state |
| --- | --- |
| Compiler host | Implemented in C17 and linked to one explicitly selected CPython installation. |
| Build and CLI | CMake target and `--source`/`--output` workflow implemented; the Python console entry is only a build-and-launch packaging adapter. |
| Artifact model | One source produces one importable extension with no retained generated C, object, manifest, registry sidecar, or per-function library. |
| Frontend | The C host parses with its pinned CPython, walks the AST directly, discovers `__all__`, records and functions, validates reachable syntax, and constructs a same-module call graph. It does not execute source. |
| Typed lowering | Reachable functions lower to source-correlated IR with refined scalar widths/ranges, aggregate shapes, record indices, ownership/cleanup information and resolved direct-call targets. |
| Generation | Public CPython wrappers, metadata, constants and registry entries are generated from IR. Private calls are generated native helpers rather than Python callables. |
| Kernel E backend | Native packetization, public callable metadata, embedded compatibility metadata, registry, loading, and media dispatch are implemented through the general frontend/lowering path. |
| Source acceptance | The generic function backend is bounded by reachable syntax and type rules and has no accepted-AST hash gate. The specialized event-loop profile uses its reviewed semantic AST hash because its C emitter implements exactly that pinned scheduling method. |
| Native event loop | A bounded compiler profile recognizes the reviewed `event_loop.py` semantic AST and emits a CPython heap type derived from `asyncio.SelectorEventLoop`. Its `_run_once` is a native C method; the generated module does not embed or execute Python source. General native-class lowering remains future work. |
| Optimization | Release C compilation and hidden visibility are implemented. Version 0.3 still uses insufficiently specialized generated aggregate containers; typed storage specialization, escape analysis and scalar replacement are the next backend milestone. |
| Platform verification | Current local acceptance covers the active host. The required macOS/Linux matrix, pinned CPython fork/revision matrix, free-threaded ABI, ASan, and UBSan runs remain outstanding. |

The research target CPython revision is
`romashorodok/cpython@070700ed4d95c16855603cecab3f41f3b587f973`.
The current developer build has not established the required release and
free-threaded verification matrix against that revision.

## Ordered Next Milestones

1. Specialize the generated backend from typed IR: concrete scalar/span/builder,
   record, fixed-tuple and typed-vector storage; direct operators and loops;
   ownership-aware cleanup; scalar replacement; and boundary-only boxing.
2. Delete the transitional tagged aggregate implementation after every
   reachable Kernel E operation uses typed lowering, then bump compatibility
   metadata to compiler 0.4.
3. Harden publication and validation: installed-driver parity, concurrent and
   failed replacement tests, independent mutation of embedded fields, signal
   cleanup strategy, toolchain identity, LTO/dead stripping, and export audits.
4. Run optimized, ASan, UBSan, free-threaded, media-integration, and full
   regression matrices on macOS arm64 and Linux x86-64 using the pinned CPython
   revision before claiming the complete compiler specification.

## CMake Build

- Require CMake 3.25 or newer and build a real C executable target named
  `wrtc-pymeta-compiler-c` with `C_STANDARD 17`, `C_STANDARD_REQUIRED YES`, and
  `C_EXTENSIONS NO`.
- Select CPython explicitly with an absolute `Python3_EXECUTABLE`. Configure
  with `find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Embed
  Development.Module)` in one call so the interpreter, embedding library,
  headers, and module ABI belong to the same installation.
- Link the compiler executable to `Python3::Python`. Generated extension
  modules use the selected installation's module ABI (`Python3::Module` when
  CMake performs the link), never a Python found independently on `PATH`.
- Fail configuration if the selected interpreter cannot run, its headers and
  embedding library disagree on major/minor version, or CMake is cross
  compiling. This compiler executes CPython during analysis and imports the
  finished extension during validation, so the bounded workflow is native,
  not cross-compiling.
- Install the native executable in `bin`. The public
  `wrtc-pymeta-compiler` command may be a packaging shim that resolves and
  invokes this driver, but it must preserve the exact CLI, output, exit-status,
  and metadata behavior. Build-tree and installed native invocation must also
  agree.

The repository implements that allowance with
`webrtc.compiler.module_compiler`: a packaging adapter that configures/builds
the shipped C target, launches it, and decodes its result. It contains no AST
analysis, lowering, C generation, extension linking, or validation pipeline.
The former Python `compiler.py` and `build.py` implementations have been
removed; compilation logic is owned only by the C17 executable.

## CLI

The stable invocation is:

```text
wrtc-pymeta-compiler --source <module.py> --output <artifact-directory>
```

- `--source` is one readable regular Python file. `--output` is a dedicated
  artifact directory, created when absent. No function list or module name is
  accepted.
- On success, stdout contains exactly one absolute artifact path plus a final
  newline. Progress is silent; diagnostics go to stderr. Exit status is zero.
- Usage errors use the CLI parser's nonzero usage status. Parse, analysis,
  lowering, toolchain, validation, and publication failures return nonzero and
  must not print an artifact path.
- Compiler subprocess output is captured. On failure, a bounded diagnostic is
  copied to stderr without changing the stdout protocol.
- The source stem must be a valid non-keyword Python identifier. The extension
  module name is `<stem>_native`, and the artifact name is exactly
  `<stem>_native<EXT_SUFFIX>`, where `EXT_SUFFIX` comes from the selected
  CPython's `sysconfig`, not from a hardcoded `.so`, CMake's platform suffix,
  or the compiler process's filename conventions.

## Atomic Publication

- Generate C, objects, response files, and the candidate extension in a unique
  temporary directory inside `--output`. A sibling location guarantees that
  final publication can use one same-filesystem atomic rename.
- Complete analysis of every required public function, compile, link, verify
  exported symbols, import the candidate with the selected CPython, and verify
  its registry and embedded metadata before publication.
- Publish with an atomic replace of the one destination path. A failed rebuild
  leaves any previous valid artifact unchanged. Concurrent builds use unique
  temporary directories; publication is whole-artifact last-writer-wins unless
  a per-destination lock is added.
- Always remove compiler-owned temporary directories after success and
  ordinary failure. Never delete unrelated files already present in
  `--output`.
- The compiler creates no manifest, registry sidecar, generated source tree, or
  per-function library. For a fresh output directory, the only retained file is
  the extension.

Current limitation: an uncatchable or externally forced termination during the
child CMake build can leave its uniquely named `.kernel_e_native-*` temporary
directory. The driver deliberately does not run Python or recursive filesystem
operations from an unsafe C signal handler; signal-safe cleanup remains future
work.

## Embedded Compatibility Metadata

The extension contains string attributes with these exact meanings:

| Attribute | Value source |
| --- | --- |
| `__pymeta_source_sha256__` | SHA-256 of the exact source bytes |
| `__pymeta_semantic_sha256__` | SHA-256 of the location-free CPython AST normalization |
| `__pymeta_compiler_version__` | stable compiler protocol/version string |
| `__pymeta_cpython_revision__` | exact selected CPython `sys.version` |
| `__pymeta_cpython_source_revision__` | pinned CPython source revision whose scheduling semantics are implemented |
| `__pymeta_target__` | selected CPython `sysconfig.get_platform()` |
| `__pymeta_architecture__` | selected CPython `platform.machine()` |
| `__pymeta_optimization__` | normalized mode, currently `release` |

The C executable obtains these values from its selected embedded CPython, using
the same Python operations as `webrtc.compiler.module_contract`. Host CMake or
compiler guesses are not substitutes for target CPython facts. The loader
requires exact equality before constructing a dispatcher.

`__pymeta_functions__` is a read-only mapping from every compiled public
function name to the identical object exposed as the module attribute. Its key
set must equal the required source function set. The extension also recreates
the source `__all__` and required public constants. No private helper is
Python-callable.

## Runtime Loading

- Load by absolute artifact path with CPython's extension loader. Reject a
  filename that does not end in one of the running interpreter's extension
  suffixes; this catches regular/free-threaded and ABI-tag mismatches before
  dispatch.
- Validate all metadata, `__all__`, registry completeness, registry
  immutability, callable identity, and required public functions before the
  first native call.
- Register one frozen module dispatcher only after validation succeeds. The
  dispatcher strongly retains the imported extension. A failure leaves the
  previous dispatcher unchanged; there is no Python fallback in
  `native-required` mode.

The production event-loop facade uses an automatic variant of this rule. It
accepts only the complete native factory/type/method surface and otherwise
calls `asyncio.new_event_loop()` directly. It never selects the interpreted
custom-loop oracle.

## macOS and Linux

- macOS output is a CPython loadable bundle with the selected interpreter's
  `EXT_SUFFIX`; do not assume `.dylib`. CPython extension symbols may be resolved
  with the toolchain's normal dynamic-lookup module policy. Set the deployment
  target from the selected CPython/toolchain and preserve universal versus
  single-architecture identity in `sysconfig.get_platform()`.
- Linux output is an ELF shared object with the selected CPython `EXT_SUFFIX`.
  Do not require or embed a build-machine `libpython` dependency unless that
  CPython's module configuration requires it. Use hidden visibility and export
  only `PyInit_<stem>_native`.
- On both platforms, reject unexpected defined exports, use response files or
  argument-vector process spawning rather than shell command construction, and
  treat compiler/linker paths and flags as opaque values supplied by the
  selected toolchain.

## Required Integration Tests

- Configure/build/install the C executable against an explicit CPython and
  invoke both build-tree and installed binaries.
- Assert stdout/stderr/exit-status behavior, exact `EXT_SUFFIX` naming, one
  retained artifact, no sidecars, and no temporary files after success and
  forced failure.
- Verify failed replacement preserves a previously valid artifact and two
  concurrent builds never expose a partial extension.
- Mutate each embedded metadata field independently and assert rejection before
  dispatch. Verify regular versus free-threaded ABI mismatch where available.
- Run extension import, registry/introspection, Kernel E differential,
  malformed-input, optimized, ASan, UBSan, media-integration, and full
  regression tests on macOS arm64 and Linux x86-64.
