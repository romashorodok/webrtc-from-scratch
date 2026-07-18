# C17 Module Compiler Integration Contract

## Scope

This contract defines the process boundary between a C17
  `wrtc-pymeta-compiler-c` executable, its pinned CPython installation, generated
extension modules, and the Python runtime loader. It does not define typed IR
or Kernel E lowering.

## Current Implementation Status

The repository currently implements a **Kernel E-specific vertical slice**, not
the general single-module compiler described by the target specification.
This distinction is intentional and testable:

| Area | Current state |
| --- | --- |
| Compiler host | Implemented in C17 and linked to one explicitly selected CPython installation. |
| Build and CLI | CMake target and `--source`/`--output` workflow implemented; the Python console entry is only a build-and-launch packaging adapter. |
| Artifact model | One source produces one importable extension with no retained generated C, object, manifest, registry sidecar, or per-function library. |
| Kernel E backend | Native packetization, public callable metadata, embedded compatibility metadata, registry, loading, and media dispatch are implemented. |
| Source acceptance | Bounded to the exact normalized AST hash of `webrtc/compiler/kernel_e.py`; any semantic source change fails the complete build. |
| Discovery and call graph | Not implemented generally. Public names, helpers, constants, signatures, and generated registry contents are fixed by the Kernel E backend template. |
| Semantic compiler | Typed IR, ownership/effect/bounds/exception analysis, cross-module internalization, and general lowering are not implemented. |
| Optimization | Release C compilation and hidden visibility are implemented. Whole-module IR optimization, proven bounds-check removal, escape analysis, LTO policy, and general helper inlining are not. |
| Platform verification | Current local acceptance covers the active host. The required macOS/Linux matrix, pinned CPython fork/revision matrix, free-threaded ABI, ASan, and UBSan runs remain outstanding. |

The research target CPython revision is
`romashorodok/cpython@070700ed4d95c16855603cecab3f41f3b587f973`.
The current developer build has not established the required release and
free-threaded verification matrix against that revision.

The embedded file `kernel_e_extension.c.in` is therefore a backend template,
not evidence that arbitrary Python functions are translated to C. Tests and
documentation must describe this as a vertical slice until general discovery,
analysis, and lowering replace the accepted-AST gate and fixed template.

## Ordered Next Milestones

1. Replace the accepted-AST equality gate with C-owned CPython AST traversal,
   `__all__`/public-function discovery, duplicate/export validation, and a
   reachable same-module call graph. Initially support a deliberately small
   syntax subset and fail the whole module for any unsupported reachable node.
2. Introduce typed semantic IR with source spans and deterministic diagnostics.
   Lower constants, scalar integers/booleans, bytes/buffers, tuples/fixed
   records, branches, loops, direct calls, and the required exception paths.
3. Generate module initialization, callable wrappers, function metadata,
   constants, and `__pymeta_functions__` from discovered IR instead of the
   Kernel E template. Keep private helpers as hidden direct C calls.
4. Port Kernel E onto the general lowering path, then delete the fixed template
   and the accepted AST hash. Differentially test every discovered export and
   prove that no wrapper or helper calls its Python implementation.
5. Harden publication and validation: installed-driver parity, concurrent and
   failed replacement tests, independent mutation of embedded fields, signal
   cleanup strategy, toolchain identity, LTO/dead stripping, and export audits.
6. Run optimized, ASan, UBSan, free-threaded, media-integration, and full
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
