"""Build the production event-loop extension for the running CPython ABI."""

from __future__ import annotations

from webrtc.compiler.module_compiler import compile_module

from .compile_policy import (
    ARTIFACT_POLICY_METADATA,
    SOURCE_PATH,
    SOURCE_PATHS,
    require_compatible_host,
)


def main() -> int:
    """Compile a native loop matching this interpreter's exact ABI."""

    require_compatible_host()
    result = compile_module(
        SOURCE_PATH,
        SOURCE_PATH.parent,
        source_paths=SOURCE_PATHS,
        artifact_metadata=ARTIFACT_POLICY_METADATA,
    )
    print(result.artifact_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
