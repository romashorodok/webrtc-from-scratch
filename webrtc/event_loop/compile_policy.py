"""Build and deployment policy for the generated event-loop artifact."""

from __future__ import annotations

import asyncio
import os
import platform
import sys
import sysconfig

from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from webrtc.compiler.native_artifact import (
    NativeClassRequirement,
    NativeModuleRequirements,
)
from webrtc.compiler.module_contract import policy_sha256, source_manifest_sha256

CPYTHON_REVISION = "070700ed4d95c16855603cecab3f41f3b587f973"
ARTIFACT_ENVIRONMENT_VARIABLE = "WEBRTC_EVENT_LOOP_NATIVE"
SOURCE_PATH = Path(__file__).with_name("loop.py")
SOURCE_PATHS = tuple(
    Path(__file__).with_name(name)
    for name in (
        "atomic.py",
        "commands.py",
        "datagrams.py",
        "loop.py",
        "scheduler.py",
        "workers.py",
    )
)
NATIVE_CLASS = "WebRTCSelectorEventLoop"
NATIVE_FACTORY = "new_event_loop"


@dataclass(frozen=True, slots=True)
class EventLoopTarget:
    revision: str = CPYTHON_REVISION
    abi: str = "exact"
    free_threaded: bool = True
    gil: str = "not_used"
    subinterpreters: str = "unsupported"


event_loop_target = EventLoopTarget()


def _policy_document() -> dict[str, object]:
    """Return the normalized, target-only policy embedded in an artifact."""

    return {
        "target": asdict(event_loop_target),
        "module_name": "event_loop_native",
        "factory": NATIVE_FACTORY,
        "native_class": NATIVE_CLASS,
        "required_methods": ["_run_once"],
        "sources": [path.name for path in SOURCE_PATHS],
    }


POLICY_SHA256 = policy_sha256(_policy_document())
SOURCE_MANIFEST_SHA256 = source_manifest_sha256(SOURCE_PATHS)
DEVELOPMENT_POLICY_SHA256 = policy_sha256(
    {
        "profile": "compiled-development",
        "production_compatible": False,
        "module_name": "loop_native",
        "factory": NATIVE_FACTORY,
        "native_class": NATIVE_CLASS,
        "required_methods": ["_run_once"],
        "sources": [path.name for path in SOURCE_PATHS],
    }
)

ARTIFACT_POLICY_METADATA: Mapping[str, str] = MappingProxyType(
    {
        "policy_sha256": POLICY_SHA256,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "event_loop_cpython_revision": event_loop_target.revision,
        "event_loop_abi": event_loop_target.abi,
        "event_loop_free_threaded": "required",
        "event_loop_gil": event_loop_target.gil,
        "event_loop_subinterpreters": event_loop_target.subinterpreters,
    }
)

NATIVE_REQUIREMENTS = NativeModuleRequirements(
    module_name="event_loop_native",
    source_path=SOURCE_PATH,
    source_paths=SOURCE_PATHS,
    functions=(NATIVE_FACTORY,),
    classes={
        NATIVE_CLASS: NativeClassRequirement(
            base=asyncio.SelectorEventLoop,
            required_methods=("_run_once",),
        )
    },
    metadata=ARTIFACT_POLICY_METADATA,
)

DEVELOPMENT_ARTIFACT_METADATA: Mapping[str, str] = MappingProxyType(
    {
        "policy_sha256": DEVELOPMENT_POLICY_SHA256,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "artifact_profile": "compiled-development",
        "production_compatible": "false",
    }
)

DEVELOPMENT_REQUIREMENTS = NativeModuleRequirements(
    module_name="loop_native",
    source_path=SOURCE_PATH,
    source_paths=SOURCE_PATHS,
    functions=(NATIVE_FACTORY,),
    classes={
        NATIVE_CLASS: NativeClassRequirement(
            base=asyncio.SelectorEventLoop,
            required_methods=("_run_once",),
        )
    },
    metadata=DEVELOPMENT_ARTIFACT_METADATA,
)


def host_compatibility_error() -> str | None:
    """Explain why this process cannot safely load the production artifact."""

    if platform.python_implementation() != "CPython":
        return "event-loop native artifact requires CPython"
    if sysconfig.get_config_var("Py_GIL_DISABLED") != 1:
        return "event-loop native artifact requires a free-threaded CPython build"
    if (sys.implementation.cache_tag or "") == "":
        return "event-loop native artifact requires an exact CPython cache tag"
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if not isinstance(suffix, str) or not suffix:
        return "event-loop native artifact requires an exact extension ABI suffix"
    return None


def require_compatible_host() -> None:
    reason = host_compatibility_error()
    if reason is not None:
        raise RuntimeError(reason)


def artifact_candidates() -> tuple[Path, ...]:
    configured = os.environ.get(ARTIFACT_ENVIRONMENT_VARIABLE)
    if configured:
        return (Path(configured),)
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if not isinstance(suffix, str) or not suffix:
        return ()
    return (SOURCE_PATH.with_name(f"event_loop_native{suffix}"),)
