"""End-to-end acceptance for the standalone C module compiler driver."""

from __future__ import annotations

import inspect
import importlib.util
import gc
import os
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pytest

from webrtc.compiler import kernel_e, runtime
from webrtc.compiler.module_contract import METADATA_ATTRIBUTES, runtime_compatibility


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NATIVE_COMPILER_SOURCE = REPOSITORY_ROOT / "webrtc/compiler/native_compiler"
KERNEL_SOURCE = Path(kernel_e.__file__).resolve()


def _compiler_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return environment


@dataclass(frozen=True)
class CCompilerBuild:
    executable: Path
    artifact: Path
    output_dir: Path


def _compile_fixture(
    build: CCompilerBuild, tmp_path: Path, name: str, source_text: str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    source = tmp_path / f"{name}.py"
    source.write_text(source_text, encoding="utf-8")
    output = tmp_path / f"{name}-output"
    completed = subprocess.run(
        [
            str(build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    return completed, output


def _load_fixture(artifact: Path, module_name: str) -> object:
    spec = importlib.util.spec_from_file_location(module_name, artifact)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_bounded_spsc_channel_lifecycle(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "generic_spsc_component",
        """
import collections
from dataclasses import dataclass
from queue import Empty, Full
from typing import Annotated
import pymeta
from pymeta.concurrent import BoundedQueue, bounded_queue, spsc

@pymeta.record(abi="tests.spsc.item.v1")
@dataclass(frozen=True, slots=True)
class Item:
    value: object

@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)
class Channel(collections.UserList):
    queue: Annotated[
        BoundedQueue[Item],
        spsc | bounded_queue(capacity="self.capacity") | pymeta.owned_by("worker"),
    ]

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor"))
    def send(self, item):
        try:
            self.queue.put_nowait(item)
        except Full:
            return False
        return True

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="worker"))
    def receive(self):
        try:
            return self.queue.get_nowait()
        except Empty:
            return None

    @pymeta.region(pymeta.required, effects=pymeta.effects(owner="reactor"))
    def close_and_drain(self):
        self.queue.close()
        values = []
        while not self.queue.empty():
            try:
                values.append(self.queue.get_nowait())
            except Empty:
                break
        return tuple(values)

def create_channel(capacity):
    channel = Channel()
    channel.capacity = capacity
    channel.queue = BoundedQueue(capacity)
    return channel
""",
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("generic_spsc_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import gc
import importlib
import importlib.util
import queue
import sys
import weakref
sys.path.insert(0, sys.argv[2])
source = importlib.import_module(sys.argv[3])
spec = importlib.util.spec_from_file_location(
    "generic_spsc_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
channel = module.create_channel(1)
class Payload:
    pass
payload = Payload()
payload_ref = weakref.ref(payload)
owned = source.Item(payload)
assert channel.send(owned)
del payload, owned
gc.collect()
assert payload_ref() is not None
received = channel.receive()
del received
gc.collect()
assert payload_ref() is None
first = source.Item(["owned"])
assert channel.send(first)
assert not channel.send(source.Item("full"))
assert channel.receive() is first
assert channel.send(first)
assert channel.close_and_drain() == (first,)
try:
    channel.send(first)
except RuntimeError:
    pass
else:
    raise AssertionError("closed generated channel accepted a send")
try:
    channel.queue = source.BoundedQueue(1)
except AttributeError:
    pass
else:
    raise AssertionError("generated SPSC field allowed reinitialization")
""",
            str(artifact),
            str(tmp_path.parent),
            f"{tmp_path.name}.generic_spsc_component",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert probe.returncode == 0, probe.stderr


def test_generic_native_heap_type_survives_gc_and_subprocess_shutdown(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "renamed_arbitrary_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helper.py").write_text(
        "DEFAULT = 7\n"
        "def transform(value):\n"
        "    return value + 5\n",
        encoding="utf-8",
    )
    source = package / "renamed_component.py"
    source.write_text(
        """
import collections
import pymeta
from .helper import DEFAULT, transform

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class GenericHeap(collections.UserList):
    payload: object

    @pymeta.region(pymeta.required)
    def mutate(self, value=DEFAULT):
        self.payload = [self.payload, transform(value)]
        return self.payload

    @pymeta.region(pymeta.required)
    def close(self):
        self.payload = None

    @pymeta.region(pymeta.required)
    def orchestrate(self, value):
        first = self.mutate(value)
        second = self.mutate(value + 1)
        return (first, second)

def create_component(value=DEFAULT):
    instance = GenericHeap()
    instance.payload = value
    return instance
""",
        encoding="utf-8",
    )
    output = tmp_path / "native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("renamed_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import gc
import importlib.util
import sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("renamed_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.__pymeta_compiler_version__ == "wrtc-pymeta-compiler/0.4"
assert module.__pymeta_cpython_revision__ == sys.version
assert len(module.__pymeta_cpython_source_revision__) == 40
assert module.__pymeta_cache_tag__ == (sys.implementation.cache_tag or "")
assert module.__pymeta_abi_flags__ == getattr(sys, "abiflags", "")
assert module.__pymeta_optimization__ == "release"
created = module.create_component()
assert type(created) is module.GenericHeap
assert created.payload == 7
explicit = module.create_component(11)
assert type(explicit) is module.GenericHeap
assert explicit.payload == 11
class Derived(module.GenericHeap):
    pass
for cls in (module.GenericHeap, Derived):
    for _ in range(2000):
        value = cls()
        value.payload = value
        assert value.payload is value
        changed = value.mutate()
        assert changed[0] is value
        assert changed[1] == 12
        assert value.payload is changed
        assert value.mutate(9)[1] == 14
        first, second = value.orchestrate(3)
        assert first[1] == 8
        assert second[1] == 9
        value.close()
        assert value.payload is None
        value.payload = value
        if cls is Derived:
            value.derived_cycle = value
        if _ == 0:
            del value.payload
            try:
                value.payload
            except AttributeError:
                pass
            else:
                raise AssertionError("deleted native field remained readable")
            value.payload = value
        del value
        if _ % 31 == 0:
            gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr


def test_native_atomic_compare_exchange_generated_lifecycle(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "atomic_component_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "atomic_component.py"
    source.write_text(
        """
from typing import Annotated
import collections
import pymeta
from pymeta.concurrent import LockedAtomic, atomic

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class AtomicCell(collections.UserList):
    state: Annotated[
        LockedAtomic[int],
        atomic[pymeta.uint[32]] | pymeta.owned_by("shared"),
    ]

    @pymeta.region(pymeta.required)
    def transition(self, expected, desired):
        _, changed = self.state.compare_exchange(expected, desired)
        return changed

def create_atomic(value=0):
    instance = AtomicCell()
    instance.state = LockedAtomic(value)
    return instance
""",
        encoding="utf-8",
    )
    output = tmp_path / "atomic-native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("atomic_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import gc
import importlib.util
import sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("atomic_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for _ in range(1000):
    cell = module.create_atomic(0)
    assert type(cell) is module.AtomicCell
    assert cell.state.load() == 0
    assert cell.transition(0, 1) is True
    assert cell.transition(0, 2) is False
    assert cell.state.compare_exchange(1, 3) == (1, True)
    assert cell.state.load() == 3
    try:
        cell.transition(object(), 4)
    except TypeError:
        pass
    else:
        raise AssertionError("object operand was accepted")
    assert cell.state.load() == 3
    try:
        cell.transition(3, object())
    except TypeError:
        pass
    else:
        raise AssertionError("object desired value was accepted")
    assert cell.state.load() == 3
    try:
        cell.transition(-1, 4)
    except OverflowError:
        pass
    else:
        raise AssertionError("negative operand was accepted")
    assert cell.state.load() == 3
    try:
        cell.state = 4
    except TypeError:
        pass
    else:
        raise AssertionError("non-atomic initializer was accepted")
    assert cell.state.load() == 3
    del cell.state
    try:
        cell.state
    except AttributeError:
        pass
    else:
        raise AssertionError("deleted atomic field remained readable")
    del cell
    if _ % 31 == 0:
        gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr


def test_generated_bounded_mpsc_channel_lifecycle(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "mpsc_component_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "mpsc_component.py"
    source.write_text(
        """
from dataclasses import dataclass
from typing import Annotated
import collections
import pymeta
from pymeta.concurrent import (
    BoundedQueue,
    LockedAtomic,
    atomic,
    bounded_queue,
    coalesced_notification,
    mpsc,
)

@pymeta.record(abi="test.channel.item.v1")
@dataclass(frozen=True, slots=True)
class Item:
    payload: object

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class Channel(collections.UserList):
    capacity: int
    state: Annotated[
        object,
        atomic[pymeta.uint[32]] | pymeta.owned_by("shared"),
    ]
    notified: Annotated[
        object,
        atomic[pymeta.uint[32]]
        | coalesced_notification
        | pymeta.owned_by("shared"),
    ]
    items: Annotated[
        BoundedQueue[Item],
        mpsc
        | bounded_queue(capacity="self.capacity")
        | pymeta.owned_by("reactor"),
    ]

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="shared")
    )
    def send(self, item: Item):
        self.items.put_nowait(item)

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="reactor")
    )
    def receive(self):
        return self.items.get_nowait()

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="reactor")
    )
    def size(self):
        return self.items.qsize()

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="reactor")
    )
    def is_empty(self):
        return self.items.empty()

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="reactor")
    )
    def rearm(self):
        self.notified.store(0)
        if not self.items.empty():
            self.notified.compare_exchange(0, 1)

    @pymeta.region(
        pymeta.required, effects=pymeta.effects(owner="reactor")
    )
    def shutdown(self):
        self.state.compare_exchange(0, 1)
        self.items.close()
        while not self.items.empty():
            self.items.get_nowait()

def create_channel(capacity):
    instance = Channel()
    instance.capacity = capacity
    instance.state = LockedAtomic(0)
    instance.notified = LockedAtomic(0)
    instance.items = BoundedQueue(capacity)
    return instance
""",
        encoding="utf-8",
    )
    output = tmp_path / "mpsc-native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("mpsc_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import gc
import importlib.util
import queue
import sys
import threading
import time
import weakref
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("mpsc_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from mpsc_component_pkg.mpsc_component import BoundedQueue, Item, LockedAtomic

for capacity in (1, 4):
    channel = module.create_channel(capacity)
    assert channel.is_empty() is True
    try:
        channel.send(object())
    except TypeError as error:
        assert "exact ABI-declared record type" in str(error)
    else:
        raise AssertionError("MPSC accepted a foreign payload type")
    for index in range(capacity):
        channel.send(Item(index))
    assert channel.size() == capacity
    try:
        channel.send(Item(999_999))
    except queue.Full:
        pass
    else:
        raise AssertionError("bounded channel accepted an item while full")
    assert [channel.receive().payload for _ in range(capacity)] == list(range(capacity))
    assert channel.is_empty() is True
    channel.send(Item(777_777))
    assert channel.receive().payload == 777_777
    try:
        channel.receive()
    except queue.Empty:
        pass
    else:
        raise AssertionError("empty channel did not raise queue.Empty")
    channel.send(Item(123_456))
    del channel
    gc.collect()

class Payload:
    pass

channel = module.create_channel(2)
payload = Payload()
payload_ref = weakref.ref(payload)
record = Item(payload)
channel.send(record)
del payload
del record
gc.collect()
assert payload_ref() is not None
record = channel.receive()
del record
gc.collect()
assert payload_ref() is None

channel = module.create_channel(3)
channel.send(Item(1))
channel.send(Item(2))
channel.items.close()
try:
    channel.send(Item(3))
except RuntimeError as error:
    assert str(error) == "queue is closed"
else:
    raise AssertionError("closed channel accepted a send")
assert channel.receive().payload == 1
assert channel.receive().payload == 2
try:
    channel.receive()
except queue.Empty:
    pass
else:
    raise AssertionError("closed drained channel did not become empty")

channel = module.create_channel(2)
del channel.items
try:
    channel.items
except AttributeError:
    pass
else:
    raise AssertionError("deleted channel storage remained visible")
channel.items = BoundedQueue(2)
channel.send(Item(888_888))
assert channel.receive().payload == 888_888
try:
    channel.items = BoundedQueue(2)
except AttributeError:
    pass
else:
    raise AssertionError("live channel storage was replaced")
for invalid in (BoundedQueue(1), BoundedQueue(3)):
    fresh = module.Channel()
    fresh.capacity = 2
    try:
        fresh.items = invalid
    except ValueError:
        pass
    else:
        raise AssertionError("invalid capacity was accepted")

# Error cleanup must leave import/module ownership intact.  A dangling module
# reference here previously caused the next successful setter to die by SIGBUS
# inside PyImport_ImportModule.
post_failure = module.create_channel(1)
post_failure.send(Item(654_321))
assert post_failure.receive().payload == 654_321

channel = module.create_channel(32)
total = 400
next_value = 0
lock = threading.Lock()
def producer():
    global next_value
    while True:
        with lock:
            if next_value >= total:
                return
            value = next_value
            next_value += 1
        while True:
            try:
                channel.send(Item(value))
                break
            except queue.Full:
                time.sleep(0)
threads = [threading.Thread(target=producer) for _ in range(4)]
for thread in threads:
    thread.start()
received = []
while len(received) < total:
    try:
        received.append(channel.receive().payload)
    except queue.Empty:
        time.sleep(0)
for thread in threads:
    thread.join()
assert sorted(received) == list(range(total))

class Derived(module.Channel):
    pass
derived = Derived()
derived.capacity = 1
derived.state = LockedAtomic(0)
derived.notified = LockedAtomic(0)
derived.items = BoundedQueue(1)
derived.send(Item(444_444))
assert derived.receive().payload == 444_444
original = module.Channel.send
events = []
def replacement(self, item):
    events.append(item.payload)
module.Channel.send = replacement
try:
    channel = module.create_channel(1)
    channel.send(Item(333_333))
    assert events == [333_333]
    assert channel.is_empty()
finally:
    module.Channel.send = original

for _ in range(100):
    channel = module.create_channel(2)
    channel.send(Item(222_222))
    channel.items.close()
    del channel
    gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr


def test_exact_component_required_region_fusion_preserves_call_semantics(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "fusion_component_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "fusion_component.py"
    source.write_text(
        """
from typing import Annotated
import collections
import pymeta

events = []

def observe(value):
    events.append(value)
    if value == "raise":
        raise LookupError("argument failed")
    return value

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class Component(collections.UserList):
    @pymeta.region(pymeta.required)
    def combine(self, first, second, *, suffix=""):
        events.append("callee")
        return (first, second, suffix)

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class Facade(collections.UserList):
    component: Annotated[
        Component,
        pymeta.exact_type(Component) | pymeta.owned_by("reactor"),
    ]

    @pymeta.region(pymeta.required)
    def run(self, first, second, *, suffix=""):
        return self.component.combine(
            observe(first), observe(second), suffix=suffix
        )
""",
        encoding="utf-8",
    )
    output = tmp_path / "fusion-native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("fusion_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import gc
import importlib.util
import sys
sys.path.insert(0, sys.argv[2])
from fusion_component_pkg import fusion_component as reference
spec = importlib.util.spec_from_file_location("fusion_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for _ in range(1000):
    facade = module.Facade()
    component = module.Component()
    facade.component = component
    reference.events.clear()
    assert facade.run("first", "second", suffix="!") == ("first", "second", "!")
    assert reference.events == ["first", "second", "callee"]
    reference.events.clear()
    try:
        facade.run("raise", "never")
    except LookupError as error:
        assert str(error) == "argument failed"
    else:
        raise AssertionError("argument exception was swallowed")
    assert reference.events == ["raise"]
    class Override(module.Component):
        def combine(self, first, second, *, suffix=""):
            reference.events.append("override")
            return (second, first, suffix)
    facade = module.Facade()
    facade.component = Override()
    reference.events.clear()
    assert facade.run("left", "right", suffix="?") == ("right", "left", "?")
    assert reference.events == ["left", "right", "override"]
    facade = module.Facade()
    facade.component = module.Component()
    original = module.Component.combine
    def replacement(self, first, second, *, suffix=""):
        reference.events.append("replacement")
        return (suffix, second, first)
    module.Component.combine = replacement
    try:
        reference.events.clear()
        assert facade.run("one", "two", suffix="!") == ("!", "two", "one")
        assert reference.events == ["one", "two", "replacement"]
    finally:
        module.Component.combine = original
    def instance_replacement(first, second, *, suffix=""):
        reference.events.append("instance")
        return (first, suffix, second)
    facade.component.combine = instance_replacement
    reference.events.clear()
    assert facade.run("alpha", "beta", suffix=".") == ("alpha", ".", "beta")
    assert reference.events == ["alpha", "beta", "instance"]
    cyclic = module.Facade()
    cyclic.component = cyclic
    del component
    del facade
    del cyclic
    if _ % 31 == 0:
        gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr


def test_multi_source_native_types_direct_calls_and_module_lifecycle(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "multi_source_native_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "events.py").write_text(
        "events = []\n"
        "def observe(value):\n"
        "    events.append(value)\n"
        "    return value\n",
        encoding="utf-8",
    )
    (package / "component.py").write_text(
        "import collections\n"
        "import pymeta\n"
        "from .events import events\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component(collections.UserList):\n"
        "    payload: object\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def combine(self, left, right, *, suffix=''):\n"
        "        events.append('callee')\n"
        "        self.payload = (left, right, suffix)\n"
        "        return self.payload\n",
        encoding="utf-8",
    )
    source = package / "facade.py"
    source.write_text(
        "import collections\n"
        "from typing import Annotated\n"
        "import pymeta\n"
        "from .component import Component\n"
        "from .events import observe\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Facade(collections.UserList):\n"
        "    component: Annotated[Component, "
        "pymeta.exact_type(Component) | pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def run(self, left, right, *, suffix=''):\n"
        "        return self.component.combine("
        "observe(left), observe(right), suffix=suffix)\n"
        "def create_facade():\n"
        "    value = Facade()\n"
        "    value.component = Component()\n"
        "    value.component.payload = None\n"
        "    return value\n",
        encoding="utf-8",
    )
    output = tmp_path / "multi-source-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("facade_native*"))
    probe_command = [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import gc
import importlib
import importlib.util
import sys
import weakref
sys.path.insert(0, sys.argv[2])
events_module = importlib.import_module("multi_source_native_pkg.events")
for iteration in range(1):
    spec = importlib.util.spec_from_file_location("facade_native", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.__pymeta_native_classes__ == ("Facade", "Component")
    assert module.__pymeta_native_regions__ == (
        "Facade.run", "Component.combine")
    assert module.__pymeta_native_factories__ == ("create_facade",)
    facade = module.create_facade()
    events_module.events.clear()
    assert facade.run("left", "right", suffix="!") == ("left", "right", "!")
    assert events_module.events == ["left", "right", "callee"]
    class Derived(module.Component):
        def combine(self, left, right, *, suffix=""):
            events_module.events.append("derived")
            return (right, left, suffix)
    facade = module.Facade()
    facade.component = Derived()
    events_module.events.clear()
    assert facade.run(1, 2, suffix="d") == (2, 1, "d")
    assert events_module.events == [1, 2, "derived"]
    facade = module.Facade()
    facade.component = module.Component()
    facade.component.payload = None
    original = module.Component.combine
    def replacement(self, left, right, *, suffix=""):
        events_module.events.append("class-patch")
        return (suffix, left, right)
    module.Component.combine = replacement
    try:
        events_module.events.clear()
        assert facade.run(3, 4, suffix="c") == ("c", 3, 4)
        assert events_module.events == [3, 4, "class-patch"]
    finally:
        module.Component.combine = original
    def instance_replacement(left, right, *, suffix=""):
        events_module.events.append("instance-patch")
        return (left, suffix, right)
    facade.component.combine = instance_replacement
    events_module.events.clear()
    assert facade.run(5, 6, suffix="i") == (5, "i", 6)
    assert events_module.events == [5, 6, "instance-patch"]
    assert module.__pymeta_module_instance_policy__ == (
        "single_live_module;subinterpreters_unsupported")
    second_spec = importlib.util.spec_from_file_location(
        "facade_native", sys.argv[1])
    second_module = importlib.util.module_from_spec(second_spec)
    try:
        second_spec.loader.exec_module(second_module)
    except RuntimeError as error:
        assert "one live module instance" in str(error)
    else:
        raise AssertionError("concurrent extension re-exec was accepted")
    del second_module, second_spec
    events_module.events.clear()
    assert facade.run(7, 8, suffix="safe") == (7, "safe", 8)
    assert events_module.events == [7, 8, "instance-patch"]
    class Marker:
        pass
    marker = Marker()
    marker_ref = weakref.ref(marker)
    facade.component.payload = marker
    facade.component.owner = facade
    del marker, facade
    gc.collect()
    assert marker_ref() is None
    del (
        Derived,
        Marker,
        instance_replacement,
        marker_ref,
        original,
        replacement,
        module,
        spec,
    )
    gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ]
    for _ in range(8):
        probe = subprocess.run(
            probe_command,
            check=False,
            capture_output=True,
            text=True,
            cwd=tmp_path,
            env=_compiler_environment(),
            timeout=120,
        )
        assert probe.returncode == 0, probe.stderr


def test_multi_source_duplicate_native_name_rejects_without_artifact(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "duplicate_native_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    dependency = package / "dependency.py"
    dependency.write_text(
        "import collections\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Duplicate(collections.UserList):\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def dependency(self):\n"
        "        return 1\n",
        encoding="utf-8",
    )
    source = package / "primary.py"
    source.write_text(
        "import collections\n"
        "import pymeta\n"
        "from .dependency import Duplicate as ImportedDuplicate\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Duplicate(collections.UserList):\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def primary(self):\n"
        "        return ImportedDuplicate\n",
        encoding="utf-8",
    )
    output = tmp_path / "duplicate-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode != 0
    assert "native class Duplicate conflicts" in completed.stderr
    assert str(source) in completed.stderr
    assert str(dependency) in completed.stderr
    assert not output.exists()


def test_generated_custom_constructors_components_and_object_base_gc(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path.parent))
    completed, _ = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "constructor_components",
        "import collections\n"
        "import pymeta\n"
        "from typing import Annotated\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component:\n"
        "    value: object\n"
        "    def __init__(self, value):\n"
        "        self.value = value\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def read(self):\n"
        "        return self.value\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Container(collections.UserList):\n"
        "    component: Annotated[Component, pymeta.exact_type(Component)]\n"
        "    label: object\n"
        "    mapping: object\n"
        "    transform: object\n"
        "    def __init__(self, value, *, label='native'):\n"
        "        super().__init__([value])\n"
        "        self.component = Component(value)\n"
        "        self.label = f'{label}-{value!r}'\n"
        "        self.mapping = {'value': value}\n"
        "        self.transform = lambda item: {'item': item}\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def read(self):\n"
        "        return self.component.read()\n",
    )

    assert completed.returncode == 0, completed.stderr
    native = _load_fixture(
        Path(completed.stdout.strip()), "constructor_components_native"
    )
    value = native.Container(7, label="compiled")
    assert type(value.component) is native.Component
    assert value.read() == 7
    assert value.label == "compiled-7"
    assert value.mapping == {"value": 7}
    assert value.transform("boxed") == {"item": "boxed"}
    assert list(value) == [7]
    source_path = (tmp_path / "constructor_components.py").resolve()
    source_module = next(
        module
        for module in tuple(sys.modules.values())
        if module is not None
        and getattr(module, "__file__", None) is not None
        and Path(module.__file__).resolve() == source_path
    )
    original_component = source_module.Component

    class ReplacementComponent:
        def __init__(self, component_value: object) -> None:
            self.value = ("replacement", component_value)

        def read(self) -> object:
            return self.value

    source_module.Component = ReplacementComponent
    replaced = native.Container(8)
    assert type(replaced.component) is ReplacementComponent
    assert replaced.read() == ("replacement", 8)
    source_module.Component = original_component
    restored = native.Container(9)
    assert type(restored.component) is native.Component
    assert restored.read() == 9
    with pytest.raises(AttributeError, match="immutable"):
        value.component = native.Component(8)
    with pytest.raises(AttributeError, match="cannot be deleted"):
        del value.component
    class Sentinel:
        pass
    sentinel = Sentinel()
    reference = __import__("weakref").ref(sentinel)
    value.label = sentinel
    value.component.value = value
    del sentinel
    del value
    assert gc.collect() >= 0
    assert reference() is None


def test_native_storage_owner_survives_cycles_and_subprocess_shutdown(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "storage_owner_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "storage_component.py"
    source.write_text(
        """
from typing import Annotated
import asyncio
import pymeta

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class NativeQueue(asyncio.SelectorEventLoop):
    work: Annotated[
        object,
        pymeta.storage.fifo | pymeta.owned_by("reactor"),
    ]

    @pymeta.region(pymeta.required)
    def hold(self, value):
        self.work.append(value)

    @pymeta.region(pymeta.required)
    def take(self):
        return self.work.popleft()

    @pymeta.region(pymeta.required)
    def state(self):
        work = self.work
        if work:
            return len(work)
        return 0
""",
        encoding="utf-8",
    )
    output = tmp_path / "storage-native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("storage_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import gc
import collections
import importlib.util
import sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("storage_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class Derived(module.NativeQueue):
    pass
for cls in (module.NativeQueue, Derived):
    for index in range(250):
        value = cls()
        value.work = collections.deque()
        marker = object()
        value.hold(marker)
        assert value.state() == 1
        assert value.take() is marker
        assert value.state() == 0
        value.hold(value)
        if cls is Derived:
            value.derived_cycle = value
        if index == 0:
            materialized = value.work
            assert materialized.popleft() is value
            del value.work
            try:
                value.work
            except AttributeError:
                pass
            else:
                raise AssertionError("deleted native FIFO remained readable")
            try:
                value.hold(value)
            except AttributeError:
                pass
            else:
                raise AssertionError("deleted native FIFO was recreated")
            value.work = collections.deque()
            value.hold(value)
        value.close()
        del value
        if index % 31 == 0:
            gc.collect()
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr


def test_proof_indexed_heap_hooks_preserve_alias_and_deopt_semantics(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    package = tmp_path / "heap_hook_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "heap_component.py"
    source.write_text(
        """
from typing import Annotated
import asyncio
import heapq
import pymeta
from pymeta.cpython import pinned_semantics

@pymeta.native_class(
    pymeta.compact_object,
    gc=pymeta.tracked,
    weakrefs=False,
)
class NativeHeap(asyncio.SelectorEventLoop):
    timers: Annotated[
        object,
        pymeta.storage.min_heap(
            key="deadline", ordering=pinned_semantics("heapq")
        )
        | pymeta.owned_by("reactor"),
    ]

    @pymeta.region(pymeta.required)
    def push(self, value):
        heapq.heappush(self.timers, value)

    @pymeta.region(pymeta.required)
    def pop(self):
        return heapq.heappop(self.timers)

    @pymeta.region(pymeta.required)
    def stats(self):
        timers = self.timers
        if timers:
            return (len(timers), timers[0])
        return (0, None)

    @pymeta.region(pymeta.required)
    def head_and_len(self):
        timers = self.timers
        return (len(timers), timers[0])

    @pymeta.region(pymeta.required)
    def snapshot(self):
        timers = self.timers
        result = []
        for value in timers:
            result.append(value)
        return result

    @pymeta.region(pymeta.required)
    def replace(self, values):
        timers = self.timers
        timers[:] = values
        heapq.heapify(timers)
""",
        encoding="utf-8",
    )
    output = tmp_path / "heap-native-output"
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = next(output.glob("heap_component_native*"))
    probe = subprocess.run(
        [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import gc
import heapq
import importlib.util
import sys
import weakref
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("heap_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class Derived(module.NativeHeap):
    pass
for cls in (module.NativeHeap, Derived):
    value = cls()
    value.timers = []
    reference = []
    try:
        assert value.stats() == (0, None)
    except AttributeError:
        pass
    for item in ((4, 0), (1, 1), (3, 2), (1, 3)):
        value.push(item)
        heapq.heappush(reference, item)
    assert value.head_and_len() == (len(reference), reference[0])
    assert value.stats() == (len(reference), reference[0])
    assert value.snapshot() == reference
    assert value.pop() == heapq.heappop(reference)
    replacement = ((2, 9), (0, 8), (5, 7))
    value.replace(iter(replacement))
    reference[:] = replacement
    heapq.heapify(reference)
    assert value.snapshot() == reference
    before = value.snapshot()
    class Broken:
        def __iter__(self):
            yield (9, 1)
            raise RuntimeError("broken replacement")
    try:
        value.replace(Broken())
    except RuntimeError as error:
        assert str(error) == "broken replacement"
    else:
        raise AssertionError("failing slice source was accepted")
    assert value.snapshot() == before
    external = []
    value.timers = external
    value.push((6, 6))
    assert external == [(6, 6)]
    del value.timers
    try:
        value.stats()
    except AttributeError:
        pass
    else:
        raise AssertionError("deleted native heap remained readable")
    try:
        value.push((7, 7))
    except AttributeError:
        pass
    else:
        raise AssertionError("deleted native heap was recreated")
    value.timers = []
    value.push((7, 7))
    assert value.pop() == (7, 7)
    value.push(value)
    reference_to_value = weakref.ref(value)
    value.close()
    del value
    gc.collect()
    assert reference_to_value() is None
""",
            str(artifact),
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert probe.returncode == 0, probe.stderr


@pytest.fixture(scope="module")
def c_compiler_build(tmp_path_factory: pytest.TempPathFactory) -> CCompilerBuild:
    root = tmp_path_factory.mktemp("c-pymeta-compiler")
    build_dir = root / "build"
    subprocess.run(
        [
            "cmake",
            "-S",
            str(NATIVE_COMPILER_SOURCE),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build_dir), "--target", "wrtc-pymeta-compiler-c"],
        check=True,
        capture_output=True,
        text=True,
    )
    executable = build_dir / (
        "wrtc-pymeta-compiler-c.exe" if sys.platform == "win32" else "wrtc-pymeta-compiler-c"
    )
    assert executable.is_file()

    output_dir = root / "artifact"
    completed = subprocess.run(
        [
            str(executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=root,
        env=_compiler_environment(),
    )
    artifact = Path(completed.stdout.strip()).resolve()
    return CCompilerBuild(executable, artifact, output_dir)


@pytest.fixture(autouse=True)
def restore_python_dispatch() -> None:
    runtime.configure_kernel_e(mode="python")
    yield
    runtime.configure_kernel_e(mode="python")


def test_c_compiler_produces_exactly_one_extension_without_sidecars(
    c_compiler_build: CCompilerBuild,
) -> None:
    expected_name = f"kernel_e_native{sysconfig.get_config_var('EXT_SUFFIX')}"
    files = sorted(
        path.resolve()
        for path in c_compiler_build.output_dir.rglob("*")
        if path.is_file()
    )
    assert c_compiler_build.artifact == (c_compiler_build.output_dir / expected_name).resolve()
    assert files == [c_compiler_build.artifact]


def test_native_driver_owns_compilation_without_python_compiler_delegation() -> None:
    driver_source = (NATIVE_COMPILER_SOURCE / "main.c").read_text(encoding="utf-8")
    assert "webrtc.compiler.module_compiler" not in driver_source
    assert "_compile_module_in_process" not in driver_source


def test_python_entry_is_only_a_native_driver_build_and_launch_shim() -> None:
    compiler_package = REPOSITORY_ROOT / "webrtc/compiler"
    shim = (compiler_package / "module_compiler.py").read_text(encoding="utf-8")

    assert not (compiler_package / "compiler.py").exists()
    assert not (compiler_package / "build.py").exists()
    assert "import ast" not in shim
    assert "_emit_extension_c" not in shim
    assert "_compile_c_extension" not in shim
    assert "compile_kernel_e" not in shim


def test_runtime_has_no_legacy_per_function_dispatch_slot() -> None:
    runtime_source = (REPOSITORY_ROOT / "webrtc/compiler/runtime.py").read_text(
        encoding="utf-8"
    )
    assert "_implementation" not in runtime_source


def test_c_compiler_rejects_non_ascii_source_stem_before_creating_output(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    source = tmp_path / "kernél.py"
    source.write_bytes(KERNEL_SOURCE.read_bytes())
    output = tmp_path / "non-ascii-output"

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "valid non-keyword Python identifier" in completed.stderr
    assert not output.exists()


def test_c_compiler_rejects_quoted_path_before_creating_output(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    output = tmp_path / 'quoted"output'

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "paths must not contain a double quote" in completed.stderr
    assert not output.exists()


def test_c_compiler_rejects_overlong_path_before_creating_temp_state(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    output = tmp_path / ("x" * 3001)

    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(KERNEL_SOURCE),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert "bounded compiler path limit" in completed.stderr
    assert list(tmp_path.iterdir()) == []


def test_c_compiled_extension_hides_all_but_module_initializer(
    c_compiler_build: CCompilerBuild,
) -> None:
    if sys.platform == "darwin":
        command = ["nm", "-gU", str(c_compiler_build.artifact)]
        expected = "_PyInit_kernel_e_native"
    elif sys.platform.startswith("linux"):
        command = ["nm", "-D", "--defined-only", str(c_compiler_build.artifact)]
        expected = "PyInit_kernel_e_native"
    else:
        pytest.skip("defined-export inspection is configured for nm platforms")
    output = subprocess.run(
        command, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    assert {line.split()[-1] for line in output if line.split()} == {expected}


def test_c_compiled_extension_loads_with_discovery_and_metadata(
    c_compiler_build: CCompilerBuild,
) -> None:
    dispatcher = runtime.load_native_module(c_compiler_build.artifact, kernel_e)
    native = dispatcher.module
    function = native.packetize_av1_frame

    assert tuple(native.__all__) == tuple(kernel_e.__all__)
    assert "packetize_av1_frame" in dir(native)
    assert getattr(native, "packetize_av1_frame") is function
    assert inspect.signature(function) == inspect.signature(kernel_e.packetize_av1_frame)
    assert function.__doc__ == kernel_e.packetize_av1_frame.__doc__
    assert function.__annotations__ == kernel_e.packetize_av1_frame.__annotations__
    assert isinstance(native.__pymeta_functions__, MappingProxyType)
    assert dict(native.__pymeta_functions__) == {"packetize_av1_frame": function}
    for key, expected in runtime_compatibility().items():
        assert getattr(native, METADATA_ATTRIBUTES[key]) == expected
    assert len(native.__pymeta_source_sha256__) == 64
    assert len(native.__pymeta_semantic_sha256__) == 64


def test_c_compiled_kernel_matches_python_results_and_errors(
    c_compiler_build: CCompilerBuild,
) -> None:
    valid_cases = (
        (b"", 3, 0, 0, 0, 0),
        (bytes.fromhex("3209010203040506070809"), 3, 1, 2, 0xFFFE, 0xFFFD),
        (bytes.fromhex("0a0201023209010203040506070809"), 6, 0, 0xFFFFFFFF, 0xFE, 0xFFFE),
    )
    native = runtime.load_native_module(c_compiler_build.artifact, kernel_e).module
    for arguments in valid_cases:
        assert native.packetize_av1_frame(*arguments) == kernel_e.packetize_av1_frame(
            *arguments
        )

    malformed = (b"\x32\x02\x01", 1200, 1, 2, 3, 4)
    with pytest.raises(ValueError) as python_error:
        kernel_e.packetize_av1_frame(*malformed)
    with pytest.raises(ValueError) as native_error:
        native.packetize_av1_frame(*malformed)
    assert native_error.value.args == python_error.value.args


def test_c_compiled_dispatch_never_calls_python_implementation(
    c_compiler_build: CCompilerBuild, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("native execution called Python")

    forbidden.__module__ = kernel_e.__name__
    monkeypatch.setattr(kernel_e, "packetize_av1_frame", forbidden)
    runtime.configure_kernel_e(
        mode="native-required", library_path=c_compiler_build.artifact
    )
    assert runtime.packetize_av1_frame(b"", 3, 0, 0, 7, 8) == ((), 7, 8)


def test_c_compiler_accepts_explicit_exports_and_shared_private_helpers(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "generic_explicit",
        '''"""Generic compiler fixture."""
import pymeta
from pymeta import required

__all__ = ["increment", "encode"]

def _offset(value: int) -> int:
    return value + 1

@required
@pymeta.region("increment", value=pymeta.u64)
def increment(value: int) -> int:
    """Increment through a shared private helper."""
    return _offset(value)

@pymeta.region("encode", value=pymeta.buffer(maximum=1024))
def encode(value: bytes) -> bytes:
    return value + bytes([_offset(32)])
''',
    )

    assert completed.returncode == 0, completed.stderr
    artifact = Path(completed.stdout.strip())
    assert artifact.parent == output
    native = _load_fixture(artifact, "generic_explicit_native")
    assert native.increment(4) == 5
    assert native.encode(b"x") == b"x!"
    assert tuple(native.__all__) == ("increment", "encode")
    assert tuple(native.__pymeta_functions__) == ("increment", "encode")
    assert not hasattr(native, "_offset")
    assert str(inspect.signature(native.increment)) == "(value: int) -> int"
    assert native.increment.__doc__ == "Increment through a shared private helper."


def test_c_compiler_discovers_implicit_public_functions(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, _ = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "generic_implicit",
        "import pymeta\n\n"
        "@pymeta.region('first', value=pymeta.u64)\n"
        "def first(value: int) -> int:\n"
        "    return value * 2\n\n"
        "def _private(value: int) -> int:\n"
        "    return value - 1\n\n"
        "@pymeta.region('second', value=pymeta.u64)\n"
        "def second(value: int) -> int:\n"
        "    return _private(value)\n",
    )

    assert completed.returncode == 0, completed.stderr
    native = _load_fixture(Path(completed.stdout.strip()), "generic_implicit_native")
    assert tuple(native.__all__) == ("first", "second")
    assert native.first(6) == 12
    assert native.second(6) == 5
    assert not hasattr(native, "_private")


def test_native_region_rejection_reports_generic_datagram_capabilities(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "renamed_reactor_component",
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component:\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor', "
        "noescape={'packet.payload'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def drain(self, loop, transport, generation):\n"
        "        if not self._is_current(transport, generation):\n"
        "            return\n"
        "        started = loop.time()\n"
        "        budget = self.config.receive_packet_budget\n"
        "        time_budget = self.config.receive_time_budget_us / 1000000\n"
        "        for _ in range(budget):\n"
        "            if loop.time() - started >= time_budget:\n"
        "                transport.request_reschedule(generation)\n"
        "                return\n"
        "            packet = transport.receive_one()\n"
        "            if packet is None:\n"
        "                return\n"
        "            transport.deliver(packet)\n",
    )

    assert completed.returncode != 0
    assert "capability_report=" in completed.stderr
    assert "renamed_reactor_component.py" in completed.stderr
    assert "'status': 'rejected'" in completed.stderr
    assert "'packet_budget'" in completed.stderr
    assert "'time_budget'" in completed.stderr
    assert "'bounded_interleaving': True" in completed.stderr
    assert "'descriptor_generation_validated': True" in completed.stderr
    assert "'datagram_runtime_lowering_available': True" in completed.stderr
    assert "'reactor_hook_emission_complete': False" in completed.stderr
    assert "'native_reactor_hook': 'not_emitted'" in completed.stderr
    assert "'code': 'reactor_hook_emission'" in completed.stderr
    assert "bounded reschedule requires no arguments" in completed.stderr
    assert not output.exists()


def test_generated_guarded_reactor_boundaries_preserve_python_semantics(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path.parent))
    completed, _ = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "guarded_reactor_component",
        "import asyncio\n"
        "import selectors\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component(asyncio.SelectorEventLoop):\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor', suspend=pymeta.never))\n"
        "    def dispatch(self, loop, events):\n"
        "        for key, mask in events:\n"
        "            reader, writer = key.data\n"
        "            if mask & selectors.EVENT_READ and reader is not None:\n"
        "                if reader._cancelled:\n"
        "                    loop._remove_reader(key.fileobj)\n"
        "                else:\n"
        "                    loop._ready.append(reader)\n"
        "            if mask & selectors.EVENT_WRITE and writer is not None:\n"
        "                if writer._cancelled:\n"
        "                    loop._remove_writer(key.fileobj)\n"
        "                else:\n"
        "                    loop._ready.append(writer)\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor', suspend=pymeta.never))\n"
        "    def _is_current(self, transport, generation):\n"
        "        return transport.generation == generation\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor', noescape={'packet'}, "
        "allocate=pymeta.never, suspend=pymeta.never))\n"
        "    def drain(self, loop, transport, generation):\n"
        "        if not self._is_current(transport, generation):\n"
        "            return\n"
        "        started = loop.time()\n"
        "        budget = transport.packet_budget\n"
        "        time_budget = transport.time_budget\n"
        "        for _ in range(budget):\n"
        "            if loop.time() - started >= time_budget:\n"
        "                transport.request_reschedule()\n"
        "                return\n"
        "            packet = transport.receive_one()\n"
        "            if packet is None:\n"
        "                return\n"
        "            transport.deliver(packet)\n",
    )
    assert completed.returncode == 0, completed.stderr
    artifact = Path(completed.stdout.strip())
    probe = subprocess.run(
        [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import importlib.util
import sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "guarded_reactor_component_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
loop = module.Component()
assert module.__pymeta_native_reactor_hook__.startswith(
    "guarded_cpython_reactor_thread")
loop.call_soon(lambda: None)
loop._run_once()
loop.close()
""",
            str(artifact),
            str(tmp_path.parent),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert probe.returncode == 0, probe.stderr
    native = _load_fixture(
        artifact, "guarded_reactor_component_native"
    )
    assert native.__pymeta_native_reactor_hook__.startswith(
        "guarded_cpython_reactor_thread"
    )

    import selectors
    import select
    import socket
    from types import SimpleNamespace

    loop = native.Component()
    left, right = socket.socketpair()
    try:
        loop.add_reader(left.fileno(), lambda: None)
        key = loop._selector.get_key(left.fileno())
        key.data[0].cancel()
        loop.dispatch(loop, [(key, selectors.EVENT_READ)])
        with pytest.raises(KeyError):
            loop._selector.get_key(left.fileno())

        monkeypatch_calls: list[int] = []
        loop.add_reader(left.fileno(), lambda: None)
        key = loop._selector.get_key(left.fileno())
        key.data[0].cancel()
        loop._remove_reader = lambda fd: monkeypatch_calls.append(fd) or False
        loop.dispatch(loop, [(key, selectors.EVENT_READ)])
        assert monkeypatch_calls == [left.fileno()]
        assert loop._selector.get_key(left.fileno()) is key
        del loop._remove_reader
        loop.remove_reader(left.fileno())

        evaluation_order: list[str] = []

        class TraceLoop:
            _ready: list[object] = []

            def __getattribute__(self, name: str) -> object:
                if name == "_remove_reader":
                    evaluation_order.append("lookup")
                return object.__getattribute__(self, name)

            def _remove_reader(self, fd: int) -> str:
                assert fd == left.fileno()
                evaluation_order.append("call")
                return "preserved-return"

        class TraceKey:
            data = (SimpleNamespace(_cancelled=True), None)

            @property
            def fileobj(self) -> int:
                evaluation_order.append("argument")
                return left.fileno()

        loop.dispatch(
            TraceLoop(), [(TraceKey(), selectors.EVENT_READ)]
        )
        assert evaluation_order == ["lookup", "argument", "call"]

        class Packet:
            def __init__(self, value: bytes) -> None:
                self.value = value
                self.releases = 0

            def release(self) -> None:
                self.releases += 1
                if self.releases != 1:
                    raise AssertionError("packet lease released more than once")

        class Transport:
            generation = 7
            packet_budget = 2
            time_budget = 1.0

            def __init__(self, protocol: object, receiver: socket.socket = left) -> None:
                self.protocol = protocol
                self.receiver = receiver
                self.packets: list[Packet] = []
                self.reschedules = 0

            def receive_one(self) -> Packet | None:
                try:
                    data = self.receiver.recv(64)
                except BlockingIOError:
                    return None
                packet = Packet(data)
                self.packets.append(packet)
                return packet

            def deliver(self, packet: Packet) -> None:
                retained = getattr(self.protocol, "packet_received", None)
                if retained is not None:
                    try:
                        retained(packet)
                    except BaseException:
                        packet.release()
                        raise
                else:
                    try:
                        self.protocol.datagram_received(packet.value, None)
                    finally:
                        packet.release()

            def request_reschedule(self) -> None:
                self.reschedules += 1
                loop.call_soon(lambda: None)

        left.setblocking(False)
        delivered: list[bytes] = []
        transport = Transport(
            SimpleNamespace(
                datagram_received=lambda data, address: delivered.append(data)
            )
        )
        right.send(b"ok")
        loop.drain(loop, transport, 7)
        assert delivered == [b"ok"]
        assert transport.packets[0].releases == 1

        retained: list[Packet] = []
        retained_transport = Transport(
            SimpleNamespace(packet_received=retained.append)
        )
        right.send(b"retained")
        loop.drain(loop, retained_transport, 7)
        assert len(retained) == 1 and retained[0].releases == 0
        retained[0].release()
        assert retained[0].releases == 1

        failures: list[tuple[str, str]] = []

        def exception_handler(
            _loop: object, context: dict[str, object]
        ) -> None:
            exception = context["exception"]
            assert isinstance(exception, BaseException)
            failures.append((type(exception).__name__, str(exception)))

        def fail_delivery(data: bytes, address: object) -> None:
            del data, address
            raise LookupError("guarded datagram failure")

        failing_transport = Transport(
            SimpleNamespace(datagram_received=fail_delivery)
        )
        loop.set_exception_handler(exception_handler)
        right.send(b"failure")
        loop.call_soon(loop.drain, loop, failing_transport, 7)
        loop._run_once()
        assert failures == [("LookupError", "guarded datagram failure")]
        assert failing_transport.packets[0].releases == 1

        right.send(b"stale")
        loop.drain(loop, transport, 6)
        assert delivered == [b"ok"]
        assert left.recv(64) == b"stale"

        transport.time_budget = -1.0
        loop.drain(loop, transport, 7)
        assert transport.reschedules == 1

        udp_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_receiver.bind(("127.0.0.1", 0))
            udp_receiver.setblocking(False)
            udp_delivery: list[bytes] = []
            udp_transport = Transport(
                SimpleNamespace(
                    datagram_received=lambda data, address:
                        udp_delivery.append(data)
                ),
                udp_receiver,
            )
            udp_sender.sendto(b"udp", udp_receiver.getsockname())
            readable, _, _ = select.select([udp_receiver], [], [], 1.0)
            assert readable == [udp_receiver]
            loop.drain(loop, udp_transport, 7)
            assert udp_delivery == [b"udp"]
            assert udp_transport.packets[0].releases == 1
        finally:
            udp_sender.close()
            udp_receiver.close()

        original_remove_writer = native.Component._remove_writer
        class_patch_calls: list[int] = []
        native.Component._remove_writer = (
            lambda self, fd: class_patch_calls.append(fd) or False
        )
        try:
            loop.add_writer(left.fileno(), lambda: None)
            class_patch_key = loop._selector.get_key(left.fileno())
            class_patch_key.data[1].cancel()
            loop.dispatch(
                loop, [(class_patch_key, selectors.EVENT_WRITE)]
            )
            assert class_patch_calls == [left.fileno()]
            assert loop._selector.get_key(left.fileno()) is class_patch_key
        finally:
            native.Component._remove_writer = original_remove_writer
            loop.remove_writer(left.fileno())

        class Derived(native.Component):
            def _remove_writer(self, fd: int) -> bool:
                monkeypatch_calls.append(-fd)
                return False

        derived = Derived()
        try:
            derived.add_writer(left.fileno(), lambda: None)
            writer_key = derived._selector.get_key(left.fileno())
            writer_key.data[1].cancel()
            derived.dispatch(
                derived, [(writer_key, selectors.EVENT_WRITE)]
            )
            assert monkeypatch_calls[-1] == -left.fileno()
            assert derived._selector.get_key(left.fileno()) is writer_key
        finally:
            derived.close()
    finally:
        left.close()
        right.close()
        loop.close()


def test_generated_native_reactor_storage_lifecycle_and_fd_generation(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path.parent))
    completed, _ = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "native_reactor_storage",
        "import asyncio\n"
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Reactor(asyncio.SelectorEventLoop):\n"
        "    selector_capacity: int\n"
        "    packet_capacity: int\n"
        "    packet_size: int\n"
        "    registry: Annotated[object, "
        "pymeta.storage.selector_registry(capacity='self.selector_capacity') "
        "| pymeta.owned_by('reactor')]\n"
        "    packets: Annotated[object, "
        "pymeta.storage.packet_slab(capacity='self.packet_capacity', "
        "buffer_size='self.packet_size') | pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def ready(self):\n"
        "        return True\n",
    )
    assert completed.returncode == 0, completed.stderr
    artifact = Path(completed.stdout.strip())
    probe = subprocess.run(
        [
            sys.executable,
            "-X",
            "faulthandler",
            "-c",
            """
import gc
import importlib.util
import select
import selectors
import socket
import sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "native_reactor_storage_native", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.__pymeta_native_reactor_state__.startswith("selector_registry")
faulted = module.Reactor()
faulted.selector_capacity = 0
try:
    faulted.registry = object()
except ValueError:
    pass
else:
    raise AssertionError("zero-capacity selector initialization succeeded")
faulted.selector_capacity = 2
faulted.registry = object()
del faulted.registry
faulted.close()
reactor = module.Reactor()
reactor.selector_capacity = 4
reactor.packet_capacity = 3
reactor.packet_size = 256
reactor.registry = object()
reactor.packets = object()
assert reactor.packets.available() == 3
left, right = socket.socketpair()
try:
    token = reactor.registry.register(
        left.fileno(), selectors.EVENT_READ, reactor)
    assert reactor.registry.is_current(token)
    right.send(b"x")
    ready = reactor.registry.poll(1000, 4)
    assert ready == [(token, 1, reactor)]
    assert reactor.registry.modify(token, selectors.EVENT_READ, "owner")
    assert reactor.registry.remove(token)
    assert not reactor.registry.is_current(token)
    replacement = reactor.registry.register(
        left.fileno(), selectors.EVENT_READ, "replacement")
    assert replacement[1] != token[1]
    assert not reactor.registry.remove(token)
    assert reactor.registry.remove(replacement)
finally:
    left.close()
    right.close()
udp_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    udp_receiver.bind(("127.0.0.1", 0))
    udp_receiver.setblocking(False)
    delivered = []
    udp_sender.sendto(b"native-slab", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    result = reactor.packets.drain(
        udp_receiver.fileno(), 2, 1_000_000_000, delivered.append)
    assert result[1] == 1 and 1 <= result[2] <= 2
    assert delivered == [b"native-slab"]
    assert reactor.packets.available() == 3
    retained = []
    udp_sender.sendto(b"retained", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    retained_result = reactor.packets.drain_retained(
        udp_receiver.fileno(), 2, 1_000_000_000, retained.append)
    assert retained_result[1] == 1 and len(retained) == 1
    assert reactor.packets.available() == 2
    assert retained[0].to_bytes() == b"retained"
    retained[0].release()
    retained[0].release()
    assert reactor.packets.available() == 3
    try:
        retained[0].to_bytes()
    except RuntimeError:
        pass
    else:
        raise AssertionError("released packet lease remained readable")
    retained.clear()
    udp_sender.sendto(b"gc-lease", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    reactor.packets.drain_retained(
        udp_receiver.fileno(), 2, 1_000_000_000, retained.append)
    assert reactor.packets.available() == 2
    retained.clear()
    gc.collect()
    assert reactor.packets.available() == 3
    def fail_delivery(payload):
        del payload
        raise LookupError("native slab callback")
    udp_sender.sendto(b"failure", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    try:
        reactor.packets.drain(
            udp_receiver.fileno(), 2, 1_000_000_000, fail_delivery)
    except LookupError as error:
        assert str(error) == "native slab callback"
    else:
        raise AssertionError("delivery exception was swallowed")
    assert reactor.packets.available() == 3
    udp_sender.sendto(b"retained-failure", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    try:
        reactor.packets.drain_retained(
            udp_receiver.fileno(), 2, 1_000_000_000, fail_delivery)
    except LookupError as error:
        assert str(error) == "native slab callback"
    else:
        raise AssertionError("retained delivery exception was swallowed")
    assert reactor.packets.available() == 3
    def release_then_fail(lease):
        lease.release()
        raise LookupError("released callback failure")
    udp_sender.sendto(b"released-failure", udp_receiver.getsockname())
    assert select.select([udp_receiver], [], [], 1.0)[0] == [udp_receiver]
    try:
        reactor.packets.drain_retained(
            udp_receiver.fileno(), 2, 1_000_000_000, release_then_fail)
    except LookupError as error:
        assert str(error) == "released callback failure"
    else:
        raise AssertionError("released callback exception was swallowed")
    assert reactor.packets.available() == 3
finally:
    udp_sender.close()
    udp_receiver.close()
del reactor.registry
reactor.registry = object()
try:
    reactor.registry = object()
except AttributeError:
    pass
else:
    raise AssertionError("reactor storage accepted repeated initialization")
reactor.close()
del reactor
assert gc.collect() >= 0
""",
            str(artifact),
            str(tmp_path.parent),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert probe.returncode == 0, probe.stderr


def test_native_concurrency_rejection_reports_unproven_safety_contract(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "renamed_concurrent_component",
        "from typing import Annotated\n"
        "import pymeta\n"
        "from pymeta.concurrent import BoundedQueue, bounded_queue, spsc\n"
        "@pymeta.record(abi='result.v1')\n"
        "class Result:\n"
        "    value: int\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component:\n"
        "    queue: Annotated[object, pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='config.capacity') | "
        "pymeta.coalesced_notification]\n"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', "
        "noescape={'packet'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def process(self, packet) -> Result:\n"
        "        return self.callback(packet)\n",
    )

    assert completed.returncode != 0
    assert "capability_report=" in completed.stderr
    assert "'mpsc'" in completed.stderr
    assert "'spsc'" in completed.stderr
    assert "'owned_shard'" in completed.stderr
    assert "'typed_record'" in completed.stderr
    assert "'queue_algorithm': 'mpsc'" in completed.stderr
    assert "'capacity': 'config.capacity'" in completed.stderr
    assert "'typed_records':" in completed.stderr
    assert "'ownership_transfer': True" in completed.stderr
    assert "'typed_worker_records': False" in completed.stderr
    assert "'worker_python_free': False" in completed.stderr
    assert "'worker_record_abi': False" in completed.stderr
    assert "'worker_reachability': False" in completed.stderr
    assert "'worker_emission_complete': False" in completed.stderr
    assert "'node_reclamation': False" in completed.stderr
    assert "'memory_ordering': 'not_proven'" in completed.stderr
    assert "worker reaches an unresolved or dynamic Python call" in completed.stderr
    assert not output.exists()


def test_owned_shard_proves_native_records_calls_and_record_result_emission(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "portable_worker_component",
        "from dataclasses import dataclass\n"
        "from typing import Annotated\n"
        "import pymeta\n"
        "from pymeta.concurrent import BoundedQueue, bounded_queue, spsc\n"
        "@pymeta.record(abi='packet.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Packet:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "    payload: Annotated[bytes, pymeta.buffer[pymeta.u8] | "
        "pymeta.read | pymeta.lifetime.call]\n"
        "@pymeta.record(abi='result.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Result:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "    value: Annotated[int, pymeta.uint[32]]\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Worker:\n"
        "    _input: Annotated[BoundedQueue[Packet], spsc | "
        "bounded_queue(capacity=1) | pymeta.owned_by('worker')]\n"
        "    _output: Annotated[BoundedQueue[Result], spsc | "
        "bounded_queue(capacity=1) | pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='worker', allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def transform(self, packet: Packet) -> Result:\n"
        "        return Result(packet.peer_id, 1)\n"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', "
        "noescape={'packet.payload'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def process(self, packet: Packet) -> Result:\n"
        "        return self.transform(packet)\n",
    )

    assert completed.returncode != 0
    assert "'worker_abi_eligible': True" in completed.stderr
    assert "'worker_record_abi': True" in completed.stderr
    assert "'worker_reachability': True" in completed.stderr
    assert "'worker_emission_complete': True" in completed.stderr
    assert "'worker_python_free': True" in completed.stderr
    assert "'kernel_emission_complete': True" in completed.stderr
    assert "'kernel_python_free': True" in completed.stderr
    assert "'worker_executor_emission_complete': True" in completed.stderr
    assert "'worker_thread_python_api_free': True" in completed.stderr
    assert not output.exists()


def test_owned_shard_rejects_constructor_injected_python_processor(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "dynamic_worker_component",
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Worker:\n"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', "
        "noescape={'packet.payload'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def process(self, packet):\n"
        "        return self._processor(packet)\n",
    )

    assert completed.returncode != 0
    assert "'worker_reachability': False" in completed.stderr
    assert "constructor-injected Python _processor callable" in completed.stderr
    assert "'worker_python_free': False" in completed.stderr
    assert not output.exists()


def test_owned_shard_accepts_only_complete_record_result_kernel(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "native_record_result_worker",
        "from dataclasses import dataclass\n"
        "from typing import Annotated\n"
        "import pymeta\n"
        "from pymeta.concurrent import BoundedQueue, bounded_queue, spsc\n"
        "@pymeta.record(abi='packet.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Packet:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "    value: Annotated[int, pymeta.uint[16]]\n"
        "@pymeta.record(abi='result.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Result:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "    value: Annotated[int, pymeta.uint[16]]\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Worker:\n"
        "    _input: Annotated[BoundedQueue[Packet], spsc | "
        "bounded_queue(capacity=1) | pymeta.owned_by('worker')]\n"
        "    _output: Annotated[BoundedQueue[Result], spsc | "
        "bounded_queue(capacity=1) | pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', noescape={'packet'}, "
        "allocate=pymeta.never, suspend=pymeta.never))\n"
        "    def process(self, packet: Packet) -> Result:\n"
        "        return Result(packet.peer_id, packet.value + 1)\n",
    )

    assert completed.returncode != 0
    assert "'worker_abi_eligible': True" in completed.stderr
    assert "'worker_record_abi': True" in completed.stderr
    assert "'worker_reachability': True" in completed.stderr
    assert "'kernel_emission_complete': True" in completed.stderr
    assert "'kernel_python_free': True" in completed.stderr
    assert "'worker_emission_complete': True" in completed.stderr
    assert "'worker_python_free': True" in completed.stderr
    assert "'worker_executor_emission_complete': True" in completed.stderr
    assert "'worker_bounded_channels': True" in completed.stderr
    assert "'worker_typed_error': True" in completed.stderr
    assert "'worker_shutdown': True" in completed.stderr
    assert "'worker_thread_python_api_free': True" in completed.stderr
    assert not output.exists() or not any(output.rglob("*"))


def test_native_worker_thread_body_has_no_python_api_reachability() -> None:
    source = (
        NATIVE_COMPILER_SOURCE / "native_worker_executor.c"
    ).read_text(encoding="utf-8")
    worker = source.split(
        "static void *worker_main(void *opaque) {", 1
    )[1].split("static void reset_result", 1)[0]

    assert "PyObject" not in worker
    assert "Py_" not in worker
    assert "PyErr" not in worker
    assert "wrtc_native_worker_record_pack" not in worker
    assert "wrtc_native_worker_record_materialize" not in worker
    assert "wrtc_native_worker_record_release" not in worker
    assert "executor->kernel(" in worker


def _native_worker_graph_source(method_bodies: list[str]) -> str:
    methods = "".join(
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='worker', allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        f"    def step_{index}(self, packet: Packet) -> Result:\n"
        f"        {body}\n"
        for index, body in enumerate(method_bodies)
    )
    return (
        "from dataclasses import dataclass\n"
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.record(abi='packet.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Packet:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "@pymeta.record(abi='result.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Result:\n"
        "    peer_id: Annotated[int, pymeta.uint[64]]\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Worker:\n"
        f"{methods}"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', "
        "noescape={'packet'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def process(self, packet: Packet) -> Result:\n"
        "        return self.step_0(packet)\n"
    )


@pytest.mark.parametrize(
    ("name", "method_bodies", "reachable", "reason"),
    (
        (
            "one_region_worker_graph",
            ["return Result(packet.peer_id)"],
            True,
            None,
        ),
        (
            "cyclic_worker_graph",
            ["return self.step_1(packet)", "return self.step_0(packet)"],
            True,
            None,
        ),
        (
            "malformed_worker_graph",
            ["return self.missing_step(packet)"],
            False,
            "worker reaches an unresolved or dynamic Python call",
        ),
    ),
)
def test_owned_shard_worker_reachability_graph_shapes_are_deterministic(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    name: str,
    method_bodies: list[str],
    reachable: bool,
    reason: str | None,
) -> None:
    source_text = _native_worker_graph_source(method_bodies)
    first, first_output = _compile_fixture(
        c_compiler_build, tmp_path, name, source_text
    )
    first_source = tmp_path / f"{name}.py"
    first_stderr = first.stderr.replace(str(first_source), "<source>")
    second, second_output = _compile_fixture(
        c_compiler_build, tmp_path, name, source_text
    )
    second_stderr = second.stderr.replace(str(first_source), "<source>")

    assert first.returncode != 0
    assert second.returncode != 0
    assert first_stderr == second_stderr
    assert f"'worker_reachability': {reachable}" in first.stderr
    assert f"{name}.py" in first.stderr
    if reason is not None:
        assert reason in first.stderr
    else:
        assert (
            "worker input/result bounded SPSC fields are not proven"
            in first.stderr
        )
    assert not first_output.exists() or not any(first_output.rglob("*"))
    assert not second_output.exists() or not any(second_output.rglob("*"))


def test_owned_shard_reachability_supports_more_than_1024_regions(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    region_count = 1025
    method_bodies = [
        f"return self.step_{index + 1}(packet)"
        for index in range(region_count - 1)
    ]
    method_bodies.append("return Result(packet.peer_id)")
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "large_worker_graph",
        _native_worker_graph_source(method_bodies),
    )

    assert completed.returncode != 0
    assert "'worker_reachability': True" in completed.stderr
    assert "worker input/result bounded SPSC fields are not proven" in completed.stderr
    assert not output.exists() or not any(output.rglob("*"))


def test_native_class_with_zero_region_graph_stays_fail_closed(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "zero_region_graph",
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Worker:\n"
        "    value: int\n",
    )

    assert completed.returncode != 0
    assert "zero_region_graph.py" in completed.stderr
    assert "'regions': []" in completed.stderr
    assert "'generator_accepted': False" in completed.stderr
    assert not output.exists() or not any(output.rglob("*"))


@pytest.mark.parametrize(
    ("name", "source_text", "location", "message"),
    (
        (
            "duplicate_exports",
            "__all__ = ['run', 'run']\n\ndef run() -> int:\n    return 1\n",
            "1:1",
            "__all__ contains duplicate names",
        ),
        (
            "missing_export",
            "__all__ = ['missing']\n",
            "1:1",
            "exported name 'missing' is missing",
        ),
        (
            "unsafe_import",
            "import os\n\ndef run() -> int:\n    return 1\n",
            "1:1",
            "unsafe import is not supported",
        ),
        (
            "reachable_lambda",
            "def run(value: int) -> int:\n    transform = lambda item: item\n    return transform(value)\n",
            "2:17",
            "unsupported reachable operation Lambda",
        ),
        (
            "recursive_graph",
            "def run(value: int) -> int:\n    return run(value)\n",
            "1:1",
            "recursive function graph is not supported",
        ),
    ),
)
def test_c_compiler_reports_stable_frontend_diagnostics_without_artifacts(
    c_compiler_build: CCompilerBuild,
    tmp_path: Path,
    name: str,
    source_text: str,
    location: str,
    message: str,
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build, tmp_path, name, source_text
    )

    source = tmp_path / f"{name}.py"
    assert completed.returncode != 0
    assert completed.stderr.strip() == f"{source}:{location}: error: {message}"
    assert not output.exists() or not any(output.rglob("*"))


def test_c_compiler_failure_does_not_replace_previous_complete_artifact(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    before = c_compiler_build.artifact.read_bytes()
    changed = tmp_path / "kernel_e.py"
    changed.write_bytes(KERNEL_SOURCE.read_bytes() + b"\nUNSUPPORTED_CHANGE = object()\n")
    completed = subprocess.run(
        [
            str(c_compiler_build.executable),
            "--source",
            str(changed),
            "--output",
            str(c_compiler_build.output_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=_compiler_environment(),
    )

    assert completed.returncode != 0
    assert c_compiler_build.artifact.read_bytes() == before
    files = [path for path in c_compiler_build.output_dir.rglob("*") if path.is_file()]
    assert files == [c_compiler_build.artifact]
