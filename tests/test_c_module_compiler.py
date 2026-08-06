"""End-to-end acceptance for the standalone C module compiler driver."""

from __future__ import annotations

import inspect
import importlib.util
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
    facade.component = Override()
    reference.events.clear()
    assert facade.run("left", "right", suffix="?") == ("right", "left", "?")
    assert reference.events == ["left", "right", "override"]
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
    facade.component = facade
    del component
    del facade
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
        "    def drain(self, loop, transport):\n"
        "        started = loop.time()\n"
        "        budget = self.config.receive_packet_budget\n"
        "        time_budget = self.config.receive_time_budget_us / 1000000\n"
        "        for _ in range(budget):\n"
        "            if loop.time() - started >= time_budget:\n"
        "                transport.request_reschedule()\n"
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
    assert not output.exists()


def test_native_concurrency_rejection_reports_unproven_safety_contract(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "renamed_concurrent_component",
        "from typing import Annotated\n"
        "import pymeta\n"
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


def test_owned_shard_proves_native_records_and_calls_but_not_missing_emitter(
    c_compiler_build: CCompilerBuild, tmp_path: Path
) -> None:
    completed, output = _compile_fixture(
        c_compiler_build,
        tmp_path,
        "portable_worker_component",
        "from dataclasses import dataclass\n"
        "from typing import Annotated\n"
        "import pymeta\n"
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
    assert "'worker_emission_complete': False" in completed.stderr
    assert "'worker_python_free': False" in completed.stderr
    assert "worker body emitter is unavailable" in completed.stderr
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
