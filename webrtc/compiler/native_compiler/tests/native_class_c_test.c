#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "native_class.h"
#include "native_class_generator.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static int error_contains(const char *text) {
    PyObject *type = NULL, *value = NULL, *traceback = NULL, *message = NULL;
    const char *utf8;
    int found = 0;
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);
    message = value == NULL ? NULL : PyObject_Str(value);
    utf8 = message == NULL ? NULL : PyUnicode_AsUTF8(message);
    if (utf8 != NULL && strstr(utf8, text) != NULL) found = 1;
    Py_XDECREF(message);
    Py_XDECREF(traceback);
    Py_XDECREF(value);
    Py_XDECREF(type);
    return found;
}

int main(void) {
    static const char generic[] =
        "from typing import Annotated\n"
        "import asyncio\n"
        "import heapq\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Scheduler(asyncio.SelectorEventLoop):\n"
        "    count: Annotated[int, pymeta.storage.native_field | "
        "pymeta.owned_by('reactor')]\n"
        "    ready: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('reactor')]\n"
        "    scheduled: Annotated[object, "
        "pymeta.storage.min_heap(key='_when', ordering='heapq') | "
        "pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(pymeta.Effect.READ, pymeta.Effect.WRITE, "
        "owner='reactor'), fusion=pymeta.fuse('timer-ready'))\n"
        "    def turn(self, ready, scheduled):\n"
        "        item = ready.popleft()\n"
        "        scheduled.append(item)\n"
        "        return heapq.heappop(scheduled)\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Inbox(object):\n"
        "    @pymeta.region(pymeta.preferred, "
        "effects=pymeta.effects(pymeta.Effect.READ))\n"
        "    def poll(self):\n"
        "        return None\n";
    static const char invalid[] =
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=True)\n"
        "class Anything(object):\n"
        "    pass\n";
    static const char no_region[] =
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Anything(object):\n"
        "    value: int\n";
    static const char ordinary[] =
        "class Record:\n"
        "    value: int\n";
    static const char facade_source[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "import queue\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Facade:\n"
        "    component: Annotated[Component, pymeta.exact_type(Component)]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def turn(self):\n"
        "        self.component.run(self)\n";
    static const char component_source[] =
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Component:\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def run(self, facade):\n"
        "        return None\n";
    static const char reactor_profile[] =
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Reactor:\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor', suspend=pymeta.never))\n"
        "    def select(self, loop, events):\n"
        "        polled = loop._selector.select(0)\n"
        "        for key, mask in events:\n"
        "            reader, writer = key.data\n"
        "            if mask & selectors.EVENT_READ:\n"
        "                loop._remove_reader(key.fileobj)\n"
        "            if mask & selectors.EVENT_WRITE:\n"
        "                loop._remove_writer(key.fileobj)\n"
        "        return polled\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(writes={'packet_pool'}, owner='reactor', "
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
        "                transport.request_reschedule()\n"
        "                return\n"
        "            packet = transport.receive_one()\n"
        "            if packet is None:\n"
        "                return\n"
        "            transport.deliver(packet)\n"
        "    @pymeta.region(pymeta.preferred, "
        "effects=pymeta.effects(owner='reactor'))\n"
        "    def receive(self, sock, buffer):\n"
        "        return sock.recvfrom_into(buffer)\n";
    static const char concurrency_profile[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.record(abi='worker.result.v1')\n"
        "class WorkerResult:\n"
        "    peer_id: int\n"
        "    value: int\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class ConcurrentInbox:\n"
        "    state: Annotated[object, pymeta.atomic[pymeta.uint[32]] | "
        "pymeta.owned_by('shared')]\n"
        "    queue: Annotated[queue.Queue[WorkerResult], pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='config.command_capacity') | "
        "pymeta.coalesced_notification | pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor'))\n"
        "    def publish(self, loop, item):\n"
        "        try:\n"
        "            self.queue.put_nowait(item)\n"
        "        except queue.Full:\n"
        "            return False\n"
        "        _, wake = self.state.compare_exchange(0, 1)\n"
        "        if wake:\n"
        "            loop._write_to_self()\n"
        "        return True\n"
        "    @pymeta.region(pymeta.required, "
        "execute=pymeta.owned_shard(key='packet.peer_id', "
        "workers='config.packet_workers', input=pymeta.spsc, "
        "output=pymeta.spsc, ordered=True), "
        "effects=pymeta.effects(owner='worker', "
        "noescape={'packet'}, allocate=pymeta.never, "
        "suspend=pymeta.never))\n"
        "    def process(self, packet) -> WorkerResult:\n"
        "        return native_transform(packet)\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeClassProgram *dependency_program = NULL;
    const WrtcNativeClassIR *scheduler;
    const WrtcNativeRegionIR *turn;
    PyObject *report = NULL, *classes = NULL, *class_report = NULL;
    PyObject *regions = NULL, *drain_report = NULL, *proofs = NULL;
    PyObject *needle = NULL;

    Py_Initialize();
    CHECK(wrtc_native_class_analyze(
              generic, sizeof generic - 1u, "renamed_source.py",
              &program) == 0);
    wrtc_native_class_resolve_calls(program);
    CHECK(program != NULL && program->class_count == 2u);
    CHECK(wrtc_native_class_requires_lowering(program));
    scheduler = &program->classes[0];
    CHECK(strcmp(scheduler->name, "Scheduler") == 0);
    CHECK(strcmp(scheduler->base, "asyncio.SelectorEventLoop") == 0);
    CHECK(scheduler->compact_object && scheduler->gc_tracked);
    CHECK(!scheduler->weakrefs);
    CHECK(scheduler->field_count == 3u);
    CHECK(strcmp(scheduler->fields[0].name, "count") == 0);
    CHECK(scheduler->fields[0].type == WRTC_TYPE_INT);
    CHECK(scheduler->fields[0].native_storage);
    CHECK(scheduler->fields[0].storage_kind == WRTC_NATIVE_FIELD_SCALAR);
    CHECK(strcmp(scheduler->fields[0].owner, "reactor") == 0);
    CHECK(scheduler->fields[1].storage_kind == WRTC_NATIVE_FIELD_FIFO);
    CHECK(scheduler->fields[2].storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP);
    CHECK(strcmp(scheduler->fields[2].heap_key, "_when") == 0);
    CHECK(strcmp(scheduler->fields[2].heap_ordering, "heapq") == 0);
    CHECK(scheduler->region_count == 1u);
    turn = &scheduler->regions[0];
    CHECK(strcmp(turn->name, "turn") == 0);
    CHECK(turn->policy == WRTC_REGION_REQUIRED);
    CHECK(strcmp(turn->owner, "reactor") == 0);
    CHECK(turn->fusion_requested);
    CHECK(turn->call_count == 3u);
    CHECK(turn->calls != NULL);
    CHECK(strcmp(turn->calls[0].target, "ready.popleft") == 0);
    CHECK(strcmp(turn->calls[1].target, "scheduled.append") == 0);
    CHECK(strcmp(turn->calls[2].target, "heapq.heappop") == 0);
    CHECK(strcmp(turn->direct_call_target, "ready.popleft") == 0);
    CHECK(turn->body != NULL && turn->body->statement_count == 3u);
    CHECK(turn->signature != NULL &&
          turn->signature->parameter_count == 3u);
    CHECK(strcmp(turn->signature->parameters[0].name, "self") == 0);
    CHECK(strcmp(turn->signature->parameters[1].name, "ready") == 0);
    CHECK(turn->body->statements[0].kind == WRTC_PY_STMT_ASSIGN);
    CHECK(turn->body->statements[0].expressions[0].kind ==
          WRTC_PY_EXPR_CALL);
    CHECK(turn->body->statements[2].kind == WRTC_PY_STMT_RETURN);
    CHECK((turn->capabilities & WRTC_REGION_READ) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_WRITE) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_FIFO) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_MIN_HEAP) != 0u);
    CHECK(program->classes[1].regions[0].policy == WRTC_REGION_PREFERRED);
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              facade_source, sizeof facade_source - 1u, "facade.py",
              &program) == 0);
    CHECK(wrtc_native_class_analyze(
              component_source, sizeof component_source - 1u, "component.py",
              &dependency_program) == 0);
    CHECK(wrtc_native_class_merge(program, dependency_program) == 0);
    wrtc_native_class_free(dependency_program);
    dependency_program = NULL;
    wrtc_native_class_resolve_calls(program);
    CHECK(program->class_count == 2u);
    CHECK(program->classes[0].regions[0].direct_callee_resolved);
    CHECK(program->classes[0].regions[0].direct_callee_fused);
    CHECK(program->classes[0].regions[0].calls[0].resolved);
    CHECK(program->classes[0].regions[0].calls[0].required_callee);
    CHECK(program->classes[0].regions[0].calls[0].exact_receiver);
    CHECK(program->classes[0].regions[0].calls[0].fused);
    CHECK(program->classes[0].regions[0].calls[0].target_class == 1u);
    CHECK(program->classes[0].regions[0].calls[0].target_region == 0u);
    CHECK(strcmp(program->classes[1].filename, "component.py") == 0);
    report = wrtc_native_class_capability_report(program, "facade.py");
    CHECK(report != NULL);
    classes = PyDict_GetItemString(report, "classes");
    class_report = classes == NULL ? NULL : PyList_GetItem(classes, 0);
    regions = class_report == NULL
                  ? NULL : PyDict_GetItemString(class_report, "regions");
    drain_report = regions == NULL ? NULL : PyList_GetItem(regions, 0);
    CHECK(drain_report != NULL);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              drain_report, "direct_callee_fused")) == 1);
    CHECK(PyList_GET_SIZE(PyDict_GetItemString(
              drain_report, "fusion_decisions")) == 1);
    CHECK(PyList_GET_SIZE(PyDict_GetItemString(
              drain_report, "remaining_python_calls")) == 0);
    Py_CLEAR(report);
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              reactor_profile, sizeof reactor_profile - 1u,
              "arbitrary_component.py", &program) == 0);
    wrtc_native_class_resolve_calls(program);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(program->classes[0].region_count == 3u);
    CHECK((program->classes[0].regions[0].capabilities &
           WRTC_REGION_SELECTOR_POLL) != 0u);
    CHECK((program->classes[0].regions[0].capabilities &
           WRTC_REGION_SELECTOR_DISPATCH) != 0u);
    CHECK(program->classes[0].regions[0].selector_shape_validated);
    CHECK(program->classes[0].regions[0]
              .selector_runtime_lowering_available);
    CHECK(program->classes[0].regions[0]
              .selector_remove_reader_hook);
    CHECK(program->classes[0].regions[0]
              .selector_remove_writer_hook);
    CHECK(program->classes[0].regions[0]
              .reactor_hook_emission_complete);
    turn = &program->classes[0].regions[1];
    CHECK(turn->loop_count == 1u);
    CHECK(turn->bounded_loop_count == 1u);
    CHECK((turn->capabilities & WRTC_REGION_BOUNDED_LOOP) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_PACKET_BUDGET) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_TIME_BUDGET) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_PACKET_POOL) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_DELIVERY) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_RESCHEDULE) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_NOESCAPE) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_NO_ALLOCATE) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_NO_SUSPEND) != 0u);
    CHECK(turn->packet_order_preserved);
    CHECK(turn->pool_lifetime_checked);
    CHECK(turn->bounded_interleaving);
    CHECK(turn->descriptor_generation_validated);
    CHECK(turn->datagram_runtime_lowering_available);
    CHECK(turn->datagram_generation_hook);
    CHECK(turn->datagram_delivery_hook);
    CHECK(turn->bounded_reschedule_hook);
    CHECK(turn->reactor_thread_serialized);
    CHECK(turn->reactor_hook_emission_complete);
    CHECK((program->classes[0].regions[2].capabilities &
           WRTC_REGION_SOCKET_RECEIVE) != 0u);
    CHECK((program->classes[0].regions[2].capabilities &
           WRTC_REGION_RECEIVE_INTO) != 0u);

    report = wrtc_native_class_capability_report(
        program, "arbitrary_component.py");
    CHECK(report != NULL && PyDict_Check(report));
    CHECK(strcmp(
              PyUnicode_AsUTF8(PyDict_GetItemString(report, "schema")),
              "pymeta.capabilities.v2") == 0);
    classes = PyDict_GetItemString(report, "classes");
    class_report = classes == NULL ? NULL : PyList_GetItem(classes, 0);
    regions = class_report == NULL
                  ? NULL : PyDict_GetItemString(class_report, "regions");
    drain_report = regions == NULL ? NULL : PyList_GetItem(regions, 1);
    proofs = drain_report == NULL
                 ? NULL : PyDict_GetItemString(drain_report, "proofs");
    CHECK(drain_report != NULL);
    CHECK(strcmp(
              PyUnicode_AsUTF8(
                  PyDict_GetItemString(drain_report, "status")),
              "rejected") == 0);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "bounded_interleaving")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "descriptor_generation_validated")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "datagram_runtime_lowering_available")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "reactor_hook_emission_complete")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "datagram_generation_hook")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "datagram_delivery_hook")) == 1);
    CHECK(PyObject_IsTrue(PyDict_GetItemString(
              proofs, "bounded_reschedule_hook")) == 1);
    needle = PyUnicode_FromString("packet_budget");
    CHECK(needle != NULL);
    CHECK(PySequence_Contains(
              PyDict_GetItemString(drain_report, "capabilities"),
              needle) == 1);
    Py_CLEAR(needle);
    Py_CLEAR(report);
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              concurrency_profile, sizeof concurrency_profile - 1u,
              "concurrency_component.py", &program) == 0);
    wrtc_native_class_resolve_calls(program);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(program->record_count == 1u);
    CHECK(strcmp(program->records[0].name, "WorkerResult") == 0);
    CHECK(program->records[0].field_count == 2u);
    CHECK(program->classes[0].field_count == 2u);
    CHECK(program->classes[0].fields[0].atomic);
    CHECK(program->classes[0].fields[0].atomic_width == 32u);
    CHECK(strcmp(program->classes[0].fields[0].atomic_memory_order,
                 "seq_cst") == 0);
    CHECK(strcmp(program->classes[0].fields[0].atomic_scope,
                 "process") == 0);
    CHECK(strcmp(program->classes[0].fields[0].atomic_linearization,
                 "compare_exchange") == 0);
    CHECK(program->classes[0].fields[1].queue_topology ==
          WRTC_QUEUE_MPSC);
    CHECK(program->classes[0].fields[1].storage_kind ==
          WRTC_NATIVE_FIELD_MPSC);
    CHECK(strcmp(program->classes[0].fields[1].queue_capacity,
                 "config.command_capacity") == 0);
    CHECK(strcmp(program->classes[0].fields[1].queue_item_type,
                 "WorkerResult") == 0);
    CHECK(!program->classes[0].fields[1].typed_queue_payload);
    CHECK(!program->classes[0].fields[1]
               .payload_representation_proven);
    CHECK(program->classes[0].fields[1].coalesced_notification);
    turn = &program->classes[0].regions[0];
    CHECK((turn->capabilities & WRTC_REGION_ATOMIC) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_COMPARE_EXCHANGE) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_MPSC) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_BOUNDED_QUEUE) != 0u);
    CHECK((turn->capabilities &
           WRTC_REGION_COALESCED_NOTIFICATION) != 0u);
    CHECK(!turn->atomic_linearization_proven);
    CHECK(!turn->queue_linearization_proven);
    CHECK(!turn->full_queue_behavior_proven);
    CHECK(!turn->wakeup_coalescing_proven);
    turn = &program->classes[0].regions[1];
    CHECK((turn->capabilities & WRTC_REGION_OWNED_SHARD) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_SPSC) != 0u);
    CHECK((turn->capabilities & WRTC_REGION_TYPED_RECORD) != 0u);
    CHECK(strcmp(turn->shard_key, "packet.peer_id") == 0);
    CHECK(strcmp(turn->shard_workers, "config.packet_workers") == 0);
    CHECK(turn->shard_ordered);
    CHECK(turn->ownership_transfer_proven);
    CHECK(!turn->typed_worker_records);
    CHECK(!turn->worker_python_free);
    CHECK(!turn->reclamation_proven);
    report = wrtc_native_class_capability_report(
        program, "concurrency_component.py");
    CHECK(report != NULL);
    classes = PyDict_GetItemString(report, "classes");
    class_report = classes == NULL ? NULL : PyList_GetItem(classes, 0);
    regions = class_report == NULL
                  ? NULL : PyDict_GetItemString(class_report, "regions");
    drain_report = regions == NULL ? NULL : PyList_GetItem(regions, 1);
    proofs = drain_report == NULL
                 ? NULL : PyDict_GetItemString(drain_report, "proofs");
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "ownership_transfer")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "typed_worker_records")) == 0);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "worker_python_free")) == 0);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "node_reclamation")) == 0);
    CHECK(strcmp(
              PyUnicode_AsUTF8(
                  PyDict_GetItemString(proofs, "memory_ordering")),
              "not_proven") == 0);
    Py_CLEAR(report);
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              ordinary, sizeof ordinary - 1u, "ordinary.py", &program) == 0);
    CHECK(program != NULL && program->class_count == 0u);
    CHECK(!wrtc_native_class_requires_lowering(program));
    CHECK(!wrtc_native_class_can_emit(program));
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              invalid, sizeof invalid - 1u, "invalid.py", &program) < 0);
    CHECK(error_contains("invalid.py:2:2: error: unsupported native_class"));
    CHECK(program == NULL);

    CHECK(wrtc_native_class_analyze(
              no_region, sizeof no_region - 1u, "no_region.py", &program) == 0);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(program->classes[0].region_count == 0u);
    CHECK(program->classes[0].field_count == 1u);
    CHECK(!wrtc_native_class_can_emit(program));
    wrtc_native_class_free(program);
    program = NULL;

    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
