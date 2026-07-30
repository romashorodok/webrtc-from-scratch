#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <string.h>

#include "native_class.h"
#include "native_class_generator.h"
#include "native_operation.h"
#include "native_storage.h"

#ifndef WRTC_MPSC_PROOF_SOURCE
#error "WRTC_MPSC_PROOF_SOURCE is required"
#endif

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static PyObject *first_region(PyObject *report) {
    PyObject *classes = PyDict_GetItemString(report, "classes");
    PyObject *class_report =
        classes == NULL ? NULL : PyList_GetItem(classes, 0);
    PyObject *regions =
        class_report == NULL
            ? NULL : PyDict_GetItemString(class_report, "regions");
    return regions == NULL ? NULL : PyList_GetItem(regions, 0);
}

static PyObject *first_field(PyObject *report) {
    PyObject *classes = PyDict_GetItemString(report, "classes");
    PyObject *class_report =
        classes == NULL ? NULL : PyList_GetItem(classes, 0);
    PyObject *fields =
        class_report == NULL
            ? NULL : PyDict_GetItemString(class_report, "fields");
    return fields == NULL ? NULL : PyList_GetItem(fields, 0);
}

static int positive_contract_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "from dataclasses import dataclass\n"
        "import collections\n"
        "import queue\n"
        "import pymeta\n"
        "@pymeta.record(abi='test.message.v1')\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Message:\n"
        "    kind: pymeta.uint[32]\n"
        "    payload: object\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Channel(collections.UserList):\n"
        "    state: Annotated[object, pymeta.atomic[pymeta.uint[32]] | "
        "pymeta.owned_by('shared')]\n"
        "    notified: Annotated[object, pymeta.atomic[pymeta.uint[32]] | "
        "pymeta.coalesced_notification | pymeta.owned_by('shared')]\n"
        "    queue: Annotated[queue.Queue[Message], pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='self.capacity') | "
        "pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='shared'))\n"
        "    def publish(self, item: Message):\n"
        "        self.queue.put_nowait(item)\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor'))\n"
        "    def rearm(self):\n"
        "        self.notified.store(0)\n"
        "        if not self.queue.empty():\n"
        "            self.notified.compare_exchange(0, 1)\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='reactor'))\n"
        "    def shutdown(self):\n"
        "        self.state.compare_exchange(0, 1)\n"
        "        self.queue.close()\n"
        "        while not self.queue.empty():\n"
        "            self.queue.get_nowait()\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *operations = NULL;
    WrtcNativeFieldIR *queue;
    PyObject *report, *field, *region, *proofs;
    size_t region_index;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_MPSC_PROOF_SOURCE,
              &program) == 0);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(program->records[0].boxed_field_count == 1u);
    CHECK(program->records[0].boxed_ownership_proven);
    CHECK(program->records[0].exact_runtime_type_guard);
    queue = &program->classes[0].fields[2];
    CHECK(queue->typed_queue_payload);
    CHECK(queue->payload_representation_proven);
    CHECK(queue->producer_admission_proven);
    CHECK(queue->producer_quiescence_proven);
    CHECK(queue->reactor_dequeue_proven);
    CHECK(queue->close_drain_order_proven);
    CHECK(queue->notification_rearm_proven);
    CHECK(queue->lifecycle_shutdown_proven);
    CHECK(queue->mpsc_memory_ordering_proven);
    CHECK(queue->reactor_reclamation_proven);
    for (region_index = 0u;
         region_index < program->classes[0].field_count; region_index++) {
        const char *why = NULL;
        CHECK(wrtc_native_storage_field_eligible(
                  &program->classes[0].fields[region_index], &why));
    }
    CHECK(wrtc_native_operation_prove(program, &operations) == 0);
    CHECK(operations != NULL && operations->complete);
    wrtc_native_operation_table_free(operations);
    for (region_index = 0u;
         region_index < program->classes[0].region_count; region_index++) {
        const WrtcNativeRegionIR *proof =
            &program->classes[0].regions[region_index];
        CHECK(proof->queue_linearization_proven);
        CHECK(proof->memory_ordering_proven);
        CHECK(proof->producer_admission_proven);
        CHECK(proof->producer_quiescence_proven);
        CHECK(proof->reactor_dequeue_proven);
        CHECK(proof->ownership_transfer_proven);
        CHECK(proof->reclamation_proven);
        CHECK(proof->full_queue_behavior_proven);
        CHECK(proof->wakeup_coalescing_proven);
        CHECK(proof->close_drain_order_proven);
        CHECK(proof->shutdown_interaction_proven);
    }
    CHECK(wrtc_native_class_can_emit(program));
    report = wrtc_native_class_capability_report(
        program, WRTC_MPSC_PROOF_SOURCE);
    CHECK(report != NULL);
    field = first_field(report);
    CHECK(field != NULL);
    region = first_region(report);
    CHECK(region != NULL);
    proofs = PyDict_GetItemString(region, "proofs");
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "producer_admission")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "producer_quiescence")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "reactor_only_dequeue")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "close_drain_order")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "node_reclamation")) == 1);
    CHECK(PyObject_IsTrue(
              PyDict_GetItemString(proofs, "ownership_transfer")) == 1);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(proofs, "memory_ordering")),
                 "release_publish_acquire_consume;"
                 "acq_rel_admission_close") == 0);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "status")),
                 "compiled") == 0);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

static int mutable_boxed_payload_rejection_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import collections\n"
        "import queue\n"
        "import pymeta\n"
        "@pymeta.record(abi='test.command.v1')\n"
        "class Command:\n"
        "    kind: pymeta.uint[32]\n"
        "    payload: object\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Inbox(collections.UserList):\n"
        "    queue: Annotated[queue.Queue[Command], pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='self.capacity') | "
        "pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required, "
        "effects=pymeta.effects(owner='shared'))\n"
        "    def publish(self, item: Command):\n"
        "        self.queue.put_nowait(item)\n";
    WrtcNativeClassProgram *program = NULL;
    PyObject *report, *region, *rejections, *rejection, *span;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, WRTC_MPSC_PROOF_SOURCE,
              &program) == 0);
    CHECK(program->records[0].boxed_field_count == 1u);
    CHECK(!program->records[0].boxed_ownership_proven);
    CHECK(!program->records[0].exact_runtime_type_guard);
    CHECK(!program->records[0].representation_proven);
    CHECK(!program->classes[0].fields[0].typed_queue_payload);
    CHECK(!wrtc_native_class_can_emit(program));
    report = wrtc_native_class_capability_report(
        program, WRTC_MPSC_PROOF_SOURCE);
    CHECK(report != NULL);
    region = first_region(report);
    CHECK(region != NULL);
    CHECK(strstr(PyUnicode_AsUTF8(
                     PyDict_GetItemString(region, "reason")),
                 "exact ABI-declared record") != NULL);
    rejections = PyDict_GetItemString(region, "rejection_reasons");
    CHECK(rejections != NULL && PyList_GET_SIZE(rejections) == 1);
    rejection = PyList_GetItem(rejections, 0);
    CHECK(strcmp(PyUnicode_AsUTF8(
                     PyDict_GetItemString(rejection, "code")),
                 "mpsc_contract_unproven") == 0);
    span = PyDict_GetItemString(rejection, "source");
    CHECK(PyLong_AsLong(PyDict_GetItemString(span, "line")) == 11);
    Py_DECREF(report);
    wrtc_native_class_free(program);
    return 0;
}

int main(void) {
    Py_Initialize();
    CHECK(positive_contract_test() == 0);
    CHECK(mutable_boxed_payload_rejection_test() == 0);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
