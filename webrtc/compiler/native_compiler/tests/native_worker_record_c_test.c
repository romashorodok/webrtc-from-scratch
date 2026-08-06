#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "native_worker_record.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", \
                __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct {
    const WrtcNativeWorkerRecord *record;
    uint64_t checksum;
} WorkerArgument;

static void *worker_main(void *opaque) {
    WorkerArgument *argument = (WorkerArgument *)opaque;
    const WrtcNativeWorkerValue *sequence = &argument->record->values[0];
    const WrtcNativeWorkerValue *payload = &argument->record->values[1];
    size_t index;
    uint64_t checksum = sequence->as.uint_value;
    for (index = 0u; index < payload->as.bytes_value.size; index++)
        checksum += payload->as.bytes_value.data[index];
    argument->checksum = checksum;
    return NULL;
}

int main(void) {
    static const WrtcNativeWorkerAbiField fields[] = {
        {"sequence", WRTC_WORKER_ABI_UINT, 16u},
        {"payload", WRTC_WORKER_ABI_READONLY_BYTES, 0u},
    };
    static const WrtcNativeWorkerAbi abi = {
        "test.packet.v1", fields, 2u
    };
    PyObject *globals = NULL, *result = NULL, *type = NULL, *value = NULL;
    PyObject *roundtrip = NULL, *bad = NULL, *payload_owner = NULL;
    Py_ssize_t owner_refs;
    WrtcNativeWorkerRecord record = {0}, moved = {0};
    WorkerArgument argument = {0};
    pthread_t worker;

    Py_Initialize();
    globals = PyDict_New();
    CHECK(globals != NULL);
    CHECK(PyDict_SetItemString(globals, "__builtins__",
                               PyEval_GetBuiltins()) == 0);
    result = PyRun_String(
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Packet:\n"
        "    sequence: int\n"
        "    payload: bytes\n"
        "value = Packet(7, b'abc')\n",
        Py_file_input, globals, globals);
    CHECK(result != NULL);
    Py_CLEAR(result);
    type = PyDict_GetItemString(globals, "Packet");
    value = PyDict_GetItemString(globals, "value");
    CHECK(type != NULL && PyType_Check(type) && value != NULL);
    payload_owner = PyObject_GetAttrString(value, "payload");
    CHECK(payload_owner != NULL);
    owner_refs = Py_REFCNT(payload_owner);
    CHECK(wrtc_native_worker_record_pack(
              value, (PyTypeObject *)type, &abi, &record) == 0);
    CHECK(Py_REFCNT(payload_owner) == owner_refs + 1);

    argument.record = &record;
    CHECK(pthread_create(&worker, NULL, worker_main, &argument) == 0);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(argument.checksum ==
          UINT64_C(7) + (uint64_t)'a' + (uint64_t)'b' + (uint64_t)'c');

    wrtc_native_worker_record_move(&moved, &record);
    CHECK(record.values == NULL && moved.values != NULL);
    roundtrip = wrtc_native_worker_record_materialize(
        &moved, (PyTypeObject *)type);
    CHECK(roundtrip != NULL);
    CHECK(PyObject_RichCompareBool(value, roundtrip, Py_EQ) == 1);

    bad = PyObject_CallFunction((PyObject *)type, "iy#", 65536, "x",
                                (Py_ssize_t)1);
    CHECK(bad != NULL);
    CHECK(wrtc_native_worker_record_pack(
              bad, (PyTypeObject *)type, &abi, &record) < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_OverflowError));
    PyErr_Clear();

    Py_CLEAR(roundtrip);
    wrtc_native_worker_record_release(&moved);
    CHECK(Py_REFCNT(payload_owner) == owner_refs);
    Py_CLEAR(payload_owner);
    Py_CLEAR(bad);
    Py_CLEAR(globals);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
