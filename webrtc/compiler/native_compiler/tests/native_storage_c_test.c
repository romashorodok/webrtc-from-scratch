#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>

#include "native_storage.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static unsigned random_state = 0x12345678u;

static unsigned next_random(void) {
    random_state = random_state * 1664525u + 1013904223u;
    return random_state;
}

static int count_visit(PyObject *object, void *argument) {
    size_t *count = argument;
    CHECK(object != NULL);
    (*count)++;
    return 0;
}

static int keep_even(PyObject *item, void *context) {
    long value = PyLong_AsLong(item);
    (void)context;
    return value >= 0 && (value & 1L) == 0L;
}

static int heap_compaction_test(void) {
    WrtcNativeMinHeap heap;
    PyObject *one = PyLong_FromLong(1);
    PyObject *two = PyLong_FromLong(2);
    PyObject *three = PyLong_FromLong(3);
    PyObject *remaining;
    wrtc_native_heap_init(&heap);
    CHECK(one != NULL && two != NULL && three != NULL);
    CHECK(wrtc_native_heap_activate(&heap, 3u) == 0);
    CHECK(wrtc_native_heap_push(&heap, one) == 0);
    CHECK(wrtc_native_heap_push(&heap, two) == 0);
    CHECK(wrtc_native_heap_push(&heap, three) == 0);
    CHECK(wrtc_native_heap_compact(&heap, keep_even, NULL) == 2u);
    CHECK(wrtc_native_heap_snapshot(&heap) == 1);
    CHECK(wrtc_native_heap_borrow(&heap, 0) == two);
    remaining = wrtc_native_heap_pop(&heap);
    CHECK(remaining == two);
    Py_DECREF(remaining);
    wrtc_native_heap_clear(&heap);
    Py_DECREF(one);
    Py_DECREF(two);
    Py_DECREF(three);
    return 0;
}

static int eligibility_test(void) {
    WrtcNativeFieldIR field = {0};
    const char *reason = NULL;
    field.storage_kind = WRTC_NATIVE_FIELD_SCALAR;
    field.type = WRTC_TYPE_INT;
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 1);
    field.storage_kind = WRTC_NATIVE_FIELD_FIFO;
    field.owner = "single_writer";
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 1);
    field.owner = "";
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 0);
    CHECK(reason != NULL);
    field.storage_kind = WRTC_NATIVE_FIELD_MIN_HEAP;
    field.owner = "single_writer";
    field.heap_ordering = "(deadline, sequence)";
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 1);
    field.heap_ordering = NULL;
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 0);
    field.storage_kind = WRTC_NATIVE_FIELD_MPSC;
    field.queue_topology = WRTC_QUEUE_MPSC;
    field.queue_capacity = "config.command_capacity";
    field.queue_item_type = "Command";
    field.typed_queue_payload = 1u;
    field.owner = "reactor";
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 1);
    field.owner = "shared";
    CHECK(wrtc_native_storage_field_eligible(&field, &reason) == 0);
    CHECK(reason != NULL);
    return 0;
}

static int ownership_test(void) {
    WrtcNativeScalar scalar;
    WrtcNativeFifo fifo;
    WrtcNativeMinHeap heap;
    PyObject *value = PyList_New(0);
    Py_ssize_t baseline;
    size_t visits = 0u;
    CHECK(value != NULL);
    baseline = Py_REFCNT(value);

    wrtc_native_scalar_init(&scalar);
    CHECK(wrtc_native_scalar_set_boxed(&scalar, value) == 0);
    CHECK(Py_REFCNT(value) == baseline + 1);
    CHECK(wrtc_native_scalar_traverse(&scalar, count_visit, &visits) == 0);
    CHECK(visits == 1u);
    wrtc_native_scalar_clear(&scalar);
    CHECK(Py_REFCNT(value) == baseline);

    visits = 0u;
    wrtc_native_fifo_init(&fifo);
    CHECK(wrtc_native_fifo_activate(&fifo, 1u) == 0);
    CHECK(wrtc_native_fifo_append(&fifo, value) == 0);
    CHECK(Py_REFCNT(value) == baseline + 1);
    CHECK(wrtc_native_fifo_traverse(&fifo, count_visit, &visits) == 0);
    CHECK(visits == 1u);
    wrtc_native_fifo_clear(&fifo);
    CHECK(Py_REFCNT(value) == baseline);

    visits = 0u;
    wrtc_native_heap_init(&heap);
    CHECK(wrtc_native_heap_activate(&heap, 1u) == 0);
    CHECK(wrtc_native_heap_push(&heap, value) == 0);
    CHECK(Py_REFCNT(value) == baseline + 1);
    CHECK(wrtc_native_heap_traverse(&heap, count_visit, &visits) == 0);
    CHECK(visits == 1u);
    wrtc_native_heap_clear(&heap);
    CHECK(Py_REFCNT(value) == baseline);
    Py_DECREF(value);
    return 0;
}

static int fifo_test(void) {
    WrtcNativeFifo fifo;
    PyObject *collections = PyImport_ImportModule("collections");
    PyObject *deque_type =
        collections == NULL
            ? NULL : PyObject_GetAttrString(collections, "deque");
    PyObject *reference =
        deque_type == NULL ? NULL : PyObject_CallNoArgs(deque_type);
    size_t step;
    wrtc_native_fifo_init(&fifo);
    CHECK(reference != NULL);
    CHECK(wrtc_native_fifo_activate(&fifo, 2u) == 0);
    for (step = 0u; step < 3000u; step++) {
        if ((next_random() & 3u) != 0u ||
            wrtc_native_fifo_snapshot(&fifo) == 0) {
            PyObject *value =
                PyLong_FromUnsignedLong(next_random() % 97u);
            PyObject *ignored;
            CHECK(value != NULL);
            CHECK(wrtc_native_fifo_append(&fifo, value) == 0);
            ignored = PyObject_CallMethod(reference, "append", "O", value);
            CHECK(ignored != NULL);
            Py_DECREF(ignored);
            Py_DECREF(value);
        } else {
            PyObject *actual = wrtc_native_fifo_popleft(&fifo);
            PyObject *expected =
                PyObject_CallMethod(reference, "popleft", NULL);
            CHECK(actual != NULL && expected != NULL);
            CHECK(PyObject_RichCompareBool(actual, expected, Py_EQ) == 1);
            Py_DECREF(expected);
            Py_DECREF(actual);
        }
        CHECK(wrtc_native_fifo_snapshot(&fifo) ==
              PyObject_Length(reference));
    }
    {
        PyObject *exposed = wrtc_native_fifo_get(&fifo, "ready");
        CHECK(exposed != NULL && exposed == fifo.boxed);
        CHECK(fifo.mode == WRTC_STORAGE_ESCAPED);
        CHECK(PyObject_RichCompareBool(exposed, reference, Py_EQ) == 1);
        Py_DECREF(exposed);
        CHECK(wrtc_native_fifo_try_adopt(&fifo) == 0);
    }
    {
        PyObject *assigned = PyObject_CallNoArgs(deque_type);
        PyObject *exposed;
        CHECK(assigned != NULL);
        CHECK(wrtc_native_fifo_set_boxed(&fifo, assigned) == 0);
        exposed = wrtc_native_fifo_get(&fifo, "ready");
        CHECK(exposed == assigned);
        Py_DECREF(exposed);
        Py_DECREF(assigned);
    }
    {
        PyObject *empty = PyObject_CallNoArgs(deque_type);
        PyObject *exposed;
        CHECK(empty != NULL);
        wrtc_native_fifo_clear(&fifo);
        CHECK(wrtc_native_fifo_adopt_initial(&fifo, empty) == 0);
        CHECK(fifo.mode == WRTC_STORAGE_NATIVE);
        CHECK(wrtc_native_fifo_truth(&fifo) == 0);
        exposed = wrtc_native_fifo_get(&fifo, "ready");
        CHECK(exposed != NULL);
        CHECK(fifo.mode == WRTC_STORAGE_ESCAPED);
        CHECK(wrtc_native_fifo_try_adopt(&fifo) == 0);
        Py_DECREF(exposed);
        Py_DECREF(empty);
    }
    {
        PyObject *assigned = PyObject_CallNoArgs(deque_type);
        CHECK(assigned != NULL);
        CHECK(wrtc_native_fifo_set_boxed(&fifo, assigned) == 0);
        CHECK(wrtc_native_fifo_try_adopt(&fifo) == 0);
        Py_DECREF(assigned);
        CHECK(wrtc_native_fifo_try_adopt(&fifo) == 1);
        CHECK(fifo.mode == WRTC_STORAGE_NATIVE);
        CHECK(wrtc_native_fifo_snapshot(&fifo) == 0);
    }
    {
        PyObject *assigned = PyObject_CallNoArgs(deque_type);
        PyObject *weak;
        CHECK(assigned != NULL);
        weak = PyWeakref_NewRef(assigned, NULL);
        CHECK(weak != NULL);
        CHECK(wrtc_native_fifo_set_boxed(&fifo, assigned) == 0);
        Py_DECREF(assigned);
        CHECK(wrtc_native_fifo_try_adopt(&fifo) == 0);
#if PY_VERSION_HEX >= 0x030D0000
        CHECK(PyWeakref_GetRef(weak, &assigned) == 1);
        CHECK(assigned == fifo.boxed);
        Py_DECREF(assigned);
#else
        assigned = PyWeakref_GetObject(weak);
        CHECK(assigned != Py_None);
        CHECK(assigned == fifo.boxed);
#endif
        Py_DECREF(weak);
    }
    CHECK(wrtc_native_fifo_delete(&fifo, "ready") == 0);
    CHECK(wrtc_native_fifo_get(&fifo, "ready") == NULL);
    CHECK(PyErr_ExceptionMatches(PyExc_AttributeError));
    PyErr_Clear();
    wrtc_native_fifo_clear(&fifo);
    Py_DECREF(reference);
    Py_DECREF(deque_type);
    Py_DECREF(collections);
    return 0;
}

static int heap_test(void) {
    WrtcNativeMinHeap heap;
    PyObject *heapq = PyImport_ImportModule("heapq");
    PyObject *reference = PyList_New(0);
    size_t step;
    wrtc_native_heap_init(&heap);
    CHECK(heapq != NULL && reference != NULL);
    CHECK(wrtc_native_heap_activate(&heap, 2u) == 0);
    for (step = 0u; step < 3000u; step++) {
        if ((next_random() & 3u) != 0u || PyList_GET_SIZE(reference) == 0) {
            PyObject *value =
                Py_BuildValue("(II)", next_random() % 19u,
                              (unsigned)step);
            PyObject *ignored;
            CHECK(value != NULL);
            CHECK(wrtc_native_heap_push(&heap, value) == 0);
            ignored = PyObject_CallMethod(
                heapq, "heappush", "OO", reference, value);
            CHECK(ignored != NULL);
            Py_DECREF(ignored);
            Py_DECREF(value);
        } else {
            PyObject *actual = wrtc_native_heap_pop(&heap);
            PyObject *expected =
                PyObject_CallMethod(heapq, "heappop", "O", reference);
            CHECK(actual != NULL && expected != NULL);
            CHECK(PyObject_RichCompareBool(actual, expected, Py_EQ) == 1);
            Py_DECREF(expected);
            Py_DECREF(actual);
        }
        CHECK(wrtc_native_heap_snapshot(&heap) ==
              PyList_GET_SIZE(reference));
        if (PyList_GET_SIZE(reference) != 0) {
            PyObject *actual = wrtc_native_heap_root(&heap);
            CHECK(actual != NULL);
            CHECK(PyObject_RichCompareBool(
                      actual, PyList_GET_ITEM(reference, 0), Py_EQ) == 1);
            Py_DECREF(actual);
        }
    }
    while (PyList_GET_SIZE(reference) != 0) {
        PyObject *actual = wrtc_native_heap_pop(&heap);
        PyObject *expected =
            PyObject_CallMethod(heapq, "heappop", "O", reference);
        CHECK(actual != NULL && expected != NULL);
        CHECK(PyObject_RichCompareBool(actual, expected, Py_EQ) == 1);
        Py_DECREF(expected);
        Py_DECREF(actual);
    }
    {
        PyObject *assigned = PyList_New(0);
        PyObject *exposed;
        CHECK(assigned != NULL);
        CHECK(wrtc_native_heap_set_boxed(&heap, assigned) == 0);
        exposed = wrtc_native_heap_get(&heap, "timers");
        CHECK(exposed == assigned);
        CHECK(wrtc_native_heap_snapshot(&heap) == 0);
        Py_DECREF(exposed);
        Py_DECREF(assigned);
    }
    {
        PyObject *empty = PyList_New(0);
        PyObject *exposed;
        CHECK(empty != NULL);
        wrtc_native_heap_clear(&heap);
        CHECK(wrtc_native_heap_adopt_initial(&heap, empty) == 0);
        CHECK(heap.mode == WRTC_STORAGE_NATIVE);
        CHECK(wrtc_native_heap_truth(&heap) == 0);
        exposed = wrtc_native_heap_get(&heap, "timers");
        CHECK(exposed != NULL);
        CHECK(heap.mode == WRTC_STORAGE_ESCAPED);
        CHECK(wrtc_native_heap_try_adopt(&heap) == 0);
        Py_DECREF(exposed);
        Py_DECREF(empty);
    }
    {
        PyObject *assigned = PyList_New(0);
        CHECK(assigned != NULL);
        CHECK(wrtc_native_heap_set_boxed(&heap, assigned) == 0);
        CHECK(wrtc_native_heap_try_adopt(&heap) == 0);
        Py_DECREF(assigned);
        CHECK(wrtc_native_heap_try_adopt(&heap) == 1);
        CHECK(heap.mode == WRTC_STORAGE_NATIVE);
        CHECK(wrtc_native_heap_snapshot(&heap) == 0);
    }
    CHECK(wrtc_native_heap_delete(&heap, "timers") == 0);
    CHECK(wrtc_native_heap_root(&heap) == NULL);
    CHECK(PyErr_ExceptionMatches(PyExc_IndexError));
    PyErr_Clear();
    CHECK(wrtc_native_heap_snapshot(&heap) < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_AttributeError));
    PyErr_Clear();
    wrtc_native_heap_clear(&heap);
    Py_DECREF(reference);
    Py_DECREF(heapq);
    return 0;
}

static int scalar_test(void) {
    WrtcNativeScalar slot;
    PyObject *marker = PyList_New(0);
    PyObject *value;
    wrtc_native_scalar_init(&slot);
    CHECK(marker != NULL);
    CHECK(wrtc_native_scalar_set_boxed(&slot, marker) == 0);
    value = wrtc_native_scalar_get(&slot, "count");
    CHECK(value == marker);
    Py_DECREF(value);
    CHECK(wrtc_native_scalar_set_int64(&slot, INT64_C(9223372036854775807)) ==
          0);
    value = wrtc_native_scalar_get(&slot, "count");
    CHECK(value != NULL &&
          PyLong_AsLongLong(value) == 9223372036854775807LL);
    Py_DECREF(value);
    CHECK(wrtc_native_scalar_set_double(&slot, 1.25) == 0);
    value = wrtc_native_scalar_get(&slot, "clock");
    CHECK(value != NULL && PyFloat_AsDouble(value) == 1.25);
    Py_DECREF(value);
    CHECK(wrtc_native_scalar_delete(&slot, "clock") == 0);
    CHECK(wrtc_native_scalar_delete(&slot, "clock") < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_AttributeError));
    PyErr_Clear();
    wrtc_native_scalar_clear(&slot);
    Py_DECREF(marker);
    return 0;
}

int main(void) {
    Py_Initialize();
    CHECK(eligibility_test() == 0);
    CHECK(ownership_test() == 0);
    CHECK(heap_compaction_test() == 0);
    CHECK(scalar_test() == 0);
    CHECK(fifo_test() == 0);
    CHECK(heap_test() == 0);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
