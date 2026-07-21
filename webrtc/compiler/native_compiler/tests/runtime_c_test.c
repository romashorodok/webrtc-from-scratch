#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "native_runtime.h"

#define CHECK(value) do { if (!(value)) { (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #value); return 1; } } while (0)

typedef struct {
    uint32_t identifier;
    WrtcByteSpan value;
} NeutralRecord;

static int check_error(PyObject *type, const char *message) {
    PyObject *actual_type = NULL, *value = NULL, *traceback = NULL, *text = NULL;
    int result = 0;
    if (!PyErr_Occurred()) return 0;
    PyErr_Fetch(&actual_type, &value, &traceback);
    PyErr_NormalizeException(&actual_type, &value, &traceback);
    text = value == NULL ? NULL : PyObject_Str(value);
    result = actual_type == type && text != NULL &&
             strcmp(PyUnicode_AsUTF8(text), message) == 0;
    Py_XDECREF(text); Py_XDECREF(traceback); Py_XDECREF(value);
    Py_XDECREF(actual_type);
    return result;
}

int main(void) {
    WrtcAllocator allocator; WrtcByteVector bytes, moved;
    WrtcByteVectorVector vectors; WrtcVector records;
    WrtcByteSpan span, slice; NeutralRecord record, popped_record;
    size_t size_value; uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64;
    PyObject *object; unsigned char input[] = {1u, 2u, 3u, 4u};
    Py_Initialize(); wrtc_allocator_init(&allocator);
    CHECK(wrtc_size_add(SIZE_MAX, 1u, &size_value) < 0);
    CHECK(wrtc_size_sub(0u, 1u, &size_value) < 0);
    CHECK(wrtc_size_mul(SIZE_MAX, 2u, &size_value) < 0);
    CHECK(wrtc_u8_add(UINT8_MAX, 1u, &u8) < 0);
    CHECK(wrtc_u16_add(UINT16_MAX, 1u, &u16) < 0);
    CHECK(wrtc_u32_add(UINT32_MAX, 1u, &u32) < 0);
    CHECK(wrtc_u64_add(UINT64_MAX, 1u, &u64) < 0);
    CHECK(wrtc_u16_wrapping_add(UINT16_MAX, 1u) == 0u);
    span = wrtc_byte_span(input, sizeof(input));
    CHECK(wrtc_byte_span_slice(span, 1u, 2u, &slice) == 0);
    CHECK(slice.length == 2u && slice.data[0] == 2u && slice.data[1] == 3u);
    CHECK(wrtc_byte_span_slice(span, 4u, 1u, &slice) < 0);
    wrtc_byte_vector_init(&bytes, &allocator);
    CHECK(wrtc_byte_vector_resize(&bytes, 8u) == 0);
    CHECK(wrtc_byte_vector_write_u16be(&bytes, 1u, UINT16_C(0x1234)) == 0);
    CHECK(wrtc_byte_vector_write_u32be(&bytes, 3u, UINT32_C(0x89abcdef)) == 0);
    CHECK(bytes.data[1] == 0x12u && bytes.data[2] == 0x34u);
    CHECK(bytes.data[3] == 0x89u && bytes.data[6] == 0xefu);
    CHECK(wrtc_byte_vector_extend(&bytes, span) == 0 && bytes.length == 12u);
    record.identifier = 42u; record.value = span;
    CHECK(wrtc_vector_init(&records, sizeof(record), &allocator) == 0);
    CHECK(wrtc_vector_append(&records, &record) == 0);
    CHECK(((const NeutralRecord *)wrtc_vector_at_const(&records, 0u))->identifier == 42u);
    CHECK(wrtc_vector_at(&records, 1u) == NULL);
    CHECK(wrtc_vector_pop(&records, &popped_record) == 0);
    CHECK(popped_record.identifier == 42u && popped_record.value.length == 4u);
    wrtc_byte_vector_vector_init(&vectors, &allocator);
    moved = bytes;
    CHECK(wrtc_byte_vector_vector_append_move(&vectors, &moved) == 0);
    CHECK(moved.data == NULL && vectors.data[0].length == 12u);
    object = PyBytes_FromStringAndSize("abc", 3);
    CHECK(object != NULL && wrtc_refine_exact_bytes(object, "frame", &span) == 0 && span.length == 3u);
    Py_DECREF(object);
    object = PyBool_FromLong(1);
    CHECK(wrtc_validate_exact_int(object, "sequence") < 0);
    CHECK(check_error(PyExc_TypeError, "sequence must be int"));
    CHECK(wrtc_refine_exact_u64(object, "sequence", 0u, 65535u, &u64) < 0);
    CHECK(check_error(PyExc_TypeError, "sequence must be int")); Py_DECREF(object);
    object = PyLong_FromLong(65536);
    CHECK(wrtc_refine_exact_u64(object, "sequence", 0u, 65535u, &u64) < 0);
    CHECK(check_error(PyExc_ValueError, "sequence must be in range 0..65535")); Py_DECREF(object);
    wrtc_allocator_fail_after(&allocator, 0u);
    wrtc_byte_vector_init(&bytes, &allocator);
    CHECK(wrtc_byte_vector_append(&bytes, 1u) < 0 && PyErr_ExceptionMatches(PyExc_MemoryError));
    PyErr_Clear();
    wrtc_byte_vector_clear(&bytes); wrtc_byte_vector_vector_clear(&vectors);
    wrtc_vector_clear(&records);
    CHECK(Py_FinalizeEx() == 0); return 0;
}
