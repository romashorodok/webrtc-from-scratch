#include "native_worker_record.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int unsigned_fits(uint64_t value, unsigned width) {
    return width == 64u || (width != 0u && value < (UINT64_C(1) << width));
}

static int signed_fits(int64_t value, unsigned width) {
    int64_t minimum, maximum;
    if (width == 64u) return 1;
    if (width == 0u || width > 63u) return 0;
    minimum = -(INT64_C(1) << (width - 1u));
    maximum = (INT64_C(1) << (width - 1u)) - 1;
    return value >= minimum && value <= maximum;
}

void wrtc_native_worker_record_release(WrtcNativeWorkerRecord *record) {
    size_t index;
    if (record == NULL) return;
    for (index = 0u; index < record->value_count; index++)
        if (record->values[index].kind == WRTC_WORKER_ABI_READONLY_BYTES) {
            PyObject *owner = (PyObject *)
                record->values[index].as.bytes_value.reactor_owner;
            Py_XDECREF(owner);
            record->values[index].as.bytes_value.reactor_owner = NULL;
        }
    free(record->values);
    memset(record, 0, sizeof(*record));
}

int wrtc_native_worker_record_pack(
    PyObject *value, PyTypeObject *exact_type,
    const WrtcNativeWorkerAbi *abi, WrtcNativeWorkerRecord *out) {
    size_t index;
    if (value == NULL || exact_type == NULL || abi == NULL || out == NULL ||
        abi->abi == NULL || abi->fields == NULL || abi->field_count == 0u) {
        PyErr_SetString(PyExc_ValueError,
                        "native worker record descriptor is incomplete");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (Py_TYPE(value) != exact_type) {
        PyErr_SetString(PyExc_TypeError,
                        "native worker record requires the exact record type");
        return -1;
    }
    out->values = calloc(abi->field_count, sizeof(*out->values));
    if (out->values == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    out->abi = abi;
    out->value_count = abi->field_count;
    for (index = 0u; index < abi->field_count; index++) {
        const WrtcNativeWorkerAbiField *field = &abi->fields[index];
        WrtcNativeWorkerValue *target = &out->values[index];
        PyObject *item = PyObject_GetAttrString(value, field->name);
        target->kind = field->kind;
        if (item == NULL) goto error;
        if (field->kind == WRTC_WORKER_ABI_UINT) {
            unsigned long long raw;
            if (!PyLong_CheckExact(item)) {
                PyErr_SetString(PyExc_TypeError,
                                "native unsigned field requires exact int");
                Py_DECREF(item);
                goto error;
            }
            raw = PyLong_AsUnsignedLongLong(item);
            if (PyErr_Occurred() ||
                !unsigned_fits((uint64_t)raw, field->width)) {
                if (!PyErr_Occurred())
                    PyErr_SetString(PyExc_OverflowError,
                                    "native unsigned field is out of range");
                Py_DECREF(item);
                goto error;
            }
            target->as.uint_value = (uint64_t)raw;
        } else if (field->kind == WRTC_WORKER_ABI_SINT) {
            long long raw;
            if (!PyLong_CheckExact(item)) {
                PyErr_SetString(PyExc_TypeError,
                                "native signed field requires exact int");
                Py_DECREF(item);
                goto error;
            }
            raw = PyLong_AsLongLong(item);
            if (PyErr_Occurred() ||
                !signed_fits((int64_t)raw, field->width)) {
                if (!PyErr_Occurred())
                    PyErr_SetString(PyExc_OverflowError,
                                    "native signed field is out of range");
                Py_DECREF(item);
                goto error;
            }
            target->as.sint_value = (int64_t)raw;
        } else if (field->kind == WRTC_WORKER_ABI_FLOAT) {
            double raw;
            if (!PyFloat_CheckExact(item)) {
                PyErr_SetString(PyExc_TypeError,
                                "native float field requires exact float");
                Py_DECREF(item);
                goto error;
            }
            raw = PyFloat_AS_DOUBLE(item);
            target->as.float_value = raw;
        } else if (field->kind == WRTC_WORKER_ABI_READONLY_BYTES) {
            if (!PyBytes_CheckExact(item)) {
                PyErr_SetString(
                    PyExc_TypeError,
                    "native readonly buffer requires exact immutable bytes");
                Py_DECREF(item);
                goto error;
            }
            target->as.bytes_value.data =
                (const unsigned char *)PyBytes_AS_STRING(item);
            target->as.bytes_value.size = (size_t)PyBytes_GET_SIZE(item);
            target->as.bytes_value.reactor_owner = item;
            item = NULL;
        } else {
            PyErr_SetString(PyExc_TypeError,
                            "unsupported native worker record field");
            Py_DECREF(item);
            goto error;
        }
        Py_XDECREF(item);
    }
    return 0;
error:
    wrtc_native_worker_record_release(out);
    return -1;
}

PyObject *wrtc_native_worker_record_materialize(
    const WrtcNativeWorkerRecord *record, PyTypeObject *exact_type) {
    PyObject *arguments;
    PyObject *result;
    size_t index;
    if (record == NULL || exact_type == NULL ||
        record->abi == NULL || record->values == NULL) {
        PyErr_SetString(PyExc_ValueError, "native worker record is empty");
        return NULL;
    }
    arguments = PyTuple_New((Py_ssize_t)record->value_count);
    if (arguments == NULL) return NULL;
    for (index = 0u; index < record->value_count; index++) {
        const WrtcNativeWorkerValue *value = &record->values[index];
        PyObject *item = NULL;
        if (value->kind == WRTC_WORKER_ABI_UINT)
            item = PyLong_FromUnsignedLongLong(value->as.uint_value);
        else if (value->kind == WRTC_WORKER_ABI_SINT)
            item = PyLong_FromLongLong(value->as.sint_value);
        else if (value->kind == WRTC_WORKER_ABI_FLOAT)
            item = PyFloat_FromDouble(value->as.float_value);
        else if (value->kind == WRTC_WORKER_ABI_READONLY_BYTES)
            item = Py_NewRef(
                (PyObject *)value->as.bytes_value.reactor_owner);
        if (item == NULL) {
            Py_DECREF(arguments);
            return NULL;
        }
        PyTuple_SET_ITEM(arguments, (Py_ssize_t)index, item);
    }
    result = PyObject_Call((PyObject *)exact_type, arguments, NULL);
    Py_DECREF(arguments);
    return result;
}

void wrtc_native_worker_record_move(
    WrtcNativeWorkerRecord *destination,
    WrtcNativeWorkerRecord *source) {
    if (destination == NULL || source == NULL || destination == source)
        return;
    *destination = *source;
    memset(source, 0, sizeof(*source));
}
