#include "native_runtime.h"

#include <limits.h>
#include <string.h>

static WrtcAllocator default_allocator = {0u, SIZE_MAX};

static WrtcAllocator *use_allocator(WrtcAllocator *allocator) {
    return allocator != NULL ? allocator : &default_allocator;
}

static void *allocate(WrtcAllocator *allocator, size_t size) {
    allocator = use_allocator(allocator);
    if (allocator->fail_after != SIZE_MAX &&
        allocator->allocation_count >= allocator->fail_after) {
        PyErr_NoMemory();
        return NULL;
    }
    allocator->allocation_count++;
    return PyMem_Malloc(size == 0u ? 1u : size);
}

static void *reallocate(WrtcAllocator *allocator, void *value, size_t size) {
    allocator = use_allocator(allocator);
    if (allocator->fail_after != SIZE_MAX &&
        allocator->allocation_count >= allocator->fail_after) {
        PyErr_NoMemory();
        return NULL;
    }
    allocator->allocation_count++;
    return PyMem_Realloc(value, size == 0u ? 1u : size);
}

void wrtc_allocator_init(WrtcAllocator *allocator) {
    allocator->allocation_count = 0u;
    allocator->fail_after = SIZE_MAX;
}

void wrtc_allocator_fail_after(WrtcAllocator *allocator,
                               size_t successful_allocations) {
    allocator->allocation_count = 0u;
    allocator->fail_after = successful_allocations;
}

void wrtc_allocator_disable_failures(WrtcAllocator *allocator) {
    allocator->allocation_count = 0u;
    allocator->fail_after = SIZE_MAX;
}

int wrtc_size_add(size_t left, size_t right, size_t *result) {
    if (left > SIZE_MAX - right) return -1;
    *result = left + right;
    return 0;
}

int wrtc_size_sub(size_t left, size_t right, size_t *result) {
    if (left < right) return -1;
    *result = left - right;
    return 0;
}

int wrtc_size_mul(size_t left, size_t right, size_t *result) {
    if (right != 0u && left > SIZE_MAX / right) return -1;
    *result = left * right;
    return 0;
}

#define CHECKED_ADD(name, type, maximum) \
    int name(type left, type right, type *result) { \
        if (left > (type)((maximum) - right)) return -1; \
        *result = (type)(left + right); \
        return 0; \
    }

CHECKED_ADD(wrtc_u8_add, uint8_t, UINT8_MAX)
CHECKED_ADD(wrtc_u16_add, uint16_t, UINT16_MAX)
CHECKED_ADD(wrtc_u32_add, uint32_t, UINT32_MAX)
CHECKED_ADD(wrtc_u64_add, uint64_t, UINT64_MAX)

#undef CHECKED_ADD

uint16_t wrtc_u16_wrapping_add(uint16_t value, uint16_t increment) {
    return (uint16_t)((uint32_t)value + (uint32_t)increment);
}

WrtcByteSpan wrtc_byte_span(const void *data, size_t length) {
    WrtcByteSpan span;
    span.data = (const uint8_t *)data;
    span.length = length;
    return span;
}

int wrtc_byte_span_slice(WrtcByteSpan span, size_t start, size_t length,
                         WrtcByteSpan *result) {
    size_t end;
    if (wrtc_size_add(start, length, &end) < 0 || end > span.length) return -1;
    result->data = span.data + start;
    result->length = length;
    return 0;
}

void wrtc_byte_vector_init(WrtcByteVector *vector, WrtcAllocator *allocator) {
    memset(vector, 0, sizeof(*vector));
    vector->allocator = use_allocator(allocator);
}

void wrtc_byte_vector_clear(WrtcByteVector *vector) {
    PyMem_Free(vector->data);
    wrtc_byte_vector_init(vector, vector->allocator);
}

static int growth(size_t current, size_t needed, size_t item_size,
                  size_t *capacity, size_t *bytes) {
    size_t next = current < 8u ? 8u : current;
    while (next < needed) {
        size_t grown;
        if (wrtc_size_add(next, next / 2u + 1u, &grown) < 0) {
            next = needed;
            break;
        }
        next = grown;
    }
    if (wrtc_size_mul(next, item_size, bytes) < 0) return -1;
    *capacity = next;
    return 0;
}

int wrtc_byte_vector_reserve(WrtcByteVector *vector, size_t capacity) {
    uint8_t *data;
    size_t grown, bytes;
    if (capacity <= vector->capacity) return 0;
    if (growth(vector->capacity, capacity, sizeof(*vector->data), &grown,
               &bytes) < 0) {
        PyErr_NoMemory();
        return -1;
    }
    data = vector->data == NULL ? allocate(vector->allocator, bytes) :
                                 reallocate(vector->allocator, vector->data, bytes);
    if (data == NULL) return -1;
    vector->data = data;
    vector->capacity = grown;
    return 0;
}

int wrtc_byte_vector_resize(WrtcByteVector *vector, size_t length) {
    size_t previous = vector->length;
    if (wrtc_byte_vector_reserve(vector, length) < 0) return -1;
    if (length > previous) memset(vector->data + previous, 0, length - previous);
    vector->length = length;
    return 0;
}

int wrtc_byte_vector_append(WrtcByteVector *vector, uint8_t value) {
    size_t length;
    if (wrtc_size_add(vector->length, 1u, &length) < 0) {
        PyErr_NoMemory();
        return -1;
    }
    if (wrtc_byte_vector_reserve(vector, length) < 0) return -1;
    vector->data[vector->length] = value;
    vector->length = length;
    return 0;
}

int wrtc_byte_vector_extend(WrtcByteVector *vector, WrtcByteSpan value) {
    size_t length;
    if (wrtc_size_add(vector->length, value.length, &length) < 0) {
        PyErr_NoMemory();
        return -1;
    }
    if (wrtc_byte_vector_reserve(vector, length) < 0) return -1;
    if (value.length != 0u)
        memcpy(vector->data + vector->length, value.data, value.length);
    vector->length = length;
    return 0;
}

int wrtc_byte_vector_write_u16be(WrtcByteVector *vector, size_t offset,
                                 uint16_t value) {
    if (offset > vector->length || vector->length - offset < 2u) return -1;
    vector->data[offset] = (uint8_t)(value >> 8u);
    vector->data[offset + 1u] = (uint8_t)value;
    return 0;
}

int wrtc_byte_vector_write_u32be(WrtcByteVector *vector, size_t offset,
                                 uint32_t value) {
    if (offset > vector->length || vector->length - offset < 4u) return -1;
    vector->data[offset] = (uint8_t)(value >> 24u);
    vector->data[offset + 1u] = (uint8_t)(value >> 16u);
    vector->data[offset + 2u] = (uint8_t)(value >> 8u);
    vector->data[offset + 3u] = (uint8_t)value;
    return 0;
}

int wrtc_vector_init(WrtcVector *vector, size_t item_size,
                     WrtcAllocator *allocator) {
    return wrtc_vector_init_with_destructor(vector, item_size, allocator,
                                            NULL, NULL);
}

int wrtc_vector_init_with_destructor(
    WrtcVector *vector, size_t item_size, WrtcAllocator *allocator,
    void (*destroy_item)(void *item, void *context), void *destroy_context) {
    if (item_size == 0u) {
        PyErr_SetString(PyExc_ValueError, "vector item size must be positive");
        return -1;
    }
    memset(vector, 0, sizeof(*vector));
    vector->item_size = item_size;
    vector->allocator = use_allocator(allocator);
    vector->destroy_item = destroy_item;
    vector->destroy_context = destroy_context;
    return 0;
}

void wrtc_vector_clear(WrtcVector *vector) {
    size_t index, item_size = vector->item_size;
    WrtcAllocator *allocator = vector->allocator;
    void (*destroy_item)(void *, void *) = vector->destroy_item;
    void *destroy_context = vector->destroy_context;
    if (destroy_item != NULL)
        for (index = 0u; index < vector->length; index++)
            destroy_item((unsigned char *)vector->data + index * item_size,
                         destroy_context);
    PyMem_Free(vector->data);
    memset(vector, 0, sizeof(*vector));
    vector->item_size = item_size;
    vector->allocator = use_allocator(allocator);
    vector->destroy_item = destroy_item;
    vector->destroy_context = destroy_context;
}

int wrtc_vector_reserve(WrtcVector *vector, size_t capacity) {
    void *data;
    size_t grown, bytes;
    if (capacity <= vector->capacity) return 0;
    if (vector->item_size == 0u ||
        growth(vector->capacity, capacity, vector->item_size, &grown, &bytes) < 0) {
        PyErr_NoMemory(); return -1;
    }
    data = vector->data == NULL ? allocate(vector->allocator, bytes) :
                                 reallocate(vector->allocator, vector->data, bytes);
    if (data == NULL) return -1;
    vector->data = data; vector->capacity = grown;
    return 0;
}

int wrtc_vector_append(WrtcVector *vector, const void *value) {
    size_t needed;
    if (value == NULL || wrtc_size_add(vector->length, 1u, &needed) < 0) {
        if (value == NULL) PyErr_BadInternalCall(); else PyErr_NoMemory();
        return -1;
    }
    if (wrtc_vector_reserve(vector, needed) < 0) return -1;
    memcpy((uint8_t *)vector->data + vector->length * vector->item_size,
           value, vector->item_size);
    vector->length = needed;
    return 0;
}

int wrtc_vector_pop(WrtcVector *vector, void *value) {
    if (vector->length == 0u || value == NULL) return -1;
    vector->length--;
    memcpy(value, (uint8_t *)vector->data + vector->length * vector->item_size,
           vector->item_size);
    return 0;
}

void *wrtc_vector_at(WrtcVector *vector, size_t index) {
    if (index >= vector->length) return NULL;
    return (uint8_t *)vector->data + index * vector->item_size;
}

const void *wrtc_vector_at_const(const WrtcVector *vector, size_t index) {
    if (index >= vector->length) return NULL;
    return (const uint8_t *)vector->data + index * vector->item_size;
}

void wrtc_byte_vector_vector_init(WrtcByteVectorVector *vector,
                                  WrtcAllocator *allocator) {
    memset(vector, 0, sizeof(*vector));
    vector->allocator = use_allocator(allocator);
}

void wrtc_byte_vector_vector_clear(WrtcByteVectorVector *vector) {
    size_t index;
    for (index = 0u; index < vector->length; index++)
        wrtc_byte_vector_clear(&vector->data[index]);
    PyMem_Free(vector->data);
    wrtc_byte_vector_vector_init(vector, vector->allocator);
}

int wrtc_byte_vector_vector_append_move(WrtcByteVectorVector *vector,
                                        WrtcByteVector *value) {
    size_t needed, capacity, bytes;
    WrtcByteVector *data;
    if (wrtc_size_add(vector->length, 1u, &needed) < 0) {
        PyErr_NoMemory(); return -1;
    }
    if (needed > vector->capacity) {
        if (growth(vector->capacity, needed, sizeof(*data), &capacity, &bytes) < 0) {
            PyErr_NoMemory(); return -1;
        }
        data = vector->data == NULL ? allocate(vector->allocator, bytes) :
            reallocate(vector->allocator, vector->data, bytes);
        if (data == NULL) return -1;
        vector->data = data; vector->capacity = capacity;
    }
    vector->data[vector->length++] = *value;
    wrtc_byte_vector_init(value, value->allocator);
    return 0;
}

int wrtc_validate_exact_bytes(PyObject *value, const char *name) {
    if (!PyBytes_CheckExact(value)) {
        PyErr_Format(PyExc_TypeError, "%s must be bytes", name);
        return -1;
    }
    return 0;
}

int wrtc_validate_exact_int(PyObject *value, const char *name) {
    if (!PyLong_CheckExact(value)) {
        PyErr_Format(PyExc_TypeError, "%s must be int", name);
        return -1;
    }
    return 0;
}

int wrtc_borrow_exact_bytes(PyObject *value, WrtcByteSpan *result) {
    if (!PyBytes_CheckExact(value)) return PyErr_BadInternalCall(), -1;
    result->data = (const uint8_t *)PyBytes_AS_STRING(value);
    result->length = (size_t)PyBytes_GET_SIZE(value);
    return 0;
}

int wrtc_refine_u64_range(PyObject *value, const char *name, uint64_t low,
                          uint64_t high, uint64_t *result) {
    unsigned long long converted;
    if (!PyLong_CheckExact(value)) return PyErr_BadInternalCall(), -1;
    converted = PyLong_AsUnsignedLongLong(value);
    if (converted == (unsigned long long)-1 && PyErr_Occurred()) {
        PyErr_Clear();
        PyErr_Format(PyExc_ValueError, "%s must be in range %llu..%llu", name,
                     (unsigned long long)low, (unsigned long long)high);
        return -1;
    }
    if ((uint64_t)converted < low || (uint64_t)converted > high) {
        PyErr_Format(PyExc_ValueError, "%s must be in range %llu..%llu", name,
                     (unsigned long long)low, (unsigned long long)high);
        return -1;
    }
    *result = (uint64_t)converted;
    return 0;
}

int wrtc_refine_exact_bytes(PyObject *value, const char *name,
                            WrtcByteSpan *result) {
    if (wrtc_validate_exact_bytes(value, name) < 0) return -1;
    return wrtc_borrow_exact_bytes(value, result);
}

int wrtc_refine_exact_u64(PyObject *value, const char *name, uint64_t low,
                          uint64_t high, uint64_t *result) {
    if (wrtc_validate_exact_int(value, name) < 0) return -1;
    return wrtc_refine_u64_range(value, name, low, high, result);
}
