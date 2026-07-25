#ifndef WRTC_NATIVE_RUNTIME_H
#define WRTC_NATIVE_RUNTIME_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t allocation_count;
    size_t fail_after;
} WrtcAllocator;

typedef struct {
    const uint8_t *data;
    size_t length;
} WrtcByteSpan;

typedef struct {
    uint8_t *data;
    size_t length;
    size_t capacity;
    WrtcAllocator *allocator;
} WrtcByteVector;

typedef struct {
    void *data;
    size_t length;
    size_t capacity;
    size_t item_size;
    WrtcAllocator *allocator;
    void (*destroy_item)(void *item, void *context);
    void *destroy_context;
} WrtcVector;

typedef struct {
    WrtcByteVector *data;
    size_t length;
    size_t capacity;
    WrtcAllocator *allocator;
} WrtcByteVectorVector;

void wrtc_allocator_init(WrtcAllocator *allocator);
void wrtc_allocator_fail_after(WrtcAllocator *allocator, size_t successful_allocations);
void wrtc_allocator_disable_failures(WrtcAllocator *allocator);

int wrtc_size_add(size_t left, size_t right, size_t *result);
int wrtc_size_sub(size_t left, size_t right, size_t *result);
int wrtc_size_mul(size_t left, size_t right, size_t *result);
int wrtc_u8_add(uint8_t left, uint8_t right, uint8_t *result);
int wrtc_u16_add(uint16_t left, uint16_t right, uint16_t *result);
int wrtc_u32_add(uint32_t left, uint32_t right, uint32_t *result);
int wrtc_u64_add(uint64_t left, uint64_t right, uint64_t *result);
uint16_t wrtc_u16_wrapping_add(uint16_t value, uint16_t increment);

WrtcByteSpan wrtc_byte_span(const void *data, size_t length);
int wrtc_byte_span_slice(WrtcByteSpan span, size_t start, size_t length,
                         WrtcByteSpan *result);

void wrtc_byte_vector_init(WrtcByteVector *vector, WrtcAllocator *allocator);
void wrtc_byte_vector_clear(WrtcByteVector *vector);
int wrtc_byte_vector_reserve(WrtcByteVector *vector, size_t capacity);
int wrtc_byte_vector_resize(WrtcByteVector *vector, size_t length);
int wrtc_byte_vector_append(WrtcByteVector *vector, uint8_t value);
int wrtc_byte_vector_extend(WrtcByteVector *vector, WrtcByteSpan value);
int wrtc_byte_vector_write_u16be(WrtcByteVector *vector, size_t offset,
                                 uint16_t value);
int wrtc_byte_vector_write_u32be(WrtcByteVector *vector, size_t offset,
                                 uint32_t value);

int wrtc_vector_init(WrtcVector *vector, size_t item_size,
                     WrtcAllocator *allocator);
int wrtc_vector_init_with_destructor(
    WrtcVector *vector, size_t item_size, WrtcAllocator *allocator,
    void (*destroy_item)(void *item, void *context), void *destroy_context);
void wrtc_vector_clear(WrtcVector *vector);
int wrtc_vector_reserve(WrtcVector *vector, size_t capacity);
int wrtc_vector_append(WrtcVector *vector, const void *value);
int wrtc_vector_pop(WrtcVector *vector, void *value);
void *wrtc_vector_at(WrtcVector *vector, size_t index);
const void *wrtc_vector_at_const(const WrtcVector *vector, size_t index);

void wrtc_byte_vector_vector_init(WrtcByteVectorVector *vector,
                                  WrtcAllocator *allocator);
void wrtc_byte_vector_vector_clear(WrtcByteVectorVector *vector);
int wrtc_byte_vector_vector_append_move(WrtcByteVectorVector *vector,
                                        WrtcByteVector *value);

/* Exact concrete-type validation: bool is deliberately rejected as int. */
int wrtc_validate_exact_bytes(PyObject *value, const char *name);
int wrtc_validate_exact_int(PyObject *value, const char *name);
int wrtc_borrow_exact_bytes(PyObject *value, WrtcByteSpan *result);
int wrtc_refine_u64_range(PyObject *value, const char *name, uint64_t low,
                          uint64_t high, uint64_t *result);
int wrtc_refine_exact_bytes(PyObject *value, const char *name,
                            WrtcByteSpan *result);
int wrtc_refine_exact_u64(PyObject *value, const char *name, uint64_t low,
                          uint64_t high, uint64_t *result);

#endif
