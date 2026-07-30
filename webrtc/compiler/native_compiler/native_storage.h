#ifndef WRTC_NATIVE_STORAGE_H
#define WRTC_NATIVE_STORAGE_H

#include <Python.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

#include "native_class.h"

typedef enum {
    WRTC_STORAGE_EMPTY = 0,
    WRTC_STORAGE_NATIVE,
    WRTC_STORAGE_BOXED
} WrtcStorageMode;

typedef enum {
    WRTC_SCALAR_NONE = 0,
    WRTC_SCALAR_INT64,
    WRTC_SCALAR_DOUBLE,
    WRTC_SCALAR_BOOL,
    WRTC_SCALAR_BOXED
} WrtcScalarTag;

typedef struct {
    WrtcScalarTag tag;
    union {
        int64_t integer;
        double floating;
        int boolean;
        PyObject *boxed;
    } value;
} WrtcNativeScalar;

typedef struct {
    WrtcStorageMode mode;
    PyObject *boxed;
    PyObject **items;
    size_t capacity;
    size_t head;
    size_t size;
} WrtcNativeFifo;

typedef struct {
    WrtcStorageMode mode;
    PyObject *boxed;
    PyObject **items;
    size_t capacity;
    size_t size;
} WrtcNativeMinHeap;

typedef struct {
    _Atomic uint_least32_t value;
    int initialized;
} WrtcNativeAtomicUint32;

typedef struct {
    _Atomic size_t sequence;
    _Atomic(void *) item;
} WrtcNativeMpscCell;

typedef struct {
    WrtcNativeMpscCell *cells;
    size_t capacity;
    _Atomic size_t enqueue_position;
    _Atomic size_t dequeue_position;
    /*
     * The high bit closes producer admission; the remaining bits count
     * producers that have been admitted and must commit before reclamation.
     * Keeping both facts in one atomic closes the check/increment race.
     */
    _Atomic size_t producer_admission;
    _Atomic unsigned notified;
} WrtcNativeMpsc;

typedef struct {
    WrtcNativeMpsc *queue;
    WrtcNativeMpscCell *cell;
    size_t position;
    unsigned active;
} WrtcNativeMpscTicket;

typedef enum {
    WRTC_MPSC_OK = 0,
    WRTC_MPSC_EMPTY,
    WRTC_MPSC_FULL,
    WRTC_MPSC_CLOSED
} WrtcNativeMpscStatus;

typedef void (*WrtcNativeMpscRelease)(void *item, void *context);

typedef struct {
    _Atomic(void *) *items;
    size_t capacity;
    _Atomic size_t producer_position;
    _Atomic size_t consumer_position;
    _Atomic size_t producer_admission;
} WrtcNativeSpsc;

typedef enum {
    WRTC_SPSC_OK = 0,
    WRTC_SPSC_EMPTY,
    WRTC_SPSC_FULL,
    WRTC_SPSC_CLOSED
} WrtcNativeSpscStatus;

typedef void (*WrtcNativeSpscRelease)(void *item, void *context);

int wrtc_native_storage_field_eligible(const WrtcNativeFieldIR *field,
                                       const char **reason);

void wrtc_native_scalar_init(WrtcNativeScalar *slot);
void wrtc_native_scalar_clear(WrtcNativeScalar *slot);
int wrtc_native_scalar_traverse(WrtcNativeScalar *slot, visitproc visit,
                                void *argument);
int wrtc_native_scalar_set_boxed(WrtcNativeScalar *slot, PyObject *value);
int wrtc_native_scalar_set_int64(WrtcNativeScalar *slot, int64_t value);
int wrtc_native_scalar_set_double(WrtcNativeScalar *slot, double value);
int wrtc_native_scalar_set_bool(WrtcNativeScalar *slot, int value);
PyObject *wrtc_native_scalar_get(const WrtcNativeScalar *slot,
                                 const char *field_name);
int wrtc_native_scalar_delete(WrtcNativeScalar *slot,
                              const char *field_name);

void wrtc_native_fifo_init(WrtcNativeFifo *fifo);
void wrtc_native_fifo_clear(WrtcNativeFifo *fifo);
int wrtc_native_fifo_traverse(WrtcNativeFifo *fifo, visitproc visit,
                              void *argument);
int wrtc_native_fifo_activate(WrtcNativeFifo *fifo, size_t capacity);
int wrtc_native_fifo_set_boxed(WrtcNativeFifo *fifo, PyObject *value);
int wrtc_native_fifo_try_adopt(WrtcNativeFifo *fifo);
PyObject *wrtc_native_fifo_get(WrtcNativeFifo *fifo,
                               const char *field_name);
int wrtc_native_fifo_delete(WrtcNativeFifo *fifo, const char *field_name);
Py_ssize_t wrtc_native_fifo_snapshot(const WrtcNativeFifo *fifo);
int wrtc_native_fifo_append(WrtcNativeFifo *fifo, PyObject *value);
PyObject *wrtc_native_fifo_popleft(WrtcNativeFifo *fifo);

void wrtc_native_heap_init(WrtcNativeMinHeap *heap);
void wrtc_native_heap_clear(WrtcNativeMinHeap *heap);
int wrtc_native_heap_traverse(WrtcNativeMinHeap *heap, visitproc visit,
                              void *argument);
int wrtc_native_heap_activate(WrtcNativeMinHeap *heap, size_t capacity);
int wrtc_native_heap_set_boxed(WrtcNativeMinHeap *heap, PyObject *value);
int wrtc_native_heap_try_adopt(WrtcNativeMinHeap *heap);
PyObject *wrtc_native_heap_get(WrtcNativeMinHeap *heap,
                               const char *field_name);
int wrtc_native_heap_delete(WrtcNativeMinHeap *heap,
                            const char *field_name);
int wrtc_native_heap_push(WrtcNativeMinHeap *heap, PyObject *value);
PyObject *wrtc_native_heap_pop(WrtcNativeMinHeap *heap);
int wrtc_native_heap_heapify(WrtcNativeMinHeap *heap);
Py_ssize_t wrtc_native_heap_snapshot(const WrtcNativeMinHeap *heap);
PyObject *wrtc_native_heap_root(const WrtcNativeMinHeap *heap);

void wrtc_native_atomic_uint32_init(WrtcNativeAtomicUint32 *slot);
void wrtc_native_atomic_uint32_clear(WrtcNativeAtomicUint32 *slot);
int wrtc_native_atomic_uint32_set(WrtcNativeAtomicUint32 *slot,
                                  uint_least32_t value);
int wrtc_native_atomic_uint32_load(const WrtcNativeAtomicUint32 *slot,
                                   uint_least32_t *value);
int wrtc_native_atomic_uint32_compare_exchange(
    WrtcNativeAtomicUint32 *slot, uint_least32_t expected,
    uint_least32_t desired, uint_least32_t *previous, int *changed);

int wrtc_native_mpsc_init(WrtcNativeMpsc *queue, size_t capacity);
WrtcNativeMpscStatus wrtc_native_mpsc_reserve(
    WrtcNativeMpsc *queue, WrtcNativeMpscTicket *ticket);
int wrtc_native_mpsc_commit(WrtcNativeMpscTicket *ticket, void *item,
                            int *should_notify);
WrtcNativeMpscStatus wrtc_native_mpsc_publish(
    WrtcNativeMpsc *queue, void *item, int *should_notify);
WrtcNativeMpscStatus wrtc_native_mpsc_try_pop(
    WrtcNativeMpsc *queue, void **item);
size_t wrtc_native_mpsc_snapshot(const WrtcNativeMpsc *queue);
int wrtc_native_mpsc_is_open(const WrtcNativeMpsc *queue);
int wrtc_native_mpsc_traverse(WrtcNativeMpsc *queue, visitproc visit,
                              void *argument);
int wrtc_native_mpsc_consumer_rearm(WrtcNativeMpsc *queue);
void wrtc_native_mpsc_close(WrtcNativeMpsc *queue);
void wrtc_native_mpsc_clear(WrtcNativeMpsc *queue,
                            WrtcNativeMpscRelease release,
                            void *context);

int wrtc_native_spsc_init(WrtcNativeSpsc *queue, size_t capacity);
WrtcNativeSpscStatus wrtc_native_spsc_try_push(
    WrtcNativeSpsc *queue, void *item);
WrtcNativeSpscStatus wrtc_native_spsc_try_pop(
    WrtcNativeSpsc *queue, void **item);
size_t wrtc_native_spsc_snapshot(const WrtcNativeSpsc *queue);
int wrtc_native_spsc_is_open(const WrtcNativeSpsc *queue);
int wrtc_native_spsc_traverse(WrtcNativeSpsc *queue, visitproc visit,
                              void *argument);
void wrtc_native_spsc_close(WrtcNativeSpsc *queue);
void wrtc_native_spsc_clear(WrtcNativeSpsc *queue,
                            WrtcNativeSpscRelease release,
                            void *context);

#endif
