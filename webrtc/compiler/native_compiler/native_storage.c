#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "native_storage.h"

static int missing(const char *name) {
    PyErr_Format(PyExc_AttributeError, "%s", name == NULL ? "field" : name);
    return -1;
}

int wrtc_native_storage_field_eligible(const WrtcNativeFieldIR *field,
                                       const char **reason) {
    if (reason != NULL) *reason = NULL;
    if (field == NULL) {
        if (reason != NULL) *reason = "field IR is absent";
        return 0;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_SCALAR) {
        if (field->type == WRTC_TYPE_INT || field->type == WRTC_TYPE_BOOL ||
            (field->declared_type != NULL &&
             strcmp(field->declared_type, "float") == 0))
            return 1;
        if (reason != NULL)
            *reason = "native scalar requires int, bool, or float";
        return 0;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO) {
        if (field->owner != NULL && field->owner[0] != '\0')
            return 1;
        if (reason != NULL)
            *reason = "native FIFO requires a single declared owner";
        return 0;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP) {
        if (field->owner == NULL || field->owner[0] == '\0') {
            if (reason != NULL)
                *reason = "native min-heap requires a single declared owner";
            return 0;
        }
        if (field->heap_ordering == NULL) {
            if (reason != NULL)
                *reason = "native min-heap requires pinned ordering";
            return 0;
        }
        return 1;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32) {
        if (!field->atomic || field->atomic_width != 32u) {
            if (reason != NULL)
                *reason = "native atomic requires explicit uint[32]";
            return 0;
        }
        if (field->owner == NULL || strcmp(field->owner, "shared") != 0) {
            if (reason != NULL)
                *reason = "native atomic requires owned_by('shared')";
            return 0;
        }
        if (field->atomic_memory_order == NULL ||
            strcmp(field->atomic_memory_order, "seq_cst") != 0 ||
            field->atomic_scope == NULL ||
            strcmp(field->atomic_scope, "process") != 0 ||
            field->atomic_linearization == NULL ||
            strcmp(field->atomic_linearization, "compare_exchange") != 0) {
            if (reason != NULL)
                *reason = "native atomic semantics are incomplete";
            return 0;
        }
        return 1;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC) {
        if (field->queue_topology != WRTC_QUEUE_MPSC ||
            field->queue_capacity == NULL) {
            if (reason != NULL)
                *reason = "native MPSC requires an explicit bounded capacity";
            return 0;
        }
        if (field->owner == NULL || strcmp(field->owner, "reactor") != 0) {
            if (reason != NULL)
                *reason = "native MPSC requires owned_by('reactor')";
            return 0;
        }
        if (field->queue_item_type == NULL ||
            !field->typed_queue_payload) {
            if (reason != NULL)
                *reason = "native MPSC payload requires an exact "
                          "ABI-declared record with proven ownership";
            return 0;
        }
        return 1;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC) {
        if (field->queue_topology != WRTC_QUEUE_SPSC ||
            field->queue_capacity == NULL) {
            if (reason != NULL)
                *reason = "native SPSC requires an explicit bounded capacity";
            return 0;
        }
        if (field->owner == NULL ||
            (strcmp(field->owner, "worker") != 0 &&
             strcmp(field->owner, "reactor") != 0)) {
            if (reason != NULL)
                *reason = "native SPSC requires worker or reactor ownership";
            return 0;
        }
        if (field->queue_item_type == NULL ||
            !field->typed_queue_payload) {
            if (reason != NULL)
                *reason = "native SPSC payload requires an exact "
                          "ABI-declared record with proven ownership";
            return 0;
        }
        return 1;
    }
    if (field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR ||
        field->storage_kind == WRTC_NATIVE_FIELD_PACKET_POOL) {
        if (field->owner == NULL || strcmp(field->owner, "reactor") != 0) {
            if (reason != NULL)
                *reason = "native reactor storage requires owned_by('reactor')";
            return 0;
        }
        if (field->reactor_capacity == NULL) {
            if (reason != NULL)
                *reason = "native reactor storage requires explicit capacity";
            return 0;
        }
        if (field->storage_kind == WRTC_NATIVE_FIELD_PACKET_POOL &&
            field->packet_buffer_size == NULL) {
            if (reason != NULL)
                *reason = "native packet slab requires explicit buffer_size";
            return 0;
        }
        return 1;
    }
    if (reason != NULL) *reason = "field does not request native storage";
    return 0;
}

void wrtc_native_scalar_init(WrtcNativeScalar *slot) {
    memset(slot, 0, sizeof(*slot));
}

void wrtc_native_scalar_clear(WrtcNativeScalar *slot) {
    if (slot->tag == WRTC_SCALAR_BOXED) Py_CLEAR(slot->value.boxed);
    slot->tag = WRTC_SCALAR_NONE;
}

int wrtc_native_scalar_traverse(WrtcNativeScalar *slot, visitproc visit,
                                void *argument) {
    if (slot->tag == WRTC_SCALAR_BOXED && slot->value.boxed != NULL)
        return visit(slot->value.boxed, argument);
    return 0;
}

int wrtc_native_scalar_set_boxed(WrtcNativeScalar *slot, PyObject *value) {
    PyObject *owned;
    if (value == NULL) return missing("field");
    owned = Py_NewRef(value);
    wrtc_native_scalar_clear(slot);
    slot->value.boxed = owned;
    slot->tag = WRTC_SCALAR_BOXED;
    return 0;
}

int wrtc_native_scalar_set_int64(WrtcNativeScalar *slot, int64_t value) {
    wrtc_native_scalar_clear(slot);
    slot->tag = WRTC_SCALAR_INT64;
    slot->value.integer = value;
    return 0;
}

int wrtc_native_scalar_set_double(WrtcNativeScalar *slot, double value) {
    wrtc_native_scalar_clear(slot);
    slot->tag = WRTC_SCALAR_DOUBLE;
    slot->value.floating = value;
    return 0;
}

int wrtc_native_scalar_set_bool(WrtcNativeScalar *slot, int value) {
    wrtc_native_scalar_clear(slot);
    slot->tag = WRTC_SCALAR_BOOL;
    slot->value.boolean = value != 0;
    return 0;
}

PyObject *wrtc_native_scalar_get(const WrtcNativeScalar *slot,
                                 const char *field_name) {
    switch (slot->tag) {
        case WRTC_SCALAR_INT64:
            return PyLong_FromLongLong((long long)slot->value.integer);
        case WRTC_SCALAR_DOUBLE:
            return PyFloat_FromDouble(slot->value.floating);
        case WRTC_SCALAR_BOOL:
            return PyBool_FromLong(slot->value.boolean);
        case WRTC_SCALAR_BOXED:
            return Py_NewRef(slot->value.boxed);
        case WRTC_SCALAR_NONE:
            (void)missing(field_name);
            return NULL;
    }
    PyErr_SetString(PyExc_SystemError, "unknown native scalar tag");
    return NULL;
}

void wrtc_native_atomic_uint32_init(WrtcNativeAtomicUint32 *slot) {
    atomic_init(&slot->value, (uint_least32_t)0u);
    slot->initialized = 0;
}

void wrtc_native_atomic_uint32_clear(WrtcNativeAtomicUint32 *slot) {
    atomic_store_explicit(&slot->value, (uint_least32_t)0u,
                          memory_order_seq_cst);
    slot->initialized = 0;
}

int wrtc_native_atomic_uint32_set(WrtcNativeAtomicUint32 *slot,
                                  uint_least32_t value) {
    atomic_store_explicit(&slot->value, value, memory_order_seq_cst);
    slot->initialized = 1;
    return 0;
}

int wrtc_native_atomic_uint32_load(const WrtcNativeAtomicUint32 *slot,
                                   uint_least32_t *value) {
    if (!slot->initialized) return missing("atomic field");
    *value = atomic_load_explicit(&slot->value, memory_order_seq_cst);
    return 0;
}

int wrtc_native_atomic_uint32_compare_exchange(
    WrtcNativeAtomicUint32 *slot, uint_least32_t expected,
    uint_least32_t desired, uint_least32_t *previous, int *changed) {
    uint_least32_t observed = expected;
    if (!slot->initialized) return missing("atomic field");
    *changed = atomic_compare_exchange_strong_explicit(
        &slot->value, &observed, desired, memory_order_seq_cst,
        memory_order_seq_cst);
    *previous = *changed ? expected : observed;
    return 0;
}

int wrtc_native_mpsc_init(WrtcNativeMpsc *queue, size_t capacity) {
    size_t index;
    if (queue == NULL || capacity == 0u ||
        capacity > SIZE_MAX / sizeof(*queue->cells))
        return -1;
    memset(queue, 0, sizeof(*queue));
    queue->cells = calloc(capacity, sizeof(*queue->cells));
    if (queue->cells == NULL) return -1;
    queue->capacity = capacity;
    for (index = 0u; index < capacity; index++) {
        atomic_init(&queue->cells[index].sequence, index);
        atomic_init(&queue->cells[index].item, NULL);
    }
    atomic_init(&queue->enqueue_position, 0u);
    atomic_init(&queue->dequeue_position, 0u);
    atomic_init(&queue->producer_admission, 0u);
    atomic_init(&queue->notified, 0u);
    return 0;
}

#define WRTC_MPSC_CLOSED_BIT \
    ((size_t)1u << (sizeof(size_t) * CHAR_BIT - 1u))
#define WRTC_MPSC_PUBLISHER_MASK (WRTC_MPSC_CLOSED_BIT - 1u)

static int mpsc_admit_producer(WrtcNativeMpsc *queue) {
    size_t state = atomic_load_explicit(
        &queue->producer_admission, memory_order_acquire);
    for (;;) {
        if ((state & WRTC_MPSC_CLOSED_BIT) != 0u)
            return 0;
        if ((state & WRTC_MPSC_PUBLISHER_MASK) ==
            WRTC_MPSC_PUBLISHER_MASK)
            return 0;
        if (atomic_compare_exchange_weak_explicit(
                &queue->producer_admission, &state, state + 1u,
                memory_order_acq_rel, memory_order_acquire))
            return 1;
    }
}

static void mpsc_release_producer(WrtcNativeMpsc *queue) {
    (void)atomic_fetch_sub_explicit(
        &queue->producer_admission, 1u, memory_order_release);
}

WrtcNativeMpscStatus wrtc_native_mpsc_reserve(
    WrtcNativeMpsc *queue, WrtcNativeMpscTicket *ticket) {
    size_t position;
    if (queue == NULL || ticket == NULL || queue->cells == NULL)
        return WRTC_MPSC_CLOSED;
    memset(ticket, 0, sizeof(*ticket));
    if (!mpsc_admit_producer(queue))
        return WRTC_MPSC_CLOSED;
    position = atomic_load_explicit(&queue->enqueue_position,
                                    memory_order_relaxed);
    for (;;) {
        const size_t consumed =
            atomic_load_explicit(&queue->dequeue_position,
                                 memory_order_acquire);
        WrtcNativeMpscCell *cell =
            &queue->cells[position % queue->capacity];
        if (position - consumed >= queue->capacity) {
            mpsc_release_producer(queue);
            return WRTC_MPSC_FULL;
        }
        const size_t sequence =
            atomic_load_explicit(&cell->sequence, memory_order_acquire);
        const intptr_t difference =
            (intptr_t)sequence - (intptr_t)position;
        if (difference == 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &queue->enqueue_position, &position, position + 1u,
                    memory_order_relaxed, memory_order_relaxed)) {
                ticket->queue = queue;
                ticket->cell = cell;
                ticket->position = position;
                ticket->active = 1u;
                return WRTC_MPSC_OK;
            }
        } else if (difference < 0) {
            mpsc_release_producer(queue);
            return WRTC_MPSC_FULL;
        } else {
            position = atomic_load_explicit(&queue->enqueue_position,
                                            memory_order_relaxed);
        }
    }
}

int wrtc_native_mpsc_commit(WrtcNativeMpscTicket *ticket, void *item,
                            int *should_notify) {
    WrtcNativeMpsc *queue;
    if (ticket == NULL || !ticket->active || item == NULL)
        return -1;
    queue = ticket->queue;
    atomic_store_explicit(&ticket->cell->item, item, memory_order_relaxed);
    atomic_store_explicit(&ticket->cell->sequence, ticket->position + 1u,
                          memory_order_release);
    if (should_notify != NULL)
        *should_notify =
            atomic_exchange_explicit(&queue->notified, 1u,
                                     memory_order_acq_rel) == 0u;
    mpsc_release_producer(queue);
    ticket->active = 0u;
    return 0;
}

WrtcNativeMpscStatus wrtc_native_mpsc_publish(
    WrtcNativeMpsc *queue, void *item, int *should_notify) {
    WrtcNativeMpscTicket ticket;
    WrtcNativeMpscStatus status =
        wrtc_native_mpsc_reserve(queue, &ticket);
    if (status != WRTC_MPSC_OK) return status;
    if (wrtc_native_mpsc_commit(&ticket, item, should_notify) < 0)
        return WRTC_MPSC_CLOSED;
    return WRTC_MPSC_OK;
}

WrtcNativeMpscStatus wrtc_native_mpsc_try_pop(
    WrtcNativeMpsc *queue, void **item) {
    WrtcNativeMpscCell *cell;
    size_t position;
    size_t sequence;
    intptr_t difference;
    if (queue == NULL || item == NULL || queue->cells == NULL)
        return WRTC_MPSC_CLOSED;
    position = atomic_load_explicit(&queue->dequeue_position,
                                    memory_order_relaxed);
    cell = &queue->cells[position % queue->capacity];
    sequence = atomic_load_explicit(&cell->sequence, memory_order_acquire);
    difference = (intptr_t)sequence -
                 (intptr_t)(position + 1u);
    if (difference < 0) return WRTC_MPSC_EMPTY;
    if (difference > 0) return WRTC_MPSC_EMPTY;
    *item = atomic_exchange_explicit(&cell->item, NULL,
                                     memory_order_relaxed);
    atomic_store_explicit(
        &cell->sequence, position + queue->capacity,
        memory_order_release);
    atomic_store_explicit(&queue->dequeue_position, position + 1u,
                          memory_order_release);
    return *item == NULL ? WRTC_MPSC_EMPTY : WRTC_MPSC_OK;
}

size_t wrtc_native_mpsc_snapshot(const WrtcNativeMpsc *queue) {
    if (queue == NULL || queue->cells == NULL) return 0u;
    const size_t published =
        atomic_load_explicit(&queue->enqueue_position, memory_order_acquire);
    const size_t consumed =
        atomic_load_explicit(&queue->dequeue_position,
                             memory_order_acquire);
    return published > consumed ? published - consumed : 0u;
}

int wrtc_native_mpsc_is_open(const WrtcNativeMpsc *queue) {
    return queue != NULL && queue->cells != NULL &&
           (atomic_load_explicit(&queue->producer_admission,
                                 memory_order_acquire) &
            WRTC_MPSC_CLOSED_BIT) == 0u;
}

int wrtc_native_mpsc_traverse(WrtcNativeMpsc *queue, visitproc visit,
                              void *argument) {
    size_t position, published;
    if (queue == NULL || queue->cells == NULL || visit == NULL) return 0;
    position = atomic_load_explicit(&queue->dequeue_position,
                                    memory_order_acquire);
    published = atomic_load_explicit(&queue->enqueue_position,
                                     memory_order_acquire);
    while (position < published) {
        WrtcNativeMpscCell *cell =
            &queue->cells[position % queue->capacity];
        const size_t sequence =
            atomic_load_explicit(&cell->sequence, memory_order_acquire);
        if (sequence == position + 1u) {
            PyObject *item = (PyObject *)atomic_load_explicit(
                &cell->item, memory_order_acquire);
            if (item != NULL) {
                const int status = visit(item, argument);
                if (status != 0) return status;
            }
        }
        position++;
    }
    return 0;
}

int wrtc_native_mpsc_consumer_rearm(WrtcNativeMpsc *queue) {
    unsigned expected = 0u;
    size_t published, consumed;
    if (queue == NULL || queue->cells == NULL) return 0;
    atomic_store_explicit(&queue->notified, 0u, memory_order_release);
    /*
     * Reservations matter here too: a later producer can publish behind a
     * stalled earlier producer.  Re-arming while work is outstanding avoids
     * losing the only notification for that publication gap.
     */
    published = atomic_load_explicit(&queue->enqueue_position,
                                     memory_order_acquire);
    consumed = atomic_load_explicit(&queue->dequeue_position,
                                    memory_order_acquire);
    if (published == consumed) return 0;
    return atomic_compare_exchange_strong_explicit(
        &queue->notified, &expected, 1u, memory_order_acq_rel,
        memory_order_acquire);
}

void wrtc_native_mpsc_close(WrtcNativeMpsc *queue) {
    size_t state;
    if (queue == NULL) return;
    state = atomic_fetch_or_explicit(
        &queue->producer_admission, WRTC_MPSC_CLOSED_BIT,
        memory_order_acq_rel);
    (void)state;
    while ((atomic_load_explicit(&queue->producer_admission,
                                 memory_order_acquire) &
            WRTC_MPSC_PUBLISHER_MASK) != 0u) {
    }
}

void wrtc_native_mpsc_clear(WrtcNativeMpsc *queue,
                            WrtcNativeMpscRelease release,
                            void *context) {
    void *item = NULL;
    if (queue == NULL) return;
    wrtc_native_mpsc_close(queue);
    while (wrtc_native_mpsc_try_pop(queue, &item) == WRTC_MPSC_OK) {
        if (release != NULL) release(item, context);
    }
    free(queue->cells);
    memset(queue, 0, sizeof(*queue));
}

#define WRTC_SPSC_CLOSED_BIT WRTC_MPSC_CLOSED_BIT
#define WRTC_SPSC_PRODUCER_BIT ((size_t)1u)

static int spsc_admit_producer(WrtcNativeSpsc *queue) {
    size_t expected = 0u;
    return atomic_compare_exchange_strong_explicit(
        &queue->producer_admission, &expected, WRTC_SPSC_PRODUCER_BIT,
        memory_order_acq_rel, memory_order_acquire);
}

static void spsc_release_producer(WrtcNativeSpsc *queue) {
    atomic_store_explicit(&queue->producer_admission, 0u,
                          memory_order_release);
}

int wrtc_native_spsc_init(WrtcNativeSpsc *queue, size_t capacity) {
    size_t index;
    if (queue == NULL || capacity == 0u ||
        capacity > SIZE_MAX / sizeof(*queue->items))
        return -1;
    memset(queue, 0, sizeof(*queue));
    queue->items = calloc(capacity, sizeof(*queue->items));
    if (queue->items == NULL) return -1;
    queue->capacity = capacity;
    for (index = 0u; index < capacity; index++)
        atomic_init(&queue->items[index], NULL);
    atomic_init(&queue->producer_position, 0u);
    atomic_init(&queue->consumer_position, 0u);
    atomic_init(&queue->producer_admission, 0u);
    return 0;
}

WrtcNativeSpscStatus wrtc_native_spsc_try_push(
    WrtcNativeSpsc *queue, void *item) {
    size_t producer, consumer;
    if (queue == NULL || queue->items == NULL || item == NULL)
        return WRTC_SPSC_CLOSED;
    if (!spsc_admit_producer(queue))
        return (atomic_load_explicit(&queue->producer_admission,
                                     memory_order_acquire) &
                WRTC_SPSC_CLOSED_BIT) != 0u
                   ? WRTC_SPSC_CLOSED : WRTC_SPSC_FULL;
    producer = atomic_load_explicit(&queue->producer_position,
                                    memory_order_relaxed);
    consumer = atomic_load_explicit(&queue->consumer_position,
                                    memory_order_acquire);
    if (producer - consumer >= queue->capacity) {
        spsc_release_producer(queue);
        return WRTC_SPSC_FULL;
    }
    atomic_store_explicit(&queue->items[producer % queue->capacity], item,
                          memory_order_relaxed);
    atomic_store_explicit(&queue->producer_position, producer + 1u,
                          memory_order_release);
    spsc_release_producer(queue);
    return WRTC_SPSC_OK;
}

WrtcNativeSpscStatus wrtc_native_spsc_try_pop(
    WrtcNativeSpsc *queue, void **item) {
    size_t producer, consumer;
    if (queue == NULL || queue->items == NULL || item == NULL)
        return WRTC_SPSC_CLOSED;
    consumer = atomic_load_explicit(&queue->consumer_position,
                                    memory_order_relaxed);
    producer = atomic_load_explicit(&queue->producer_position,
                                    memory_order_acquire);
    if (consumer == producer) return WRTC_SPSC_EMPTY;
    *item = atomic_exchange_explicit(
        &queue->items[consumer % queue->capacity], NULL,
        memory_order_relaxed);
    atomic_store_explicit(&queue->consumer_position, consumer + 1u,
                          memory_order_release);
    return *item == NULL ? WRTC_SPSC_EMPTY : WRTC_SPSC_OK;
}

size_t wrtc_native_spsc_snapshot(const WrtcNativeSpsc *queue) {
    size_t producer, consumer;
    if (queue == NULL || queue->items == NULL) return 0u;
    producer = atomic_load_explicit(&queue->producer_position,
                                    memory_order_acquire);
    consumer = atomic_load_explicit(&queue->consumer_position,
                                    memory_order_acquire);
    return producer - consumer;
}

int wrtc_native_spsc_is_open(const WrtcNativeSpsc *queue) {
    return queue != NULL && queue->items != NULL &&
           (atomic_load_explicit(&queue->producer_admission,
                                 memory_order_acquire) &
            WRTC_SPSC_CLOSED_BIT) == 0u;
}

int wrtc_native_spsc_traverse(WrtcNativeSpsc *queue, visitproc visit,
                              void *argument) {
    size_t consumer, producer;
    if (queue == NULL || queue->items == NULL || visit == NULL) return 0;
    consumer = atomic_load_explicit(&queue->consumer_position,
                                    memory_order_acquire);
    producer = atomic_load_explicit(&queue->producer_position,
                                    memory_order_acquire);
    while (consumer < producer) {
        PyObject *item = (PyObject *)atomic_load_explicit(
            &queue->items[consumer % queue->capacity],
            memory_order_acquire);
        if (item != NULL) {
            const int status = visit(item, argument);
            if (status != 0) return status;
        }
        consumer++;
    }
    return 0;
}

void wrtc_native_spsc_close(WrtcNativeSpsc *queue) {
    size_t state;
    if (queue == NULL) return;
    for (;;) {
        state = atomic_load_explicit(&queue->producer_admission,
                                     memory_order_acquire);
        if ((state & WRTC_SPSC_CLOSED_BIT) != 0u) break;
        if (state == 0u) {
            size_t expected = 0u;
            if (atomic_compare_exchange_weak_explicit(
                    &queue->producer_admission, &expected,
                    WRTC_SPSC_CLOSED_BIT, memory_order_acq_rel,
                    memory_order_acquire))
                break;
        }
    }
}

void wrtc_native_spsc_clear(WrtcNativeSpsc *queue,
                            WrtcNativeSpscRelease release,
                            void *context) {
    void *item = NULL;
    if (queue == NULL) return;
    wrtc_native_spsc_close(queue);
    while (wrtc_native_spsc_try_pop(queue, &item) == WRTC_SPSC_OK)
        if (release != NULL) release(item, context);
    free(queue->items);
    memset(queue, 0, sizeof(*queue));
}

int wrtc_native_scalar_delete(WrtcNativeScalar *slot,
                              const char *field_name) {
    if (slot->tag == WRTC_SCALAR_NONE) return missing(field_name);
    wrtc_native_scalar_clear(slot);
    return 0;
}

static void fifo_native_clear(WrtcNativeFifo *fifo) {
    size_t index;
    for (index = 0u; index < fifo->size; index++) {
        const size_t position = (fifo->head + index) % fifo->capacity;
        Py_CLEAR(fifo->items[position]);
    }
    free(fifo->items);
    fifo->items = NULL;
    fifo->capacity = fifo->head = fifo->size = 0u;
}

void wrtc_native_fifo_init(WrtcNativeFifo *fifo) {
    memset(fifo, 0, sizeof(*fifo));
}

void wrtc_native_fifo_clear(WrtcNativeFifo *fifo) {
    if (fifo->mode == WRTC_STORAGE_BOXED) Py_CLEAR(fifo->boxed);
    if (fifo->mode == WRTC_STORAGE_NATIVE) fifo_native_clear(fifo);
    fifo->mode = WRTC_STORAGE_EMPTY;
}

int wrtc_native_fifo_traverse(WrtcNativeFifo *fifo, visitproc visit,
                              void *argument) {
    size_t index;
    if (fifo->mode == WRTC_STORAGE_BOXED && fifo->boxed != NULL)
        return visit(fifo->boxed, argument);
    if (fifo->mode == WRTC_STORAGE_NATIVE)
        for (index = 0u; index < fifo->size; index++) {
            const size_t position =
                (fifo->head + index) % fifo->capacity;
            const int status = visit(fifo->items[position], argument);
            if (status != 0) return status;
        }
    return 0;
}

int wrtc_native_fifo_activate(WrtcNativeFifo *fifo, size_t capacity) {
    PyObject **items;
    if (fifo->mode != WRTC_STORAGE_EMPTY) {
        PyErr_SetString(PyExc_RuntimeError,
                        "FIFO activation requires empty storage");
        return -1;
    }
    if (capacity == 0u) capacity = 8u;
    items = calloc(capacity, sizeof(*items));
    if (items == NULL) return PyErr_NoMemory(), -1;
    fifo->items = items;
    fifo->capacity = capacity;
    fifo->mode = WRTC_STORAGE_NATIVE;
    return 0;
}

int wrtc_native_fifo_set_boxed(WrtcNativeFifo *fifo, PyObject *value) {
    PyObject *owned = Py_NewRef(value);
    wrtc_native_fifo_clear(fifo);
    fifo->boxed = owned;
    fifo->mode = WRTC_STORAGE_BOXED;
    return 0;
}

int wrtc_native_fifo_append(WrtcNativeFifo *fifo, PyObject *value);

static int has_weakrefs(PyObject *value) {
    return Py_TYPE(value)->tp_weaklistoffset != 0 &&
           *PyObject_GET_WEAKREFS_LISTPTR(value) != NULL;
}

int wrtc_native_fifo_try_adopt(WrtcNativeFifo *fifo) {
    WrtcNativeFifo native;
    PyObject *collections = NULL, *deque = NULL, *iterator = NULL;
    PyObject *item;
    Py_ssize_t length;
    int status = -1;
    if (fifo->mode != WRTC_STORAGE_BOXED ||
        Py_REFCNT(fifo->boxed) != 1 ||
        has_weakrefs(fifo->boxed))
        return 0;
    collections = PyImport_ImportModule("collections");
    deque = collections == NULL
                ? NULL : PyObject_GetAttrString(collections, "deque");
    if (deque == NULL) goto done;
    if (!Py_IS_TYPE(fifo->boxed, (PyTypeObject *)deque)) {
        status = 0;
        goto done;
    }
    iterator = PyObject_GetIter(fifo->boxed);
    if (iterator == NULL) goto done;
    length = PyObject_Length(fifo->boxed);
    if (length < 0) goto done;
    wrtc_native_fifo_init(&native);
    if (wrtc_native_fifo_activate(&native, (size_t)length) < 0)
        goto done;
    while ((item = PyIter_Next(iterator)) != NULL) {
        if (wrtc_native_fifo_append(&native, item) < 0) {
            Py_DECREF(item);
            wrtc_native_fifo_clear(&native);
            goto done;
        }
        Py_DECREF(item);
    }
    if (PyErr_Occurred()) {
        wrtc_native_fifo_clear(&native);
        goto done;
    }
    wrtc_native_fifo_clear(fifo);
    *fifo = native;
    status = 1;
done:
    Py_XDECREF(iterator);
    Py_XDECREF(deque);
    Py_XDECREF(collections);
    return status;
}

static int fifo_grow(WrtcNativeFifo *fifo) {
    const size_t capacity = fifo->capacity + fifo->capacity / 2u + 1u;
    PyObject **items = calloc(capacity, sizeof(*items));
    size_t index;
    if (items == NULL) return PyErr_NoMemory(), -1;
    for (index = 0u; index < fifo->size; index++)
        items[index] =
            fifo->items[(fifo->head + index) % fifo->capacity];
    free(fifo->items);
    fifo->items = items;
    fifo->capacity = capacity;
    fifo->head = 0u;
    return 0;
}

int wrtc_native_fifo_append(WrtcNativeFifo *fifo, PyObject *value) {
    if (fifo->mode == WRTC_STORAGE_BOXED) {
        PyObject *result =
            PyObject_CallMethod(fifo->boxed, "append", "O", value);
        if (result == NULL) return -1;
        Py_DECREF(result);
        return 0;
    }
    if (fifo->mode != WRTC_STORAGE_NATIVE) {
        PyErr_SetString(PyExc_AttributeError, "FIFO storage is deleted");
        return -1;
    }
    if (fifo->size == fifo->capacity && fifo_grow(fifo) < 0) return -1;
    fifo->items[(fifo->head + fifo->size) % fifo->capacity] =
        Py_NewRef(value);
    fifo->size++;
    return 0;
}

PyObject *wrtc_native_fifo_popleft(WrtcNativeFifo *fifo) {
    PyObject *value;
    if (fifo->mode == WRTC_STORAGE_BOXED)
        return PyObject_CallMethod(fifo->boxed, "popleft", NULL);
    if (fifo->mode != WRTC_STORAGE_NATIVE || fifo->size == 0u) {
        PyErr_SetString(PyExc_IndexError, "pop from an empty deque");
        return NULL;
    }
    value = fifo->items[fifo->head];
    fifo->items[fifo->head] = NULL;
    fifo->head = (fifo->head + 1u) % fifo->capacity;
    fifo->size--;
    return value;
}

Py_ssize_t wrtc_native_fifo_snapshot(const WrtcNativeFifo *fifo) {
    if (fifo->mode == WRTC_STORAGE_NATIVE)
        return (Py_ssize_t)fifo->size;
    if (fifo->mode == WRTC_STORAGE_BOXED)
        return PyObject_Length(fifo->boxed);
    PyErr_SetString(PyExc_AttributeError, "FIFO storage is deleted");
    return -1;
}

PyObject *wrtc_native_fifo_get(WrtcNativeFifo *fifo,
                               const char *field_name) {
    PyObject *collections, *deque, *items, *value;
    size_t index;
    if (fifo->mode == WRTC_STORAGE_BOXED) return Py_NewRef(fifo->boxed);
    if (fifo->mode != WRTC_STORAGE_NATIVE) {
        (void)missing(field_name);
        return NULL;
    }
    items = PyList_New((Py_ssize_t)fifo->size);
    if (items == NULL) return NULL;
    for (index = 0u; index < fifo->size; index++)
        PyList_SET_ITEM(
            items, (Py_ssize_t)index,
            Py_NewRef(fifo->items[(fifo->head + index) % fifo->capacity]));
    collections = PyImport_ImportModule("collections");
    deque = collections == NULL
                ? NULL : PyObject_GetAttrString(collections, "deque");
    value = deque == NULL ? NULL : PyObject_CallOneArg(deque, items);
    Py_XDECREF(deque);
    Py_XDECREF(collections);
    Py_DECREF(items);
    if (value == NULL) return NULL;
    wrtc_native_fifo_clear(fifo);
    fifo->boxed = Py_NewRef(value);
    fifo->mode = WRTC_STORAGE_BOXED;
    return value;
}

int wrtc_native_fifo_delete(WrtcNativeFifo *fifo, const char *field_name) {
    if (fifo->mode == WRTC_STORAGE_EMPTY) return missing(field_name);
    wrtc_native_fifo_clear(fifo);
    return 0;
}

static void heap_native_clear(WrtcNativeMinHeap *heap) {
    size_t index;
    for (index = 0u; index < heap->size; index++) Py_CLEAR(heap->items[index]);
    free(heap->items);
    heap->items = NULL;
    heap->capacity = heap->size = 0u;
}

void wrtc_native_heap_init(WrtcNativeMinHeap *heap) {
    memset(heap, 0, sizeof(*heap));
}

void wrtc_native_heap_clear(WrtcNativeMinHeap *heap) {
    if (heap->mode == WRTC_STORAGE_BOXED) Py_CLEAR(heap->boxed);
    if (heap->mode == WRTC_STORAGE_NATIVE) heap_native_clear(heap);
    heap->mode = WRTC_STORAGE_EMPTY;
}

int wrtc_native_heap_traverse(WrtcNativeMinHeap *heap, visitproc visit,
                              void *argument) {
    size_t index;
    if (heap->mode == WRTC_STORAGE_BOXED && heap->boxed != NULL)
        return visit(heap->boxed, argument);
    if (heap->mode == WRTC_STORAGE_NATIVE)
        for (index = 0u; index < heap->size; index++) {
            const int status = visit(heap->items[index], argument);
            if (status != 0) return status;
        }
    return 0;
}

int wrtc_native_heap_activate(WrtcNativeMinHeap *heap, size_t capacity) {
    if (heap->mode != WRTC_STORAGE_EMPTY) {
        PyErr_SetString(PyExc_RuntimeError,
                        "heap activation requires empty storage");
        return -1;
    }
    if (capacity == 0u) capacity = 8u;
    heap->items = calloc(capacity, sizeof(*heap->items));
    if (heap->items == NULL) return PyErr_NoMemory(), -1;
    heap->capacity = capacity;
    heap->mode = WRTC_STORAGE_NATIVE;
    return 0;
}

int wrtc_native_heap_set_boxed(WrtcNativeMinHeap *heap, PyObject *value) {
    PyObject *owned = Py_NewRef(value);
    wrtc_native_heap_clear(heap);
    heap->boxed = owned;
    heap->mode = WRTC_STORAGE_BOXED;
    return 0;
}

int wrtc_native_heap_try_adopt(WrtcNativeMinHeap *heap) {
    WrtcNativeMinHeap native;
    Py_ssize_t index, size;
    if (heap->mode != WRTC_STORAGE_BOXED ||
        Py_REFCNT(heap->boxed) != 1 ||
        !PyList_CheckExact(heap->boxed))
        return 0;
    size = PyList_GET_SIZE(heap->boxed);
    wrtc_native_heap_init(&native);
    if (wrtc_native_heap_activate(&native, (size_t)size) < 0)
        return -1;
    for (index = 0; index < size; index++) {
        native.items[(size_t)index] =
            Py_NewRef(PyList_GET_ITEM(heap->boxed, index));
        native.size++;
    }
    wrtc_native_heap_clear(heap);
    *heap = native;
    return 1;
}

static int heap_grow(WrtcNativeMinHeap *heap) {
    const size_t capacity = heap->capacity + heap->capacity / 2u + 1u;
    PyObject **items =
        realloc(heap->items, capacity * sizeof(*items));
    if (items == NULL) return PyErr_NoMemory(), -1;
    heap->items = items;
    heap->capacity = capacity;
    return 0;
}

static int heap_less(PyObject *left, PyObject *right) {
    return PyObject_RichCompareBool(left, right, Py_LT);
}

static int heap_siftdown(WrtcNativeMinHeap *heap, size_t start,
                         size_t position) {
    PyObject *item = Py_NewRef(heap->items[position]);
    while (position > start) {
        const size_t parent_position = (position - 1u) >> 1u;
        PyObject *parent = heap->items[parent_position];
        const int less = heap_less(item, parent);
        if (less < 0) {
            Py_DECREF(item);
            return -1;
        }
        if (!less) break;
        Py_INCREF(parent);
        Py_SETREF(heap->items[position], parent);
        position = parent_position;
    }
    Py_SETREF(heap->items[position], item);
    return 0;
}

static int heap_siftup(WrtcNativeMinHeap *heap, size_t position) {
    const size_t end = heap->size, start = position;
    PyObject *item = Py_NewRef(heap->items[position]);
    size_t child = position * 2u + 1u;
    while (child < end) {
        const size_t right = child + 1u;
        if (right < end) {
            const int left_less =
                heap_less(heap->items[child], heap->items[right]);
            if (left_less < 0) {
                Py_DECREF(item);
                return -1;
            }
            if (!left_less) child = right;
        }
        Py_INCREF(heap->items[child]);
        Py_SETREF(heap->items[position], heap->items[child]);
        position = child;
        child = position * 2u + 1u;
    }
    Py_SETREF(heap->items[position], item);
    return heap_siftdown(heap, start, position);
}

int wrtc_native_heap_push(WrtcNativeMinHeap *heap, PyObject *value) {
    if (heap->mode == WRTC_STORAGE_BOXED) {
        PyObject *module = PyImport_ImportModule("heapq");
        PyObject *result = module == NULL
                               ? NULL : PyObject_CallMethod(
                                             module, "heappush", "OO",
                                             heap->boxed, value);
        Py_XDECREF(module);
        if (result == NULL) return -1;
        Py_DECREF(result);
        return 0;
    }
    if (heap->mode != WRTC_STORAGE_NATIVE) {
        PyErr_SetString(PyExc_AttributeError, "heap storage is deleted");
        return -1;
    }
    if (heap->size == heap->capacity && heap_grow(heap) < 0) return -1;
    heap->items[heap->size] = Py_NewRef(value);
    heap->size++;
    return heap_siftdown(heap, 0u, heap->size - 1u);
}

PyObject *wrtc_native_heap_pop(WrtcNativeMinHeap *heap) {
    PyObject *last, *result;
    if (heap->mode == WRTC_STORAGE_BOXED) {
        PyObject *module = PyImport_ImportModule("heapq");
        result = module == NULL
                     ? NULL : PyObject_CallMethod(
                                   module, "heappop", "O", heap->boxed);
        Py_XDECREF(module);
        return result;
    }
    if (heap->mode != WRTC_STORAGE_NATIVE || heap->size == 0u) {
        PyErr_SetString(PyExc_IndexError, "index out of range");
        return NULL;
    }
    heap->size--;
    last = heap->items[heap->size];
    heap->items[heap->size] = NULL;
    if (heap->size == 0u) return last;
    result = Py_NewRef(heap->items[0]);
    Py_SETREF(heap->items[0], last);
    if (heap_siftup(heap, 0u) < 0) {
        Py_DECREF(result);
        return NULL;
    }
    return result;
}

int wrtc_native_heap_heapify(WrtcNativeMinHeap *heap) {
    size_t position;
    if (heap->mode == WRTC_STORAGE_BOXED) {
        PyObject *module = PyImport_ImportModule("heapq");
        PyObject *result = module == NULL
                               ? NULL : PyObject_CallMethod(
                                             module, "heapify", "O",
                                             heap->boxed);
        Py_XDECREF(module);
        if (result == NULL) return -1;
        Py_DECREF(result);
        return 0;
    }
    if (heap->mode != WRTC_STORAGE_NATIVE) {
        PyErr_SetString(PyExc_AttributeError, "heap storage is deleted");
        return -1;
    }
    position = heap->size >> 1u;
    while (position > 0u)
        if (heap_siftup(heap, --position) < 0) return -1;
    return 0;
}

Py_ssize_t wrtc_native_heap_snapshot(const WrtcNativeMinHeap *heap) {
    if (heap->mode == WRTC_STORAGE_NATIVE)
        return (Py_ssize_t)heap->size;
    if (heap->mode == WRTC_STORAGE_BOXED)
        return PyObject_Length(heap->boxed);
    PyErr_SetString(PyExc_AttributeError, "heap storage is deleted");
    return -1;
}

PyObject *wrtc_native_heap_root(const WrtcNativeMinHeap *heap) {
    if (heap->mode == WRTC_STORAGE_BOXED)
        return PySequence_GetItem(heap->boxed, 0);
    if (heap->mode != WRTC_STORAGE_NATIVE || heap->size == 0u) {
        PyErr_SetString(PyExc_IndexError, "list index out of range");
        return NULL;
    }
    return Py_NewRef(heap->items[0]);
}

PyObject *wrtc_native_heap_get(WrtcNativeMinHeap *heap,
                               const char *field_name) {
    PyObject *value;
    size_t index;
    if (heap->mode == WRTC_STORAGE_BOXED) return Py_NewRef(heap->boxed);
    if (heap->mode != WRTC_STORAGE_NATIVE) {
        (void)missing(field_name);
        return NULL;
    }
    value = PyList_New((Py_ssize_t)heap->size);
    if (value == NULL) return NULL;
    for (index = 0u; index < heap->size; index++)
        PyList_SET_ITEM(value, (Py_ssize_t)index,
                        Py_NewRef(heap->items[index]));
    wrtc_native_heap_clear(heap);
    heap->boxed = Py_NewRef(value);
    heap->mode = WRTC_STORAGE_BOXED;
    return value;
}

int wrtc_native_heap_delete(WrtcNativeMinHeap *heap,
                            const char *field_name) {
    if (heap->mode == WRTC_STORAGE_EMPTY) return missing(field_name);
    wrtc_native_heap_clear(heap);
    return 0;
}
