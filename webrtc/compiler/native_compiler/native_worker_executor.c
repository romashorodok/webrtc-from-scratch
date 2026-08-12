#include "native_worker_executor.h"

#include "native_storage.h"
#include "native_worker_record.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    SLOT_FREE = 0,
    SLOT_QUEUED,
    SLOT_CLAIMED,
    SLOT_CANCELLED,
    SLOT_COMPLETED
} SlotState;

typedef struct {
    WrtcNativeWorkerRecord input;
    WrtcNativeWorkerRecord result;
    WrtcNativeWorkerValue *result_values;
    WrtcNativeWorkerError error;
    _Atomic unsigned state;
    _Atomic uint64_t generation;
} WorkerSlot;

struct WrtcNativeWorkerExecutor {
    WrtcNativeSpsc input;
    WrtcNativeSpsc completion;
    WorkerSlot *slots;
    size_t *free_slots;
    size_t slot_count;
    size_t free_count;
    const WrtcNativeWorkerAbi *input_abi;
    const WrtcNativeWorkerAbi *result_abi;
    WrtcNativeWorkerKernel kernel;
    void *kernel_context;
    WrtcNativeWorkerNotify notify;
    void *notify_context;
    pthread_t thread;
    pthread_mutex_t wait_mutex;
    pthread_cond_t wait_condition;
    _Atomic uint64_t wake_epoch;
    _Atomic uint64_t next_sequence;
    _Atomic unsigned completion_notified;
    _Atomic unsigned started;
    _Atomic unsigned stopped;
    unsigned joined;
    unsigned input_initialized;
    unsigned completion_initialized;
    unsigned mutex_initialized;
    unsigned condition_initialized;
};

static int abi_valid(const WrtcNativeWorkerAbi *abi, int result) {
    size_t index;
    if (abi == NULL || abi->abi == NULL || abi->fields == NULL ||
        abi->field_count == 0u)
        return 0;
    for (index = 0u; index < abi->field_count; index++) {
        const WrtcNativeWorkerAbiField *field = &abi->fields[index];
        if (field->name == NULL || field->kind < WRTC_WORKER_ABI_UINT ||
            field->kind > WRTC_WORKER_ABI_READONLY_BYTES)
            return 0;
        if (result && field->kind == WRTC_WORKER_ABI_READONLY_BYTES)
            return 0;
    }
    return 1;
}

static void wake_worker(WrtcNativeWorkerExecutor *executor) {
    (void)pthread_mutex_lock(&executor->wait_mutex);
    (void)atomic_fetch_add_explicit(&executor->wake_epoch, UINT64_C(1),
                                    memory_order_release);
    (void)pthread_cond_signal(&executor->wait_condition);
    (void)pthread_mutex_unlock(&executor->wait_mutex);
}

static void wait_worker(WrtcNativeWorkerExecutor *executor,
                        int waiting_for_completion_space) {
    uint64_t observed = atomic_load_explicit(&executor->wake_epoch,
                                             memory_order_acquire);
    (void)pthread_mutex_lock(&executor->wait_mutex);
    if (atomic_load_explicit(&executor->wake_epoch, memory_order_acquire) ==
            observed &&
        (waiting_for_completion_space
             ? wrtc_native_spsc_snapshot(&executor->completion) >=
                   executor->completion.capacity
             : (wrtc_native_spsc_snapshot(&executor->input) == 0u &&
                wrtc_native_spsc_is_open(&executor->input))))
        (void)pthread_cond_wait(&executor->wait_condition,
                                &executor->wait_mutex);
    (void)pthread_mutex_unlock(&executor->wait_mutex);
}

static void notify_completion(WrtcNativeWorkerExecutor *executor) {
    unsigned expected = 0u;
    if (atomic_compare_exchange_strong_explicit(
            &executor->completion_notified, &expected, 1u,
            memory_order_acq_rel, memory_order_acquire) &&
        executor->notify != NULL)
        executor->notify(executor->notify_context);
}

static void *worker_main(void *opaque) {
    WrtcNativeWorkerExecutor *executor = opaque;
    WorkerSlot *pending = NULL;
    for (;;) {
        if (pending != NULL) {
            WrtcNativeSpscStatus published =
                wrtc_native_spsc_try_push(&executor->completion, pending);
            if (published == WRTC_SPSC_OK) {
                notify_completion(executor);
                pending = NULL;
                continue;
            }
            if (published == WRTC_SPSC_FULL) {
                wait_worker(executor, 1);
                continue;
            }
            break;
        }
        {
            void *raw = NULL;
            WrtcNativeSpscStatus received =
                wrtc_native_spsc_try_pop(&executor->input, &raw);
            if (received == WRTC_SPSC_OK) {
                WorkerSlot *slot = raw;
                unsigned expected = SLOT_QUEUED;
                memset(&slot->error, 0, sizeof(slot->error));
                slot->error.sequence = atomic_fetch_add_explicit(
                    &executor->next_sequence, UINT64_C(1),
                    memory_order_relaxed);
                if (!atomic_compare_exchange_strong_explicit(
                        &slot->state, &expected, SLOT_CLAIMED,
                        memory_order_acq_rel, memory_order_acquire)) {
                    if (expected == SLOT_CANCELLED)
                        slot->error.code = WRTC_WORKER_ERROR_CANCELLED;
                    else {
                        slot->error.code = WRTC_WORKER_ERROR_PROCESSOR;
                        slot->error.processor_status = -1;
                    }
                } else {
                    int status = executor->kernel(
                        &slot->input, &slot->result, &slot->error,
                        executor->kernel_context);
                    if (status != 0 && slot->error.code ==
                                           WRTC_WORKER_ERROR_NONE) {
                        slot->error.code = WRTC_WORKER_ERROR_PROCESSOR;
                        slot->error.processor_status = status;
                    }
                }
                atomic_store_explicit(&slot->state, SLOT_COMPLETED,
                                      memory_order_release);
                pending = slot;
                continue;
            }
            if (!wrtc_native_spsc_is_open(&executor->input) &&
                wrtc_native_spsc_snapshot(&executor->input) == 0u)
                break;
            wait_worker(executor, 0);
        }
    }
    atomic_store_explicit(&executor->stopped, 1u, memory_order_release);
    wake_worker(executor);
    return NULL;
}

static void reset_result(WorkerSlot *slot) {
    size_t index;
    for (index = 0u; index < slot->result.value_count; index++) {
        WrtcNativeWorkerAbiKind kind = slot->result.values[index].kind;
        memset(&slot->result.values[index].as, 0,
               sizeof(slot->result.values[index].as));
        slot->result.values[index].kind = kind;
    }
}

int wrtc_native_worker_executor_create(
    WrtcNativeWorkerExecutor **out, size_t input_capacity,
    size_t completion_capacity, const WrtcNativeWorkerAbi *input_abi,
    const WrtcNativeWorkerAbi *result_abi, WrtcNativeWorkerKernel kernel,
    void *kernel_context, WrtcNativeWorkerNotify notify,
    void *notify_context) {
    WrtcNativeWorkerExecutor *executor;
    size_t index, field;
    if (out == NULL || input_capacity == 0u || completion_capacity == 0u ||
        input_capacity > SIZE_MAX - completion_capacity ||
        !abi_valid(input_abi, 0) || !abi_valid(result_abi, 1) ||
        kernel == NULL)
        return -1;
    *out = NULL;
    executor = calloc(1u, sizeof(*executor));
    if (executor == NULL) return -1;
    executor->slot_count = input_capacity + completion_capacity;
    if (executor->slot_count > SIZE_MAX / sizeof(*executor->slots) ||
        executor->slot_count > SIZE_MAX / sizeof(*executor->free_slots))
        goto error;
    executor->slots = calloc(executor->slot_count, sizeof(*executor->slots));
    executor->free_slots = malloc(executor->slot_count *
                                  sizeof(*executor->free_slots));
    if (executor->slots == NULL || executor->free_slots == NULL) goto error;
    if (wrtc_native_spsc_init(&executor->input, input_capacity) < 0)
        goto error;
    executor->input_initialized = 1u;
    if (wrtc_native_spsc_init(&executor->completion,
                              completion_capacity) < 0)
        goto error;
    executor->completion_initialized = 1u;
    executor->input_abi = input_abi;
    executor->result_abi = result_abi;
    executor->kernel = kernel;
    executor->kernel_context = kernel_context;
    executor->notify = notify;
    executor->notify_context = notify_context;
    for (index = 0u; index < executor->slot_count; index++) {
        WorkerSlot *slot = &executor->slots[index];
        slot->result_values = calloc(result_abi->field_count,
                                     sizeof(*slot->result_values));
        if (slot->result_values == NULL) goto error;
        slot->result.abi = result_abi;
        slot->result.values = slot->result_values;
        slot->result.value_count = result_abi->field_count;
        for (field = 0u; field < result_abi->field_count; field++)
            slot->result.values[field].kind = result_abi->fields[field].kind;
        atomic_init(&slot->state, SLOT_FREE);
        atomic_init(&slot->generation, UINT64_C(1));
        executor->free_slots[index] = executor->slot_count - index - 1u;
    }
    executor->free_count = executor->slot_count;
    if (pthread_mutex_init(&executor->wait_mutex, NULL) != 0) goto error;
    executor->mutex_initialized = 1u;
    if (pthread_cond_init(&executor->wait_condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&executor->wait_mutex);
        executor->mutex_initialized = 0u;
        goto error;
    }
    executor->condition_initialized = 1u;
    atomic_init(&executor->wake_epoch, 0u);
    atomic_init(&executor->next_sequence, 0u);
    atomic_init(&executor->completion_notified, 0u);
    atomic_init(&executor->started, 0u);
    atomic_init(&executor->stopped, 0u);
    *out = executor;
    return 0;
error:
    if (executor->slots != NULL)
        for (index = 0u; index < executor->slot_count; index++)
            free(executor->slots[index].result_values);
    if (executor->input_initialized)
        wrtc_native_spsc_clear(&executor->input, NULL, NULL);
    if (executor->completion_initialized)
        wrtc_native_spsc_clear(&executor->completion, NULL, NULL);
    free(executor->free_slots);
    free(executor->slots);
    free(executor);
    return -1;
}

int wrtc_native_worker_executor_start(WrtcNativeWorkerExecutor *executor) {
    unsigned expected = 0u;
    if (executor == NULL ||
        !atomic_compare_exchange_strong_explicit(
            &executor->started, &expected, 1u, memory_order_acq_rel,
            memory_order_acquire))
        return -1;
    if (pthread_create(&executor->thread, NULL, worker_main, executor) != 0) {
        atomic_store_explicit(&executor->started, 0u, memory_order_release);
        return -1;
    }
    return 0;
}

WrtcNativeWorkerExecutorStatus wrtc_native_worker_executor_try_submit(
    WrtcNativeWorkerExecutor *executor, WrtcNativeWorkerRecord *input,
    WrtcNativeWorkerTicket *ticket) {
    WorkerSlot *slot;
    size_t slot_index;
    WrtcNativeSpscStatus status;
    if (executor == NULL || input == NULL || input->abi != executor->input_abi ||
        input->values == NULL ||
        !atomic_load_explicit(&executor->started, memory_order_acquire))
        return WRTC_WORKER_EXECUTOR_INVALID;
    if (!wrtc_native_spsc_is_open(&executor->input))
        return WRTC_WORKER_EXECUTOR_CLOSED;
    if (executor->free_count == 0u) return WRTC_WORKER_EXECUTOR_FULL;
    slot_index = executor->free_slots[--executor->free_count];
    slot = &executor->slots[slot_index];
    wrtc_native_worker_record_move(&slot->input, input);
    atomic_store_explicit(&slot->state, SLOT_QUEUED, memory_order_release);
    status = wrtc_native_spsc_try_push(&executor->input, slot);
    if (status != WRTC_SPSC_OK) {
        wrtc_native_worker_record_move(input, &slot->input);
        atomic_store_explicit(&slot->state, SLOT_FREE, memory_order_release);
        executor->free_slots[executor->free_count++] = slot_index;
        return status == WRTC_SPSC_CLOSED ? WRTC_WORKER_EXECUTOR_CLOSED
                                          : WRTC_WORKER_EXECUTOR_FULL;
    }
    if (ticket != NULL) {
        ticket->executor = executor;
        ticket->slot = slot_index;
        ticket->generation = atomic_load_explicit(
            &slot->generation, memory_order_acquire);
    }
    wake_worker(executor);
    return WRTC_WORKER_EXECUTOR_OK;
}

int wrtc_native_worker_executor_cancel(WrtcNativeWorkerTicket ticket) {
    WorkerSlot *slot;
    unsigned expected = SLOT_QUEUED;
    if (ticket.executor == NULL || ticket.slot >= ticket.executor->slot_count)
        return 0;
    slot = &ticket.executor->slots[ticket.slot];
    if (atomic_load_explicit(&slot->generation, memory_order_acquire) !=
        ticket.generation)
        return 0;
    return atomic_compare_exchange_strong_explicit(
        &slot->state, &expected, SLOT_CANCELLED, memory_order_acq_rel,
        memory_order_acquire);
}

WrtcNativeWorkerExecutorStatus wrtc_native_worker_executor_try_consume(
    WrtcNativeWorkerExecutor *executor, WrtcNativeWorkerConsume consume,
    void *context) {
    void *raw = NULL;
    WorkerSlot *slot;
    size_t index;
    int consumed = 0;
    if (executor == NULL) return WRTC_WORKER_EXECUTOR_INVALID;
    if (wrtc_native_spsc_try_pop(&executor->completion, &raw) != WRTC_SPSC_OK)
        return WRTC_WORKER_EXECUTOR_EMPTY;
    slot = raw;
    if (consume != NULL) consumed = consume(&slot->result, &slot->error, context);
    wrtc_native_worker_record_release(&slot->input);
    reset_result(slot);
    memset(&slot->error, 0, sizeof(slot->error));
    atomic_store_explicit(&slot->state, SLOT_FREE, memory_order_release);
    (void)atomic_fetch_add_explicit(&slot->generation, UINT64_C(1),
                                    memory_order_release);
    index = (size_t)(slot - executor->slots);
    executor->free_slots[executor->free_count++] = index;
    wake_worker(executor);
    return consumed == 0 ? WRTC_WORKER_EXECUTOR_OK
                         : WRTC_WORKER_EXECUTOR_INVALID;
}

int wrtc_native_worker_executor_consumer_rearm(
    WrtcNativeWorkerExecutor *executor) {
    unsigned expected = 0u;
    if (executor == NULL) return 0;
    atomic_store_explicit(&executor->completion_notified, 0u,
                          memory_order_release);
    if (wrtc_native_spsc_snapshot(&executor->completion) == 0u) return 0;
    if (atomic_compare_exchange_strong_explicit(
            &executor->completion_notified, &expected, 1u,
            memory_order_acq_rel, memory_order_acquire)) {
        if (executor->notify != NULL)
            executor->notify(executor->notify_context);
        return 1;
    }
    return 0;
}

size_t wrtc_native_worker_executor_completion_count(
    const WrtcNativeWorkerExecutor *executor) {
    return executor == NULL ? 0u :
        wrtc_native_spsc_snapshot(&executor->completion);
}

void wrtc_native_worker_executor_close_admission(
    WrtcNativeWorkerExecutor *executor) {
    if (executor == NULL) return;
    wrtc_native_spsc_close(&executor->input);
    wake_worker(executor);
}

int wrtc_native_worker_executor_is_stopped(
    const WrtcNativeWorkerExecutor *executor) {
    return executor != NULL &&
           atomic_load_explicit(&executor->stopped, memory_order_acquire);
}

int wrtc_native_worker_executor_shutdown(
    WrtcNativeWorkerExecutor *executor, WrtcNativeWorkerConsume consume,
    void *context) {
    if (executor == NULL) return -1;
    if (!atomic_load_explicit(&executor->started, memory_order_acquire)) {
        wrtc_native_worker_executor_close_admission(executor);
        wrtc_native_spsc_close(&executor->completion);
        atomic_store_explicit(&executor->stopped, 1u, memory_order_release);
        return 0;
    }
    wrtc_native_worker_executor_close_admission(executor);
    while (!wrtc_native_worker_executor_is_stopped(executor) ||
           wrtc_native_spsc_snapshot(&executor->completion) != 0u) {
        WrtcNativeWorkerExecutorStatus status =
            wrtc_native_worker_executor_try_consume(executor, consume, context);
        if (status == WRTC_WORKER_EXECUTOR_EMPTY) sched_yield();
        else if (status != WRTC_WORKER_EXECUTOR_OK) return -1;
    }
    if (atomic_load_explicit(&executor->started, memory_order_acquire) &&
        !executor->joined) {
        if (pthread_join(executor->thread, NULL) != 0) return -1;
        executor->joined = 1u;
    }
    wrtc_native_spsc_close(&executor->completion);
    return 0;
}

void wrtc_native_worker_executor_destroy(
    WrtcNativeWorkerExecutor *executor) {
    size_t index;
    if (executor == NULL) return;
    if (atomic_load_explicit(&executor->started, memory_order_acquire) &&
        !executor->joined)
        (void)wrtc_native_worker_executor_shutdown(executor, NULL, NULL);
    for (index = 0u; index < executor->slot_count; index++) {
        wrtc_native_worker_record_release(&executor->slots[index].input);
        free(executor->slots[index].result_values);
    }
    if (executor->input_initialized)
        wrtc_native_spsc_clear(&executor->input, NULL, NULL);
    if (executor->completion_initialized)
        wrtc_native_spsc_clear(&executor->completion, NULL, NULL);
    if (executor->condition_initialized)
        (void)pthread_cond_destroy(&executor->wait_condition);
    if (executor->mutex_initialized)
        (void)pthread_mutex_destroy(&executor->wait_mutex);
    free(executor->free_slots);
    free(executor->slots);
    free(executor);
}
