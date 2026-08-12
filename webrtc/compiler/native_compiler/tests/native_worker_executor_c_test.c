#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "native_worker_executor.h"
#include "native_worker_record.h"

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #condition); return 1; } } while (0)

static const WrtcNativeWorkerAbiField input_fields[] = {
    {"shard", WRTC_WORKER_ABI_UINT, 64u},
    {"value", WRTC_WORKER_ABI_UINT, 64u},
};
static const WrtcNativeWorkerAbi input_abi = {
    "test.executor.input.v1", input_fields, 2u
};
static const WrtcNativeWorkerAbiField result_fields[] = {
    {"shard", WRTC_WORKER_ABI_UINT, 64u},
    {"value", WRTC_WORKER_ABI_UINT, 64u},
};
static const WrtcNativeWorkerAbi result_abi = {
    "test.executor.result.v1", result_fields, 2u
};

typedef struct {
    _Atomic unsigned blocked;
    _Atomic unsigned entered;
    _Atomic size_t notifications;
} KernelContext;

typedef struct {
    uint64_t *values;
    WrtcNativeWorkerErrorCode *errors;
    size_t capacity;
    size_t count;
    int failed;
} Results;

static WrtcNativeWorkerRecord make_input(uint64_t shard, uint64_t value) {
    WrtcNativeWorkerRecord record = {0};
    record.abi = &input_abi;
    record.value_count = 2u;
    record.values = calloc(2u, sizeof(*record.values));
    if (record.values != NULL) {
        record.values[0].kind = WRTC_WORKER_ABI_UINT;
        record.values[0].as.uint_value = shard;
        record.values[1].kind = WRTC_WORKER_ABI_UINT;
        record.values[1].as.uint_value = value;
    }
    return record;
}

static int kernel(const WrtcNativeWorkerRecord *input,
                  WrtcNativeWorkerRecord *output,
                  WrtcNativeWorkerError *error, void *opaque) {
    KernelContext *context = opaque;
    uint64_t value = input->values[1].as.uint_value;
    atomic_store_explicit(&context->entered, 1u, memory_order_release);
    while (atomic_load_explicit(&context->blocked, memory_order_acquire)) {
    }
    if (input->values[0].as.uint_value == UINT64_C(1) &&
        value == UINT64_C(13)) {
        error->code = WRTC_WORKER_ERROR_PROCESSOR;
        error->processor_status = 713;
        return 713;
    }
    output->values[0].as.uint_value = input->values[0].as.uint_value;
    output->values[1].as.uint_value = value * UINT64_C(2);
    return 0;
}

static void notify(void *opaque) {
    KernelContext *context = opaque;
    (void)atomic_fetch_add_explicit(&context->notifications, 1u,
                                    memory_order_relaxed);
}

static int consume(const WrtcNativeWorkerRecord *result,
                   const WrtcNativeWorkerError *error, void *opaque) {
    Results *results = opaque;
    if (results->count >= results->capacity) {
        results->failed = 1;
        return -1;
    }
    results->values[results->count] = result->values[1].as.uint_value;
    results->errors[results->count] = error->code;
    results->count++;
    return 0;
}

static int wait_for_count(WrtcNativeWorkerExecutor *executor,
                          Results *results, size_t wanted) {
    struct timespec deadline = {0};
    size_t observed = results->count;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_sec += 5;
    while (results->count < wanted) {
        struct timespec now = {0};
        WrtcNativeWorkerExecutorStatus status =
            wrtc_native_worker_executor_try_consume(
                executor, consume, results);
        if (status != WRTC_WORKER_EXECUTOR_OK &&
            status != WRTC_WORKER_EXECUTOR_EMPTY)
            return -1;
        if (results->count != observed) {
            observed = results->count;
            CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
            deadline.tv_sec += 5;
        } else {
            CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec &&
                 now.tv_nsec >= deadline.tv_nsec)) {
                (void)fprintf(stderr,
                              "worker progress stalled: consumed=%zu wanted=%zu\n",
                              results->count, wanted);
                return -1;
            }
            sched_yield();
        }
    }
    return 0;
}

static int wait_for_kernel_entry(const KernelContext *context) {
    struct timespec deadline = {0};
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) return -1;
    deadline.tv_sec += 5;
    while (!atomic_load_explicit(&context->entered, memory_order_acquire)) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec &&
             now.tv_nsec >= deadline.tv_nsec))
            return -1;
        sched_yield();
    }
    return 0;
}

static int capacity_close_cancel_test(void) {
    WrtcNativeWorkerExecutor *executor = NULL;
    KernelContext context = {0};
    uint64_t values[16] = {0};
    WrtcNativeWorkerErrorCode errors[16] = {0};
    Results results = {values, errors, 16u, 0u, 0};
    WrtcNativeWorkerRecord first = make_input(7u, 1u);
    WrtcNativeWorkerRecord second = make_input(7u, 2u);
    WrtcNativeWorkerRecord third = make_input(7u, 3u);
    WrtcNativeWorkerTicket ticket = {0};
    CHECK(first.values != NULL && second.values != NULL && third.values != NULL);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 1u, 1u, &input_abi, &result_abi, kernel, &context,
              notify, &context) == 0);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &first, NULL) ==
          WRTC_WORKER_EXECUTOR_INVALID);
    CHECK(wrtc_native_worker_executor_start(executor) == 0);
    CHECK(wrtc_native_worker_executor_start(executor) < 0);
    atomic_store_explicit(&context.blocked, 1u, memory_order_release);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &first, NULL) ==
          WRTC_WORKER_EXECUTOR_OK);
    CHECK(wait_for_kernel_entry(&context) == 0);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &second, &ticket) ==
          WRTC_WORKER_EXECUTOR_OK);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &third, NULL) ==
          WRTC_WORKER_EXECUTOR_FULL);
    CHECK(wrtc_native_worker_executor_cancel(ticket));
    atomic_store_explicit(&context.blocked, 0u, memory_order_release);
    CHECK(wait_for_count(executor, &results, 2u) == 0);
    CHECK(values[0] == 2u && errors[0] == WRTC_WORKER_ERROR_NONE);
    CHECK(errors[1] == WRTC_WORKER_ERROR_CANCELLED);
    CHECK(atomic_load_explicit(&context.notifications,
                               memory_order_relaxed) >= 1u);
    (void)wrtc_native_worker_executor_consumer_rearm(executor);
    wrtc_native_worker_executor_close_admission(executor);
    wrtc_native_worker_executor_close_admission(executor);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &third, NULL) ==
          WRTC_WORKER_EXECUTOR_CLOSED);
    CHECK(wrtc_native_worker_executor_shutdown(executor, consume, &results) == 0);
    CHECK(wrtc_native_worker_executor_shutdown(executor, consume, &results) == 0);
    wrtc_native_worker_executor_destroy(executor);
    wrtc_native_worker_record_release(&third);
    CHECK(!results.failed);
    return 0;
}

static int stress_and_error_test(size_t count) {
    WrtcNativeWorkerExecutor *executor = NULL;
    KernelContext context = {0};
    uint64_t *values = calloc(count + 1u, sizeof(*values));
    WrtcNativeWorkerErrorCode *errors =
        calloc(count + 1u, sizeof(*errors));
    Results results = {values, errors, count + 1u, 0u, 0};
    size_t submitted = 0u;
    size_t observed_progress = 0u;
    struct timespec progress_deadline = {0};
    CHECK(values != NULL && errors != NULL);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 31u, 31u, &input_abi, &result_abi, kernel, &context,
              notify, &context) == 0);
    CHECK(wrtc_native_worker_executor_start(executor) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &progress_deadline) == 0);
    progress_deadline.tv_sec += 5;
    while (submitted < count) {
        WrtcNativeWorkerRecord input = make_input(4u, submitted + 1u);
        WrtcNativeWorkerExecutorStatus status;
        CHECK(input.values != NULL);
        do {
            struct timespec now = {0};
            status = wrtc_native_worker_executor_try_submit(
                executor, &input, NULL);
            while (wrtc_native_worker_executor_try_consume(
                       executor, consume, &results) ==
                   WRTC_WORKER_EXECUTOR_OK) {
            }
            if (submitted + results.count != observed_progress) {
                observed_progress = submitted + results.count;
                CHECK(clock_gettime(CLOCK_MONOTONIC,
                                    &progress_deadline) == 0);
                progress_deadline.tv_sec += 5;
            } else if (status == WRTC_WORKER_EXECUTOR_FULL) {
                CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
                if (now.tv_sec > progress_deadline.tv_sec ||
                    (now.tv_sec == progress_deadline.tv_sec &&
                     now.tv_nsec >= progress_deadline.tv_nsec)) {
                    (void)fprintf(stderr,
                                  "worker stress stalled: submitted=%zu consumed=%zu target=%zu\n",
                                  submitted, results.count, count);
                    wrtc_native_worker_record_release(&input);
                    return 1;
                }
                sched_yield();
            }
        } while (status == WRTC_WORKER_EXECUTOR_FULL);
        CHECK(status == WRTC_WORKER_EXECUTOR_OK);
        submitted++;
    }
    CHECK(wrtc_native_worker_executor_shutdown(executor, consume, &results) == 0);
    CHECK(results.count == count && !results.failed);
    for (submitted = 0u; submitted < count; submitted++) {
        if (values[submitted] != (submitted + 1u) * 2u ||
            errors[submitted] != WRTC_WORKER_ERROR_NONE)
            (void)fprintf(stderr,
                          "mismatch at %zu: value=%llu error=%d\n",
                          submitted,
                          (unsigned long long)values[submitted],
                          (int)errors[submitted]);
        CHECK(values[submitted] == (submitted + 1u) * 2u &&
              errors[submitted] == WRTC_WORKER_ERROR_NONE);
    }
    wrtc_native_worker_executor_destroy(executor);
    free(errors);
    free(values);
    return 0;
}

static int typed_error_test(void) {
    WrtcNativeWorkerExecutor *executor = NULL;
    KernelContext context = {0};
    uint64_t value = 0u;
    WrtcNativeWorkerErrorCode error = WRTC_WORKER_ERROR_NONE;
    Results results = {&value, &error, 1u, 0u, 0};
    WrtcNativeWorkerRecord input = make_input(1u, 13u);
    CHECK(input.values != NULL);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 1u, 1u, &input_abi, &result_abi, kernel, &context,
              NULL, NULL) == 0);
    CHECK(wrtc_native_worker_executor_start(executor) == 0);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &input, NULL) ==
          WRTC_WORKER_EXECUTOR_OK);
    CHECK(wrtc_native_worker_executor_shutdown(executor, consume, &results) == 0);
    CHECK(results.count == 1u && error == WRTC_WORKER_ERROR_PROCESSOR);
    wrtc_native_worker_executor_destroy(executor);
    return 0;
}

typedef struct {
    uint64_t checksum;
    size_t count;
} ByteResult;

static int bytes_kernel(const WrtcNativeWorkerRecord *input,
                        WrtcNativeWorkerRecord *output,
                        WrtcNativeWorkerError *error, void *context) {
    size_t index;
    uint64_t checksum = input->values[0].as.uint_value;
    (void)error;
    (void)context;
    for (index = 0u;
         index < input->values[1].as.bytes_value.size; index++)
        checksum += input->values[1].as.bytes_value.data[index];
    output->values[0].as.uint_value = checksum;
    return 0;
}

static int consume_bytes(const WrtcNativeWorkerRecord *result,
                         const WrtcNativeWorkerError *error, void *opaque) {
    ByteResult *captured = opaque;
    if (error->code != WRTC_WORKER_ERROR_NONE) return -1;
    captured->checksum = result->values[0].as.uint_value;
    captured->count++;
    return 0;
}

static int retained_bytes_lifecycle_test(void) {
    static const WrtcNativeWorkerAbiField byte_fields[] = {
        {"sequence", WRTC_WORKER_ABI_UINT, 16u},
        {"payload", WRTC_WORKER_ABI_READONLY_BYTES, 0u},
    };
    static const WrtcNativeWorkerAbi byte_abi = {
        "test.executor.bytes.v1", byte_fields, 2u
    };
    static const WrtcNativeWorkerAbiField checksum_fields[] = {
        {"checksum", WRTC_WORKER_ABI_UINT, 64u},
    };
    static const WrtcNativeWorkerAbi checksum_abi = {
        "test.executor.checksum.v1", checksum_fields, 1u
    };
    WrtcNativeWorkerExecutor *executor = NULL;
    WrtcNativeWorkerRecord input = {0};
    PyObject *globals = NULL, *result = NULL, *type = NULL, *value = NULL;
    PyObject *owner = NULL;
    Py_ssize_t owner_refs;
    ByteResult captured = {0};
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
        "value = Packet(5, b'abc')\n",
        Py_file_input, globals, globals);
    CHECK(result != NULL);
    Py_CLEAR(result);
    type = PyDict_GetItemString(globals, "Packet");
    value = PyDict_GetItemString(globals, "value");
    CHECK(type != NULL && value != NULL);
    owner = PyObject_GetAttrString(value, "payload");
    CHECK(owner != NULL);
    owner_refs = Py_REFCNT(owner);
    CHECK(wrtc_native_worker_record_pack(
              value, (PyTypeObject *)type, &byte_abi, &input) == 0);
    CHECK(Py_REFCNT(owner) == owner_refs + 1);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 1u, 1u, &byte_abi, &checksum_abi,
              bytes_kernel, NULL, NULL, NULL) == 0);
    CHECK(wrtc_native_worker_executor_start(executor) == 0);
    CHECK(wrtc_native_worker_executor_try_submit(executor, &input, NULL) ==
          WRTC_WORKER_EXECUTOR_OK);
    CHECK(wrtc_native_worker_executor_shutdown(
              executor, consume_bytes, &captured) == 0);
    CHECK(captured.count == 1u &&
          captured.checksum == UINT64_C(5) + (uint64_t)'a' +
                                   (uint64_t)'b' + (uint64_t)'c');
    CHECK(Py_REFCNT(owner) == owner_refs);
    wrtc_native_worker_executor_destroy(executor);
    Py_CLEAR(owner);
    Py_CLEAR(globals);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}

static int stress_count(size_t *count) {
    static const size_t default_count = 2048u;
    const char *configured = getenv("WRTC_WORKER_EXECUTOR_STRESS_COUNT");
    char *end = NULL;
    unsigned long long parsed;
    if (configured == NULL || configured[0] == '\0') {
        *count = default_count;
        return 0;
    }
    parsed = strtoull(configured, &end, 10);
    if (end == configured || *end != '\0' || parsed < 64u ||
        parsed > (unsigned long long)(SIZE_MAX - 1u))
        return -1;
    *count = (size_t)parsed;
    return 0;
}

int main(void) {
    WrtcNativeWorkerExecutor *executor = NULL;
    size_t count = 0u;
    static const WrtcNativeWorkerAbiField bad_fields[] = {
        {"payload", WRTC_WORKER_ABI_READONLY_BYTES, 0u}
    };
    static const WrtcNativeWorkerAbi bad_result = {
        "test.bad.result.v1", bad_fields, 1u
    };
    CHECK(stress_count(&count) == 0);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 0u, 1u, &input_abi, &result_abi, kernel, NULL,
              NULL, NULL) < 0 && executor == NULL);
    CHECK(wrtc_native_worker_executor_create(
              &executor, 1u, 1u, &input_abi, &bad_result, kernel, NULL,
              NULL, NULL) < 0 && executor == NULL);
    CHECK(capacity_close_cancel_test() == 0);
    CHECK(typed_error_test() == 0);
    CHECK(stress_and_error_test(count) == 0);
    CHECK(retained_bytes_lifecycle_test() == 0);
    return 0;
}
