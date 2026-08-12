#ifndef WRTC_NATIVE_WORKER_EXECUTOR_H
#define WRTC_NATIVE_WORKER_EXECUTOR_H

#include <stddef.h>
#include <stdint.h>

#include "native_worker_abi.h"

typedef struct WrtcNativeWorkerExecutor WrtcNativeWorkerExecutor;

typedef enum {
    WRTC_WORKER_ERROR_NONE = 0,
    WRTC_WORKER_ERROR_CANCELLED,
    WRTC_WORKER_ERROR_PROCESSOR,
    WRTC_WORKER_ERROR_SHUTDOWN
} WrtcNativeWorkerErrorCode;

typedef struct {
    WrtcNativeWorkerErrorCode code;
    int processor_status;
    uint64_t sequence;
} WrtcNativeWorkerError;

typedef int (*WrtcNativeWorkerKernel)(
    const WrtcNativeWorkerRecord *input,
    WrtcNativeWorkerRecord *output,
    WrtcNativeWorkerError *error,
    void *context);

/* This hook is a native notification only.  It must not call the Python API. */
typedef void (*WrtcNativeWorkerNotify)(void *context);

typedef int (*WrtcNativeWorkerConsume)(
    const WrtcNativeWorkerRecord *result,
    const WrtcNativeWorkerError *error,
    void *context);

typedef enum {
    WRTC_WORKER_EXECUTOR_OK = 0,
    WRTC_WORKER_EXECUTOR_EMPTY,
    WRTC_WORKER_EXECUTOR_FULL,
    WRTC_WORKER_EXECUTOR_CLOSED,
    WRTC_WORKER_EXECUTOR_INVALID
} WrtcNativeWorkerExecutorStatus;

typedef struct {
    WrtcNativeWorkerExecutor *executor;
    size_t slot;
    uint64_t generation;
} WrtcNativeWorkerTicket;

int wrtc_native_worker_executor_create(
    WrtcNativeWorkerExecutor **out,
    size_t input_capacity,
    size_t completion_capacity,
    const WrtcNativeWorkerAbi *input_abi,
    const WrtcNativeWorkerAbi *result_abi,
    WrtcNativeWorkerKernel kernel,
    void *kernel_context,
    WrtcNativeWorkerNotify notify,
    void *notify_context);

int wrtc_native_worker_executor_start(WrtcNativeWorkerExecutor *executor);

/* On OK ownership of input moves into the executor.  Otherwise it is retained. */
WrtcNativeWorkerExecutorStatus wrtc_native_worker_executor_try_submit(
    WrtcNativeWorkerExecutor *executor,
    WrtcNativeWorkerRecord *input,
    WrtcNativeWorkerTicket *ticket);

/* Cancellation wins only while the job remains queued and unclaimed. */
int wrtc_native_worker_executor_cancel(WrtcNativeWorkerTicket ticket);

/* Reactor-only.  The callback's result view is valid only for this call. */
WrtcNativeWorkerExecutorStatus wrtc_native_worker_executor_try_consume(
    WrtcNativeWorkerExecutor *executor,
    WrtcNativeWorkerConsume consume,
    void *context);

/* Reactor-side reset/empty/CAS rearm for coalesced completion notification. */
int wrtc_native_worker_executor_consumer_rearm(
    WrtcNativeWorkerExecutor *executor);
size_t wrtc_native_worker_executor_completion_count(
    const WrtcNativeWorkerExecutor *executor);

void wrtc_native_worker_executor_close_admission(
    WrtcNativeWorkerExecutor *executor);
int wrtc_native_worker_executor_is_stopped(
    const WrtcNativeWorkerExecutor *executor);

/* Cold lifecycle boundary.  close/drain/join is idempotent. */
int wrtc_native_worker_executor_shutdown(
    WrtcNativeWorkerExecutor *executor,
    WrtcNativeWorkerConsume consume,
    void *context);
void wrtc_native_worker_executor_destroy(
    WrtcNativeWorkerExecutor *executor);

#endif
