#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "native_storage.h"

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

enum { THREAD_COUNT = 4, INCREMENTS = 10000 };

typedef struct {
    WrtcNativeAtomicUint32 *slot;
    int failed;
} Worker;

static void *increment(void *argument) {
    Worker *worker = argument;
    int index;
    for (index = 0; index < INCREMENTS; index++) {
        for (;;) {
            uint_least32_t expected, previous;
            int changed;
            if (wrtc_native_atomic_uint32_load(
                    worker->slot, &expected) < 0 ||
                wrtc_native_atomic_uint32_compare_exchange(
                    worker->slot, expected, expected + 1u, &previous,
                    &changed) < 0) {
                worker->failed = 1;
                return NULL;
            }
            if (changed) break;
            if (previous == expected) {
                worker->failed = 1;
                return NULL;
            }
        }
    }
    return NULL;
}

int main(void) {
    WrtcNativeAtomicUint32 slot;
    uint_least32_t previous, value;
    int changed;
    pthread_t threads[THREAD_COUNT];
    Worker workers[THREAD_COUNT];
    int index;

    Py_Initialize();
    wrtc_native_atomic_uint32_init(&slot);
    CHECK(wrtc_native_atomic_uint32_set(&slot, 7u) == 0);
    CHECK(wrtc_native_atomic_uint32_compare_exchange(
              &slot, 7u, 9u, &previous, &changed) == 0);
    CHECK(previous == 7u && changed);
    CHECK(wrtc_native_atomic_uint32_compare_exchange(
              &slot, 7u, 11u, &previous, &changed) == 0);
    CHECK(previous == 9u && !changed);
    CHECK(wrtc_native_atomic_uint32_load(&slot, &value) == 0);
    CHECK(value == 9u);

    CHECK(wrtc_native_atomic_uint32_set(&slot, 0u) == 0);
    for (index = 0; index < THREAD_COUNT; index++) {
        workers[index].slot = &slot;
        workers[index].failed = 0;
        CHECK(pthread_create(&threads[index], NULL, increment,
                             &workers[index]) == 0);
    }
    for (index = 0; index < THREAD_COUNT; index++) {
        CHECK(pthread_join(threads[index], NULL) == 0);
        CHECK(!workers[index].failed);
    }
    CHECK(wrtc_native_atomic_uint32_load(&slot, &value) == 0);
    CHECK(value == (uint_least32_t)(THREAD_COUNT * INCREMENTS));
    wrtc_native_atomic_uint32_clear(&slot);
    CHECK(wrtc_native_atomic_uint32_load(&slot, &value) < 0);
    CHECK(PyErr_ExceptionMatches(PyExc_AttributeError));
    PyErr_Clear();
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
