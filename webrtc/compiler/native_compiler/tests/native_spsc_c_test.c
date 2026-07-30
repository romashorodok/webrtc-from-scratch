#include <Python.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "native_storage.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", \
                __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct {
    WrtcNativeSpsc *queue;
    size_t count;
    int failed;
} Stress;

static void *produce(void *argument) {
    Stress *stress = argument;
    size_t value;
    for (value = 1u; value <= stress->count; value++) {
        WrtcNativeSpscStatus status;
        do {
            status = wrtc_native_spsc_try_push(
                stress->queue, (void *)(uintptr_t)value);
        } while (status == WRTC_SPSC_FULL);
        if (status != WRTC_SPSC_OK) {
            stress->failed = 1;
            break;
        }
    }
    return NULL;
}

static void *consume(void *argument) {
    Stress *stress = argument;
    size_t expected = 1u;
    while (expected <= stress->count) {
        void *item = NULL;
        WrtcNativeSpscStatus status =
            wrtc_native_spsc_try_pop(stress->queue, &item);
        if (status == WRTC_SPSC_EMPTY) continue;
        if (status != WRTC_SPSC_OK ||
            (size_t)(uintptr_t)item != expected) {
            stress->failed = 1;
            break;
        }
        expected++;
    }
    return NULL;
}

static int boundary_test(size_t capacity) {
    WrtcNativeSpsc queue;
    size_t round, index;
    CHECK(wrtc_native_spsc_init(&queue, capacity) == 0);
    for (round = 0u; round < 2000u; round++) {
        for (index = 0u; index < capacity; index++)
            CHECK(wrtc_native_spsc_try_push(
                      &queue,
                      (void *)(uintptr_t)(round * capacity + index + 1u)) ==
                  WRTC_SPSC_OK);
        CHECK(wrtc_native_spsc_try_push(
                  &queue, (void *)(uintptr_t)1u) == WRTC_SPSC_FULL);
        CHECK(wrtc_native_spsc_snapshot(&queue) == capacity);
        for (index = 0u; index < capacity; index++) {
            void *item = NULL;
            CHECK(wrtc_native_spsc_try_pop(&queue, &item) ==
                  WRTC_SPSC_OK);
            CHECK((size_t)(uintptr_t)item ==
                  round * capacity + index + 1u);
        }
        {
            void *item = NULL;
            CHECK(wrtc_native_spsc_try_pop(&queue, &item) ==
                  WRTC_SPSC_EMPTY);
        }
    }
    wrtc_native_spsc_close(&queue);
    CHECK(!wrtc_native_spsc_is_open(&queue));
    CHECK(wrtc_native_spsc_try_push(
              &queue, (void *)(uintptr_t)1u) == WRTC_SPSC_CLOSED);
    wrtc_native_spsc_clear(&queue, NULL, NULL);
    return 0;
}

int main(void) {
    WrtcNativeSpsc queue;
    Stress stress;
    pthread_t producer, consumer;
    CHECK(boundary_test(1u) == 0);
    CHECK(boundary_test(7u) == 0);
    CHECK(wrtc_native_spsc_init(&queue, 257u) == 0);
    stress.queue = &queue;
    stress.count = 100000u;
    stress.failed = 0;
    CHECK(pthread_create(&producer, NULL, produce, &stress) == 0);
    CHECK(pthread_create(&consumer, NULL, consume, &stress) == 0);
    CHECK(pthread_join(producer, NULL) == 0);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(!stress.failed);
    CHECK(wrtc_native_spsc_snapshot(&queue) == 0u);
    wrtc_native_spsc_close(&queue);
    wrtc_native_spsc_clear(&queue, NULL, NULL);
    return 0;
}
