#include <Python.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "native_storage.h"

#define CHECK(value)                                                          \
    do {                                                                      \
        if (!(value)) {                                                       \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__,         \
                    __LINE__, #value);                                        \
            return 1;                                                         \
        }                                                                     \
    } while (0)

typedef struct {
    WrtcNativeMpsc *queue;
    size_t producer;
    size_t count;
} Producer;

typedef struct {
    WrtcNativeMpsc *queue;
    _Atomic size_t *ready;
    _Atomic size_t *published;
    uintptr_t value;
} ClosingProducer;

static void *publish_many(void *opaque) {
    Producer *producer = opaque;
    size_t index;
    for (index = 0u; index < producer->count; index++) {
        const uintptr_t encoded =
            1u + producer->producer * producer->count + index;
        WrtcNativeMpscStatus status;
        do {
            status = wrtc_native_mpsc_publish(
                producer->queue, (void *)encoded, NULL);
        } while (status == WRTC_MPSC_FULL);
        if (status != WRTC_MPSC_OK) return (void *)(uintptr_t)1u;
    }
    return NULL;
}

static void *publish_until_closed(void *opaque) {
    ClosingProducer *producer = opaque;
    atomic_fetch_add_explicit(producer->ready, 1u, memory_order_release);
    for (;;) {
        WrtcNativeMpscStatus status = wrtc_native_mpsc_publish(
            producer->queue, (void *)producer->value, NULL);
        if (status == WRTC_MPSC_OK) {
            atomic_fetch_add_explicit(
                producer->published, 1u, memory_order_relaxed);
            producer->value += 16u;
        } else if (status == WRTC_MPSC_CLOSED) {
            return NULL;
        }
    }
}

static int wrap_full_and_notification_test(void) {
    WrtcNativeMpsc queue;
    void *item = NULL;
    int notify = 0;
    size_t round;
    CHECK(wrtc_native_mpsc_init(&queue, 3u) == 0);
    for (round = 0u; round < 200u; round++) {
        CHECK(wrtc_native_mpsc_publish(
                  &queue, (void *)(uintptr_t)(round * 3u + 1u),
                  &notify) == WRTC_MPSC_OK);
        CHECK(notify == 1);
        CHECK(wrtc_native_mpsc_publish(
                  &queue, (void *)(uintptr_t)(round * 3u + 2u),
                  &notify) == WRTC_MPSC_OK);
        CHECK(notify == 0);
        CHECK(wrtc_native_mpsc_publish(
                  &queue, (void *)(uintptr_t)(round * 3u + 3u),
                  &notify) == WRTC_MPSC_OK);
        CHECK(wrtc_native_mpsc_publish(
                  &queue, (void *)(uintptr_t)9999u,
                  &notify) == WRTC_MPSC_FULL);
        CHECK(wrtc_native_mpsc_snapshot(&queue) == 3u);
        CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
        CHECK((uintptr_t)item == round * 3u + 1u);
        CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
        CHECK((uintptr_t)item == round * 3u + 2u);
        CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
        CHECK((uintptr_t)item == round * 3u + 3u);
        CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_EMPTY);
        CHECK(wrtc_native_mpsc_consumer_rearm(&queue) == 0);
    }
    wrtc_native_mpsc_clear(&queue, NULL, NULL);
    return 0;
}

static int capacity_one_test(void) {
    WrtcNativeMpsc queue;
    void *item = NULL;
    int notify = 0;
    CHECK(wrtc_native_mpsc_init(&queue, 1u) == 0);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)1u, &notify) == WRTC_MPSC_OK);
    CHECK(notify == 1);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)2u, &notify) == WRTC_MPSC_FULL);
    CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
    CHECK((uintptr_t)item == 1u);
    CHECK(wrtc_native_mpsc_consumer_rearm(&queue) == 0);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)2u, &notify) == WRTC_MPSC_OK);
    CHECK(notify == 1);
    CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
    CHECK((uintptr_t)item == 2u);
    wrtc_native_mpsc_close(&queue);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)3u, &notify) ==
          WRTC_MPSC_CLOSED);
    wrtc_native_mpsc_clear(&queue, NULL, NULL);
    return 0;
}

static int publication_gap_test(void) {
    WrtcNativeMpsc queue;
    WrtcNativeMpscTicket first, second;
    void *item = NULL;
    int notify = 0;
    CHECK(wrtc_native_mpsc_init(&queue, 2u) == 0);
    CHECK(wrtc_native_mpsc_reserve(&queue, &first) == WRTC_MPSC_OK);
    CHECK(wrtc_native_mpsc_reserve(&queue, &second) == WRTC_MPSC_OK);
    CHECK(wrtc_native_mpsc_commit(
              &second, (void *)(uintptr_t)2u, &notify) == 0);
    CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_EMPTY);
    CHECK(wrtc_native_mpsc_consumer_rearm(&queue) == 1);
    CHECK(wrtc_native_mpsc_commit(
              &first, (void *)(uintptr_t)1u, &notify) == 0);
    CHECK(notify == 0);
    CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
    CHECK((uintptr_t)item == 1u);
    CHECK(wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK);
    CHECK((uintptr_t)item == 2u);
    wrtc_native_mpsc_clear(&queue, NULL, NULL);
    return 0;
}

static void count_release(void *item, void *context) {
    size_t *count = context;
    if (item != NULL) (*count)++;
}

static int reclamation_and_close_test(void) {
    WrtcNativeMpsc queue;
    size_t released = 0u;
    int notify;
    CHECK(wrtc_native_mpsc_init(&queue, 4u) == 0);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)1u, &notify) == WRTC_MPSC_OK);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)2u, &notify) == WRTC_MPSC_OK);
    wrtc_native_mpsc_close(&queue);
    CHECK(wrtc_native_mpsc_publish(
              &queue, (void *)(uintptr_t)3u, &notify) ==
          WRTC_MPSC_CLOSED);
    wrtc_native_mpsc_clear(&queue, count_release, &released);
    CHECK(released == 2u);
    return 0;
}

static int stress_test(void) {
    enum { PRODUCERS = 4, ITEMS = 20000 };
    WrtcNativeMpsc queue;
    Producer producers[PRODUCERS];
    pthread_t threads[PRODUCERS];
    unsigned char *seen;
    size_t consumed = 0u, index;
    CHECK(wrtc_native_mpsc_init(&queue, 257u) == 0);
    seen = calloc((size_t)PRODUCERS * ITEMS, 1u);
    CHECK(seen != NULL);
    for (index = 0u; index < PRODUCERS; index++) {
        producers[index].queue = &queue;
        producers[index].producer = index;
        producers[index].count = ITEMS;
        CHECK(pthread_create(&threads[index], NULL, publish_many,
                             &producers[index]) == 0);
    }
    while (consumed < (size_t)PRODUCERS * ITEMS) {
        void *item = NULL;
        if (wrtc_native_mpsc_try_pop(&queue, &item) == WRTC_MPSC_OK) {
            const uintptr_t encoded = (uintptr_t)item;
            CHECK(encoded >= 1u &&
                  encoded <= (uintptr_t)PRODUCERS * ITEMS);
            CHECK(seen[encoded - 1u] == 0u);
            seen[encoded - 1u] = 1u;
            consumed++;
        }
    }
    for (index = 0u; index < PRODUCERS; index++) {
        void *result = NULL;
        CHECK(pthread_join(threads[index], &result) == 0);
        CHECK(result == NULL);
    }
    for (index = 0u; index < (size_t)PRODUCERS * ITEMS; index++)
        CHECK(seen[index] == 1u);
    free(seen);
    wrtc_native_mpsc_clear(&queue, NULL, NULL);
    return 0;
}

static int shutdown_publication_race_test(void) {
    enum { PRODUCERS = 4, ROUNDS = 200 };
    size_t round;
    for (round = 0u; round < ROUNDS; round++) {
        WrtcNativeMpsc queue;
        ClosingProducer producers[PRODUCERS];
        pthread_t threads[PRODUCERS];
        _Atomic size_t ready;
        _Atomic size_t published;
        size_t index, consumed = 0u;
        void *item = NULL;
        atomic_init(&ready, 0u);
        atomic_init(&published, 0u);
        CHECK(wrtc_native_mpsc_init(&queue, 17u) == 0);
        for (index = 0u; index < PRODUCERS; index++) {
            producers[index].queue = &queue;
            producers[index].ready = &ready;
            producers[index].published = &published;
            producers[index].value = index + 1u;
            CHECK(pthread_create(
                      &threads[index], NULL, publish_until_closed,
                      &producers[index]) == 0);
        }
        while (atomic_load_explicit(&ready, memory_order_acquire) !=
               PRODUCERS) {
        }
        wrtc_native_mpsc_close(&queue);
        for (index = 0u; index < PRODUCERS; index++) {
            void *result = NULL;
            CHECK(pthread_join(threads[index], &result) == 0);
            CHECK(result == NULL);
        }
        CHECK(!wrtc_native_mpsc_is_open(&queue));
        while (wrtc_native_mpsc_try_pop(&queue, &item) ==
               WRTC_MPSC_OK)
            consumed++;
        CHECK(consumed == atomic_load_explicit(
                              &published, memory_order_relaxed));
        CHECK(consumed <= 17u);
        wrtc_native_mpsc_clear(&queue, NULL, NULL);
    }
    return 0;
}

int main(void) {
    CHECK(capacity_one_test() == 0);
    CHECK(wrap_full_and_notification_test() == 0);
    CHECK(publication_gap_test() == 0);
    CHECK(reclamation_and_close_test() == 0);
    CHECK(stress_test() == 0);
    CHECK(shutdown_publication_race_test() == 0);
    return 0;
}
