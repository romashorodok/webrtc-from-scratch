#if !defined(WRTC_NATIVE_REACTOR_EMBEDDED)
#include "native_reactor.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#endif

int wrtc_native_reactor_emit_cpython_runtime(FILE *file) {
    if (file == NULL) return -1;
    return fputs(
        "static PyObject*wrtc_reactor_guarded_call(PyObject*callable,"
        "PyObject*args,PyObject*kwargs){"
        "if(!PyGILState_Check()){PyErr_SetString(PyExc_RuntimeError,"
        "\"reactor Python callback requires the reactor-thread GIL\");"
        "return NULL;}if(!PyCallable_Check(callable)){PyErr_Format("
        "PyExc_TypeError,\"'%s' object is not callable\","
        "Py_TYPE(callable)->tp_name);return NULL;}"
        "return PyObject_Call(callable,args,kwargs);}\n",
        file) < 0 ? -1 : 0;
}

typedef struct {
    int descriptor;
    uint64_t generation;
    unsigned events;
    void *data;
    unsigned active;
} SelectorSlot;

struct WrtcNativeSelector {
    SelectorSlot *slots;
#if !defined(_WIN32)
    struct pollfd *poll_descriptors;
    size_t *poll_slots;
#endif
    size_t capacity;
    uint64_t next_generation;
};

static int valid_events(unsigned events) {
    const unsigned supported =
        (unsigned)WRTC_REACTOR_READ | (unsigned)WRTC_REACTOR_WRITE;
    return events != 0u &&
           (events & ~supported) == 0u;
}

static size_t find_descriptor(const WrtcNativeSelector *selector,
                              int descriptor) {
    size_t index;
    for (index = 0u; index < selector->capacity; index++)
        if (selector->slots[index].active &&
            selector->slots[index].descriptor == descriptor)
            return index;
    return SIZE_MAX;
}

static size_t find_token(const WrtcNativeSelector *selector,
                         WrtcNativeDescriptorToken token) {
    size_t index = find_descriptor(selector, token.descriptor);
    if (index == SIZE_MAX ||
        selector->slots[index].generation != token.generation)
        return SIZE_MAX;
    return index;
}

int wrtc_native_selector_create(WrtcNativeSelector **out, size_t capacity) {
    WrtcNativeSelector *selector;
    if (out == NULL || capacity == 0u ||
#if !defined(_WIN32)
        capacity > (size_t)UINT_MAX ||
#endif
        capacity > SIZE_MAX / sizeof(SelectorSlot))
        return -1;
    *out = NULL;
    selector = calloc(1u, sizeof(*selector));
    if (selector == NULL) return -1;
    selector->slots = calloc(capacity, sizeof(*selector->slots));
#if !defined(_WIN32)
    selector->poll_descriptors =
        calloc(capacity, sizeof(*selector->poll_descriptors));
    selector->poll_slots = calloc(capacity, sizeof(*selector->poll_slots));
#endif
    if (selector->slots == NULL
#if !defined(_WIN32)
        || selector->poll_descriptors == NULL || selector->poll_slots == NULL
#endif
    ) {
        wrtc_native_selector_destroy(selector);
        return -1;
    }
    selector->capacity = capacity;
    selector->next_generation = UINT64_C(1);
    *out = selector;
    return 0;
}

void wrtc_native_selector_destroy(WrtcNativeSelector *selector) {
    if (selector == NULL) return;
#if !defined(_WIN32)
    free(selector->poll_slots);
    free(selector->poll_descriptors);
#endif
    free(selector->slots);
    free(selector);
}

WrtcNativeReactorStatus wrtc_native_selector_register(
    WrtcNativeSelector *selector, int descriptor, unsigned events, void *data,
    WrtcNativeDescriptorToken *token) {
    size_t index;
    uint64_t generation;
    if (selector == NULL || descriptor < 0 || !valid_events(events) ||
        token == NULL)
        return WRTC_REACTOR_INVALID;
    if (find_descriptor(selector, descriptor) != SIZE_MAX)
        return WRTC_REACTOR_INVALID;
    for (index = 0u; index < selector->capacity; index++)
        if (!selector->slots[index].active) break;
    if (index == selector->capacity) return WRTC_REACTOR_FULL;
    if (selector->next_generation == 0u) return WRTC_REACTOR_INVALID;
    generation = selector->next_generation++;
    selector->slots[index].descriptor = descriptor;
    selector->slots[index].generation = generation;
    selector->slots[index].events = events;
    selector->slots[index].data = data;
    selector->slots[index].active = 1u;
    token->descriptor = descriptor;
    token->generation = generation;
    return WRTC_REACTOR_OK;
}

WrtcNativeReactorStatus wrtc_native_selector_modify(
    WrtcNativeSelector *selector, WrtcNativeDescriptorToken token,
    unsigned events, void *data) {
    size_t index;
    if (selector == NULL || !valid_events(events))
        return WRTC_REACTOR_INVALID;
    index = find_token(selector, token);
    if (index == SIZE_MAX) return WRTC_REACTOR_STALE;
    selector->slots[index].events = events;
    selector->slots[index].data = data;
    return WRTC_REACTOR_OK;
}

WrtcNativeReactorStatus wrtc_native_selector_remove(
    WrtcNativeSelector *selector, WrtcNativeDescriptorToken token) {
    size_t index;
    if (selector == NULL) return WRTC_REACTOR_INVALID;
    index = find_token(selector, token);
    if (index == SIZE_MAX) return WRTC_REACTOR_STALE;
    memset(&selector->slots[index], 0, sizeof(selector->slots[index]));
    selector->slots[index].descriptor = -1;
    return WRTC_REACTOR_OK;
}

int wrtc_native_selector_token_is_current(
    const WrtcNativeSelector *selector, WrtcNativeDescriptorToken token) {
    return selector != NULL && find_token(selector, token) != SIZE_MAX;
}

WrtcNativeReactorStatus wrtc_native_selector_wait(
    WrtcNativeSelector *selector, int timeout_milliseconds,
    WrtcNativeReadyEvent *events, size_t event_capacity, size_t *event_count,
    int *system_error) {
#if defined(_WIN32)
    (void)selector; (void)timeout_milliseconds; (void)events;
    (void)event_capacity;
    if (event_count != NULL) *event_count = 0u;
    if (system_error != NULL) *system_error = 0;
    return WRTC_REACTOR_UNAVAILABLE;
#else
    size_t index, polled = 0u, emitted = 0u;
    int status;
    if (event_count != NULL) *event_count = 0u;
    if (system_error != NULL) *system_error = 0;
    if (selector == NULL || event_count == NULL ||
        (event_capacity != 0u && events == NULL) || timeout_milliseconds < -1)
        return WRTC_REACTOR_INVALID;
    for (index = 0u; index < selector->capacity; index++) {
        short requested = 0;
        if (!selector->slots[index].active) continue;
        if ((selector->slots[index].events & WRTC_REACTOR_READ) != 0u)
            requested = (short)(requested | POLLIN);
        if ((selector->slots[index].events & WRTC_REACTOR_WRITE) != 0u)
            requested = (short)(requested | POLLOUT);
        selector->poll_descriptors[polled].fd =
            selector->slots[index].descriptor;
        selector->poll_descriptors[polled].events = requested;
        selector->poll_descriptors[polled].revents = 0;
        selector->poll_slots[polled] = index;
        polled++;
    }
    status = poll(selector->poll_descriptors, (nfds_t)polled,
                  timeout_milliseconds);
    if (status < 0) {
        if (errno == EINTR) return WRTC_REACTOR_EMPTY;
        if (system_error != NULL) *system_error = errno;
        return WRTC_REACTOR_SYSTEM_ERROR;
    }
    if (status == 0) return WRTC_REACTOR_EMPTY;
    for (index = 0u; index < polled && emitted < event_capacity; index++) {
        const struct pollfd *polled_descriptor =
            &selector->poll_descriptors[index];
        const SelectorSlot *slot;
        unsigned ready = 0u;
        if (polled_descriptor->revents == 0) continue;
        slot = &selector->slots[selector->poll_slots[index]];
        if (!slot->active || slot->descriptor != polled_descriptor->fd)
            continue;
        if ((polled_descriptor->revents & (POLLIN | POLLHUP)) != 0)
            ready |= WRTC_REACTOR_READ;
        if ((polled_descriptor->revents & POLLOUT) != 0)
            ready |= WRTC_REACTOR_WRITE;
        if ((polled_descriptor->revents & (POLLERR | POLLNVAL)) != 0)
            ready |= WRTC_REACTOR_ERROR;
        events[emitted].token.descriptor = slot->descriptor;
        events[emitted].token.generation = slot->generation;
        events[emitted].events = ready;
        events[emitted].data = slot->data;
        emitted++;
    }
    *event_count = emitted;
    return emitted == 0u ? WRTC_REACTOR_EMPTY : WRTC_REACTOR_OK;
#endif
}

#if !defined(_WIN32)
typedef struct {
    unsigned char *data;
    uint64_t generation;
    unsigned in_use;
} PacketSlot;

struct WrtcNativePacketPool {
    PacketSlot *slots;
    unsigned char *storage;
    size_t capacity;
    size_t buffer_size;
    size_t available;
    uint64_t next_generation;
};

static uint64_t monotonic_nanoseconds(void) {
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0u;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
           (uint64_t)value.tv_nsec;
}

int wrtc_native_packet_pool_create(WrtcNativePacketPool **out,
                                   size_t capacity, size_t buffer_size) {
    WrtcNativePacketPool *pool;
    size_t index;
    if (out == NULL || capacity == 0u || buffer_size == 0u ||
        capacity > SIZE_MAX / sizeof(PacketSlot) ||
        capacity > SIZE_MAX / buffer_size)
        return -1;
    *out = NULL;
    pool = calloc(1u, sizeof(*pool));
    if (pool == NULL) return -1;
    pool->slots = calloc(capacity, sizeof(*pool->slots));
    pool->storage = malloc(capacity * buffer_size);
    if (pool->slots == NULL || pool->storage == NULL) {
        wrtc_native_packet_pool_destroy(pool);
        return -1;
    }
    for (index = 0u; index < capacity; index++)
        pool->slots[index].data = pool->storage + index * buffer_size;
    pool->capacity = capacity;
    pool->buffer_size = buffer_size;
    pool->available = capacity;
    pool->next_generation = UINT64_C(1);
    *out = pool;
    return 0;
}

void wrtc_native_packet_pool_destroy(WrtcNativePacketPool *pool) {
    if (pool == NULL) return;
    free(pool->storage);
    free(pool->slots);
    free(pool);
}

size_t wrtc_native_packet_pool_available(const WrtcNativePacketPool *pool) {
    return pool == NULL ? 0u : pool->available;
}

static WrtcNativeReactorStatus acquire_packet(
    WrtcNativePacketPool *pool, WrtcNativeDatagramPacket *packet) {
    size_t index;
    uint64_t generation;
    for (index = 0u; index < pool->capacity; index++)
        if (!pool->slots[index].in_use) break;
    if (index == pool->capacity) return WRTC_REACTOR_FULL;
    if (pool->next_generation == 0u) return WRTC_REACTOR_INVALID;
    generation = pool->next_generation++;
    pool->slots[index].in_use = 1u;
    pool->slots[index].generation = generation;
    pool->available--;
    memset(packet, 0, sizeof(*packet));
    packet->pool = pool;
    packet->slot = index;
    packet->generation = generation;
    packet->data = pool->slots[index].data;
    return WRTC_REACTOR_OK;
}

WrtcNativeReactorStatus wrtc_native_datagram_packet_release(
    WrtcNativeDatagramPacket *packet) {
    WrtcNativePacketPool *pool;
    PacketSlot *slot;
    if (packet == NULL || packet->pool == NULL) return WRTC_REACTOR_INVALID;
    pool = packet->pool;
    if (packet->slot >= pool->capacity) return WRTC_REACTOR_INVALID;
    slot = &pool->slots[packet->slot];
    if (!slot->in_use || slot->generation != packet->generation)
        return WRTC_REACTOR_STALE;
    slot->in_use = 0u;
    pool->available++;
    packet->pool = NULL;
    packet->data = NULL;
    packet->size = 0u;
    return WRTC_REACTOR_OK;
}

WrtcNativeReactorStatus wrtc_native_datagram_drain(
    int descriptor, WrtcNativePacketPool *pool, size_t packet_budget,
    uint64_t time_budget_nanoseconds, WrtcNativePacketDeliver deliver,
    void *context, WrtcNativeDatagramDrainResult *result) {
    uint64_t started;
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (descriptor < 0 || pool == NULL || packet_budget == 0u ||
        time_budget_nanoseconds == 0u || deliver == NULL || result == NULL)
        return WRTC_REACTOR_INVALID;
    started = monotonic_nanoseconds();
    for (;;) {
        WrtcNativeDatagramPacket packet;
        WrtcNativeReactorStatus acquired;
        ssize_t received;
        WrtcNativePacketDisposition disposition;
        uint64_t now;
        if (result->packets >= packet_budget) {
            result->reason = WRTC_DATAGRAM_YIELD_PACKET_BUDGET;
            result->reschedule = 1;
            return WRTC_REACTOR_OK;
        }
        now = monotonic_nanoseconds();
        if (now == 0u || started == 0u || now - started >= time_budget_nanoseconds) {
            result->reason = WRTC_DATAGRAM_YIELD_TIME_BUDGET;
            result->reschedule = 1;
            return WRTC_REACTOR_OK;
        }
        acquired = acquire_packet(pool, &packet);
        if (acquired != WRTC_REACTOR_OK) {
            result->reason = WRTC_DATAGRAM_YIELD_POOL_EXHAUSTED;
            result->reschedule = 1;
            return acquired;
        }
        packet.address_size = (socklen_t)sizeof(packet.address);
        received = recvfrom(descriptor, packet.data, pool->buffer_size,
                            MSG_DONTWAIT, (struct sockaddr *)&packet.address,
                            &packet.address_size);
        result->receive_syscalls++;
        if (received < 0) {
            int saved_error = errno;
            (void)wrtc_native_datagram_packet_release(&packet);
            if (saved_error == EAGAIN || saved_error == EWOULDBLOCK) {
                result->reason = WRTC_DATAGRAM_YIELD_DRAINED;
                return WRTC_REACTOR_EMPTY;
            }
            if (saved_error == EINTR) continue;
            result->reason = WRTC_DATAGRAM_YIELD_SYSTEM_ERROR;
            result->system_error = saved_error;
            return WRTC_REACTOR_SYSTEM_ERROR;
        }
        packet.size = (size_t)received;
        result->packets++;
        disposition = deliver(&packet, context);
        if (disposition != WRTC_PACKET_RETAINED && packet.pool != NULL)
            (void)wrtc_native_datagram_packet_release(&packet);
        if (disposition == WRTC_PACKET_DELIVERY_ERROR) {
            result->reason = WRTC_DATAGRAM_YIELD_DELIVERY_ERROR;
            return WRTC_REACTOR_SYSTEM_ERROR;
        }
    }
}
#endif
