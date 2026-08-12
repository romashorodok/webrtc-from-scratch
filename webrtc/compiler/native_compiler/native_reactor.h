#ifndef WRTC_NATIVE_REACTOR_H
#define WRTC_NATIVE_REACTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#endif

typedef enum {
    WRTC_REACTOR_OK = 0,
    WRTC_REACTOR_EMPTY,
    WRTC_REACTOR_FULL,
    WRTC_REACTOR_STALE,
    WRTC_REACTOR_UNAVAILABLE,
    WRTC_REACTOR_INVALID,
    WRTC_REACTOR_SYSTEM_ERROR
} WrtcNativeReactorStatus;

enum {
    WRTC_REACTOR_READ = 1u << 0,
    WRTC_REACTOR_WRITE = 1u << 1,
    WRTC_REACTOR_ERROR = 1u << 2
};

typedef struct WrtcNativeSelector WrtcNativeSelector;

typedef struct {
    int descriptor;
    uint64_t generation;
} WrtcNativeDescriptorToken;

typedef struct {
    WrtcNativeDescriptorToken token;
    unsigned events;
    void *data;
} WrtcNativeReadyEvent;

/* Reactor-owned registry. Registration, modification and removal are serialized. */
int wrtc_native_selector_create(WrtcNativeSelector **out, size_t capacity);
void wrtc_native_selector_destroy(WrtcNativeSelector *selector);
WrtcNativeReactorStatus wrtc_native_selector_register(
    WrtcNativeSelector *selector, int descriptor, unsigned events, void *data,
    WrtcNativeDescriptorToken *token);
WrtcNativeReactorStatus wrtc_native_selector_modify(
    WrtcNativeSelector *selector, WrtcNativeDescriptorToken token,
    unsigned events, void *data);
WrtcNativeReactorStatus wrtc_native_selector_remove(
    WrtcNativeSelector *selector, WrtcNativeDescriptorToken token);
int wrtc_native_selector_token_is_current(
    const WrtcNativeSelector *selector, WrtcNativeDescriptorToken token);
WrtcNativeReactorStatus wrtc_native_selector_wait(
    WrtcNativeSelector *selector, int timeout_milliseconds,
    WrtcNativeReadyEvent *events, size_t event_capacity, size_t *event_count,
    int *system_error);

#if !defined(_WIN32)
typedef struct WrtcNativePacketPool WrtcNativePacketPool;

typedef struct {
    WrtcNativePacketPool *pool;
    size_t slot;
    uint64_t generation;
    unsigned char *data;
    size_t size;
    struct sockaddr_storage address;
    socklen_t address_size;
} WrtcNativeDatagramPacket;

typedef enum {
    WRTC_PACKET_CONSUMED = 0,
    WRTC_PACKET_RETAINED,
    WRTC_PACKET_DELIVERY_ERROR
} WrtcNativePacketDisposition;

typedef WrtcNativePacketDisposition (*WrtcNativePacketDeliver)(
    WrtcNativeDatagramPacket *packet, void *context);

typedef enum {
    WRTC_DATAGRAM_YIELD_DRAINED = 0,
    WRTC_DATAGRAM_YIELD_PACKET_BUDGET,
    WRTC_DATAGRAM_YIELD_TIME_BUDGET,
    WRTC_DATAGRAM_YIELD_POOL_EXHAUSTED,
    WRTC_DATAGRAM_YIELD_DELIVERY_ERROR,
    WRTC_DATAGRAM_YIELD_SYSTEM_ERROR
} WrtcNativeDatagramYield;

typedef struct {
    size_t packets;
    size_t receive_syscalls;
    WrtcNativeDatagramYield reason;
    int reschedule;
    int system_error;
} WrtcNativeDatagramDrainResult;

int wrtc_native_packet_pool_create(WrtcNativePacketPool **out,
                                   size_t capacity, size_t buffer_size);
void wrtc_native_packet_pool_destroy(WrtcNativePacketPool *pool);
size_t wrtc_native_packet_pool_available(const WrtcNativePacketPool *pool);
WrtcNativeReactorStatus wrtc_native_datagram_packet_release(
    WrtcNativeDatagramPacket *packet);

/*
 * Bounded, nonblocking, reactor-thread receive. Delivery observes packets in
 * syscall order. RETAINED transfers one pool lease to the callback; every
 * other disposition releases it before returning.
 */
WrtcNativeReactorStatus wrtc_native_datagram_drain(
    int descriptor, WrtcNativePacketPool *pool, size_t packet_budget,
    uint64_t time_budget_nanoseconds, WrtcNativePacketDeliver deliver,
    void *context, WrtcNativeDatagramDrainResult *result);
#endif

/* Emit the CPython-extension-only guarded reactor call boundary. */
int wrtc_native_reactor_emit_cpython_runtime(FILE *file);

#endif
