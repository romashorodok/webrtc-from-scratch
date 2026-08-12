#include "native_reactor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #condition); return 1; } } while (0)

static int emitted_cpython_runtime_test(void) {
    FILE *file = tmpfile();
    char source[1024];
    size_t length;
    CHECK(file != NULL);
    CHECK(wrtc_native_reactor_emit_cpython_runtime(file) == 0);
    CHECK(fflush(file) == 0);
    CHECK(fseek(file, 0L, SEEK_SET) == 0);
    length = fread(source, 1u, sizeof(source) - 1u, file);
    CHECK(!ferror(file));
    source[length] = '\0';
    CHECK(fclose(file) == 0);
    CHECK(strstr(source, "PyGILState_Check") != NULL);
    CHECK(strstr(source, "PyCallable_Check") != NULL);
    CHECK(strstr(source, "PyObject_Call") != NULL);
    CHECK(strstr(source, "SelectorEventLoop") == NULL);
    CHECK(strstr(source, "Datagram") == NULL);
    CHECK(strstr(source, "event_loop") == NULL);
    return 0;
}

#if !defined(_WIN32)
static int selector_generation_test(void) {
    WrtcNativeSelector *selector = NULL;
    WrtcNativeDescriptorToken first = {0}, replacement = {0};
    WrtcNativeReadyEvent event = {0};
    int pair[2] = {-1, -1};
    size_t count = 0u;
    int error = 0;
    char marker = 'x';
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(wrtc_native_selector_create(&selector, 2u) == 0);
    CHECK(wrtc_native_selector_register(selector, pair[0], WRTC_REACTOR_READ,
                                        &marker, &first) == WRTC_REACTOR_OK);
    CHECK(wrtc_native_selector_modify(selector, first,
                                      WRTC_REACTOR_READ | WRTC_REACTOR_WRITE,
                                      &marker) == WRTC_REACTOR_OK);
    CHECK(write(pair[1], "a", 1u) == 1);
    CHECK(wrtc_native_selector_wait(selector, 1000, &event, 1u, &count,
                                    &error) == WRTC_REACTOR_OK);
    CHECK(count == 1u && event.token.generation == first.generation &&
          event.data == &marker &&
          (event.events & WRTC_REACTOR_READ) != 0u);
    CHECK(wrtc_native_selector_remove(selector, first) == WRTC_REACTOR_OK);
    CHECK(!wrtc_native_selector_token_is_current(selector, first));
    CHECK(wrtc_native_selector_modify(selector, first, WRTC_REACTOR_READ,
                                      NULL) == WRTC_REACTOR_STALE);
    CHECK(wrtc_native_selector_register(selector, pair[0], WRTC_REACTOR_READ,
                                        NULL, &replacement) == WRTC_REACTOR_OK);
    CHECK(replacement.generation != first.generation);
    CHECK(wrtc_native_selector_remove(selector, first) == WRTC_REACTOR_STALE);
    CHECK(wrtc_native_selector_token_is_current(selector, replacement));
    CHECK(wrtc_native_selector_remove(selector, replacement) == WRTC_REACTOR_OK);
    wrtc_native_selector_destroy(selector);
    CHECK(close(pair[0]) == 0);
    CHECK(close(pair[1]) == 0);
    return 0;
}

typedef struct {
    unsigned char values[32];
    size_t lengths[32];
    size_t count;
    size_t retain_at;
    WrtcNativeDatagramPacket retained;
} Delivery;

static WrtcNativePacketDisposition capture_packet(
    WrtcNativeDatagramPacket *packet, void *opaque) {
    Delivery *delivery = opaque;
    if (delivery->count >= 32u || packet->size == 0u)
        return WRTC_PACKET_DELIVERY_ERROR;
    delivery->values[delivery->count] = packet->data[0];
    delivery->lengths[delivery->count] = packet->size;
    delivery->count++;
    if (delivery->count == delivery->retain_at) {
        delivery->retained = *packet;
        return WRTC_PACKET_RETAINED;
    }
    return WRTC_PACKET_CONSUMED;
}

static int udp_pair(int *receiver, int *sender,
                    struct sockaddr_in *receiver_address) {
    socklen_t size = (socklen_t)sizeof(*receiver_address);
    *receiver = socket(AF_INET, SOCK_DGRAM, 0);
    *sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (*receiver < 0 || *sender < 0) return -1;
    memset(receiver_address, 0, sizeof(*receiver_address));
    receiver_address->sin_family = AF_INET;
    receiver_address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    receiver_address->sin_port = 0;
    if (bind(*receiver, (struct sockaddr *)receiver_address,
             sizeof(*receiver_address)) != 0 ||
        getsockname(*receiver, (struct sockaddr *)receiver_address, &size) != 0)
        return -1;
    return 0;
}

static int wait_readable(int descriptor) {
    struct pollfd item = {descriptor, POLLIN, 0};
    return poll(&item, 1u, 1000) == 1 && (item.revents & POLLIN) != 0;
}

static int datagram_budget_order_ownership_test(void) {
    WrtcNativePacketPool *pool = NULL;
    WrtcNativeDatagramDrainResult result = {0};
    Delivery delivery = {0};
    struct sockaddr_in address;
    int receiver = -1, sender = -1;
    size_t index;
    CHECK(udp_pair(&receiver, &sender, &address) == 0);
    CHECK(wrtc_native_packet_pool_create(&pool, 4u, 256u) == 0);
    for (index = 0u; index < 6u; index++) {
        unsigned char payload[2] = {(unsigned char)index, 0xa5u};
        CHECK(sendto(sender, payload, sizeof(payload), 0,
                     (struct sockaddr *)&address, sizeof(address)) ==
              (ssize_t)sizeof(payload));
    }
    CHECK(wait_readable(receiver));
    CHECK(wrtc_native_datagram_drain(receiver, pool, 3u,
              UINT64_C(1000000000), capture_packet, &delivery, &result) ==
          WRTC_REACTOR_OK);
    CHECK(result.packets == 3u && result.reschedule &&
          result.reason == WRTC_DATAGRAM_YIELD_PACKET_BUDGET);
    CHECK(delivery.count == 3u);
    for (index = 0u; index < 3u; index++)
        CHECK(delivery.values[index] == (unsigned char)index &&
              delivery.lengths[index] == 2u);
    CHECK(wrtc_native_packet_pool_available(pool) == 4u);
    delivery.retain_at = 4u;
    CHECK(wrtc_native_datagram_drain(receiver, pool, 3u,
              UINT64_C(1000000000), capture_packet, &delivery, &result) ==
          WRTC_REACTOR_OK);
    CHECK(delivery.count == 6u && delivery.values[3] == 3u &&
          delivery.values[4] == 4u && delivery.values[5] == 5u);
    CHECK(wrtc_native_packet_pool_available(pool) == 3u);
    CHECK(wrtc_native_datagram_packet_release(&delivery.retained) ==
          WRTC_REACTOR_OK);
    CHECK(wrtc_native_datagram_packet_release(&delivery.retained) ==
          WRTC_REACTOR_INVALID);
    CHECK(wrtc_native_packet_pool_available(pool) == 4u);
    wrtc_native_packet_pool_destroy(pool);
    CHECK(close(receiver) == 0);
    CHECK(close(sender) == 0);
    return 0;
}

static int pool_backpressure_and_time_budget_test(void) {
    WrtcNativePacketPool *pool = NULL;
    WrtcNativeDatagramDrainResult result = {0};
    Delivery delivery = {0};
    struct sockaddr_in address;
    int receiver = -1, sender = -1;
    unsigned char payload = 7u;
    WrtcNativeReactorStatus status;
    CHECK(udp_pair(&receiver, &sender, &address) == 0);
    CHECK(wrtc_native_packet_pool_create(&pool, 1u, 64u) == 0);
    delivery.retain_at = 1u;
    CHECK(sendto(sender, &payload, 1u, 0, (struct sockaddr *)&address,
                 sizeof(address)) == 1);
    CHECK(wait_readable(receiver));
    status = wrtc_native_datagram_drain(receiver, pool, 8u,
              UINT64_C(1000000000), capture_packet, &delivery, &result);
    if (status != WRTC_REACTOR_FULL)
        (void)fprintf(stderr,
                      "backpressure status=%d packets=%zu reason=%d available=%zu\n",
                      (int)status, result.packets, (int)result.reason,
                      wrtc_native_packet_pool_available(pool));
    CHECK(status == WRTC_REACTOR_FULL);
    CHECK(result.packets == 1u && result.reschedule &&
          result.reason == WRTC_DATAGRAM_YIELD_POOL_EXHAUSTED);
    CHECK(wrtc_native_datagram_packet_release(&delivery.retained) ==
          WRTC_REACTOR_OK);
    CHECK(sendto(sender, &payload, 1u, 0, (struct sockaddr *)&address,
                 sizeof(address)) == 1);
    CHECK(wait_readable(receiver));
    CHECK(wrtc_native_datagram_drain(receiver, pool, 8u, 1u,
              capture_packet, &delivery, &result) == WRTC_REACTOR_OK);
    CHECK(result.reason == WRTC_DATAGRAM_YIELD_TIME_BUDGET &&
          result.reschedule);
    wrtc_native_packet_pool_destroy(pool);
    CHECK(close(receiver) == 0);
    CHECK(close(sender) == 0);
    return 0;
}
#endif

int main(void) {
    CHECK(emitted_cpython_runtime_test() == 0);
#if defined(_WIN32)
    WrtcNativeSelector *selector = NULL;
    CHECK(wrtc_native_selector_create(&selector, 1u) == 0);
    CHECK(wrtc_native_selector_wait(selector, 0, NULL, 0u, &(size_t){0},
                                    NULL) == WRTC_REACTOR_UNAVAILABLE);
    wrtc_native_selector_destroy(selector);
#else
    CHECK(selector_generation_test() == 0);
    CHECK(datagram_budget_order_ownership_test() == 0);
    CHECK(pool_backpressure_and_time_budget_test() == 0);
#endif
    return 0;
}
