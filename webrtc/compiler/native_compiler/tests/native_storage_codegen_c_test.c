#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_storage_codegen.h"

#define CHECK(value) do { if (!(value)) return 1; } while (0)

int main(void) {
    FILE *output = tmpfile();
    char *text;
    long length;
    CHECK(output != NULL);
    CHECK(wrtc_native_storage_emit_runtime(output) == 0);
    CHECK(fflush(output) == 0 && fseek(output, 0, SEEK_END) == 0);
    length = ftell(output);
    CHECK(length > 0 && fseek(output, 0, SEEK_SET) == 0);
    text = malloc((size_t)length + 1u);
    CHECK(text != NULL);
    CHECK(fread(text, 1u, (size_t)length, output) == (size_t)length);
    text[length] = '\0';
    CHECK(strstr(text, "wrtc_native_scalar_set_boxed") != NULL);
    CHECK(strstr(text, "wrtc_native_fifo_popleft") != NULL);
    CHECK(strstr(text, "wrtc_native_heap_push") != NULL);
    CHECK(strstr(text,
                 "wrtc_native_atomic_uint32_compare_exchange") != NULL);
    CHECK(strstr(text, "wrtc_native_mpsc_publish") != NULL);
    CHECK(strstr(text, "memory_order_release") != NULL);
    CHECK(strstr(text, "memory_order_seq_cst") != NULL);
    CHECK(strstr(text, "native_storage.h") == NULL);
    free(text);
    CHECK(fclose(output) == 0);
    return 0;
}
