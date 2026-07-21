#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler_core.h"

#ifndef WRTC_KERNEL_E_SOURCE
#error "WRTC_KERNEL_E_SOURCE is required"
#endif

#define CHECK(value) do { if (!(value)) { (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #value); return 1; } } while (0)

static char *read_source(size_t *length) {
    FILE *file = fopen(WRTC_KERNEL_E_SOURCE, "rb"); long end; char *source;
    if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (end = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) return NULL;
    source = malloc((size_t)end + 1u); if (source == NULL) { (void)fclose(file); return NULL; }
    if (fread(source, 1, (size_t)end, file) != (size_t)end) { free(source); (void)fclose(file); return NULL; }
    source[end] = '\0'; *length = (size_t)end; (void)fclose(file); return source;
}

int main(void) {
    WrtcCompilerCore *core = NULL; const WrtcFunctionIR *entry; char *source; size_t length, i, reachable = 0, exception_edges = 0, blocks = 0;
    Py_Initialize(); source = read_source(&length); CHECK(source != NULL);
    CHECK(wrtc_compiler_core_analyze(source, length, WRTC_KERNEL_E_SOURCE, &core) == 0);
    CHECK(core != NULL); CHECK(core->record_count == 2u);
    CHECK(core->records[0].field_count == 3u); CHECK(core->records[1].field_count == 5u);
    CHECK(core->records[0].property_count == 2u); CHECK(core->records[1].property_count == 0u);
    CHECK(core->records[0].fields[2].type == WRTC_TYPE_BUFFER);
    CHECK(core->records[1].fields[1].has_default);
    CHECK(PyList_GET_SIZE(core->exports) == 1);
    entry = wrtc_compiler_core_find_function(core, "packetize_av1_frame");
    CHECK(entry != NULL && entry->is_public && entry->is_reachable);
    CHECK(entry->type == WRTC_TYPE_TUPLE); CHECK(entry->call_count >= 4u);
    for (i = 0; i < core->function_count; i++) if (core->functions[i].is_reachable) {
        reachable++; blocks += core->functions[i].block_count; exception_edges += core->functions[i].exception_edge_count;
    }
    CHECK(reachable == core->function_count); CHECK(reachable >= 10u);
    CHECK(blocks >= 20u); CHECK(exception_edges >= 5u);
    CHECK(strstr(core->lowered_source, "@pymeta") == NULL);
    wrtc_compiler_core_free(core); free(source); CHECK(Py_FinalizeEx() == 0); return 0;
}
