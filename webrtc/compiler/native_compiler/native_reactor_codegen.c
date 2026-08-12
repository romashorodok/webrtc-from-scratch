#include "native_reactor_codegen.h"

#include "native_reactor_source.h"

int wrtc_native_reactor_emit_runtime(FILE *file) {
    if (file == NULL) return -1;
    if (fputs("#define WRTC_NATIVE_REACTOR_EMBEDDED 1\n", file) < 0)
        return -1;
    if (fwrite(wrtc_native_reactor_header_source, 1u,
               sizeof(wrtc_native_reactor_header_source) - 1u,
               file) != sizeof(wrtc_native_reactor_header_source) - 1u)
        return -1;
    return fwrite(wrtc_native_reactor_implementation_source, 1u,
                  sizeof(wrtc_native_reactor_implementation_source) - 1u,
                  file) ==
                   sizeof(wrtc_native_reactor_implementation_source) - 1u
               ? 0
               : -1;
}
