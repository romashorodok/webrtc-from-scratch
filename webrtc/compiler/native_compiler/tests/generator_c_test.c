#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler_core.h"
#include "generator.h"
#include "lowering.h"

#define CHECK(value) do { if (!(value)) { (void)fprintf(stderr, "check failed: %s\n", #value); if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

int main(void) {
    static const char source[] =
        "import pymeta\n__all__=['increment']\n"
        "def helper(value: int) -> int:\n    return value + 1\n"
        "@pymeta.required\n@pymeta.region('increment', value=pymeta.u16)\n"
        "def increment(value: int) -> int:\n    return helper(value)\n";
    WrtcCompilerCore *core = NULL;
    WrtcLoweringProgram *program = NULL;
    FILE *file;
    char *text;
    long length;
    Py_Initialize();
    CHECK(wrtc_compiler_core_analyze(source, sizeof(source) - 1u,
                                     "fixture.py", &core) == 0);
    CHECK(wrtc_lowering_build(core, &program) == 0);
    file = tmpfile();
    CHECK(file != NULL);
    CHECK(wrtc_emit_extension(file, "fixture_native", program,
                              "source-hash", "semantic-hash", "revision",
                              "target", "architecture") == 0);
    CHECK(fflush(file) == 0 && fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    CHECK(length > 0 && fseek(file, 0, SEEK_SET) == 0);
    text = malloc((size_t)length + 1u);
    CHECK(text != NULL);
    CHECK(fread(text, 1u, (size_t)length, file) == (size_t)length);
    text[length] = '\0';
    CHECK(strstr(text, "PyInit_fixture_native") != NULL);
    CHECK(strstr(text, "wrtc-pymeta-compiler/0.3") != NULL);
    CHECK(strstr(text, "source_bytes") == NULL);
    CHECK(strstr(text, "Py_CompileString") == NULL);
    CHECK(strstr(text, "PyEval_EvalCode") == NULL);
    CHECK(strstr(text, "PyRun_String") == NULL);
    CHECK(strstr(text, "typedef struct{Kind kind") == NULL);
    CHECK(strstr(text, "static PyObject*eval(") == NULL);
    CHECK(strstr(text, "PyNumber_Add") == NULL);
    CHECK(strstr(text, "static Nv nh_0") != NULL);
    CHECK(strstr(text, "static Nv nv_range") == NULL);
    CHECK(strstr(text, "static Nv nv_enumerate") == NULL);
    CHECK(strstr(text, "strcmp(op") == NULL);
    CHECK(strstr(text, "NvArena arena") != NULL);
    CHECK(strstr(text, "nv_arena_clear(&arena)") != NULL);
    CHECK(strstr(text, "cap+cap/2u+1u") != NULL);
    CHECK(strstr(text, "PyMem_Realloc(v->owner,v->n+1u)") == NULL);
    CHECK(strstr(text, "WebRTC") == NULL && strstr(text, "RTP") == NULL &&
          strstr(text, "Obu") == NULL && strstr(text, "PacketMetadata") == NULL);
    free(text);
    (void)fclose(file);
    wrtc_lowering_free(program);
    wrtc_compiler_core_free(core);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
