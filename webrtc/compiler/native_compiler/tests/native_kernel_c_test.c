#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_class.h"
#include "native_kernel.h"

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #condition); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static const char source[] =
    "from dataclasses import dataclass\n"
    "from typing import Annotated\n"
    "import pymeta\n"
    "from pymeta.concurrent import BoundedQueue, bounded_queue, spsc\n"
    "@pymeta.record(abi='input.v1')\n"
    "@dataclass(frozen=True, slots=True)\n"
    "class Input:\n"
    "    value: Annotated[int, pymeta.uint[16]]\n"
    "@pymeta.record(abi='result.v1')\n"
    "@dataclass(frozen=True, slots=True)\n"
    "class Result:\n"
    "    value: Annotated[int, pymeta.uint[16]]\n"
    "@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)\n"
    "class Kernels:\n"
    "    _input: Annotated[BoundedQueue[Input], spsc | bounded_queue(capacity=1) | pymeta.owned_by('worker')]\n"
    "    _output: Annotated[BoundedQueue[Result], spsc | bounded_queue(capacity=1) | pymeta.owned_by('reactor')]\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def increment(self, value: Annotated[int, pymeta.uint[16]]) -> Annotated[int, pymeta.uint[16]]:\n"
    "        return value + 1\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def wrap_increment(self, value: Annotated[int, pymeta.uint[16] | pymeta.wrap]) -> Annotated[int, pymeta.uint[16] | pymeta.wrap]:\n"
    "        return value + 1\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def divide(self, value: Annotated[int, pymeta.uint[16]], divisor: Annotated[int, pymeta.uint[16]]) -> Annotated[int, pymeta.uint[16]]:\n"
    "        return value // divisor\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def accumulate(self, packet: Input, limit: Annotated[int, pymeta.uint[16]]) -> Annotated[int, pymeta.uint[16]]:\n"
    "        total = packet.value\n"
    "        if limit > 0:\n"
    "            total = self.increment(total)\n"
    "        for index in range(limit):\n"
    "            total += index\n"
    "        return total\n"
    "    @pymeta.region(pymeta.required, execute=pymeta.owned_shard(key='packet.value', workers='config.workers', input=pymeta.spsc, output=pymeta.spsc, ordered=True), effects=pymeta.effects(owner='worker', noescape={'packet'}, allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def process(self, packet: Input) -> Result:\n"
    "        return Result(packet.value + 1)\n";

static const char rejected_source[] =
    "from typing import Annotated\n"
    "import pymeta\n"
    "@pymeta.native_class(pymeta.compact_object, gc=pymeta.tracked, weakrefs=False)\n"
    "class Rejected:\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def dynamic(self, value: Annotated[int, pymeta.uint[16]]) -> Annotated[int, pymeta.uint[16]]:\n"
    "        return callback(value)\n"
    "    @pymeta.region(pymeta.required, effects=pymeta.effects(owner='worker', allocate=pymeta.never, suspend=pymeta.never))\n"
    "    def allocated(self, value: Annotated[int, pymeta.uint[16]]) -> Annotated[int, pymeta.uint[16]]:\n"
    "        temporary = [value]\n"
    "        return value\n";

int main(void) {
    WrtcNativeClassProgram *program = NULL;
    FILE *generated;
    FILE *inspection;
    char *generated_text;
    long generated_size;
    int command_status;
    Py_Initialize();
    CHECK(wrtc_native_class_analyze(source, strlen(source),
                                    "portable_kernel.py", &program) == 0);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(program->classes[0].region_count == 5u);
    if (!program->classes[0].regions[0].kernel_emission_complete)
        (void)fprintf(stderr, "kernel rejection: %s result=%s\n",
                      program->classes[0].regions[0].kernel_rejection_reason,
                      program->classes[0].regions[0].result_type);
    CHECK(program->classes[0].regions[0].kernel_emission_complete);
    CHECK(program->classes[0].regions[3].kernel_emission_complete);
    CHECK(program->classes[0].regions[3].kernel_python_free);
    CHECK(program->classes[0].regions[3].kernel_statement_count == 6u);
    CHECK(program->classes[0].regions[3].kernel_emitted_statement_count == 6u);
    CHECK(program->classes[0].regions[3].kernel_call_count == 2u);
    CHECK(program->classes[0].regions[3].kernel_emitted_call_count == 2u);
    CHECK(program->classes[0].regions[4].kernel_emission_complete);
    CHECK(program->classes[0].regions[4].worker_emission_complete);
    CHECK(program->classes[0].regions[4].worker_python_free);
    generated = fopen("/tmp/wrtc_native_kernel_generated.c", "w");
    CHECK(generated != NULL);
    CHECK(wrtc_native_kernel_emit(generated, program, "fixture") == 0);
    CHECK(fputs(
        "int main(void){int s=0;uint64_t v=fixture_0_3(7,3,&s);"
        "if(s||v!=11)return 1;s=0;v=fixture_0_0(65535,&s);"
        "if(s!=NK_OVERFLOW||v!=0)return 2;s=0;v=fixture_0_1(65535,&s);"
        "if(s||v!=0)return 3;s=0;v=fixture_0_2(7,0,&s);"
        "if(s!=NK_DIVZERO||v!=0)return 4;s=0;v=0;"
        "if(fixture_0_4(8,&v,&s)||s||v!=9)return 5;"
        "WrtcNativeWorkerValue iv[1]={0},ov[1]={0};"
        "WrtcNativeWorkerRecord ir={0},or={0};WrtcNativeWorkerError e={0};"
        "iv[0].as.uint_value=12;ir.values=iv;ir.value_count=1;"
        "or.values=ov;or.value_count=1;"
        "if(fixture_worker_0_4(&ir,&or,&e,0)||e.code||"
        "ov[0].as.uint_value!=13)return 6;return 0;}\n",
        generated) >= 0);
    CHECK(fclose(generated) == 0);
    inspection = fopen("/tmp/wrtc_native_kernel_generated.c", "rb");
    CHECK(inspection != NULL);
    CHECK(fseek(inspection, 0L, SEEK_END) == 0);
    generated_size = ftell(inspection);
    CHECK(generated_size > 0L);
    CHECK(fseek(inspection, 0L, SEEK_SET) == 0);
    generated_text = malloc((size_t)generated_size + 1u);
    CHECK(generated_text != NULL);
    CHECK(fread(generated_text, 1u, (size_t)generated_size, inspection) ==
          (size_t)generated_size);
    generated_text[(size_t)generated_size] = '\0';
    CHECK(fclose(inspection) == 0);
    CHECK(strstr(generated_text, "Python.h") == NULL);
    CHECK(strstr(generated_text, "PyObject") == NULL);
    CHECK(strstr(generated_text, "Py_") == NULL);
    free(generated_text);
    command_status = system(
        "cc -std=c17 -Wall -Wextra -Wconversion -Werror "
        "-I\"" WRTC_NATIVE_COMPILER_SOURCE_DIR "\" "
        "/tmp/wrtc_native_kernel_generated.c -o "
        "/tmp/wrtc_native_kernel_generated && "
        "/tmp/wrtc_native_kernel_generated");
    CHECK(command_status == 0);
    wrtc_native_class_free(program);
    program = NULL;
    CHECK(wrtc_native_class_analyze(rejected_source, strlen(rejected_source),
                                    "rejected_kernel.py", &program) == 0);
    CHECK(program != NULL && program->class_count == 1u);
    CHECK(!program->classes[0].regions[0].kernel_emission_complete);
    CHECK(strstr(program->classes[0].regions[0].kernel_rejection_reason,
                 "exact required native-region call") != NULL);
    CHECK(program->classes[0].regions[0].kernel_rejection_span.line == 7);
    CHECK(!program->classes[0].regions[1].kernel_emission_complete);
    CHECK(strstr(program->classes[0].regions[1].kernel_rejection_reason,
                 "Python objects or allocation") != NULL);
    CHECK(program->classes[0].regions[1].kernel_emitted_statement_count == 0u);
    wrtc_native_class_free(program);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
