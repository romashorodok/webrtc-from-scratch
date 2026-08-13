#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_class.h"
#include "native_operation.h"

#ifndef WRTC_LOOP_SOURCE
#error "WRTC_LOOP_SOURCE is required"
#endif
#ifndef WRTC_SCHEDULER_SOURCE
#error "WRTC_SCHEDULER_SOURCE is required"
#endif

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "check failed at %s:%d: %s\n", \
                  __FILE__, __LINE__, #value); \
    if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static char *read_source(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    long end;
    char *source;
    if (file == NULL || fseek(file, 0, SEEK_END) != 0 ||
        (end = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0)
        return NULL;
    source = malloc((size_t)end + 1u);
    if (source == NULL) {
        (void)fclose(file);
        return NULL;
    }
    if (fread(source, 1u, (size_t)end, file) != (size_t)end) {
        free(source);
        (void)fclose(file);
        return NULL;
    }
    source[end] = '\0';
    *length = (size_t)end;
    (void)fclose(file);
    return source;
}

static const WrtcNativeFieldIR *operation_field(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *table,
    const WrtcNativeOperationIR *operation) {
    const WrtcNativeFieldOperationProof *proof =
        &table->fields[operation->field_proof_index];
    return &program->classes[proof->class_index].fields[proof->field_index];
}

static int fixture_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import heapq\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Vessel:\n"
        "    queue: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('one')]\n"
        "    agenda: Annotated[object, "
        "pymeta.storage.min_heap(key='key', ordering='heapq') | "
        "pymeta.owned_by('one')]\n"
        "    tally: Annotated[int, pymeta.storage.native_field | "
        "pymeta.owned_by('one')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def cycle(self, value):\n"
        "        local_agenda = self.agenda\n"
        "        if self.queue:\n"
        "            value = self.queue.popleft()\n"
        "        self.queue.append(value)\n"
        "        count = len(self.queue)\n"
        "        root = local_agenda[0]\n"
        "        retained = []\n"
        "        local_agenda[:] = retained\n"
        "        heapq.heapify(local_agenda)\n"
        "        heapq.heappush(local_agenda, root)\n"
        "        root = heapq.heappop(local_agenda)\n"
        "        self.tally += count\n"
        "        count = self.tally\n"
        "        self.tally = count\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *table = NULL;
    size_t index;
    unsigned seen = 0u;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, "renamed_fixture.py",
              &program) == 0);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    if (table != NULL && !table->complete)
        for (index = 0u; index < table->operation_count; index++)
            if (table->operations[index].kind ==
                WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE) {
                const WrtcNativeFieldIR *field =
                    operation_field(program, table,
                                    &table->operations[index]);
                (void)fprintf(
                    stderr, "unsupported %s at %d:%d: %s\n", field->name,
                    table->operations[index].span.line,
                    table->operations[index].span.column,
                    table->operations[index].detail);
            }
    CHECK(table != NULL && table->complete);
    CHECK(table->field_count == 3u);
    for (index = 0u; index < table->field_count; index++)
        CHECK(table->fields[index].touched &&
              table->fields[index].complete);
    for (index = 0u; index < table->operation_count; index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        CHECK(operation->evaluation_order == index);
        CHECK(operation->span.line > 0);
        CHECK(operation->has_exception_edge);
        if (operation->kind == WRTC_NATIVE_OP_LENGTH)
            CHECK(operation->result_representation ==
                  WRTC_NATIVE_REPR_PY_SSIZE_T);
        if (operation->kind == WRTC_NATIVE_OP_TRUTH)
            CHECK(operation->result_representation ==
                  WRTC_NATIVE_REPR_BOOL);
        if (operation->kind == WRTC_NATIVE_OP_ROOT_READ) {
            CHECK(operation->result_representation ==
                  WRTC_NATIVE_REPR_BORROWED_PYOBJECT);
            CHECK(operation->result_ownership ==
                  WRTC_NATIVE_OWNERSHIP_BORROWED);
            CHECK(operation->result_nullable);
        }
        if (operation->kind == WRTC_NATIVE_OP_FIFO_POPLEFT ||
            operation->kind == WRTC_NATIVE_OP_HEAP_POP) {
            CHECK(operation->result_representation ==
                  WRTC_NATIVE_REPR_OWNED_PYOBJECT);
            CHECK(operation->result_ownership ==
                  WRTC_NATIVE_OWNERSHIP_OWNED);
        }
        seen |= 1u << (unsigned)operation->kind;
    }
    CHECK((seen & (1u << WRTC_NATIVE_OP_ALIAS_BIND)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_FIFO_APPEND)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_FIFO_POPLEFT)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_LENGTH)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_TRUTH)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_ROOT_READ)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_SLICE_ASSIGN)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_HEAPIFY)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_HEAP_PUSH)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_HEAP_POP)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_SCALAR_READ)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_SCALAR_WRITE)) != 0u);
    CHECK((seen & (1u << WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE)) != 0u);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    return 0;
}

static int rejection_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Holder:\n"
        "    work: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('one')]\n"
        "    spare: Annotated[int, pymeta.storage.native_field | "
        "pymeta.owned_by('one')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def expose(self, flag):\n"
        "        alias = self.work\n"
        "        if flag:\n"
        "            alias = []\n"
        "        return len(alias)\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *table = NULL;
    size_t index;
    int rejected = 0;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, "escape_fixture.py",
              &program) == 0);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    CHECK(table != NULL && !table->complete);
    CHECK(table->field_count == 2u && !table->fields[0].complete);
    CHECK(!table->fields[1].touched && !table->fields[1].complete);
    for (index = 0u; index < table->operation_count; index++)
        if (table->operations[index].kind ==
            WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE) {
            CHECK(table->operations[index].detail != NULL);
            rejected = 1;
        }
    CHECK(rejected);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    return 0;
}

static int invalid_call_shape_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import heapq\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Holder:\n"
        "    work: Annotated[object, pymeta.storage.fifo | "
        "pymeta.owned_by('one')]\n"
        "    timers: Annotated[object, "
        "pymeta.storage.min_heap(key='key', ordering='heapq') | "
        "pymeta.owned_by('one')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def invalid(self, value):\n"
        "        self.work.append()\n"
        "        heapq.heappush(self.timers)\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *table = NULL;
    size_t index;
    size_t rejected = 0u;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, "invalid_calls.py",
              &program) == 0);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    CHECK(table != NULL && !table->complete);
    for (index = 0u; index < table->operation_count; index++)
        if (table->operations[index].kind ==
            WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE) {
            CHECK(table->operations[index].detail != NULL);
            CHECK(strstr(table->operations[index].detail,
                         "shape") != NULL ||
                  strstr(table->operations[index].detail,
                         "method") != NULL);
            rejected++;
        }
    CHECK(rejected == 2u);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    return 0;
}

static int atomic_rejection_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "from pymeta.concurrent import atomic\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class InvalidOwner:\n"
        "    state: Annotated[object, atomic[pymeta.uint[32]] | "
        "pymeta.owned_by('reactor')]\n"
        "    wide: Annotated[object, atomic[pymeta.uint[64]] | "
        "pymeta.owned_by('shared')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def transition(self):\n"
        "        previous, changed = self.state.compare_exchange(0, 1)\n"
        "        return changed\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def wide_transition(self):\n"
        "        _, changed = self.wide.compare_exchange(0, 1)\n"
        "        return changed\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *table = NULL;
    size_t index;
    unsigned shape_rejected = 0u, ownership_rejected = 0u;
    unsigned width_rejected = 0u;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, "atomic_rejection.py",
              &program) == 0);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    CHECK(table != NULL && !table->complete);
    CHECK(table->field_count == 2u);
    for (index = 0u; index < table->operation_count; index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        if (operation->kind != WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE)
            continue;
        CHECK(operation->detail != NULL);
        if (strstr(operation->detail, "owned_by('shared')") != NULL)
            ownership_rejected = 1u;
        if (strstr(operation->detail, "discarding") != NULL)
            shape_rejected = 1u;
        if (strstr(operation->detail, "uint[32]") != NULL)
            width_rejected = 1u;
    }
    CHECK(ownership_rejected && shape_rejected && width_rejected);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    return 0;
}

static int mpsc_operation_test(void) {
    static const char source[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Inbox:\n"
        "    queue: Annotated[object, pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='config.capacity') | "
        "pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def operations(self, item):\n"
        "        self.queue.put_nowait(item)\n"
        "        size = self.queue.qsize()\n"
        "        if not self.queue.empty():\n"
        "            return self.queue.get_nowait()\n"
        "        return size\n";
    static const char rejected_source[] =
        "from typing import Annotated\n"
        "import pymeta\n"
        "@pymeta.native_class(pymeta.compact_object, "
        "gc=pymeta.tracked, weakrefs=False)\n"
        "class Inbox:\n"
        "    queue: Annotated[object, pymeta.mpsc | "
        "pymeta.bounded_queue(capacity='config.capacity') | "
        "pymeta.owned_by('reactor')]\n"
        "    @pymeta.region(pymeta.required)\n"
        "    def unsupported(self, item):\n"
        "        self.queue.put(item)\n";
    WrtcNativeClassProgram *program = NULL;
    WrtcNativeOperationTable *table = NULL;
    unsigned seen[4] = {0u, 0u, 0u, 0u};
    size_t index;
    CHECK(wrtc_native_class_analyze(
              source, sizeof source - 1u, "mpsc_operations.py",
              &program) == 0);
    CHECK(program->classes[0].fields[0].storage_kind ==
          WRTC_NATIVE_FIELD_MPSC);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    CHECK(table != NULL && table->complete);
    for (index = 0u; index < table->operation_count; index++) {
        const WrtcNativeOperationKind kind = table->operations[index].kind;
        if (kind >= WRTC_NATIVE_OP_MPSC_PUT_NOWAIT &&
            kind <= WRTC_NATIVE_OP_MPSC_EMPTY)
            seen[(size_t)kind -
                 (size_t)WRTC_NATIVE_OP_MPSC_PUT_NOWAIT]++;
    }
    CHECK(seen[0] == 1u && seen[1] == 1u &&
          seen[2] == 1u && seen[3] == 1u);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    table = NULL;
    program = NULL;

    CHECK(wrtc_native_class_analyze(
              rejected_source, sizeof rejected_source - 1u,
              "mpsc_rejected.py", &program) == 0);
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    CHECK(table != NULL && !table->complete);
    CHECK(table->operation_count == 1u);
    CHECK(table->operations[0].kind ==
          WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    return 0;
}

static int scheduler_test(void) {
    char *loop_source, *scheduler_source;
    size_t loop_length, scheduler_length, index;
    WrtcNativeClassProgram *program = NULL, *scheduler = NULL;
    WrtcNativeOperationTable *table = NULL;
    unsigned ready = 0u, scheduled = 0u, scalar = 0u, atomic = 0u;
    loop_source = read_source(WRTC_LOOP_SOURCE, &loop_length);
    scheduler_source =
        read_source(WRTC_SCHEDULER_SOURCE, &scheduler_length);
    CHECK(loop_source != NULL && scheduler_source != NULL);
    CHECK(wrtc_native_class_analyze(
              loop_source, loop_length, WRTC_LOOP_SOURCE, &program) == 0);
    CHECK(wrtc_native_class_analyze(
              scheduler_source, scheduler_length, WRTC_SCHEDULER_SOURCE,
              &scheduler) == 0);
    CHECK(wrtc_native_class_merge(program, scheduler) == 0);
    wrtc_native_class_free(scheduler);
    scheduler = NULL;
    CHECK(wrtc_native_operation_prove(program, &table) == 0);
    if (table != NULL && !table->complete)
        for (index = 0u; index < table->operation_count; index++)
            if (table->operations[index].kind ==
                WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE) {
                const WrtcNativeFieldIR *field =
                    operation_field(program, table,
                                    &table->operations[index]);
                (void)fprintf(
                    stderr, "unsupported %s at %d:%d: %s\n", field->name,
                    table->operations[index].span.line,
                    table->operations[index].span.column,
                    table->operations[index].detail);
            }
    CHECK(table != NULL && table->complete);
    CHECK(table->field_count == 5u);
    for (index = 0u; index < table->operation_count; index++) {
        const WrtcNativeOperationIR *operation = &table->operations[index];
        const WrtcNativeFieldIR *field =
            operation_field(program, table, operation);
        if (strcmp(field->name, "_ready") == 0) {
            ready++;
            CHECK(operation->kind == WRTC_NATIVE_OP_TRUTH ||
                  operation->kind == WRTC_NATIVE_OP_LENGTH ||
                  operation->kind == WRTC_NATIVE_OP_FIFO_APPEND ||
                  operation->kind == WRTC_NATIVE_OP_FIFO_POPLEFT);
        } else if (strcmp(field->name, "_scheduled") == 0) {
            scheduled++;
            CHECK(operation->kind == WRTC_NATIVE_OP_ALIAS_BIND ||
                  operation->kind == WRTC_NATIVE_OP_TRUTH ||
                  operation->kind == WRTC_NATIVE_OP_LENGTH ||
                  operation->kind == WRTC_NATIVE_OP_ROOT_READ ||
                  operation->kind == WRTC_NATIVE_OP_ITERATE ||
                  operation->kind == WRTC_NATIVE_OP_SLICE_ASSIGN ||
                  operation->kind == WRTC_NATIVE_OP_HEAPIFY ||
                  operation->kind == WRTC_NATIVE_OP_HEAP_PUSH ||
                  operation->kind == WRTC_NATIVE_OP_HEAP_POP ||
                  operation->kind == WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED);
        } else if (strcmp(field->name, "_state") == 0) {
            atomic++;
            CHECK(operation->kind ==
                  WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE);
        } else {
            scalar++;
            CHECK(operation->kind == WRTC_NATIVE_OP_SCALAR_READ ||
                  operation->kind == WRTC_NATIVE_OP_SCALAR_WRITE ||
                  operation->kind ==
                      WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE);
        }
    }
    CHECK(ready >= 6u && scheduled >= 10u && scalar >= 4u);
    CHECK(atomic == 3u);
    wrtc_native_operation_table_free(table);
    wrtc_native_class_free(program);
    free(scheduler_source);
    free(loop_source);
    return 0;
}

int main(void) {
    Py_Initialize();
    CHECK(fixture_test() == 0);
    CHECK(rejection_test() == 0);
    CHECK(invalid_call_shape_test() == 0);
    CHECK(atomic_rejection_test() == 0);
    CHECK(mpsc_operation_test() == 0);
    CHECK(scheduler_test() == 0);
    CHECK(Py_FinalizeEx() == 0);
    return 0;
}
