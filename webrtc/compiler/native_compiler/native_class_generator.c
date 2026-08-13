#include "native_class_generator.h"
#include "aot_codegen.h"
#include "boxed_codegen.h"
#include "boxed_module.h"
#include "native_operation.h"
#include "native_kernel.h"
#include "native_reactor.h"
#include "native_reactor_codegen.h"
#include "native_storage.h"
#include "native_storage_codegen.h"
#include "native_worker_codegen.h"

#include <stdlib.h>
#include <string.h>

static int quote(FILE *file, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (fputc('"', file) == EOF) return -1;
    while (*cursor != 0u) {
        unsigned char ch = *cursor++;
        if (ch == '\\' || ch == '"') {
            if (fputc('\\', file) == EOF) return -1;
        }
        if (ch == '\n') {
            if (fputs("\\n", file) < 0) return -1;
        } else if (ch == '\r') {
            if (fputs("\\r", file) < 0) return -1;
        } else if (ch < 32u || ch > 126u) {
            if (fprintf(file, "\\%03o", (unsigned)ch) < 0) return -1;
        } else if (fputc((int)ch, file) == EOF) {
            return -1;
        }
    }
    return fputc('"', file) == EOF ? -1 : 0;
}

static int compatible_base(const char *base) {
    return base == NULL || strcmp(base, "object") == 0 ||
           strcmp(base, "builtins.object") == 0 || strchr(base, '.') != NULL;
}

static int object_base(const char *base) {
    return base == NULL || strcmp(base, "object") == 0 ||
           strcmp(base, "builtins.object") == 0;
}

static int class_has_globals(const WrtcNativeClassIR *class_ir) {
    /* Every emitted type needs its live defining-module dictionary so that
     * guarded class-global substitution can compare against the original
     * source type instead of freezing a copied global. */
    return class_ir != NULL;
}

static int emit_python_method_fallback_copy(
    FILE *file, const WrtcNativeClassIR *class_ir, size_t class_index) {
    size_t index;
    if (fprintf(
            file,
            "static int pm%zu(PyObject*d,PyObject*s){PyObject*m=NULL,*items=NULL;"
            "Py_ssize_t i,n;if(!d||!s)return -1;m=PyObject_GetAttrString(s,"
            "\"__dict__\");if(!m)return -1;items=PyMapping_Items(m);"
            "Py_DECREF(m);if(!items)return -1;n=PyList_GET_SIZE(items);"
            "for(i=0;i<n;i++){PyObject*p=PyList_GET_ITEM(items,i),"
            "*k=PyTuple_GET_ITEM(p,0),*v=PyTuple_GET_ITEM(p,1);"
            "const char*z;if(!PyUnicode_CheckExact(k))continue;"
            "z=PyUnicode_AsUTF8(k);if(!z){Py_DECREF(items);return -1;}"
            "if((z[0]=='_'&&z[1]=='_')",
            class_index) < 0)
        return -1;
    for (index = 0u; index < class_ir->field_count; index++)
        if (fputs("||strcmp(z,", file) < 0 ||
            quote(file, class_ir->fields[index].name) < 0 ||
            fputs(")==0", file) < 0)
            return -1;
    for (index = 0u; index < class_ir->region_count; index++)
        if (fputs("||strcmp(z,", file) < 0 ||
            quote(file, class_ir->regions[index].name) < 0 ||
            fputs(")==0", file) < 0)
            return -1;
    return fputs(
               ")continue;if(PyDict_SetItem(PyType_GetDict((PyTypeObject*)d),k,v)<0){Py_DECREF(items);"
               "return -1;}}Py_DECREF(items);PyType_Modified((PyTypeObject*)d);"
               "return 0;}\n",
               file) < 0
               ? -1
               : 0;
}

static int program_has_constructors(
    const WrtcNativeClassProgram *program) {
    size_t index;
    for (index = 0u; index < program->class_count; index++)
        if (program->classes[index].custom_constructor) return 1;
    return 0;
}

static int program_has_workers(const WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if ((program->classes[class_index].regions[region_index]
                     .capabilities & WRTC_REGION_OWNED_SHARD) != 0u)
                return 1;
    return 0;
}

static const WrtcNativeRegionIR *owned_worker_region(
    const WrtcNativeClassIR *class_ir, size_t *region_index) {
    size_t index;
    for (index = 0u; index < class_ir->region_count; index++)
        if ((class_ir->regions[index].capabilities & WRTC_REGION_OWNED_SHARD) != 0u) {
            if (region_index != NULL) *region_index = index;
            return &class_ir->regions[index];
        }
    return NULL;
}

static size_t worker_queue_field(const WrtcNativeClassIR *class_ir,
                                 const char *owner) {
    size_t index;
    for (index = 0u; index < class_ir->field_count; index++)
        if (class_ir->fields[index].storage_kind == WRTC_NATIVE_FIELD_SPSC &&
            class_ir->fields[index].owner != NULL &&
            strcmp(class_ir->fields[index].owner, owner) == 0)
            return index;
    return SIZE_MAX;
}

static const WrtcPyExprIR *assignment_target_for_rhs(
    const WrtcPySuiteIR *suite, const char *rhs_name) {
    size_t index;
    if (suite == NULL) return NULL;
    for (index = 0u; index < suite->statement_count; index++) {
        const WrtcPyStmtIR *statement = &suite->statements[index];
        const WrtcPyExprIR *rhs;
        if (statement->kind != WRTC_PY_STMT_ASSIGN ||
            statement->expression_count < 2u) continue;
        rhs = &statement->expressions[0];
        if (rhs->kind == WRTC_PY_EXPR_NAME && rhs->operation != NULL &&
            strcmp(rhs->operation, rhs_name) == 0)
            return &statement->expressions[1];
    }
    return NULL;
}

static const WrtcPyExprIR *worker_thread_target(
    const WrtcNativeClassIR *class_ir) {
    size_t index;
    const WrtcPySuiteIR *suite = class_ir->constructor_body;
    if (suite == NULL) return NULL;
    for (index = 0u; index < suite->statement_count; index++) {
        const WrtcPyStmtIR *statement = &suite->statements[index];
        const WrtcPyExprIR *rhs, *callee;
        if (statement->kind != WRTC_PY_STMT_ASSIGN ||
            statement->expression_count < 2u) continue;
        rhs = &statement->expressions[0];
        if (rhs->kind != WRTC_PY_EXPR_CALL || rhs->child_count == 0u) continue;
        callee = &rhs->children[0];
        if (callee->kind == WRTC_PY_EXPR_ATTRIBUTE && callee->operation != NULL &&
            strcmp(callee->operation, "Thread") == 0)
            return &statement->expressions[1];
    }
    return NULL;
}

static size_t class_field_index(const WrtcNativeClassIR *class_ir,
                                const char *name) {
    size_t index;
    for (index = 0u; index < class_ir->field_count; index++)
        if (strcmp(class_ir->fields[index].name, name) == 0) return index;
    return SIZE_MAX;
}

static size_t worker_processor_field(const WrtcNativeClassIR *class_ir) {
    size_t index;
    const WrtcPySignatureIR *signature = class_ir->constructor_signature;
    if (signature == NULL) return SIZE_MAX;
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcPyParameterIR *parameter = &signature->parameters[index];
        const WrtcPyExprIR *target;
        if ((parameter->annotation == NULL ||
             strstr(parameter->annotation, "Callable") == NULL ||
             strstr(parameter->annotation, "None") == NULL) &&
            (!parameter->has_default || parameter->default_expression == NULL ||
             strcmp(parameter->default_expression, "None") != 0)) continue;
        target = assignment_target_for_rhs(class_ir->constructor_body,
                                           parameter->name);
        if (target != NULL && target->kind == WRTC_PY_EXPR_ATTRIBUTE &&
            target->operation != NULL)
            return class_field_index(class_ir, target->operation);
    }
    return SIZE_MAX;
}

static size_t worker_callback_field(const WrtcNativeClassIR *class_ir,
                                    size_t processor_field) {
    size_t index;
    const WrtcPySignatureIR *signature = class_ir->constructor_signature;
    if (signature == NULL) return SIZE_MAX;
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcPyParameterIR *parameter = &signature->parameters[index];
        const WrtcPyExprIR *target;
        size_t field;
        if (parameter->annotation == NULL ||
            strstr(parameter->annotation, "Callable") == NULL) continue;
        target = assignment_target_for_rhs(class_ir->constructor_body,
                                           parameter->name);
        if (target == NULL || target->kind != WRTC_PY_EXPR_ATTRIBUTE ||
            target->operation == NULL) continue;
        field = class_field_index(class_ir, target->operation);
        if (field != SIZE_MAX && field != processor_field) return field;
    }
    return SIZE_MAX;
}

static size_t worker_loop_field(const WrtcNativeClassIR *class_ir,
                                const WrtcNativeRegionIR *region) {
    const char *start, *end;
    char *name;
    size_t result;
    (void)class_ir;
    if (region == NULL || region->shard_workers == NULL ||
        strncmp(region->shard_workers, "self.", 5u) != 0) return SIZE_MAX;
    start = region->shard_workers + 5u;
    end = strchr(start, '.');
    if (end == NULL) end = start + strlen(start);
    name = malloc((size_t)(end - start) + 1u);
    if (name == NULL) return SIZE_MAX;
    memcpy(name, start, (size_t)(end - start));
    name[end - start] = '\0';
    result = class_field_index(class_ir, name);
    free(name);
    return result;
}

static size_t worker_thread_field(const WrtcNativeClassIR *class_ir) {
    const WrtcPyExprIR *target = worker_thread_target(class_ir);
    if (target == NULL || target->kind != WRTC_PY_EXPR_ATTRIBUTE ||
        target->operation == NULL) return SIZE_MAX;
    return class_field_index(class_ir, target->operation);
}

static const WrtcTypedRecordIR *generated_record_type(
    const WrtcNativeClassProgram *, const char *, size_t *);
static const WrtcTypedRecordIR *worker_input_record_generated(
    const WrtcNativeClassProgram *, const WrtcNativeRegionIR *, size_t *);

static size_t worker_capacity_field(const WrtcNativeClassIR *class_ir,
                                    size_t input_field) {
    const char *path, *name;
    if (input_field >= class_ir->field_count) return SIZE_MAX;
    path = class_ir->fields[input_field].queue_capacity;
    if (path == NULL || strncmp(path, "self.", 5u) != 0 ||
        strchr(path + 5u, '.') != NULL) return SIZE_MAX;
    name = path + 5u;
    return class_field_index(class_ir, name);
}

static int worker_attachment_shape(
    const WrtcNativeClassProgram *program,
    const WrtcNativeClassIR *class_ir) {
    const WrtcNativeRegionIR *region = owned_worker_region(class_ir, NULL);
    size_t input_field, output_field, processor_field;
    if (region == NULL) return 1;
    input_field = worker_queue_field(class_ir, "worker");
    output_field = worker_queue_field(class_ir, "reactor");
    processor_field = worker_processor_field(class_ir);
    return input_field != SIZE_MAX && output_field != SIZE_MAX &&
           worker_thread_field(class_ir) != SIZE_MAX &&
           worker_capacity_field(class_ir, input_field) != SIZE_MAX &&
           processor_field != SIZE_MAX &&
           worker_callback_field(class_ir, processor_field) != SIZE_MAX &&
           worker_loop_field(class_ir, region) != SIZE_MAX &&
           worker_input_record_generated(program, region, NULL) != NULL &&
           generated_record_type(program, region->result_type, NULL) != NULL;
}

static const WrtcTypedRecordIR *generated_record_type(
    const WrtcNativeClassProgram *program, const char *name,
    size_t *record_index) {
    size_t index;
    const char *short_name;
    if (name == NULL) return NULL;
    short_name = strrchr(name, '.');
    short_name = short_name == NULL ? name : short_name + 1;
    for (index = 0u; index < program->record_count; index++)
        if (strcmp(program->records[index].name, short_name) == 0) {
            if (record_index != NULL) *record_index = index;
            return &program->records[index];
        }
    return NULL;
}

static const WrtcTypedRecordIR *worker_input_record_generated(
    const WrtcNativeClassProgram *program,
    const WrtcNativeRegionIR *region, size_t *record_index) {
    size_t index;
    if (region == NULL || region->signature == NULL) return NULL;
    for (index = 0u; index < region->signature->parameter_count; index++) {
        const WrtcPyParameterIR *parameter =
            &region->signature->parameters[index];
        if (strcmp(parameter->name, "self") != 0)
            return generated_record_type(program, parameter->annotation,
                                         record_index);
    }
    return NULL;
}

static const char *worker_abi_kind(WrtcWorkerRecordFieldKind kind) {
    switch (kind) {
        case WRTC_WORKER_FIELD_UINT: return "WRTC_WORKER_ABI_UINT";
        case WRTC_WORKER_FIELD_SINT: return "WRTC_WORKER_ABI_SINT";
        case WRTC_WORKER_FIELD_FLOAT: return "WRTC_WORKER_ABI_FLOAT";
        case WRTC_WORKER_FIELD_READONLY_BUFFER:
            return "WRTC_WORKER_ABI_READONLY_BYTES";
        default: return NULL;
    }
}

static int emit_worker_abis(FILE *file,
                            const WrtcNativeClassProgram *program) {
    size_t record_index, field_index;
    for (record_index = 0u; record_index < program->record_count;
         record_index++) {
        const WrtcTypedRecordIR *record = &program->records[record_index];
        if (!record->worker_abi_eligible) continue;
        if (fprintf(file, "static const WrtcNativeWorkerAbiField waif%zu[]={",
                    record_index) < 0) return -1;
        for (field_index = 0u; field_index < record->field_count;
             field_index++) {
            const WrtcWorkerRecordFieldIR *field = &record->fields[field_index];
            const char *kind = worker_abi_kind(field->kind);
            if (kind == NULL || fputc('{', file) == EOF ||
                quote(file, field->name) < 0 ||
                fprintf(file, ",%s,%u},", kind, field->width) < 0)
                return -1;
        }
        if (fputs("};static const WrtcNativeWorkerAbi wai", file) < 0 ||
            fprintf(file, "%zu={", record_index) < 0 ||
            quote(file, record->abi) < 0 ||
            fprintf(file, ",waif%zu,%zu};", record_index,
                    record->field_count) < 0)
            return -1;
    }
    return fputc('\n', file) == EOF ? -1 : 0;
}

static int expression_has_super(const WrtcPyExprIR *expression) {
    size_t index;
    if (expression->kind == WRTC_PY_EXPR_CALL &&
        expression->child_count != 0u &&
        expression->children[0].kind == WRTC_PY_EXPR_NAME &&
        expression->children[0].text != NULL &&
        strcmp(expression->children[0].text, "super") == 0)
        return 1;
    for (index = 0u; index < expression->child_count; index++)
        if (expression_has_super(&expression->children[index])) return 1;
    return 0;
}

static int statements_have_super(const WrtcPyStmtIR *statements,
                                 size_t count) {
    size_t index, expression;
    for (index = 0u; index < count; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        for (expression = 0u; expression < statement->expression_count;
             expression++)
            if (expression_has_super(&statement->expressions[expression]))
                return 1;
        if (statements_have_super(statement->body, statement->body_count) ||
            statements_have_super(statement->orelse,
                                  statement->orelse_count) ||
            statements_have_super(statement->finalbody,
                                  statement->finalbody_count) ||
            statements_have_super(statement->handlers,
                                  statement->handler_count))
            return 1;
    }
    return 0;
}

static int mpsc_contract_complete(const WrtcNativeRegionIR *region) {
    if ((region->capabilities & WRTC_REGION_MPSC) == 0u) return 1;
    return region->queue_linearization_proven &&
           region->memory_ordering_proven &&
           region->producer_admission_proven &&
           region->producer_quiescence_proven &&
           region->reactor_dequeue_proven &&
           region->ownership_transfer_proven &&
           region->reclamation_proven &&
           region->full_queue_behavior_proven &&
           region->wakeup_coalescing_proven &&
           region->close_drain_order_proven &&
           region->shutdown_interaction_proven;
}

static int spsc_contract_complete(const WrtcNativeRegionIR *region) {
    if ((region->capabilities & WRTC_REGION_SPSC) == 0u) return 1;
    return region->queue_linearization_proven &&
           region->memory_ordering_proven &&
           region->producer_admission_proven &&
           region->producer_quiescence_proven &&
           region->ownership_transfer_proven &&
           region->reclamation_proven &&
           region->full_queue_behavior_proven &&
           region->close_drain_order_proven &&
           region->shutdown_interaction_proven &&
           region->typed_worker_records;
}

int wrtc_native_class_can_emit(const WrtcNativeClassProgram *program) {
    size_t class_index;
    WrtcNativeOperationTable *operations = NULL;
    int has_storage = 0;
    if (program == NULL || program->class_count == 0u)
        return 0;
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        const WrtcNativeClassIR *class_ir = &program->classes[class_index];
        size_t field_index;
        /*
         * Region signatures and environments are not complete in the IR yet.
         * Never manufacture a Python method or silently omit one.
         */
        if (!class_ir->compact_object || !class_ir->gc_tracked ||
            class_ir->weakrefs || class_ir->custom_new ||
            class_ir->region_count == 0u ||
            (class_ir->custom_constructor &&
             (class_ir->constructor_body == NULL ||
              class_ir->constructor_signature == NULL)) ||
            !compatible_base(class_ir->base)) {
            return 0;
        }
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++) {
            const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
            if (field->name == NULL ||
                (field->storage_kind != WRTC_NATIVE_FIELD_PYOBJECT &&
                 !wrtc_native_storage_field_eligible(field, NULL))) {
                return 0;
            }
            if (field->storage_kind != WRTC_NATIVE_FIELD_PYOBJECT)
                has_storage = 1;
        }
        for (field_index = 0u; field_index < class_ir->region_count;
             field_index++) {
            const WrtcNativeRegionIR *region =
                &class_ir->regions[field_index];
            /* An owned shard is emit-able only when its constructor fields,
             * typed records, queues, executor kernel, and reactor adapter can
             * all be connected structurally. */
            unsigned unsupported =
                worker_attachment_shape(program, class_ir)
                    ? 0u : WRTC_REGION_OWNED_SHARD;
            if ((region->capabilities & WRTC_REGION_PACKET_POOL) != 0u &&
                !region->reactor_hook_emission_complete)
                unsupported |= WRTC_REGION_PACKET_POOL;
            if (region->body == NULL || region->signature == NULL ||
                (region->capabilities & unsupported) != 0u ||
                ((region->selector_runtime_lowering_available ||
                  region->datagram_runtime_lowering_available) &&
                 !region->reactor_hook_emission_complete) ||
                (((region->capabilities & WRTC_REGION_OWNED_SHARD) != 0u) &&
                 !region->worker_emission_complete) ||
                !mpsc_contract_complete(region) ||
                (((region->capabilities & WRTC_REGION_OWNED_SHARD) == 0u) &&
                !spsc_contract_complete(region))) {
                return 0;
            }
        }
        if (class_ir->region_count != 0u) {
            char *module_name = wrtc_boxed_module_name(class_ir->filename);
            if (module_name == NULL) {
                PyErr_Clear();
                return 0;
            }
            free(module_name);
        }
    }
    for (class_index = 0u; class_index < program->factory_count;
         class_index++) {
        const WrtcNativeFactoryIR *factory =
            &program->factories[class_index];
        char *module_name;
        if (factory->name == NULL || factory->target_class == NULL ||
            factory->body == NULL || factory->signature == NULL ||
            statements_have_super(factory->body->statements,
                                  factory->body->statement_count)) {
            return 0;
        }
        module_name = wrtc_boxed_module_name(factory->filename);
        if (module_name == NULL) {
            PyErr_Clear();
            return 0;
        }
        free(module_name);
    }
    if (program->factory_name != NULL && program->factory_count == 0u) {
        return 0;
    }
    if (has_storage) {
        size_t proof_index;
        if (wrtc_native_operation_prove(program, &operations) < 0 ||
            operations == NULL || !operations->complete) {
            wrtc_native_operation_table_free(operations);
            PyErr_Clear();
            return 0;
        }
        for (proof_index = 0u; proof_index < operations->field_count;
             proof_index++)
            if (!operations->fields[proof_index].touched ||
                !operations->fields[proof_index].complete) {
                wrtc_native_operation_table_free(operations);
                return 0;
            }
        for (proof_index = 0u; proof_index < operations->operation_count;
             proof_index++) {
            const WrtcNativeOperationKind kind =
                operations->operations[proof_index].kind;
            if (kind != WRTC_NATIVE_OP_SCALAR_READ &&
                kind != WRTC_NATIVE_OP_SCALAR_WRITE &&
                kind != WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE &&
                kind != WRTC_NATIVE_OP_BOXED_WRITE &&
                kind != WRTC_NATIVE_OP_ALIAS_BIND &&
                kind != WRTC_NATIVE_OP_LENGTH &&
                kind != WRTC_NATIVE_OP_TRUTH &&
                kind != WRTC_NATIVE_OP_ROOT_READ &&
                kind != WRTC_NATIVE_OP_ITERATE &&
                kind != WRTC_NATIVE_OP_SLICE_ASSIGN &&
                kind != WRTC_NATIVE_OP_FIFO_APPEND &&
                kind != WRTC_NATIVE_OP_FIFO_POPLEFT &&
                kind != WRTC_NATIVE_OP_HEAPIFY &&
                kind != WRTC_NATIVE_OP_HEAP_PUSH &&
                kind != WRTC_NATIVE_OP_HEAP_POP &&
                kind != WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED &&
                kind != WRTC_NATIVE_OP_ATOMIC_LOAD &&
                kind != WRTC_NATIVE_OP_ATOMIC_STORE &&
                kind != WRTC_NATIVE_OP_MPSC_PUT_NOWAIT &&
                kind != WRTC_NATIVE_OP_MPSC_GET_NOWAIT &&
                kind != WRTC_NATIVE_OP_MPSC_QSIZE &&
                kind != WRTC_NATIVE_OP_MPSC_EMPTY &&
                kind != WRTC_NATIVE_OP_MPSC_CLOSE &&
                kind != WRTC_NATIVE_OP_SPSC_PUT_NOWAIT &&
                kind != WRTC_NATIVE_OP_SPSC_GET_NOWAIT &&
                kind != WRTC_NATIVE_OP_SPSC_QSIZE &&
                kind != WRTC_NATIVE_OP_SPSC_EMPTY &&
                kind != WRTC_NATIVE_OP_SPSC_CLOSE &&
                kind != WRTC_NATIVE_OP_SELECTOR_REGISTER &&
                kind != WRTC_NATIVE_OP_SELECTOR_IS_CURRENT &&
                kind != WRTC_NATIVE_OP_SELECTOR_OWNER &&
                kind != WRTC_NATIVE_OP_SELECTOR_REMOVE &&
                kind != WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE) {
                wrtc_native_operation_table_free(operations);
                return 0;
            }
        }
        for (class_index = 0u; class_index < program->class_count;
             class_index++) {
            size_t region_index;
            for (region_index = 0u;
                 region_index <
                     program->classes[class_index].region_count;
                 region_index++) {
                const WrtcNativeRegionIR *region =
                    &program->classes[class_index].regions[region_index];
                size_t operation_index;
                int lowered = 0;
                if ((region->capabilities &
                     (WRTC_REGION_ATOMIC |
                      WRTC_REGION_COMPARE_EXCHANGE)) == 0u)
                    continue;
                for (operation_index = 0u;
                     operation_index < operations->operation_count;
                     operation_index++)
                    if (operations->operations[operation_index]
                                .region_class_index == class_index &&
                        operations->operations[operation_index]
                                .region_index == region_index &&
                        (operations->operations[operation_index].kind ==
                             WRTC_NATIVE_OP_ATOMIC_LOAD ||
                         operations->operations[operation_index].kind ==
                             WRTC_NATIVE_OP_ATOMIC_STORE ||
                         operations->operations[operation_index].kind ==
                             WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE))
                        lowered = 1;
                if (!lowered) {
                    wrtc_native_operation_table_free(operations);
                    return 0;
                }
            }
        }
        wrtc_native_operation_table_free(operations);
    }
    return 1;
}

static int emit_field_decl(FILE *file, const WrtcNativeFieldIR *field,
                           size_t index) {
    (void)field;
    return fprintf(file, "PyObject*f%zu;", index) < 0 ? -1 : 0;
}

static const WrtcTypedRecordIR *queue_record(
    const WrtcNativeClassProgram *program,
    const WrtcNativeFieldIR *field) {
    const char *declared;
    size_t index;
    if (program == NULL || field == NULL || field->queue_item_type == NULL)
        return NULL;
    declared = strrchr(field->queue_item_type, '.');
    declared = declared == NULL ? field->queue_item_type : declared + 1;
    for (index = 0u; index < program->record_count; index++)
        if (strcmp(program->records[index].name, declared) == 0)
            return &program->records[index];
    return NULL;
}

static int emit_storage_accessor(FILE *file,
                                 const WrtcNativeClassProgram *program,
                                 size_t class_index,
                                 const WrtcNativeFieldIR *field,
                                 size_t field_index) {
    const int kind =
        field->storage_kind == WRTC_NATIVE_FIELD_SCALAR ? 1 :
        field->storage_kind == WRTC_NATIVE_FIELD_FIFO ? 2 :
        field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP ? 3 :
        field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32 ? 4 :
        field->storage_kind == WRTC_NATIVE_FIELD_MPSC ? 5 :
        field->storage_kind == WRTC_NATIVE_FIELD_SPSC ? 6 :
        field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR ? 7 : 8;
    if (fprintf(file,
                "static NSO**np%zu_%zu(PyObject*self){H%zu*d=(H%zu*)"
                "PyObject_GetTypeData(self,dt(self,%zu));return(NSO**)&d->f%zu;}"
                "static PyObject*ng%zu_%zu(PyObject*self,void*c){"
                "NSO*o=*np%zu_%zu(self);(void)c;if(!o){PyErr_SetString("
                "PyExc_AttributeError,",
                class_index, field_index, class_index, class_index,
                class_index, field_index, class_index, field_index,
                class_index, field_index) < 0 ||
        quote(file, field->name) < 0 ||
        fputs(");return NULL;}", file) < 0)
        return -1;
    if (kind == 1) {
        if (fputs("return wrtc_native_scalar_get(&o->u.s,", file) < 0 ||
            quote(file, field->name) < 0 || fputs(");}", file) < 0)
            return -1;
    } else if (kind == 2) {
        if (fputs("return wrtc_native_fifo_get(&o->u.f,", file) < 0 ||
            quote(file, field->name) < 0 || fputs(");}", file) < 0)
            return -1;
    } else if (kind == 3 &&
               (fputs("return wrtc_native_heap_get(&o->u.h,", file) < 0 ||
               quote(file, field->name) < 0 || fputs(");}", file) < 0)) {
        return -1;
    } else if (kind >= 4 && kind <= 8 &&
               fputs("return Py_NewRef((PyObject*)o);}", file) < 0) {
        return -1;
    }
    if (fprintf(file,
                "static int ns%zu_%zu(PyObject*self,PyObject*v,void*c){"
                "NSO**p=np%zu_%zu(self);NSO*o=*p;(void)c;if(!v){if(!o){"
                "PyErr_SetString(PyExc_AttributeError,",
                class_index, field_index, class_index, field_index) < 0 ||
        quote(file, field->name) < 0 ||
        fputs(");return -1;}", file) < 0)
        return -1;
    if (kind == 1) {
        if (fputs("if(wrtc_native_scalar_delete(&o->u.s,", file) < 0 ||
            quote(file, field->name) < 0 ||
            fputs(")<0)return -1;Py_CLEAR(*p);return 0;}if(!o){o=no(self,1);"
                  "if(!o)return -1;*p=o;}return "
                  "wrtc_native_scalar_set_boxed(&o->u.s,v);}", file) < 0)
            return -1;
    } else if (kind == 2) {
        if (fputs("if(wrtc_native_fifo_delete(&o->u.f,", file) < 0 ||
            quote(file, field->name) < 0 ||
            fputs(")<0)return -1;Py_CLEAR(*p);return 0;}if(!o){o=no(self,2);"
                  "if(!o)return -1;*p=o;return "
                  "wrtc_native_fifo_adopt_initial(&o->u.f,v);}return "
                  "wrtc_native_fifo_set_boxed(&o->u.f,v);}", file) < 0)
            return -1;
    } else if (kind == 3 &&
               (fputs("if(wrtc_native_heap_delete(&o->u.h,", file) < 0 ||
               quote(file, field->name) < 0 ||
               fputs(")<0)return -1;Py_CLEAR(*p);return 0;}if(!o){o=no(self,3);"
                     "if(!o)return -1;*p=o;return "
                     "wrtc_native_heap_adopt_initial(&o->u.h,v);}return "
                     "wrtc_native_heap_set_boxed(&o->u.h,v);}", file) < 0)) {
        return -1;
    } else if (kind == 4 &&
               fputs("wrtc_native_atomic_uint32_clear(&o->u.a);"
                     "Py_CLEAR(*p);return 0;}return nai(self,v,p);}",
                     file) < 0) {
        return -1;
    } else if (kind == 5 || kind == 6) {
        const WrtcTypedRecordIR *record = queue_record(program, field);
        char *record_module =
            record == NULL ? NULL : wrtc_boxed_module_name(record->filename);
        if (record == NULL || record_module == NULL) {
            free(record_module);
            return -1;
        }
        if (fputs(kind == 5
                      ? "wrtc_native_mpsc_clear(&o->u.m,nd,NULL);"
                        "Py_CLEAR(*p);return 0;}return nmq(self,v,p,5,"
                      : "wrtc_native_spsc_clear(&o->u.p,nd,NULL);"
                        "Py_CLEAR(*p);return 0;}return nmq(self,v,p,6,",
                  file) < 0 ||
            quote(file, field->queue_capacity) < 0 ||
            fputc(',', file) == EOF ||
            quote(file, record_module) < 0 ||
            fputc(',', file) == EOF ||
            quote(file, record->name) < 0 ||
            fputs(");}", file) < 0) {
            free(record_module);
            return -1;
        }
        free(record_module);
    } else if (kind == 7 || kind == 8) {
        if (fputs(kind == 7
                      ? "wrtc_native_selector_destroy(o->u.r);"
                      : "wrtc_native_packet_pool_destroy(o->u.b);",
                  file) < 0 ||
            fputs("o->u.r=NULL;Py_CLEAR(*p);return 0;}return nri(self,p,",
                  file) < 0 ||
            fprintf(file, "%d,", kind) < 0 ||
            quote(file, field->reactor_capacity) < 0 ||
            fputc(',', file) == EOF ||
            quote(file, field->packet_buffer_size == NULL
                            ? "0" : field->packet_buffer_size) < 0 ||
            fputs(");}", file) < 0)
            return -1;
    }
    return 0;
}

static int emit_span_test(FILE *file, WrtcSourceSpan span) {
    return fprintf(file,
                   "e->span.line==%d&&e->span.column==%d&&"
                   "e->span.end_line==%d&&e->span.end_column==%d",
                   span.line, span.column, span.end_line,
                   span.end_column) < 0 ? -1 : 0;
}

static size_t fused_call_count(const WrtcNativeClassProgram *program) {
    size_t class_index, region_index, call_index, count = 0u;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            for (call_index = 0u;
                 call_index <
                     program->classes[class_index].regions[region_index]
                         .call_count;
                 call_index++)
                if (program->classes[class_index]
                        .regions[region_index].calls[call_index].fused)
                    count++;
    return count;
}

static size_t emitted_region_count(const WrtcNativeClassProgram *program) {
    size_t class_index, count = 0u;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        count += program->classes[class_index].region_count;
    return count;
}

static size_t region_manifest_index(const WrtcNativeClassProgram *program,
                                    size_t wanted_class,
                                    size_t wanted_region) {
    size_t class_index, region_index, index = 0u;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++, index++)
            if (class_index == wanted_class && region_index == wanted_region)
                return index;
    return (size_t)-1;
}

static int region_has_native_operations(
    const WrtcNativeOperationTable *operations, size_t class_index,
    size_t region_index) {
    size_t index;
    if (operations == NULL) return 0;
    for (index = 0u; index < operations->operation_count; index++)
        if (operations->operations[index].region_class_index == class_index &&
            operations->operations[index].region_index == region_index)
            return 1;
    return 0;
}

static size_t call_graph_manifest_count(
    const WrtcNativeClassProgram *program) {
    size_t class_index, region_index, count = emitted_region_count(program);
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            count += program->classes[class_index].regions[region_index]
                         .call_count;
    return count;
}

static size_t fused_call_index(const WrtcNativeClassProgram *program,
                               size_t wanted_class, size_t wanted_region,
                               size_t wanted_call) {
    size_t class_index, region_index, call_index, count = 0u;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            for (call_index = 0u;
                 call_index <
                     program->classes[class_index].regions[region_index]
                         .call_count;
                 call_index++) {
                const WrtcNativeCallEdgeIR *edge =
                    &program->classes[class_index]
                         .regions[region_index].calls[call_index];
                if (class_index == wanted_class &&
                    region_index == wanted_region &&
                    call_index == wanted_call)
                    return count;
                if (edge->fused) count++;
            }
    return (size_t)-1;
}

static int emit_fused_call_case(
    FILE *file, const WrtcNativeCallEdgeIR *edge, size_t fusion_index) {
    const char *method;
    if (!edge->fused || edge->target == NULL) return 0;
    method = strrchr(edge->target, '.');
    method = method == NULL ? edge->target : method + 1;
    if (fputs("if(", file) < 0 ||
        emit_span_test(file, edge->span) < 0 ||
        fputs("){PyObject*recv=NULL,*callable=NULL,*result=NULL,*current,"
              "*original,*small[8]={0},**av=small;PyTypeObject*expected;"
              "size_t i,ac=e->positional_count+e->keyword_count;"
              "int direct=0;*h=1;"
              "if(e->kind!=WRTC_PY_EXPR_CALL||e->child_count==0u||"
              "e->children[0].kind!=WRTC_PY_EXPR_ATTRIBUTE||"
              "e->children[0].child_count==0u){PyErr_SetString("
              "PyExc_SystemError,\"invalid fused call IR\");return NULL;}"
              "recv=wrtc_boxed_hook_evaluate("
              "&e->children[0].children[0],f);if(!recv)return NULL;"
              "callable=PyObject_GetAttrString(recv,",
              file) < 0 ||
        quote(file, method) < 0 ||
        fputs(");if(callable){wrtc_native_allocation_alloc("
              "WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);"
              "wrtc_native_allocation_free("
              "WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);}"
              "if(!callable)goto done", file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs(
              "expected=dt((PyObject*)c,",
              file) < 0 ||
        fprintf(file, "%zu);if(!expected)goto done%zu;"
                      "original=fd((PyObject*)c,%zu);"
                      "current=PyDict_GetItemString(PyType_GetDict(expected),",
                edge->target_class, fusion_index, fusion_index) < 0 ||
        quote(file, method) < 0 ||
        fputs(");direct=Py_TYPE(recv)==expected&&current==original&&"
              "PyCFunction_Check(callable)&&"
              "PyCFunction_GetSelf(callable)==recv&&"
              "PyCFunction_GetFunction(callable)=="
              "(PyCFunction)(void(*)(void))w",
              file) < 0 ||
        fprintf(file, "%zu_%zu;"
                      "if(ac>8u){av=PyMem_Calloc(ac,sizeof(*av));"
                      "if(!av){PyErr_NoMemory();goto done%zu;}"
                      "wrtc_native_allocation_alloc("
                      "WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);}",
                edge->target_class, edge->target_region, fusion_index) < 0 ||
        fputs(
              "for(i=0u;i<ac;i++){PyObject*v="
              "wrtc_boxed_hook_evaluate(&e->children[1u+i],f);"
              "if(!v)goto done",
              file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs("av[i]=v;}"
              "if(!direct){wrtc_native_allocation_alloc("
              "WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);"
              "wrtc_native_allocation_pause();result=PyObject_Vectorcall("
              "callable,av,e->positional_count,e->cached_keyword_names);"
              "wrtc_native_allocation_resume();wrtc_native_allocation_free("
              "WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);}else "
              "result=w",
              file) < 0 ||
        fprintf(file, "%zu_%zu(recv,av,(Py_ssize_t)e->positional_count,"
                      "e->cached_keyword_names);done%zu:"
                      "for(i=0u;i<ac;i++)Py_XDECREF(av[i]);"
                      "if(av!=small){wrtc_native_allocation_free("
                      "WRTC_NATIVE_ALLOC_ARGUMENT_VECTOR_OVERFLOW);"
                      "PyMem_Free(av);}Py_XDECREF(callable);"
                      "Py_XDECREF(recv);return result;}",
                edge->target_class, edge->target_region,
                fusion_index) < 0)
        return -1;
    return 0;
}

static int emit_reactor_call_case(FILE *file,
                                  const WrtcNativeCallEdgeIR *edge,
                                  size_t hook_index) {
    const char *method;
    if (edge == NULL || edge->reactor_hook == WRTC_REACTOR_HOOK_NONE ||
        !edge->reactor_hook_shape_proven || edge->target == NULL)
        return 0;
    method = strrchr(edge->target, '.');
    method = method == NULL ? edge->target : method + 1;
    if (fputs("if(e->kind==WRTC_PY_EXPR_CALL&&e->child_count>0u&&"
              "e->children[0].kind==WRTC_PY_EXPR_ATTRIBUTE&&"
              "e->children[0].child_count==1u&&"
              "e->children[0].operation!=NULL&&strcmp("
              "e->children[0].operation,",
              file) < 0 ||
        quote(file, method) < 0 ||
        fprintf(file,
                ")==0&&e->positional_count==%zuu&&"
                "e->keyword_count==0u){PyObject*recv=NULL,*callable=NULL,"
                "*args=NULL,*kwargs=NULL,*result=NULL;size_t i;*h=1;"
                "recv=wrtc_boxed_hook_evaluate("
                "&e->children[0].children[0],f);if(!recv)return NULL;"
                "callable=PyObject_GetAttrString(recv,",
                edge->positional_count) < 0 ||
        quote(file, method) < 0 ||
        fprintf(file,
                ");if(callable){wrtc_native_allocation_alloc("
                "WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);"
                "wrtc_native_allocation_free("
                "WRTC_NATIVE_ALLOC_ATTRIBUTE_OR_BOUND_METHOD);}"
                "if(!callable)goto rdone%zu;args=PyTuple_New(%zu);"
                "if(args)wrtc_native_allocation_alloc("
                "WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);kwargs=PyDict_New();"
                "if(kwargs)wrtc_native_allocation_alloc("
                "WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);"
                "if(!args||!kwargs)goto rdone%zu;"
                "for(i=0u;i<e->positional_count;i++){PyObject*v="
                "wrtc_boxed_hook_evaluate(&e->children[1u+i],f);"
                "if(!v)goto rdone%zu;PyTuple_SET_ITEM(args,(Py_ssize_t)i,v);}"
                "wrtc_native_allocation_pause();result=wrtc_reactor_guarded_call("
                "callable,args,kwargs);wrtc_native_allocation_resume();"
                "rdone%zu:if(kwargs)wrtc_native_allocation_free("
                "WRTC_NATIVE_ALLOC_KEYWORD_DICTIONARY);"
                "if(args)wrtc_native_allocation_free("
                "WRTC_NATIVE_ALLOC_TEMPORARY_TUPLE);"
                "Py_XDECREF(kwargs);Py_XDECREF(args);"
                "Py_XDECREF(callable);Py_XDECREF(recv);return result;}",
                hook_index, edge->positional_count, hook_index,
                hook_index, hook_index) < 0)
        return -1;
    return 0;
}

static int emit_region_hooks(
    FILE *file, const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *table, size_t class_index,
    size_t region_index) {
    size_t operation_index;
    const WrtcNativeRegionIR *region =
        &program->classes[class_index].regions[region_index];
    if (fprintf(file,
                "static PyObject*ne%zu_%zu(void*c,const WrtcPyExprIR*e,"
                "void*f,int*h){(void)c;(void)e;(void)f;*h=0;",
                class_index, region_index) < 0)
        return -1;
    for (operation_index = 0u;
         table != NULL && operation_index < table->operation_count;
         operation_index++) {
        const WrtcNativeOperationIR *operation =
            &table->operations[operation_index];
        const WrtcNativeFieldOperationProof *proof;
        const WrtcNativeFieldIR *field;
        const char *runtime_expression = NULL;
        if (operation->region_class_index != class_index ||
            operation->region_index != region_index)
            continue;
        proof = &table->fields[operation->field_proof_index];
        field = &program->classes[proof->class_index]
                     .fields[proof->field_index];
        switch (operation->kind) {
            case WRTC_NATIVE_OP_ALIAS_BIND:
            case WRTC_NATIVE_OP_TRUTH:
            case WRTC_NATIVE_OP_ITERATE:
                runtime_expression = "e";
                break;
            case WRTC_NATIVE_OP_SCALAR_READ:
                runtime_expression = "e";
                break;
            case WRTC_NATIVE_OP_LENGTH:
            case WRTC_NATIVE_OP_HEAPIFY:
            case WRTC_NATIVE_OP_HEAP_POP:
            case WRTC_NATIVE_OP_HEAP_PUSH:
            case WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED:
                runtime_expression = "&e->children[1]";
                break;
            case WRTC_NATIVE_OP_ROOT_READ:
                runtime_expression = "&e->children[0]";
                break;
            case WRTC_NATIVE_OP_FIFO_APPEND:
            case WRTC_NATIVE_OP_FIFO_POPLEFT:
            case WRTC_NATIVE_OP_ATOMIC_LOAD:
            case WRTC_NATIVE_OP_ATOMIC_STORE:
            case WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE:
            case WRTC_NATIVE_OP_MPSC_PUT_NOWAIT:
            case WRTC_NATIVE_OP_MPSC_GET_NOWAIT:
            case WRTC_NATIVE_OP_MPSC_QSIZE:
            case WRTC_NATIVE_OP_MPSC_EMPTY:
            case WRTC_NATIVE_OP_MPSC_CLOSE:
            case WRTC_NATIVE_OP_SPSC_PUT_NOWAIT:
            case WRTC_NATIVE_OP_SPSC_GET_NOWAIT:
            case WRTC_NATIVE_OP_SPSC_QSIZE:
            case WRTC_NATIVE_OP_SPSC_EMPTY:
            case WRTC_NATIVE_OP_SPSC_CLOSE:
            case WRTC_NATIVE_OP_SELECTOR_REGISTER:
            case WRTC_NATIVE_OP_SELECTOR_IS_CURRENT:
            case WRTC_NATIVE_OP_SELECTOR_OWNER:
            case WRTC_NATIVE_OP_SELECTOR_REMOVE:
                runtime_expression = "&e->children[0].children[0]";
                break;
            default:
                continue;
        }
        /*
         * The proof span selects the exact IR node.  Inspect that node here
         * instead of baking source names or event-loop shapes into emission.
         */
        if (fputs("if(", file) < 0 ||
            emit_span_test(file, operation->span) < 0 ||
            fputs("){PyObject*r=NULL,*v=NULL,*q=NULL;NSO**p=NULL;NSO*o;"
                  "(void)v;(void)q;*h=1;",
                  file) < 0)
            return -1;
        if (operation->kind == WRTC_NATIVE_OP_ALIAS_BIND) {
            if (fputs("if(e->kind==WRTC_PY_EXPR_NAME){r="
                      "wrtc_boxed_hook_local(e->operation,f);"
                      "if(!r)return NULL;o=nal(r);if(!o){Py_DECREF(r);"
                      "return NULL;}return r;}"
                      "r=wrtc_boxed_hook_evaluate(&e->children[0],f);"
                      "if(!r)return NULL;",
                      file) < 0 ||
                fprintf(file,
                        "p=np%zu_%zu(r);o=*p;Py_DECREF(r);"
                        "if(!o){PyErr_SetString(PyExc_AttributeError,",
                        proof->class_index, proof->field_index) < 0 ||
                quote(file, field->name) < 0 ||
                fputs(");return NULL;}return nac(o);}", file) < 0)
                return -1;
            continue;
        }
        /*
         * Emit storage lookup from the known operation shape.  Calls and
         * subscripts are lowered below using their statically fixed child.
         */
        if (operation->kind == WRTC_NATIVE_OP_TRUTH ||
            operation->kind == WRTC_NATIVE_OP_ITERATE ||
            operation->kind == WRTC_NATIVE_OP_SCALAR_READ) {
            if (fputs("if(e->kind==WRTC_PY_EXPR_NAME){r="
                      "wrtc_boxed_hook_local(e->operation,f);if(!r)return NULL;"
                      "o=nal(r);Py_DECREF(r);if(!o)return NULL;}else{r="
                      "wrtc_boxed_hook_evaluate(&e->children[0],f);"
                      "if(!r)return NULL;",
                      file) < 0 ||
                fprintf(file, "p=np%zu_%zu(r);o=*p;Py_DECREF(r);",
                        proof->class_index, proof->field_index) < 0 ||
                fputs("if(!o){PyErr_SetString(PyExc_AttributeError,", file) < 0 ||
                quote(file, field->name) < 0 ||
                fputs(");return NULL;}}", file) < 0)
                return -1;
        } else {
            if (fprintf(file,
                        "{const WrtcPyExprIR*x=(%s);"
                        "if(x->kind==WRTC_PY_EXPR_NAME){r="
                        "wrtc_boxed_hook_local(x->operation,f);"
                        "if(!r)return NULL;o=nal(r);Py_DECREF(r);"
                        "if(!o)return NULL;}else{r=wrtc_boxed_hook_evaluate("
                        "&x->children[0],f);if(!r)return NULL;"
                        "p=np%zu_%zu(r);o=*p;",
                        runtime_expression, proof->class_index,
                        proof->field_index) < 0)
                return -1;
            if (fputs("Py_DECREF(r);if(!o){PyErr_SetString("
                      "PyExc_AttributeError,",
                      file) < 0 ||
                quote(file, field->name) < 0 ||
                fputs(");return NULL;}}}", file) < 0) {
                return -1;
            }
        }
        switch (operation->kind) {
            case WRTC_NATIVE_OP_SCALAR_READ:
                if (fputs("return wrtc_native_scalar_get(&o->u.s,", file) < 0 ||
                    quote(file, field->name) < 0 ||
                    fputs(");}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_LENGTH:
                if (fprintf(file,
                            "{Py_ssize_t n=%s(&o->u.%c);if(n<0)return NULL;"
                            "return PyLong_FromSsize_t(n);}}",
                            field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                                ? "wrtc_native_fifo_snapshot"
                                : "wrtc_native_heap_snapshot",
                            field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                                ? 'f' : 'h') < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_TRUTH:
                if (fprintf(file,
                            "{int z=%s(&o->u.%c);if(z<0)return NULL;"
                            "return PyBool_FromLong(z);}}",
                            field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                                ? "wrtc_native_fifo_truth"
                                : "wrtc_native_heap_truth",
                            field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                                ? 'f' : 'h') < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_ROOT_READ:
                if (fputs("return wrtc_native_heap_root(&o->u.h);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_ITERATE:
                if (fputs("return wrtc_native_heap_get(&o->u.h,", file) < 0 ||
                    quote(file, field->name) < 0 ||
                    fputs(");}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_FIFO_APPEND:
                if (fputs("if(o->u.f.mode==WRTC_STORAGE_BOXED){q="
                          "PyObject_GetAttrString(o->u.f.boxed,\"append\");"
                          "if(!q)return NULL;v=wrtc_boxed_hook_evaluate("
                          "&e->children[1],f);if(!v){Py_DECREF(q);return NULL;}"
                          "r=PyObject_CallOneArg(q,v);Py_DECREF(v);Py_DECREF(q);"
                          "return r;}v=wrtc_boxed_hook_evaluate("
                          "&e->children[1],f);if(!v)return NULL;"
                          "if(wrtc_native_fifo_append(&o->u.f,v)<0){"
                          "Py_DECREF(v);return NULL;}Py_DECREF(v);"
                          "return Py_NewRef(Py_None);}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_FIFO_POPLEFT:
                if (fputs("return wrtc_native_fifo_popleft(&o->u.f);}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_HEAPIFY:
                if (fputs("if(wrtc_native_heap_heapify(&o->u.h)<0)"
                          "return NULL;return Py_NewRef(Py_None);}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_HEAP_PUSH:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[2],f);"
                          "if(!v)return NULL;if(wrtc_native_heap_push("
                          "&o->u.h,v)<0){Py_DECREF(v);return NULL;}"
                          "Py_DECREF(v);return Py_NewRef(Py_None);}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_HEAP_POP:
                if (fputs("return wrtc_native_heap_pop(&o->u.h);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED:
                if (fputs("{Py_ssize_t z="
                          "wrtc_native_heap_compact_cancelled(&o->u.h);"
                          "return z<0?NULL:PyLong_FromSsize_t(z);}}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_ATOMIC_LOAD:
                if (fputs("{uint_least32_t x;if("
                          "wrtc_native_atomic_uint32_load(&o->u.a,&x)<0)"
                          "return NULL;return PyLong_FromUnsignedLong("
                          "(unsigned long)x);}}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_ATOMIC_STORE:
                if (fputs("{uint_least32_t x;v=wrtc_boxed_hook_evaluate("
                          "&e->children[1],f);if(!v)return NULL;"
                          "if(n32(v,&x)<0){Py_DECREF(v);return NULL;}"
                          "Py_DECREF(v);if(wrtc_native_atomic_uint32_set("
                          "&o->u.a,x)<0)return NULL;"
                          "return Py_NewRef(Py_None);}}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE:
                if (fputs(
                        "{uint_least32_t ev,dv,pv;int changed;"
                        "v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                        "if(!v)return NULL;q=wrtc_boxed_hook_evaluate("
                        "&e->children[2],f);if(!q){Py_DECREF(v);return NULL;}"
                        "if(n32(v,&ev)<0||n32(q,&dv)<0){Py_DECREF(v);"
                        "Py_DECREF(q);return NULL;}Py_DECREF(v);Py_DECREF(q);"
                        "if(wrtc_native_atomic_uint32_compare_exchange("
                        "&o->u.a,ev,dv,&pv,&changed)<0)return NULL;"
                        "v=PyLong_FromUnsignedLong((unsigned long)pv);"
                        "q=PyBool_FromLong(changed);if(!v||!q){"
                        "Py_XDECREF(v);Py_XDECREF(q);return NULL;}"
                        "r=PyTuple_Pack(2,v,q);Py_DECREF(v);Py_DECREF(q);"
                        "return r;}}",
                        file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_MPSC_PUT_NOWAIT:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                          "if(!v)return NULL;r=nqp(o,v);Py_DECREF(v);"
                          "return r;}",
                          file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_MPSC_GET_NOWAIT:
                if (fputs("return nqg(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_MPSC_QSIZE:
                if (fputs("return nqs(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_MPSC_EMPTY:
                if (fputs("return nqz(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_MPSC_CLOSE:
                if (fputs("return nqc(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SPSC_PUT_NOWAIT:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                          "if(!v)return NULL;r=nqp(o,v);Py_DECREF(v);"
                          "return r;}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SPSC_GET_NOWAIT:
                if (fputs("return nqg(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SPSC_QSIZE:
                if (fputs("return nqs(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SPSC_EMPTY:
                if (fputs("return nqz(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SPSC_CLOSE:
                if (fputs("return nqc(o,NULL);}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SELECTOR_REGISTER:
                if (fputs("{PyObject*a=PyTuple_New(3);size_t i;if(!a)"
                          "return NULL;for(i=0u;i<3u;i++){v="
                          "wrtc_boxed_hook_evaluate(&e->children[1u+i],f);"
                          "if(!v){Py_DECREF(a);return NULL;}PyTuple_SET_ITEM("
                          "a,(Py_ssize_t)i,v);}r=nrr(o,a);Py_DECREF(a);"
                          "return r;}}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SELECTOR_IS_CURRENT:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                          "if(!v)return NULL;r=nrc(o,v);Py_DECREF(v);"
                          "return r;}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SELECTOR_OWNER:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                          "if(!v)return NULL;r=nro(o,v);Py_DECREF(v);"
                          "return r;}", file) < 0)
                    return -1;
                break;
            case WRTC_NATIVE_OP_SELECTOR_REMOVE:
                if (fputs("v=wrtc_boxed_hook_evaluate(&e->children[1],f);"
                          "if(!v)return NULL;r=nrd(o,v);Py_DECREF(v);"
                          "return r;}", file) < 0)
                    return -1;
                break;
            default:
                return -1;
        }
    }
    for (operation_index = 0u; operation_index < region->call_count;
         operation_index++) {
        if (emit_reactor_call_case(
                file, &region->calls[operation_index], operation_index) < 0)
            return -1;
        if (emit_fused_call_case(
                file, &region->calls[operation_index],
                fused_call_index(program, class_index, region_index,
                                 operation_index)) < 0)
            return -1;
    }
    if ((region->capabilities & WRTC_REGION_HANDLE_RUN) != 0u &&
        fputs("if(e->kind==WRTC_PY_EXPR_CALL&&e->child_count==1u&&"
              "e->positional_count==0u&&e->keyword_count==0u&&"
              "e->children[0].kind==WRTC_PY_EXPR_ATTRIBUTE&&"
              "e->children[0].operation&&strcmp(e->children[0].operation,"
              "\"_run\")==0&&e->children[0].child_count==1u){PyObject*v;"
              "*h=1;v=wrtc_boxed_hook_evaluate(&e->children[0].children[0],f);"
              "if(!v)return NULL;{PyObject*r=whr((PyObject*)c,v);Py_DECREF(v);"
              "return r;}}",
              file) < 0)
        return -1;
    if (fputs("return NULL;}", file) < 0 ||
        fprintf(file,
                "static int na%zu_%zu(void*c,const WrtcPyExprIR*e,PyObject*v,"
                "void*f,int*h){(void)c;(void)e;(void)v;(void)f;*h=0;",
                class_index, region_index) < 0)
        return -1;
    for (operation_index = 0u;
         table != NULL && operation_index < table->operation_count;
         operation_index++) {
        const WrtcNativeOperationIR *operation =
            &table->operations[operation_index];
        const WrtcNativeFieldOperationProof *proof;
        const WrtcNativeFieldIR *field;
        int kind;
        if (operation->region_class_index != class_index ||
            operation->region_index != region_index ||
            (operation->kind != WRTC_NATIVE_OP_SCALAR_WRITE &&
             operation->kind != WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE &&
             operation->kind != WRTC_NATIVE_OP_BOXED_WRITE &&
             operation->kind != WRTC_NATIVE_OP_SLICE_ASSIGN))
            continue;
        proof = &table->fields[operation->field_proof_index];
        field = &program->classes[proof->class_index]
                     .fields[proof->field_index];
        kind = field->storage_kind == WRTC_NATIVE_FIELD_SCALAR ? 1 :
               field->storage_kind == WRTC_NATIVE_FIELD_FIFO ? 2 : 3;
        if (fputs("if(", file) < 0 ||
            emit_span_test(file, operation->span) < 0 ||
            fputs("){PyObject*r=NULL,*q=NULL;NSO**p=NULL;NSO*o;(void)q;*h=1;",
                  file) < 0)
            return -1;
        if (operation->kind == WRTC_NATIVE_OP_SLICE_ASSIGN) {
            if (fprintf(file,
                        "{const WrtcPyExprIR*x=&e->children[0];"
                        "if(x->kind==WRTC_PY_EXPR_NAME){r="
                        "wrtc_boxed_hook_local(x->operation,f);"
                        "if(!r)return -1;o=nal(r);Py_DECREF(r);"
                        "if(!o)return -1;}else{r=wrtc_boxed_hook_evaluate("
                        "&x->children[0],f);if(!r)return -1;"
                        "p=np%zu_%zu(r);o=*p;Py_DECREF(r);"
                        "if(!o){PyErr_SetString(PyExc_AttributeError,",
                        proof->class_index, proof->field_index) < 0 ||
                quote(file, field->name) < 0 ||
                fputs(");return -1;}}}r=wrtc_native_heap_get(&o->u.h,",
                      file) < 0 ||
                quote(file, field->name) < 0 ||
                fputs(");if(!r)return -1;q=wrtc_boxed_hook_evaluate("
                      "&e->children[1],f);if(!q){Py_DECREF(r);return -1;}"
                      "{int z=PyObject_SetItem(r,q,v);Py_DECREF(q);"
                      "Py_DECREF(r);return z;}}",
                      file) < 0)
                return -1;
            continue;
        }
        if (fputs("r=wrtc_boxed_hook_evaluate(&e->children[0],f);"
                  "if(!r)return -1;",
                  file) < 0 ||
            fprintf(file,
                    "p=np%zu_%zu(r);o=*p;if(!o){o=no(r,%d);if(!o){"
                    "Py_DECREF(r);return -1;}*p=o;}Py_DECREF(r);",
                    proof->class_index, proof->field_index, kind) < 0)
            return -1;
        if (field->storage_kind == WRTC_NATIVE_FIELD_SCALAR) {
            if (field->type == WRTC_TYPE_BOOL) {
                if (fputs("if(PyBool_Check(v))return "
                          "wrtc_native_scalar_set_bool(&o->u.s,v==Py_True);"
                          "return wrtc_native_scalar_set_boxed(&o->u.s,v);}",
                          file) < 0)
                    return -1;
            } else if (field->declared_type != NULL &&
                       strcmp(field->declared_type, "float") == 0) {
                if (fputs("if(PyFloat_CheckExact(v))return "
                          "wrtc_native_scalar_set_double(&o->u.s,"
                          "PyFloat_AS_DOUBLE(v));return "
                          "wrtc_native_scalar_set_boxed(&o->u.s,v);}",
                          file) < 0)
                    return -1;
            } else if (fputs("if(PyLong_CheckExact(v)){long long x="
                             "PyLong_AsLongLong(v);"
                             "if(!(x==-1&&PyErr_Occurred()))return "
                             "wrtc_native_scalar_set_int64(&o->u.s,"
                             "(int64_t)x);PyErr_Clear();}return "
                             "wrtc_native_scalar_set_boxed(&o->u.s,v);}",
                             file) < 0) {
                return -1;
            }
        } else if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO) {
            if (fputs("return wrtc_native_fifo_set_boxed(&o->u.f,v);}",
                      file) < 0)
                return -1;
        } else if (fputs("return wrtc_native_heap_set_boxed(&o->u.h,v);}",
                         file) < 0) {
            return -1;
        }
    }
    return fprintf(file,
                   "return 0;}static WrtcBoxedNativeHooks hk%zu_%zu={NULL,"
                   "ne%zu_%zu,na%zu_%zu};",
                   class_index, region_index, class_index, region_index,
                   class_index, region_index) < 0 ? -1 : 0;
}

static int emit_class(FILE *file, const char *module,
                      const WrtcNativeClassProgram *program,
                      const WrtcNativeOperationTable *operations,
                      const WrtcNativeClassIR *class_ir, size_t class_index) {
    size_t field_index, region_index;
    if (fputs("typedef struct{", file) < 0) return -1;
    for (field_index = 0u; field_index < class_ir->field_count; field_index++)
        if (emit_field_decl(file, &class_ir->fields[field_index],
                            field_index) < 0)
            return -1;
    if (fprintf(file, "}H%zu;\n", class_index) < 0) return -1;
    if (object_base(class_ir->base)) {
        if (fprintf(file,
                    "static int ct%zu(PyObject*self,visitproc visit,void*arg){"
                    "H%zu*d=(H%zu*)PyObject_GetTypeData(self,dt(self,%zu));"
                    "int z;(void)d;(void)visit;(void)arg;(void)z;",
                    class_index, class_index, class_index, class_index) < 0)
            return -1;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++)
            if (fprintf(file,
                        "if(d->f%zu&&(z=visit(d->f%zu,arg))!=0)return z;",
                        field_index, field_index) < 0)
                return -1;
        if (fprintf(file,
                    "return 0;}static int cc%zu(PyObject*self){H%zu*d="
                    "(H%zu*)PyObject_GetTypeData(self,dt(self,%zu));(void)d;",
                    class_index, class_index, class_index, class_index) < 0)
            return -1;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++)
            if (fprintf(file, "Py_CLEAR(d->f%zu);", field_index) < 0)
                return -1;
        if (fprintf(file,
                    "return 0;}static void cd%zu(PyObject*self){"
                    "PyObject_GC_UnTrack(self);(void)cc%zu(self);"
                    "Py_TYPE(self)->tp_free(self);}\n",
                    class_index, class_index) < 0)
            return -1;
    }
    for (field_index = 0u; field_index < class_ir->field_count; field_index++)
        if (class_ir->fields[field_index].storage_kind !=
                WRTC_NATIVE_FIELD_PYOBJECT &&
            emit_storage_accessor(file, program, class_index,
                                  &class_ir->fields[field_index],
                                  field_index) < 0)
            return -1;
    for (field_index = 0u; field_index < class_ir->field_count; field_index++) {
        const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
        if (field->storage_kind != WRTC_NATIVE_FIELD_PYOBJECT ||
            !field->exact_type)
            continue;
        if (fprintf(file,
                    "static PyObject*eg%zu_%zu(PyObject*self,void*unused){"
                    "H%zu*d=(H%zu*)PyObject_GetTypeData(self,dt(self,%zu));"
                    "(void)unused;if(!d->f%zu){PyErr_SetString(PyExc_AttributeError,",
                    class_index, field_index, class_index, class_index,
                    class_index, field_index) < 0 ||
            quote(file, field->name) < 0 ||
            fprintf(file,
                    ");return NULL;}return Py_NewRef(d->f%zu);}"
                    "static int es%zu_%zu(PyObject*self,PyObject*v,void*unused){"
                    "H%zu*d=(H%zu*)PyObject_GetTypeData(self,dt(self,%zu));"
                    "(void)unused;if(!v){PyErr_SetString(PyExc_AttributeError,"
                    "\"exact component field cannot be deleted\");return -1;}"
                    "if(d->f%zu){PyErr_SetString(PyExc_AttributeError,"
                    "\"exact component field is immutable after initialization\");"
                    "return -1;}d->f%zu=Py_NewRef(v);return 0;}\n",
                    field_index, class_index, field_index, class_index,
                    class_index, class_index, field_index, field_index) < 0)
            return -1;
    }
    for (region_index = 0u; region_index < class_ir->region_count;
         region_index++) {
        char hook_argument[64] = "", globals_symbol[32];
        const int aot = wrtc_aot_region_supported(
            &class_ir->regions[region_index]);
        const int direct = wrtc_aot_region_direct_supported(
            program, operations, class_index, region_index);
        (void)snprintf(globals_symbol, sizeof globals_symbol,
                       "g%zu_globals", class_index);
        int has_hooks = !direct && region_has_native_operations(
                                      operations, class_index, region_index);
        size_t call_index;
        for (call_index = 0u;
             call_index < class_ir->regions[region_index].call_count;
             call_index++)
            if (!direct &&
                class_ir->regions[region_index].calls[call_index].fused)
                has_hooks = 1;
            else if (!direct && class_ir->regions[region_index]
                         .calls[call_index].reactor_hook !=
                     WRTC_REACTOR_HOOK_NONE)
                has_hooks = 1;
        if (has_hooks &&
            emit_region_hooks(file, program, operations, class_index,
                              region_index) < 0)
            return -1;
        if (has_hooks)
            (void)snprintf(hook_argument, sizeof hook_argument,
                           "&hooks,");
        if (aot && wrtc_aot_emit_region(
                       file, class_index, region_index,
                       &class_ir->regions[region_index],
                       program, operations,
                       globals_symbol, has_hooks) < 0) {
            (void)fprintf(stderr, "AOT emission failed for %s.%s\n",
                          class_ir->name,
                          class_ir->regions[region_index].name);
            return -1;
        }
        if (fprintf(file,
                    "static PyObject*w%zu_%zu(PyObject*self,"
                    "PyObject*const*args,Py_ssize_t nargs,PyObject*kwnames){"
                    "PyObject*locals=NULL,*result=NULL,*globals=g%zu_globals;",
                    class_index, region_index, class_index) < 0)
            return -1;
        if (fputs("wrtc_native_allocation_region_enter(", file) < 0 ||
            quote(file, class_ir->name) < 0 || fputs("\".\"", file) < 0 ||
            quote(file, class_ir->regions[region_index].name) < 0 ||
            fputs(");", file) < 0)
            return -1;
        if (direct) {
            size_t operation_index;
            const size_t manifest_index = region_manifest_index(
                program, class_index, region_index);
            if (fprintf(file,
                        "{WrtcSchedulerContext context;if(!wg(self,%zu,%zu,"
                        "&context)){result=wf(self,%zu,args,nargs,kwnames);"
                        "goto done;}}",
                        class_index, manifest_index, manifest_index) < 0)
                return -1;
            for (operation_index = 0u;
                 operations != NULL &&
                 operation_index < operations->operation_count;
                 operation_index++) {
                const WrtcNativeOperationIR *operation =
                    &operations->operations[operation_index];
                const WrtcNativeFieldOperationProof *proof;
                const WrtcNativeFieldIR *field;
                const char *owner = "self";
                char owner_buffer[48];
                size_t parameter_index;
                if (operation->region_class_index != class_index ||
                    operation->region_index != region_index)
                    continue;
                proof = &operations->fields[operation->field_proof_index];
                field = &program->classes[proof->class_index]
                             .fields[proof->field_index];
                if (proof->class_index != class_index) {
                    owner = NULL;
                    for (parameter_index = 1u;
                         parameter_index < class_ir->regions[region_index]
                                               .signature->parameter_count;
                         parameter_index++) {
                        const char *annotation =
                            class_ir->regions[region_index].signature
                                ->parameters[parameter_index].annotation;
                        if (annotation != NULL &&
                            strstr(annotation,
                                   program->classes[proof->class_index].name) !=
                                NULL) {
                            (void)snprintf(owner_buffer, sizeof owner_buffer,
                                           "args[%zu]", parameter_index - 1u);
                            owner = owner_buffer;
                            break;
                        }
                    }
                    if (owner == NULL) return -1;
                }
                if (fprintf(file,
                            "{NSO*guarded=*np%zu_%zu(%s);if(!guarded",
                            proof->class_index, proof->field_index, owner) < 0)
                    return -1;
                if ((field->storage_kind == WRTC_NATIVE_FIELD_FIFO &&
                     fputs("||guarded->u.f.mode!=WRTC_STORAGE_NATIVE", file) < 0) ||
                    (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP &&
                     fputs("||guarded->u.h.mode!=WRTC_STORAGE_NATIVE", file) < 0) ||
                    (field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                     fputs("||!guarded->u.a.initialized", file) < 0) ||
                    (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     fputs("||!guarded->u.m.cells", file) < 0))
                    return -1;
                if (fprintf(file,
                            "){"
                            "result=wf(self,%zu,args,nargs,kwnames);"
                            "goto done;}}",
                            manifest_index) < 0)
                    return -1;
            }
        }
        if (has_hooks &&
            fprintf(file,
                    "WrtcBoxedNativeHooks hooks=hk%zu_%zu;"
                    "hooks.context=self;",
                    class_index, region_index) < 0)
            return -1;
        if (aot &&
            fprintf(file,
                    "{int aot_status=wad%zu_%zu_0(self,args,nargs,kwnames,"
                    "%s&result);if(aot_status<=0)goto done;}",
                    class_index, region_index,
                    has_hooks ? "&hooks," : "NULL,") < 0)
            return -1;
        if (fprintf(file,
                    "if(!globals)goto done;if(wrtc_boxed_bind_method("
                    "&r%zu_%zu_sig,self,args,nargs,kwnames,&locals)<0)goto done;"
                    "if(%s("
                    "&r%zu_%zu_suite,globals,locals,%s&result)<0)goto done;"
                    "done:wrtc_native_allocation_release_locals(locals);"
                    "wrtc_native_allocation_region_leave();return result;}\n",
                    class_index, region_index,
                    has_hooks ? "wrtc_boxed_execute_with_hooks" :
                                "wrtc_boxed_execute",
                    class_index, region_index,
                    hook_argument) < 0)
            return -1;
    }
    if (class_ir->custom_constructor &&
        fprintf(file,
                "static int ci%zu(PyObject*self,PyObject*args,PyObject*kwargs){"
                "PyObject*full=NULL,*locals=NULL,*result=NULL;Py_ssize_t i,n;"
                "WCC context={self,%zu};WrtcBoxedNativeHooks hooks={&context,"
                "wce,NULL};wrtc_native_allocation_region_enter(\"__init__\");"
                "if(!g%zu_globals||cg%zu(self)<0)goto done;"
                "n=PyTuple_GET_SIZE(args);"
                "full=PyTuple_New(n+1);if(!full)goto done;PyTuple_SET_ITEM("
                "full,0,Py_NewRef(self));for(i=0;i<n;i++)PyTuple_SET_ITEM("
                "full,i+1,Py_NewRef(PyTuple_GET_ITEM(args,i)));"
                "if(wrtc_boxed_bind(&c%zu_sig,full,kwargs,&locals)<0)goto done;"
                "if(wrtc_boxed_execute_with_hooks(&c%zu_suite,g%zu_globals,"
                "locals,&hooks,&result)<0)goto done;if(result!=Py_None){"
                "PyErr_Format(PyExc_TypeError,\"__init__() should return None,"
                " not '%%s'\",Py_TYPE(result)->tp_name);Py_CLEAR(result);}"
                "done:Py_XDECREF(result);"
                "wrtc_native_allocation_release_locals(locals);Py_XDECREF(full);"
                "wrtc_native_allocation_region_leave();"
                "return PyErr_Occurred()?-1:0;}\n",
                class_index, class_index, class_index, class_index,
                class_index, class_index, class_index) < 0)
        return -1;
    if (fprintf(file, "static PyMethodDef mm%zu[]={", class_index) < 0)
        return -1;
    for (region_index = 0u; region_index < class_ir->region_count;
         region_index++) {
        if (fputc('{', file) == EOF ||
            quote(file, class_ir->regions[region_index].name) < 0 ||
            fprintf(file, ",(PyCFunction)(void(*)(void))w%zu_%zu,"
                          "METH_FASTCALL|METH_KEYWORDS,NULL},",
                    class_index, region_index) < 0)
            return -1;
    }
    if (fputs("{NULL,NULL,0,NULL}};", file) < 0) return -1;
    for (field_index = 0u; field_index < class_ir->field_count; field_index++)
        if (field_index == 0u &&
            fprintf(file, "static PyMemberDef mb%zu[]={", class_index) < 0)
            return -1;
    for (field_index = 0u; field_index < class_ir->field_count; field_index++) {
        char hidden[64];
        const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
        (void)snprintf(hidden, sizeof hidden, "__pymeta_storage_%zu",
                       field_index);
        if (fputc('{', file) == EOF ||
            quote(file, field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT &&
                                  !field->exact_type
                            ? field->name : hidden) < 0 ||
            fprintf(file, ",T_OBJECT_EX,offsetof(H%zu,f%zu),"
                          "Py_RELATIVE_OFFSET%s,NULL},",
                    class_index, field_index,
                    field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT
                        ? "" : "|Py_READONLY") < 0)
            return -1;
    }
    if (class_ir->field_count == 0u &&
        fprintf(file, "static PyMemberDef mb%zu[]={", class_index) < 0)
        return -1;
    if (fputs("{NULL,0,0,0,NULL}};", file) < 0) return -1;
    if (fprintf(file, "static PyGetSetDef gs%zu[]={", class_index) < 0)
        return -1;
    for (field_index = 0u; field_index < class_ir->field_count; field_index++) {
        const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
        if (field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT &&
            !field->exact_type)
            continue;
        if (fputc('{', file) == EOF || quote(file, field->name) < 0 ||
            fprintf(file, ",(getter)%s%zu_%zu,(setter)%s%zu_%zu,NULL,NULL},",
                    field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT
                        ? "eg" : "ng",
                    class_index, field_index,
                    field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT
                        ? "es" : "ns",
                    class_index, field_index) < 0)
            return -1;
    }
    if (fputs("{NULL,NULL,NULL,NULL,NULL}};", file) < 0) return -1;
    if (fprintf(file,
                "static PyType_Slot sl%zu[]={"
                "{Py_tp_new,(void*)PyType_GenericNew},"
                "{Py_tp_members,(void*)mb%zu},{Py_tp_methods,(void*)mm%zu},"
                "{Py_tp_getset,(void*)gs%zu},",
                class_index, class_index, class_index, class_index) < 0)
        return -1;
    if (class_ir->custom_constructor &&
        fprintf(file, "{Py_tp_init,(void*)ci%zu},", class_index) < 0)
        return -1;
    if (object_base(class_ir->base) &&
        fprintf(file,
                "{Py_tp_traverse,(void*)ct%zu},{Py_tp_clear,(void*)cc%zu},"
                "{Py_tp_dealloc,(void*)cd%zu},",
                class_index, class_index, class_index) < 0)
        return -1;
    if (fprintf(file,
                "{0,NULL}};static PyType_Spec sp%zu={",
                class_index) < 0 ||
        fprintf(file, "\"%s.%s\"", module, class_ir->name) < 0 ||
        fprintf(file, ",-(Py_ssize_t)sizeof(H%zu),0,Py_TPFLAGS_DEFAULT|"
                      "Py_TPFLAGS_BASETYPE%s,sl%zu};\n",
                class_index,
                object_base(class_ir->base) ? "|Py_TPFLAGS_HAVE_GC" : "",
                class_index) < 0)
        return -1;
    return 0;
}

static int emit_module_string(FILE *file, const char *name,
                              const char *value) {
    if (fputs("if(PyModule_AddStringConstant(m,", file) < 0 ||
        quote(file, name) < 0 || fputc(',', file) == EOF ||
        quote(file, value) < 0 || fputs(")<0)goto error;", file) < 0)
        return -1;
    return 0;
}

static int program_has_storage(const WrtcNativeClassProgram *program) {
    size_t class_index, field_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (field_index = 0u;
             field_index < program->classes[class_index].field_count;
             field_index++)
            if (program->classes[class_index].fields[field_index]
                    .storage_kind != WRTC_NATIVE_FIELD_PYOBJECT)
                return 1;
    return 0;
}

static int program_has_reactor_hooks(
    const WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (program->classes[class_index].regions[region_index]
                    .reactor_hook_emission_complete)
                return 1;
    return 0;
}

static int program_has_handle_run(const WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if ((program->classes[class_index].regions[region_index]
                     .capabilities & WRTC_REGION_HANDLE_RUN) != 0u)
                return 1;
    return 0;
}

static int program_has_direct_regions(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations) {
    size_t class_index, region_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (wrtc_aot_region_direct_supported(
                    program, operations, class_index, region_index))
                return 1;
    return 0;
}

static int program_has_complete_scheduler_graph(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations) {
    static const char *const roots[] = {
        "_run_once", "call_soon", "_call_soon", "call_at", "call_later",
        "call_soon_threadsafe"
    };
    size_t class_index, root_index, region_index;
    for (class_index = 0u; class_index < program->class_count; class_index++) {
        if (strcmp(program->classes[class_index].name,
                   "WebRTCSelectorEventLoop") != 0)
            continue;
        for (root_index = 0u; root_index < sizeof roots / sizeof roots[0];
             root_index++) {
            int found = 0;
            for (region_index = 0u;
                 region_index < program->classes[class_index].region_count;
                 region_index++)
                if (strcmp(program->classes[class_index].regions[region_index].name,
                           roots[root_index]) == 0) {
                    found = wrtc_aot_region_direct_supported(
                        program, operations, class_index, region_index);
                    break;
                }
            if (!found) return 0;
        }
        return 1;
    }
    return 0;
}

static int program_has_reactor_storage(
    const WrtcNativeClassProgram *program) {
    size_t class_index, field_index;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (field_index = 0u;
             field_index < program->classes[class_index].field_count;
             field_index++) {
            const WrtcNativeStorageKind kind =
                program->classes[class_index].fields[field_index].storage_kind;
            if (kind == WRTC_NATIVE_FIELD_SELECTOR ||
                kind == WRTC_NATIVE_FIELD_PACKET_POOL)
                return 1;
        }
    return 0;
}

static int emit_storage_owner(FILE *file) {
    return fputs(
        "typedef struct{PyObject_HEAD int k;int wk;WA*wa;PyTypeObject*rt;"
        "PyObject*owners;"
        "union{WrtcNativeScalar s;"
        "WrtcNativeFifo f;WrtcNativeMinHeap h;WrtcNativeAtomicUint32 a;"
        "WrtcNativeMpsc m;WrtcNativeSpsc p;WrtcNativeSelector*r;"
        "WrtcNativePacketPool*b;WrtcNativeDatagramPacket d;}u;}NSO;"
        "static void wadt(void*q,WA*a){NSO*o=(NSO*)q;if(!o||o->wa!=a)return;"
        "o->wa=NULL;o->wk=0;if(a->iq==q)a->iq=NULL;if(a->oq==q)a->oq=NULL;}"
        "static void nd(void*i,void*c){(void)c;Py_DECREF((PyObject*)i);}"
        "static int notr(NSO*o,visitproc v,void*a){"
        "if(o->rt){int z=v((PyObject*)o->rt,a);if(z)return z;}"
        "if(o->owners){int z=v(o->owners,a);if(z)return z;}"
        "if(o->k==1)return wrtc_native_scalar_traverse(&o->u.s,v,a);"
        "if(o->k==2)return wrtc_native_fifo_traverse(&o->u.f,v,a);"
        "if(o->k==3)return wrtc_native_heap_traverse(&o->u.h,v,a);"
        "if(o->k==5)return wrtc_native_mpsc_traverse(&o->u.m,v,a);"
        "if(o->k==6)return wrtc_native_spsc_traverse(&o->u.p,v,a);return 0;}"
        "static int nocl(NSO*o){if(o->wa)wadt(o,o->wa);"
        "if(o->k==1)wrtc_native_scalar_clear(&o->u.s);"
        "else if(o->k==2)wrtc_native_fifo_clear(&o->u.f);"
        "else if(o->k==3)wrtc_native_heap_clear(&o->u.h);"
        "else if(o->k==4)wrtc_native_atomic_uint32_clear(&o->u.a);"
        "else if(o->k==5)wrtc_native_mpsc_clear(&o->u.m,nd,NULL);"
        "else if(o->k==6)wrtc_native_spsc_clear(&o->u.p,nd,NULL);"
        "else if(o->k==7)wrtc_native_selector_destroy(o->u.r);"
        "else if(o->k==8)wrtc_native_packet_pool_destroy(o->u.b);"
        "else if(o->k==9)(void)wrtc_native_datagram_packet_release(&o->u.d);"
        "Py_CLEAR(o->rt);Py_CLEAR(o->owners);o->k=0;return 0;}"
        "static void node(NSO*o){PyObject_GC_UnTrack((PyObject*)o);"
        "(void)nocl(o);Py_TYPE(o)->tp_free((PyObject*)o);}"
        "static int n32(PyObject*v,uint_least32_t*out){unsigned long x;"
        "if(!PyLong_Check(v)){PyErr_SetString(PyExc_TypeError,"
        "\"atomic uint32 operand must be an integer\");return -1;}"
        "x=PyLong_AsUnsignedLong(v);if((x==(unsigned long)-1&&"
        "PyErr_Occurred())||x>UINT32_MAX){if(!PyErr_Occurred())"
        "PyErr_SetString(PyExc_OverflowError,"
        "\"atomic uint32 operand is out of range\");return -1;}"
        "*out=(uint_least32_t)x;return 0;}"
        "static PyObject*nol(NSO*o,PyObject*unused){uint_least32_t v;"
        "(void)unused;if(o->k!=4){PyErr_SetString(PyExc_TypeError,"
        "\"load requires atomic storage\");return NULL;}"
        "if(wrtc_native_atomic_uint32_load(&o->u.a,&v)<0)return NULL;"
        "return PyLong_FromUnsignedLong((unsigned long)v);}"
        "static PyObject*nostore(NSO*o,PyObject*v){uint_least32_t x;"
        "if(o->k!=4){PyErr_SetString(PyExc_TypeError,"
        "\"store requires atomic storage\");return NULL;}"
        "if(n32(v,&x)<0||wrtc_native_atomic_uint32_set(&o->u.a,x)<0)"
        "return NULL;return Py_NewRef(Py_None);}"
        "static PyObject*nox(NSO*o,PyObject*args){PyObject*e,*d,*p,*b,*r;"
        "uint_least32_t ev,dv,pv;int changed;"
        "if(o->k!=4){PyErr_SetString(PyExc_TypeError,"
        "\"compare_exchange requires atomic storage\");return NULL;}"
        "if(!PyArg_UnpackTuple(args,\"compare_exchange\",2,2,&e,&d)||"
        "n32(e,&ev)<0||n32(d,&dv)<0)return NULL;"
        "if(wrtc_native_atomic_uint32_compare_exchange("
        "&o->u.a,ev,dv,&pv,&changed)<0)return NULL;"
        "p=PyLong_FromUnsignedLong((unsigned long)pv);"
        "b=PyBool_FromLong(changed);if(!p||!b){Py_XDECREF(p);"
        "Py_XDECREF(b);return NULL;}r=PyTuple_Pack(2,p,b);"
        "Py_DECREF(p);Py_DECREF(b);return r;}"
        "static int nqe(const char*n){PyObject*m=PyImport_ImportModule("
        "\"queue\"),*e;if(!m)return -1;e=PyObject_GetAttrString(m,n);"
        "Py_DECREF(m);if(!e)return -1;PyErr_SetNone(e);Py_DECREF(e);return -1;}"
        "static PyObject*nqp(NSO*o,PyObject*v){WrtcNativeMpscStatus s;"
        "int notify=0;if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"put_nowait requires bounded queue storage\");return NULL;}"
        "if(o->wa&&o->wk==1)return wasub(o->wa,v);"
        "if(!o->rt||Py_TYPE(v)!=o->rt){PyErr_SetString(PyExc_TypeError,"
        "\"queue publication requires the exact ABI-declared record type\");"
        "return NULL;}"
        "Py_INCREF(v);if(o->k==5)s=wrtc_native_mpsc_publish(&o->u.m,v,&notify);"
        "else s=(WrtcNativeMpscStatus)wrtc_native_spsc_try_push(&o->u.p,v);"
        "if(s==WRTC_MPSC_OK)return Py_NewRef(Py_None);Py_DECREF(v);"
        "if(s==WRTC_MPSC_FULL){(void)nqe(\"Full\");return NULL;}"
        "PyErr_SetString(PyExc_RuntimeError,\"queue is closed\");return NULL;}"
        "static PyObject*nqg(NSO*o,PyObject*unused){void*i=NULL;"
        "WrtcNativeMpscStatus s;(void)unused;if(o->k!=5&&o->k!=6){"
        "PyErr_SetString(PyExc_TypeError,"
        "\"get_nowait requires bounded queue storage\");return NULL;}"
        "if(o->wa&&o->wk==2){PyObject*r=wag(o->wa);if(!r&&!PyErr_Occurred())"
        "(void)nqe(\"Empty\");return r;}"
        "if(o->wa&&o->wk==1){PyObject*r=wapop(o->wa);if(!r&&!PyErr_Occurred())"
        "(void)nqe(\"Empty\");return r;}"
        "if(o->k==5)s=wrtc_native_mpsc_try_pop(&o->u.m,&i);"
        "else s=(WrtcNativeMpscStatus)wrtc_native_spsc_try_pop(&o->u.p,&i);"
        "if(s==WRTC_MPSC_OK)return(PyObject*)i;"
        "(void)nqe(\"Empty\");return NULL;}"
        "static PyObject*nqs(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"qsize requires bounded queue storage\");return NULL;}"
        "if(o->wa&&o->wk==2)return PyLong_FromSsize_t(waqs(o->wa));"
        "if(o->wa&&o->wk==1)return PyLong_FromSsize_t(o->wa->pending?"
        "PyList_GET_SIZE(o->wa->pending):0);"
        "return PyLong_FromSize_t(o->k==5?wrtc_native_mpsc_snapshot(&o->u.m):"
        "wrtc_native_spsc_snapshot(&o->u.p));}"
        "static PyObject*nqz(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"empty requires bounded queue storage\");return NULL;}"
        "if(o->wa)return PyBool_FromLong(o->wk==2?waqs(o->wa)==0:"
        "(!o->wa->pending||PyList_GET_SIZE(o->wa->pending)==0));"
        "return PyBool_FromLong((o->k==5?wrtc_native_mpsc_snapshot(&o->u.m):"
        "wrtc_native_spsc_snapshot(&o->u.p))==0u);}"
        "static PyObject*nqclosed(NSO*o,void*unused){int open;(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"closed requires bounded queue storage\");return NULL;}"
        "if(o->wa)open=!o->wa->admission_closed&&!o->wa->closed;"
        "else open=o->k==5?wrtc_native_mpsc_is_open(&o->u.m):"
        "wrtc_native_spsc_is_open(&o->u.p);return PyBool_FromLong(!open);}"
        "static int nrt(PyObject*k,WrtcNativeDescriptorToken*t){"
        "unsigned long long g;if(!PyArg_ParseTuple(k,\"iK\",&t->descriptor,"
        "&g))return -1;t->generation=(uint64_t)g;return 0;}"
        "static PyObject*nrr(NSO*o,PyObject*args){int fd;unsigned int ev;"
        "PyObject*d=Py_None,*k=NULL;WrtcNativeDescriptorToken t;"
        "WrtcNativeReactorStatus s;if(o->k!=7||!o->u.r){PyErr_SetString("
        "PyExc_TypeError,\"register requires live selector storage\");"
        "return NULL;}if(!PyGILState_Check()){PyErr_SetString("
        "PyExc_RuntimeError,\"selector mutation requires reactor-thread GIL\");"
        "return NULL;}if(!PyArg_ParseTuple(args,\"iI|O:register\",&fd,&ev,&d))"
        "return NULL;s=wrtc_native_selector_register(o->u.r,fd,ev,NULL,&t);"
        "if(s!=WRTC_REACTOR_OK){PyErr_Format(PyExc_RuntimeError,"
        "\"selector register failed: %d\",(int)s);return NULL;}"
        "k=Py_BuildValue(\"(iK)\",t.descriptor,"
        "(unsigned long long)t.generation);if(!k||PyDict_SetItem(o->owners,k,d)<0){"
        "(void)wrtc_native_selector_remove(o->u.r,t);Py_XDECREF(k);return NULL;}"
        "return k;}"
        "static PyObject*nrm(NSO*o,PyObject*args){PyObject*k,*d=Py_None;"
        "unsigned int ev;WrtcNativeDescriptorToken t;WrtcNativeReactorStatus s;"
        "if(o->k!=7||!o->u.r){PyErr_SetString(PyExc_TypeError,"
        "\"modify requires live selector storage\");return NULL;}"
        "if(!PyArg_ParseTuple(args,\"OI|O:modify\",&k,&ev,&d)||nrt(k,&t)<0)"
        "return NULL;s=wrtc_native_selector_modify(o->u.r,t,ev,NULL);"
        "if(s==WRTC_REACTOR_STALE)return Py_NewRef(Py_False);"
        "if(s!=WRTC_REACTOR_OK){PyErr_Format(PyExc_RuntimeError,"
        "\"selector modify failed: %d\",(int)s);return NULL;}"
        "if(PyDict_SetItem(o->owners,k,d)<0)return NULL;return Py_NewRef(Py_True);}"
        "static PyObject*nrd(NSO*o,PyObject*k){WrtcNativeDescriptorToken t;"
        "WrtcNativeReactorStatus s;if(o->k!=7||!o->u.r){PyErr_SetString("
        "PyExc_TypeError,\"remove requires live selector storage\");return NULL;}"
        "if(nrt(k,&t)<0)return NULL;s=wrtc_native_selector_remove(o->u.r,t);"
        "if(s==WRTC_REACTOR_STALE)return Py_NewRef(Py_False);"
        "if(s!=WRTC_REACTOR_OK){PyErr_Format(PyExc_RuntimeError,"
        "\"selector remove failed: %d\",(int)s);return NULL;}"
        "if(PyDict_DelItem(o->owners,k)<0)return NULL;return Py_NewRef(Py_True);}"
        "static PyObject*nrc(NSO*o,PyObject*k){WrtcNativeDescriptorToken t;"
        "if(o->k!=7||!o->u.r||nrt(k,&t)<0)return NULL;return PyBool_FromLong("
        "wrtc_native_selector_token_is_current(o->u.r,t));}"
        "static PyObject*nro(NSO*o,PyObject*k){PyObject*v;if(o->k!=7||!o->u.r){"
        "PyErr_SetString(PyExc_TypeError,\"owner requires live selector storage\");"
        "return NULL;}v=PyDict_GetItemWithError(o->owners,k);if(!v&&!PyErr_Occurred())"
        "PyErr_SetObject(PyExc_KeyError,k);return v?Py_NewRef(v):NULL;}"
        "static PyObject*nrp(NSO*o,PyObject*args){int timeout,syserr=0;"
        "Py_ssize_t limit,i;size_t count=0u;WrtcNativeReadyEvent*events=NULL;"
        "WrtcNativeReactorStatus s;PyObject*result=NULL;if(o->k!=7||!o->u.r){"
        "PyErr_SetString(PyExc_TypeError,\"poll requires live selector storage\");"
        "return NULL;}if(!PyArg_ParseTuple(args,\"in:poll\",&timeout,&limit))"
        "return NULL;if(limit<=0){PyErr_SetString(PyExc_ValueError,"
        "\"poll event limit must be positive\");return NULL;}events=PyMem_Calloc("
        "(size_t)limit,sizeof(*events));if(!events)return PyErr_NoMemory();"
        "s=wrtc_native_selector_wait(o->u.r,timeout,events,(size_t)limit,&count,"
        "&syserr);if(s!=WRTC_REACTOR_OK){PyMem_Free(events);if(s=="
        "WRTC_REACTOR_SYSTEM_ERROR){errno=syserr;return PyErr_SetFromErrno("
        "PyExc_OSError);}PyErr_Format(PyExc_RuntimeError,"
        "\"selector poll failed: %d\",(int)s);return NULL;}"
        "result=PyList_New((Py_ssize_t)count);if(!result){PyMem_Free(events);"
        "return NULL;}for(i=0;i<(Py_ssize_t)count;i++){PyObject*k=Py_BuildValue("
        "\"(iK)\",events[i].token.descriptor,(unsigned long long)"
        "events[i].token.generation),*d,*item;if(!k)goto fail;d=PyDict_GetItemWithError("
        "o->owners,k);if(!d){Py_DECREF(k);if(!PyErr_Occurred())PyErr_SetString("
        "PyExc_RuntimeError,\"ready token has no boxed owner\");goto fail;}"
        "item=Py_BuildValue(\"(OIO)\",k,events[i].events,d);Py_DECREF(k);"
        "if(!item)goto fail;PyList_SET_ITEM(result,i,item);}PyMem_Free(events);"
        "return result;fail:PyMem_Free(events);Py_DECREF(result);return NULL;}"
        "static PyObject*npa(NSO*o,PyObject*unused){(void)unused;if(o->k!=8||"
        "!o->u.b){PyErr_SetString(PyExc_TypeError,"
        "\"available requires live packet slab storage\");return NULL;}"
        "return PyLong_FromSize_t(wrtc_native_packet_pool_available(o->u.b));}"
        "static WrtcNativePacketDisposition npy(WrtcNativeDatagramPacket*p,"
        "void*c){PyObject*callback=(PyObject*)c,*payload,*result;"
        "if(!PyGILState_Check()){PyErr_SetString(PyExc_RuntimeError,"
        "\"datagram delivery requires reactor-thread GIL\");"
        "return WRTC_PACKET_DELIVERY_ERROR;}payload=PyBytes_FromStringAndSize("
        "(const char*)p->data,(Py_ssize_t)p->size);if(!payload)"
        "return WRTC_PACKET_DELIVERY_ERROR;result=PyObject_CallOneArg("
        "callback,payload);Py_DECREF(payload);if(!result)"
        "return WRTC_PACKET_DELIVERY_ERROR;Py_DECREF(result);"
        "return WRTC_PACKET_CONSUMED;}"
        "typedef struct{NSO*owner;PyObject*callback;}NPC;"
        "static WrtcNativePacketDisposition npl(WrtcNativeDatagramPacket*p,"
        "void*c){NPC*x=(NPC*)c;NSO*lease;PyObject*result;int retained;"
        "if(!PyGILState_Check()){PyErr_SetString(PyExc_RuntimeError,"
        "\"retained datagram delivery requires reactor-thread GIL\");"
        "return WRTC_PACKET_DELIVERY_ERROR;}lease=PyObject_GC_New(NSO,"
        "Py_TYPE(x->owner));if(!lease){PyErr_NoMemory();return "
        "WRTC_PACKET_DELIVERY_ERROR;}lease->k=9;lease->rt=NULL;"
        "lease->owners=NULL;lease->u.d=*p;PyObject_GC_Track((PyObject*)lease);"
        "result=PyObject_CallOneArg(x->callback,(PyObject*)lease);if(!result){"
        "if(lease->k==0)p->pool=NULL;else lease->k=0;"
        "Py_DECREF((PyObject*)lease);return "
        "WRTC_PACKET_DELIVERY_ERROR;}Py_DECREF(result);if(lease->k!=9){"
        "p->pool=NULL;Py_DECREF((PyObject*)lease);return WRTC_PACKET_CONSUMED;}"
        "retained=Py_REFCNT(lease)>1;if(!retained)lease->k=0;"
        "Py_DECREF((PyObject*)lease);return retained?WRTC_PACKET_RETAINED:"
        "WRTC_PACKET_CONSUMED;}"
        "static PyObject*nlt(NSO*o,PyObject*unused){(void)unused;if(o->k!=9){"
        "PyErr_SetString(PyExc_RuntimeError,\"packet lease is released\");"
        "return NULL;}return PyBytes_FromStringAndSize((const char*)o->u.d.data,"
        "(Py_ssize_t)o->u.d.size);}"
        "static PyObject*nlr(NSO*o,PyObject*unused){WrtcNativeReactorStatus s;"
        "(void)unused;if(o->k!=9)return Py_NewRef(Py_None);s="
        "wrtc_native_datagram_packet_release(&o->u.d);o->k=0;if(s!="
        "WRTC_REACTOR_OK){PyErr_SetString(PyExc_RuntimeError,"
        "\"packet lease release failed\");return NULL;}return Py_NewRef(Py_None);}"
        "static PyObject*npd(NSO*o,PyObject*args){int fd;Py_ssize_t budget;"
        "unsigned long long nanos;PyObject*callback;WrtcNativeDatagramDrainResult r;"
        "WrtcNativeReactorStatus s;if(o->k!=8||!o->u.b){PyErr_SetString("
        "PyExc_TypeError,\"drain requires live packet slab storage\");"
        "return NULL;}if(!PyArg_ParseTuple(args,\"inKO:drain\",&fd,&budget,"
        "&nanos,&callback))return NULL;if(budget<=0||!PyCallable_Check(callback)){"
        "PyErr_SetString(PyExc_ValueError,"
        "\"drain requires positive budget and callable delivery\");return NULL;}"
        "s=wrtc_native_datagram_drain(fd,o->u.b,(size_t)budget,(uint64_t)nanos,"
        "npy,callback,&r);if(PyErr_Occurred())return NULL;if(r.packets>"
        "(size_t)PY_SSIZE_T_MAX||r.receive_syscalls>(size_t)PY_SSIZE_T_MAX)"
        "return PyErr_NoMemory();return Py_BuildValue(\"(inniii)\",(int)s,"
        "(Py_ssize_t)r.packets,(Py_ssize_t)r.receive_syscalls,(int)r.reason,"
        "r.reschedule,r.system_error);}"
        "static PyObject*npr(NSO*o,PyObject*args){int fd;Py_ssize_t budget;"
        "unsigned long long nanos;PyObject*callback;WrtcNativeDatagramDrainResult r;"
        "WrtcNativeReactorStatus s;NPC context;if(o->k!=8||!o->u.b){"
        "PyErr_SetString(PyExc_TypeError,"
        "\"drain_retained requires live packet slab storage\");return NULL;}"
        "if(!PyArg_ParseTuple(args,\"inKO:drain_retained\",&fd,&budget,"
        "&nanos,&callback))return NULL;if(budget<=0||!PyCallable_Check(callback)){"
        "PyErr_SetString(PyExc_ValueError,"
        "\"drain_retained requires positive budget and callable delivery\");"
        "return NULL;}context.owner=o;context.callback=callback;s="
        "wrtc_native_datagram_drain(fd,o->u.b,(size_t)budget,(uint64_t)nanos,"
        "npl,&context,&r);if(PyErr_Occurred())return NULL;if(r.packets>"
        "(size_t)PY_SSIZE_T_MAX||r.receive_syscalls>(size_t)PY_SSIZE_T_MAX)"
        "return PyErr_NoMemory();return Py_BuildValue(\"(inniii)\",(int)s,"
        "(Py_ssize_t)r.packets,(Py_ssize_t)r.receive_syscalls,(int)r.reason,"
        "r.reschedule,r.system_error);}"
        "static PyObject*nqc(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"close requires bounded queue storage\");return NULL;}"
        "if(o->wa&&o->wk==1)return waco(o->wa,NULL);"
        "if(o->wa&&o->wk==2)return Py_NewRef(Py_None);"
        "if(o->k==5)wrtc_native_mpsc_close(&o->u.m);"
        "else wrtc_native_spsc_close(&o->u.p);return Py_NewRef(Py_None);}"
        "static PyMethodDef nom[]={{\"load\",(PyCFunction)nol,METH_NOARGS,NULL},"
        "{\"store\",(PyCFunction)nostore,METH_O,NULL},"
        "{\"compare_exchange\",(PyCFunction)nox,METH_VARARGS,NULL},"
        "{\"put_nowait\",(PyCFunction)nqp,METH_O,NULL},"
        "{\"get_nowait\",(PyCFunction)nqg,METH_NOARGS,NULL},"
        "{\"qsize\",(PyCFunction)nqs,METH_NOARGS,NULL},"
        "{\"empty\",(PyCFunction)nqz,METH_NOARGS,NULL},"
        "{\"register\",(PyCFunction)nrr,METH_VARARGS,NULL},"
        "{\"modify\",(PyCFunction)nrm,METH_VARARGS,NULL},"
        "{\"remove\",(PyCFunction)nrd,METH_O,NULL},"
        "{\"is_current\",(PyCFunction)nrc,METH_O,NULL},"
        "{\"owner\",(PyCFunction)nro,METH_O,NULL},"
        "{\"poll\",(PyCFunction)nrp,METH_VARARGS,NULL},"
        "{\"available\",(PyCFunction)npa,METH_NOARGS,NULL},"
        "{\"drain\",(PyCFunction)npd,METH_VARARGS,NULL},"
        "{\"drain_retained\",(PyCFunction)npr,METH_VARARGS,NULL},"
        "{\"to_bytes\",(PyCFunction)nlt,METH_NOARGS,NULL},"
        "{\"release\",(PyCFunction)nlr,METH_NOARGS,NULL},"
        "{\"close\",(PyCFunction)nqc,METH_NOARGS,NULL},"
        "{NULL,NULL,0,NULL}};"
        "static PyGetSetDef nog[]={{\"closed\",(getter)nqclosed,NULL,NULL,NULL},"
        "{NULL,NULL,NULL,NULL,NULL}};"
        "static PyType_Slot nosl[]={{Py_tp_traverse,(void*)notr},"
        "{Py_tp_clear,(void*)nocl},{Py_tp_dealloc,(void*)node},"
        "{Py_tp_methods,(void*)nom},{Py_tp_getset,(void*)nog},{0,NULL}};"
        "static PyType_Spec nosp={\"pymeta.NativeStorageOwner\",sizeof(NSO),"
        "0,Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,nosl};"
        "static const char wrtc_nalias_name[]="
        "\"pymeta.native-storage-alias\";"
        "static void nad(PyObject*c){NSO*o=(NSO*)PyCapsule_GetPointer("
        "c,wrtc_nalias_name);"
        "if(o)Py_DECREF((PyObject*)o);else PyErr_Clear();}"
        "static PyObject*nac(NSO*o){PyObject*c;Py_INCREF((PyObject*)o);"
        "c=PyCapsule_New(o,wrtc_nalias_name,nad);"
        "if(!c)Py_DECREF((PyObject*)o);return c;}"
        "static NSO*nal(PyObject*c){return(NSO*)PyCapsule_GetPointer("
        "c,wrtc_nalias_name);}"
        "static int nai(PyObject*,PyObject*,NSO**);"
        "static int nri(PyObject*,NSO**,int,const char*,const char*);"
        "static NSO*no(PyObject*self,int k){PyTypeObject*t=nt(self);"
        "(void)nac;(void)nal;(void)nai;(void)nri;"
        "NSO*o;if(!t)return NULL;o=PyObject_GC_New(NSO,t);if(!o)return NULL;"
        "o->k=k;o->wk=0;o->wa=NULL;o->rt=NULL;o->owners=NULL;"
        "if(k==1)wrtc_native_scalar_init(&o->u.s);"
        "else if(k==2)wrtc_native_fifo_init(&o->u.f);"
        "else if(k==3)wrtc_native_heap_init(&o->u.h);"
        "else if(k==4)wrtc_native_atomic_uint32_init(&o->u.a);"
        "else{PyObject_GC_Del(o);PyErr_SetString(PyExc_SystemError,"
        "\"storage kind requires specialized initialization\");return NULL;}"
        "PyObject_GC_Track((PyObject*)o);return o;}"
        "static int nai(PyObject*self,PyObject*v,NSO**p){"
        "PyObject*m=NULL,*t=NULL,*loaded=NULL;uint_least32_t initial;"
        "NSO*o=*p;m=PyImport_ImportModule(\"pymeta.concurrent\");"
        "if(m)t=PyObject_GetAttrString(m,\"LockedAtomic\");"
        "Py_XDECREF(m);if(!t)return -1;"
        "if(!PyType_Check(t)||Py_TYPE(v)!=(PyTypeObject*)t){Py_DECREF(t);"
        "PyErr_SetString(PyExc_TypeError,"
        "\"atomic field initialization requires exact LockedAtomic\");"
        "return -1;}loaded=PyObject_CallMethod(v,\"load\",NULL);"
        "Py_DECREF(t);if(!loaded)return -1;"
        "if(n32(loaded,&initial)<0){Py_DECREF(loaded);return -1;}"
        "Py_DECREF(loaded);if(o&&o->u.a.initialized){PyErr_SetString("
        "PyExc_AttributeError,\"atomic field may only be initialized once\");"
        "return -1;}if(!o){o=no(self,4);if(!o)return -1;*p=o;}"
        "return wrtc_native_atomic_uint32_set(&o->u.a,initial);}"
        "static PyObject*ncp(PyObject*self,const char*path){"
        "const char*p;PyObject*o;if(!path||strncmp(path,\"self.\",5)!=0){"
        "PyErr_SetString(PyExc_TypeError,"
        "\"bounded capacity must be a resolvable self field path\");"
        "return NULL;}o=Py_NewRef(self);p=path+5;while(*p){const char*d="
        "strchr(p,'.');size_t z=d?(size_t)(d-p):strlen(p);char*n;"
        "PyObject*x;if(z==0u){Py_DECREF(o);PyErr_SetString(PyExc_TypeError,"
        "\"bounded capacity path contains an empty component\");return NULL;}"
        "n=PyMem_Malloc(z+1u);if(!n){Py_DECREF(o);return PyErr_NoMemory();}"
        "memcpy(n,p,z);n[z]='\\0';x=PyObject_GetAttrString(o,n);"
        "PyMem_Free(n);Py_DECREF(o);if(!x)return NULL;o=x;"
        "if(!d)break;p=d+1;}return o;}\n"
        "static PyObject*ncv(PyObject*self,const char*s){char*e=NULL;"
        "unsigned long long x;if(!s)return NULL;if(strncmp(s,\"self.\",5)==0)"
        "return ncp(self,s);x=strtoull(s,&e,10);if(!e||*e!='\\0'){"
        "PyErr_SetString(PyExc_TypeError,\"reactor capacity must be an "
        "integer or self field path\");return NULL;}"
        "return PyLong_FromUnsignedLongLong(x);}"
        "static int nri(PyObject*self,NSO**p,int k,const char*cs,const char*bs){"
        "PyObject*c=NULL,*b=NULL;PyTypeObject*t;NSO*o=NULL;size_t cap,buf=0u;"
        "if(*p){PyErr_SetString(PyExc_AttributeError,"
        "\"reactor storage may only be initialized once\");return -1;}"
        "if(!PyGILState_Check()){PyErr_SetString(PyExc_RuntimeError,"
        "\"reactor storage initialization requires reactor-thread GIL\");"
        "return -1;}c=ncv(self,cs);if(!c)return -1;"
        "cap=PyLong_AsSize_t(c);Py_DECREF(c);if(PyErr_Occurred())return -1;"
        "if(cap==0u){PyErr_SetString(PyExc_ValueError,"
        "\"reactor capacity must be positive\");return -1;}"
        "if(k==8){b=ncv(self,bs);if(!b)return -1;buf=PyLong_AsSize_t(b);"
        "Py_DECREF(b);if(PyErr_Occurred())return -1;if(buf==0u){"
        "PyErr_SetString(PyExc_ValueError,"
        "\"packet buffer size must be positive\");return -1;}}"
        "t=nt(self);if(!t)return -1;o=PyObject_GC_New(NSO,t);if(!o)return -1;"
        "o->k=k;o->wk=0;o->wa=NULL;o->rt=NULL;o->owners=PyDict_New();o->u.r=NULL;"
        "if(!o->owners)goto fail;if((k==7?wrtc_native_selector_create("
        "&o->u.r,cap):wrtc_native_packet_pool_create(&o->u.b,cap,buf))<0){"
        "PyErr_NoMemory();goto fail;}PyObject_GC_Track((PyObject*)o);*p=o;"
        "return 0;fail:Py_XDECREF(o->owners);PyObject_GC_Del(o);return -1;}\n"
        "#if defined(__GNUC__)||defined(__clang__)\n"
        "#define WRTC_UNUSED __attribute__((unused))\n"
        "#else\n#define WRTC_UNUSED\n#endif\n"
        "static int WRTC_UNUSED nmq(PyObject*self,PyObject*v,NSO**p,int k,"
        "const char*path,const char*rm,const char*rn){"
        "PyObject*m=NULL,*t=NULL,*decl=NULL,*sz=NULL,*closed=NULL,*cap=NULL;"
        "PyObject*rt=NULL;"
        "NSO*o=NULL;"
        "PyTypeObject*ot;size_t capacity,declared;int empty,isclosed;"
        "m=PyImport_ImportModule(\"pymeta.concurrent\");"
        "if(m)t=PyObject_GetAttrString(m,\"BoundedQueue\");"
        "Py_XDECREF(m);m=NULL;if(!t)return -1;"
        "if(!PyType_Check(t)||Py_TYPE(v)!=(PyTypeObject*)t){Py_DECREF(t);"
        "PyErr_SetString(PyExc_TypeError,"
        "\"queue initialization requires exact BoundedQueue\");return -1;}"
        "Py_DECREF(t);t=NULL;"
        "sz=PyObject_CallMethod(v,\"qsize\",NULL);"
        "closed=PyObject_GetAttrString(v,\"closed\");"
        "cap=PyObject_GetAttrString(v,\"capacity\");"
        "decl=ncp(self,path);"
        "if(!sz||!closed||!cap||!decl)goto fail;"
        "capacity=PyLong_AsSize_t(cap);"
        "declared=PyLong_AsSize_t(decl);empty=PyObject_IsTrue(sz);"
        "isclosed=PyObject_IsTrue(closed);"
        "if(PyErr_Occurred()||empty<0||isclosed<0)goto fail;"
        "if(capacity==0u||capacity!=declared){PyErr_SetString(PyExc_ValueError,"
        "\"queue capacity must be positive and match its declared field\");"
        "goto fail;}if(empty){PyErr_SetString(PyExc_ValueError,"
        "\"queue initialization queue must be empty\");goto fail;}"
        "if(isclosed){PyErr_SetString(PyExc_ValueError,"
        "\"queue initialization queue must be open\");goto fail;}"
        "if(*p){PyErr_SetString(PyExc_AttributeError,"
        "\"queue field may only be initialized once\");goto fail;}"
        "m=PyImport_ImportModule(rm);if(m)rt=PyObject_GetAttrString(m,rn);"
        "Py_XDECREF(m);m=NULL;if(!rt)goto fail;"
        "if(!PyType_Check(rt)){PyErr_SetString(PyExc_TypeError,"
        "\"queue ABI record guard did not resolve to a type\");goto fail;}"
        "ot=nt(self);if(!ot)goto fail;o=PyObject_GC_New(NSO,ot);"
        "if(!o)goto fail;o->k=k;o->wk=0;o->wa=NULL;"
        "o->rt=(PyTypeObject*)rt;o->owners=NULL;rt=NULL;"
        "if((k==5?wrtc_native_mpsc_init(&o->u.m,capacity):"
        "wrtc_native_spsc_init(&o->u.p,capacity))<0){Py_CLEAR(o->rt);"
        "PyObject_GC_Del(o);"
        "o=NULL;PyErr_NoMemory();goto fail;}PyObject_GC_Track((PyObject*)o);"
        "*p=o;Py_DECREF(sz);Py_DECREF(closed);Py_DECREF(cap);Py_DECREF(decl);"
        "return 0;fail:Py_XDECREF(m);Py_XDECREF(t);Py_XDECREF(rt);"
        "Py_XDECREF(sz);Py_XDECREF(closed);Py_XDECREF(cap);"
        "Py_XDECREF(decl);return -1;}\n",
        file) < 0 ? -1 : 0;
}

static int emit_native_class_extension(
    FILE *file, const char *module, const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations,
    const char *source_hash, const char *semantic_hash, const char *revision,
    const char *target, const char *architecture,
    const char *extension_suffix, PyObject *artifact_metadata) {
    size_t index;
    Py_ssize_t position = 0;
    PyObject *key, *value;
    const int has_storage = program_has_storage(program);
    const int has_reactor_hooks = program_has_reactor_hooks(program);
    const int has_reactor_storage = program_has_reactor_storage(program);
    const int has_reactor_runtime = has_reactor_hooks || has_storage;
    const int has_handle_run = program_has_handle_run(program);
    const int has_direct = program_has_direct_regions(program, operations);
    const int has_constructors = program_has_constructors(program);
    const int has_workers = program_has_workers(program);
    const size_t fusion_count = fused_call_count(program);
    if (file == NULL || module == NULL || program == NULL)
        return -1;
    if (fputs("#define PY_SSIZE_T_CLEAN\n#include <Python.h>\n"
              "#include <structmember.h>\n#include <stddef.h>\n"
              "#include <stdint.h>\n#include <string.h>\n"
              "#if PY_VERSION_HEX < 0x030C0000\n"
              "#error \"native heap data requires CPython 3.12 or newer\"\n"
              "#endif\n"
              "typedef struct MS MS;typedef struct{MS*module;PyObject*receiver;"
              "uint64_t epoch;}WrtcSchedulerContext;"
              "static struct PyModuleDef md;"
              "static MS*sm(PyObject*);"
              "static PyTypeObject*dt(PyObject*,size_t);",
              file) < 0 ||
        (has_handle_run &&
         fputs("static PyObject*whr(PyObject*,PyObject*);", file) < 0) ||
        (fusion_count != 0u &&
         fputs("static PyObject*fd(PyObject*,size_t);", file) < 0) ||
        (has_storage &&
         fputs("static PyTypeObject*nt(PyObject*);", file) < 0) ||
        (has_direct &&
         fputs("static int wg(PyObject*,size_t,size_t,WrtcSchedulerContext*);"
               "static PyObject*wf(PyObject*,size_t,PyObject*const*,"
               "Py_ssize_t,PyObject*);", file) < 0) ||
        fputs(
              "static PyObject*rb(const char*n){const char*dot;PyObject*m,*b;"
              "char*p;size_t z;if(!n||strcmp(n,\"object\")==0||"
              "strcmp(n,\"builtins.object\")==0)return Py_NewRef("
              "(PyObject*)&PyBaseObject_Type);dot=strrchr(n,'.');"
              "if(!dot){PyErr_SetString(PyExc_ImportError,\"base must be dotted\");"
              "return NULL;}z=(size_t)(dot-n);p=PyMem_Malloc(z+1u);"
              "if(!p)return PyErr_NoMemory();memcpy(p,n,z);p[z]='\\0';"
              "m=PyImport_ImportModule(p);PyMem_Free(p);if(!m)return NULL;"
              "b=PyObject_GetAttrString(m,dot+1);Py_DECREF(m);"
              "if(b&&!PyType_Check(b)){Py_DECREF(b);PyErr_SetString("
              "PyExc_TypeError,\"base is not a type\");return NULL;}"
              "if(b&&((((PyTypeObject*)b)->tp_flags&Py_TPFLAGS_HAVE_GC)==0)){"
              "Py_DECREF(b);PyErr_SetString(PyExc_TypeError,"
              "\"native boxed fields require a GC-tracked base\");return NULL;}"
              "return b;}\n",
              file) < 0)
        return -1;
    if (fputs(
            "static int ta(PyObject*t,Py_ssize_t i,const char*n){"
            "PyObject*v=PyUnicode_FromString(n);if(!v)return -1;"
            "PyTuple_SET_ITEM(t,i,v);return 0;}"
            "static int ma(PyObject*m,const char*n,PyObject*v){"
            "if(!v)return -1;if(PyModule_AddObject(m,n,v)<0){"
            "Py_DECREF(v);return -1;}return 0;}\n",
            file) < 0)
        return -1;
    if (wrtc_boxed_emit_runtime(file) < 0 ||
        (wrtc_aot_program_has_regions(program) &&
         wrtc_aot_emit_runtime(file) < 0)) return -1;
    if (has_constructors &&
        fputs(
            "static PyObject*wwa(PyObject*,size_t,int*);"
            "typedef struct{PyObject*self;size_t ci;}WCC;"
            "static PyObject*wce(void*opaque,const WrtcPyExprIR*e,void*f,"
            "int*h){WCC*c=(WCC*)opaque;const WrtcPyExprIR*a,*q;"
            "PyTypeObject*t,*b;PyObject*args=NULL,*full=NULL,*kwargs=NULL,"
            "*callable=NULL,*r=NULL;size_t i;if(!c||!e||"
            "e->kind!=WRTC_PY_EXPR_CALL||"
            "e->child_count==0u)return NULL;a=&e->children[0];"
            "if(a->kind==WRTC_PY_EXPR_ATTRIBUTE&&a->operation&&"
            "strcmp(a->operation,\"Thread\")==0)return wwa(c->self,c->ci,h);"
            "if(a->kind!=WRTC_PY_EXPR_ATTRIBUTE||!a->operation||"
            "strcmp(a->operation,\"__init__\")!=0||a->child_count!=1u)"
            "return NULL;q=&a->children[0];if(q->kind!=WRTC_PY_EXPR_CALL||"
            "q->child_count!=1u||q->positional_count!=0u||"
            "q->keyword_count!=0u||q->children[0].kind!=WRTC_PY_EXPR_NAME||"
            "!q->children[0].operation||strcmp(q->children[0].operation,"
            "\"super\")!=0)return NULL;*h=1;t=dt(c->self,c->ci);"
            "if(!t||!(b=t->tp_base)){PyErr_SetString(PyExc_TypeError,"
            "\"native constructor base is unavailable\");return NULL;}"
            "callable=PyObject_GetAttrString((PyObject*)b,\"__init__\");"
            "if(!callable)return NULL;args=PyTuple_New("
            "(Py_ssize_t)e->positional_count);"
            "kwargs=PyDict_New();if(!args||!kwargs)goto done;"
            "for(i=0u;i<e->positional_count;i++){PyObject*v="
            "wrtc_boxed_hook_evaluate(&e->children[1u+i],f);"
            "if(!v)goto done;PyTuple_SET_ITEM(args,(Py_ssize_t)i,v);}"
            "for(i=0u;i<e->keyword_count;i++){PyObject*v="
            "wrtc_boxed_hook_evaluate(&e->children[1u+e->positional_count+i],f);"
            "if(!v||PyDict_SetItemString(kwargs,e->keyword_names[i],v)<0){"
            "Py_XDECREF(v);goto done;}Py_DECREF(v);}full=PyTuple_New("
            "(Py_ssize_t)e->positional_count+1);if(!full)goto done;"
            "PyTuple_SET_ITEM(full,0,Py_NewRef(c->self));for(i=0u;i<"
            "e->positional_count;i++)PyTuple_SET_ITEM(full,(Py_ssize_t)i+1,"
            "Py_NewRef(PyTuple_GET_ITEM(args,(Py_ssize_t)i)));r=PyObject_Call("
            "callable,full,kwargs);done:Py_XDECREF(callable);Py_XDECREF(kwargs);"
            "Py_XDECREF(full);Py_XDECREF(args);return r;}\n",
            file) < 0)
        return -1;
    if (has_reactor_runtime && wrtc_native_reactor_emit_runtime(file) < 0)
        return -1;
    if (has_reactor_hooks &&
        wrtc_native_reactor_emit_cpython_runtime(file) < 0)
        return -1;
    if (has_storage && wrtc_native_storage_emit_runtime(file) < 0)
        return -1;
    /* Storage owners carry an optional worker attachment.  Emit the generic
     * adapter declarations for storage-only artifacts as well; no executor is
     * created unless a proof-complete owned worker constructor selects it. */
    if (has_storage &&
        (wrtc_native_worker_emit_runtime(file) < 0 ||
         wrtc_native_worker_emit_cpython_adapter(file) < 0))
        return -1;
    if (has_workers &&
        (emit_worker_abis(file, program) < 0 ||
         wrtc_native_kernel_emit(file, program, "wk") < 0))
        return -1;
    if (has_storage && emit_storage_owner(file) < 0) return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        if (program->classes[index].custom_constructor &&
            fprintf(file, "static int cg%zu(PyObject*);", index) < 0)
            return -1;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file,
                        "static PyObject*w%zu_%zu(PyObject*,PyObject*const*,"
                        "Py_ssize_t,PyObject*);",
                        index, region_index) < 0)
                return -1;
    }
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        if (class_has_globals(&program->classes[index])) {
            char globals_symbol[32];
            char *module_name =
                wrtc_boxed_module_name(program->classes[index].filename);
            if (module_name == NULL) return -1;
            (void)snprintf(globals_symbol, sizeof globals_symbol, "g%zu",
                           index);
            if (wrtc_boxed_emit_module_globals(
                    file, globals_symbol, module_name) < 0) {
                free(module_name);
                return -1;
            }
            free(module_name);
        }
        if (program->classes[index].custom_constructor) {
            char suite_symbol[64], signature_symbol[64];
            (void)snprintf(suite_symbol, sizeof suite_symbol,
                           "c%zu_suite", index);
            (void)snprintf(signature_symbol, sizeof signature_symbol,
                           "c%zu_sig", index);
            if (wrtc_boxed_emit_suite(
                    file, suite_symbol,
                    program->classes[index].constructor_body) < 0 ||
                wrtc_boxed_emit_signature(
                    file, signature_symbol,
                    program->classes[index].constructor_signature) < 0)
                return -1;
        }
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++) {
            char suite_symbol[64], signature_symbol[64];
            (void)snprintf(suite_symbol, sizeof suite_symbol,
                           "r%zu_%zu_suite", index, region_index);
            (void)snprintf(signature_symbol, sizeof signature_symbol,
                           "r%zu_%zu_sig", index, region_index);
            if (wrtc_boxed_emit_suite(
                    file, suite_symbol,
                    program->classes[index].regions[region_index].body) < 0 ||
                wrtc_boxed_emit_signature(
                    file, signature_symbol,
                    program->classes[index].regions[region_index].signature) < 0)
                return -1;
        }
    }
    for (index = 0u; index < program->factory_count; index++) {
        char suite_symbol[64], signature_symbol[64], globals_symbol[32];
        char *module_name =
            wrtc_boxed_module_name(program->factories[index].filename);
        if (module_name == NULL) return -1;
        (void)snprintf(suite_symbol, sizeof suite_symbol, "f%zu_suite",
                       index);
        (void)snprintf(signature_symbol, sizeof signature_symbol,
                       "f%zu_sig", index);
        (void)snprintf(globals_symbol, sizeof globals_symbol, "fg%zu",
                       index);
        if (wrtc_boxed_emit_module_globals(
                file, globals_symbol, module_name) < 0 ||
            wrtc_boxed_emit_suite(
                file, suite_symbol, program->factories[index].body) < 0 ||
            wrtc_boxed_emit_signature(
                file, signature_symbol,
                program->factories[index].signature) < 0) {
            free(module_name);
            return -1;
        }
        free(module_name);
        if (fprintf(file,
                    "static PyObject*fw%zu(PyObject*self,PyObject*args,"
                    "PyObject*kwargs){PyObject*locals=NULL,*result=NULL;"
                    "(void)self;wrtc_native_allocation_region_enter(", index) < 0 ||
            quote(file, program->factories[index].name) < 0 ||
            fprintf(file,
                    ");if(wrtc_boxed_bind(&f%zu_sig,args,kwargs,"
                    "&locals)<0)goto done;if(wrtc_boxed_execute(&f%zu_suite,"
                    "fg%zu_globals,locals,&result)<0)result=NULL;"
                    "done:wrtc_native_allocation_release_locals(locals);"
                    "wrtc_native_allocation_region_leave();return result;}\n",
                    index, index, index) < 0)
            return -1;
    }
    if (fputs("static PyMethodDef fm[]={", file) < 0) return -1;
    for (index = 0u; index < program->factory_count; index++) {
        if (fputc('{', file) == EOF ||
            quote(file, program->factories[index].name) < 0 ||
            fprintf(file, ",(PyCFunction)(void(*)(void))fw%zu,"
                          "METH_VARARGS|METH_KEYWORDS,NULL},", index) < 0)
            return -1;
    }
    if (fputs(
            "{\"__pymeta_native_allocation_counters__\","
            "wrtc_native_allocation_counters,METH_NOARGS,NULL},"
            "{\"__pymeta_reset_native_allocation_counters__\","
            "wrtc_native_reset_allocation_counters,METH_NOARGS,NULL},"
            "{NULL,NULL,0,NULL}};", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        if (emit_class(file, module, program, operations,
                       &program->classes[index], index) < 0)
            return -1;
        if (emit_python_method_fallback_copy(
                file, &program->classes[index], index) < 0)
            return -1;
    }
    if (has_direct) {
        if (fputs("static const char*grn[]={", file) < 0) return -1;
        for (index = 0u; index < program->class_count; index++) {
            size_t region_index;
            for (region_index = 0u;
                 region_index < program->classes[index].region_count;
                 region_index++)
                if (quote(file,
                          program->classes[index].regions[region_index].name) < 0 ||
                    fputc(',', file) == EOF)
                    return -1;
        }
        if (fputs("NULL};", file) < 0) return -1;
    }
    if (fprintf(file,
                "struct MS{PyObject*t[%zu];PyObject*sg[%zu];PyObject*ot[%zu];"
                "PyObject*nt;PyObject*wt;PyObject*rt[%zu];PyObject*fd[%zu];"
                "PyObject*hr[7];PyObject*od[%zu];PyObject*nd[%zu];"
                "uint64_t invalidation_epoch;unsigned active;};"
                "static size_t mlive=0u;",
                program->class_count,
                program->class_count,
                program->class_count,
                program->record_count == 0u ? 1u : program->record_count,
                fusion_count == 0u ? 1u : fusion_count,
                emitted_region_count(program) == 0u
                    ? 1u : emitted_region_count(program),
                emitted_region_count(program) == 0u
                    ? 1u : emitted_region_count(program)) < 0 ||
        fputs("static MS*sm(PyObject*o){PyObject*m="
               "PyType_GetModuleByDef(Py_TYPE(o),&md);"
               "return m?(MS*)PyModule_GetState(m):NULL;}"
               "static PyTypeObject*dt(PyObject*o,size_t i){"
               "MS*s=sm(o);return s?(PyTypeObject*)s->t[i]:NULL;}",
               file) < 0 ||
        (fusion_count != 0u &&
         fputs("static PyObject*fd(PyObject*o,size_t i){"
               "MS*s=sm(o);return s?s->fd[i]:NULL;}", file) < 0) ||
        (has_storage &&
         fputs("static PyTypeObject*nt(PyObject*o){MS*s=sm(o);"
               "return s?(PyTypeObject*)s->nt:NULL;}", file) < 0) ||
        0)
        return -1;
    if (has_direct && fputs(
            "static int wg(PyObject*o,size_t ci,size_t ri,"
            "WrtcSchedulerContext*c){MS*s=sm(o);PyObject*current;"
            "if(!s||!s->active||Py_TYPE(o)!=(PyTypeObject*)s->t[ci])"
            "return 0;"
            "current=PyObject_GetAttrString(s->ot[ci],grn[ri]);"
            "if(!current){PyErr_Clear();s->invalidation_epoch++;return 0;}"
            "if(current!=s->od[ri]){Py_DECREF(current);"
            "s->invalidation_epoch++;return 0;}Py_DECREF(current);"
            "current=PyObject_GetAttrString(s->t[ci],grn[ri]);"
            "if(!current){PyErr_Clear();s->invalidation_epoch++;return 0;}"
            "if(current!=s->nd[ri]){Py_DECREF(current);"
            "s->invalidation_epoch++;return 0;}Py_DECREF(current);"
            "c->module=s;c->receiver=o;"
            "c->epoch=s->invalidation_epoch;return 1;}"
            "static PyObject*wf(PyObject*o,size_t ri,PyObject*const*a,"
            "Py_ssize_t n,PyObject*k){MS*s=sm(o);Py_ssize_t i,kn=k?"
            "PyTuple_GET_SIZE(k):0,total=n+kn;PyObject*small[9],**v=small,*r;"
            "if(!s||!s->od[ri]){PyErr_SetString(PyExc_RuntimeError,"
            "\"native fallback descriptor is unavailable\");return NULL;}"
            "wrtc_native_allocation_alloc("
            "WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);"
            "if(total+1>9){v=PyMem_Malloc((size_t)(total+1)*sizeof(*v));"
            "if(!v){wrtc_native_allocation_free("
            "WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);"
            "return PyErr_NoMemory();}}v[0]=o;for(i=0;i<total;i++)"
            "v[i+1]=a[i];wrtc_native_allocation_pause();r=PyObject_Vectorcall("
            "s->od[ri],v,(size_t)(n+1),k);wrtc_native_allocation_resume();"
            "if(v!=small)PyMem_Free(v);wrtc_native_allocation_free("
            "WRTC_NATIVE_ALLOC_FALLBACK_DEOPTIMIZATION);return r;}", file) < 0)
        return -1;
    if (has_handle_run && fputs(
            "static PyObject*WRTC_AOT_UNUSED whr(PyObject*l,PyObject*h){MS*s=sm(l);"
            "PyObject*d,*v,*hl=NULL,*cb=NULL,*args=NULL,*ctx=NULL,*run=NULL,*full=NULL,*r=NULL;"
            "PyObject*et=NULL,*ev=NULL,*tb=NULL,*fm=NULL,*fmt=NULL,*dbg=NULL,*msg=NULL,*cd=NULL,*src=NULL,*ceh=NULL;"
            "int cancelled,i;if(!s||!s->hr[0]||(Py_TYPE(h)!=(PyTypeObject*)s->hr[0]&&"
            "Py_TYPE(h)!=(PyTypeObject*)s->hr[6]))goto dynamic;"
            "d=PyType_GetDict((PyTypeObject*)s->hr[0]);for(i=1;i<6;i++){v=PyDict_GetItemString(d,"
            "i==1?\"_run\":i==2?\"_callback\":i==3?\"_args\":i==4?\"_cancelled\":\"_context\");"
            "if(v!=s->hr[i])goto dynamic;}args=PyObject_GetAttrString(h,\"_args\");"
            "if(!args)return NULL;if(!PyTuple_CheckExact(args)){Py_CLEAR(args);goto dynamic;}"
            "v=PyObject_GetAttrString(h,\"_cancelled\");if(!v)goto done;cancelled=PyObject_IsTrue(v);Py_DECREF(v);"
            "if(cancelled<0)goto done;if(cancelled){r=Py_NewRef(Py_None);goto done;}"
            "cb=PyObject_GetAttrString(h,\"_callback\");ctx=PyObject_GetAttrString(h,\"_context\");"
            "if(!cb||!ctx)goto done;run=PyObject_GetAttrString(ctx,\"run\");if(!run)goto done;"
            "full=PyTuple_New(PyTuple_GET_SIZE(args)+1);if(!full)goto done;PyTuple_SET_ITEM(full,0,Py_NewRef(cb));"
            "for(i=0;i<PyTuple_GET_SIZE(args);i++)PyTuple_SET_ITEM(full,i+1,Py_NewRef(PyTuple_GET_ITEM(args,i)));"
            "r=PyObject_Call(run,full,NULL);if(r)goto done;PyErr_Fetch(&et,&ev,&tb);PyErr_NormalizeException(&et,&ev,&tb);"
            "if(et&&(PyErr_GivenExceptionMatches(et,PyExc_SystemExit)||PyErr_GivenExceptionMatches(et,PyExc_KeyboardInterrupt))){"
            "PyErr_Restore(et,ev,tb);et=ev=tb=NULL;goto done;}fm=PyImport_ImportModule(\"asyncio.format_helpers\");"
            "if(!fm)goto handler_fail;fmt=PyObject_GetAttrString(fm,\"_format_callback_source\");"
            "hl=PyObject_GetAttrString(h,\"_loop\");if(!hl)goto handler_fail;"
            "dbg=PyObject_CallMethod(hl,\"get_debug\",NULL);if(!fmt||!dbg)goto handler_fail;"
            "cd=PyDict_New();if(!cd)goto handler_fail;{PyObject*kw=Py_BuildValue(\"{s:O}\",\"debug\",dbg);"
            "PyObject*fa=PyTuple_Pack(2,cb,args);if(!kw||!fa){Py_XDECREF(kw);Py_XDECREF(fa);goto handler_fail;}"
            "v=PyObject_Call(fmt,fa,kw);Py_DECREF(fa);Py_DECREF(kw);}if(!v)goto handler_fail;"
            "msg=PyUnicode_FromFormat(\"Exception in callback %U\",v);Py_DECREF(v);if(!msg)goto handler_fail;"
            "if(PyDict_SetItemString(cd,\"message\",msg)<0||PyDict_SetItemString(cd,\"exception\",ev)<0||"
            "PyDict_SetItemString(cd,\"handle\",h)<0)goto handler_fail;src=PyObject_GetAttrString(h,\"_source_traceback\");"
            "if(!src)goto handler_fail;if(src!=Py_None&&PyDict_SetItemString(cd,\"source_traceback\",src)<0)goto handler_fail;"
            "ceh=PyObject_GetAttrString(hl,\"call_exception_handler\");if(!ceh)goto handler_fail;"
            "v=PyObject_CallOneArg(ceh,cd);if(!v)goto handler_raised;Py_DECREF(v);r=Py_NewRef(Py_None);goto handled;"
            "handler_fail:PyErr_Clear();PyErr_Restore(et,ev,tb);et=ev=tb=NULL;handled:Py_XDECREF(et);Py_XDECREF(ev);Py_XDECREF(tb);goto done;"
            "handler_raised:Py_CLEAR(et);Py_CLEAR(ev);Py_CLEAR(tb);goto done;"
            "dynamic:run=PyObject_GetAttrString(h,\"_run\");if(run)r=PyObject_CallNoArgs(run);"
            "done:Py_XDECREF(ceh);Py_XDECREF(src);Py_XDECREF(cd);Py_XDECREF(msg);Py_XDECREF(dbg);Py_XDECREF(fmt);Py_XDECREF(fm);"
            "Py_XDECREF(full);Py_XDECREF(run);Py_XDECREF(ctx);Py_XDECREF(cb);Py_XDECREF(args);Py_XDECREF(hl);return r;}", file) < 0)
        return -1;
    if (has_constructors) {
        if (fputs("static PyObject*wwa(PyObject*o,size_t ci,int*h){MS*s=sm(o);"
                  "if(!s){PyErr_SetString(PyExc_RuntimeError,"
                  "\"native module state is unavailable\");return NULL;}"
                  "(void)ci;*h=0;", file) < 0)
            return -1;
        for (index = 0u; index < program->class_count; index++) {
            const WrtcNativeClassIR *class_ir = &program->classes[index];
            const WrtcNativeRegionIR *region;
            const WrtcTypedRecordIR *input_record, *output_record;
            size_t region_index, input_field, output_field, processor_field;
            size_t callback_field, loop_field, capacity_field;
            size_t input_record_index, output_record_index;
            if (!worker_attachment_shape(program, class_ir)) continue;
            region = owned_worker_region(class_ir, &region_index);
            if (region == NULL) continue;
            input_field = worker_queue_field(class_ir, "worker");
            output_field = worker_queue_field(class_ir, "reactor");
            processor_field = worker_processor_field(class_ir);
            callback_field = worker_callback_field(class_ir, processor_field);
            loop_field = worker_loop_field(class_ir, region);
            capacity_field = worker_capacity_field(class_ir, input_field);
            input_record = worker_input_record_generated(
                program, region, &input_record_index);
            output_record = generated_record_type(
                program, region->result_type, &output_record_index);
            if (input_record == NULL || output_record == NULL) return -1;
            if (fprintf(file,
                        "if(ci==%zu){H%zu*d=(H%zu*)PyObject_GetTypeData(o,"
                        "dt(o,%zu));PyObject*cur,*orig;WA*a;size_t cap;"
                        "if(Py_TYPE(o)!=(PyTypeObject*)s->t[%zu]||"
                        "!d->f%zu||d->f%zu!=Py_None||!d->f%zu||!d->f%zu||"
                        "!d->f%zu||!d->f%zu)return NULL;cur=PyDict_GetItemString("
                        "PyType_GetDict((PyTypeObject*)s->t[%zu]),\"_run\");"
                        "orig=PyDict_GetItemString(s->sg[%zu],\"%s\");"
                        "orig=orig&&PyType_Check(orig)?PyDict_GetItemString("
                        "PyType_GetDict((PyTypeObject*)orig),\"_run\"):NULL;"
                        "if(cur&&cur!=orig)return NULL;cap=PyLong_AsSize_t("
                        "d->f%zu);if(PyErr_Occurred())return NULL;a=wane("
                        "(PyTypeObject*)s->wt,cap,&wai%zu,&wai%zu,"
                        "(PyTypeObject*)s->rt[%zu],(PyTypeObject*)s->rt[%zu],"
                        "wk_worker_%zu_%zu,d->f%zu,d->f%zu,o,\"%s\",d->f%zu,d->f%zu);"
                        "if(!a)return NULL;"
                        "((NSO*)d->f%zu)->wa=a;((NSO*)d->f%zu)->wk=1;"
                        "((NSO*)d->f%zu)->wa=a;((NSO*)d->f%zu)->wk=2;"
                        "*h=1;return (PyObject*)a;}",
                        index, index, index, index, index,
                        input_field, processor_field, output_field,
                        loop_field, callback_field, capacity_field,
                        index, index, class_ir->name, capacity_field,
                        input_record_index, output_record_index,
                        input_record_index, output_record_index,
                        index, region_index, loop_field, callback_field,
                        class_ir->fields[callback_field].name,
                        input_field, output_field,
                        input_field, input_field, output_field, output_field) < 0)
                return -1;
        }
        if (fputs("return NULL;}", file) < 0) return -1;
    }
    for (index = 0u; index < program->class_count; index++) {
        size_t target_index;
        if (!program->classes[index].custom_constructor) continue;
        if (fprintf(file, "static int cg%zu(PyObject*o){MS*s=sm(o);"
                          "PyObject*v;if(!s){PyErr_SetString(PyExc_RuntimeError,"
                          "\"native module state is unavailable\");return -1;}",
                    index) < 0)
            return -1;
        for (target_index = 0u; target_index < program->class_count;
             target_index++) {
            if (fputs("v=PyDict_GetItemString(s->sg[", file) < 0 ||
                fprintf(file, "%zu],", index) < 0 ||
                quote(file, program->classes[target_index].name) < 0 ||
                fprintf(file, ");if(v==s->ot[%zu])v=s->t[%zu];"
                              "if(v){if(PyDict_SetItemString(g%zu_globals,",
                        target_index, target_index, index) < 0 ||
                quote(file, program->classes[target_index].name) < 0 ||
                fputs(",v)<0)return -1;}else if(PyDict_DelItemString(g",
                      file) < 0 ||
                fprintf(file, "%zu_globals,", index) < 0 ||
                quote(file, program->classes[target_index].name) < 0 ||
                fputs(")<0){if(PyErr_ExceptionMatches(PyExc_KeyError))"
                      "PyErr_Clear();else return -1;}", file) < 0)
                return -1;
        }
        if (fputs("return 0;}", file) < 0) return -1;
    }
    if (fputs("static int mt(PyObject*m,visitproc visit,void*arg){MS*s="
              "(MS*)PyModule_GetState(m);if(!s)return 0;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_VISIT(s->t[%zu]);", index) < 0) return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_VISIT(s->sg[%zu]);Py_VISIT(s->ot[%zu]);",
                    index, index) < 0)
            return -1;
    for (index = 0u; index < fusion_count; index++)
        if (fprintf(file, "Py_VISIT(s->fd[%zu]);", index) < 0) return -1;
    if (fputs("Py_VISIT(s->nt);Py_VISIT(s->wt);", file) < 0) return -1;
    if (has_handle_run &&
        fputs("{size_t i;for(i=0u;i<7u;i++)Py_VISIT(s->hr[i]);}", file) < 0)
        return -1;
    if (fprintf(file,
                "{size_t i;for(i=0u;i<%zuu;i++){Py_VISIT(s->od[i]);"
                "Py_VISIT(s->nd[i]);}}",
                emitted_region_count(program)) < 0)
        return -1;
    for (index = 0u; index < program->record_count; index++)
        if (fprintf(file, "Py_VISIT(s->rt[%zu]);", index) < 0) return -1;
    if (fputs("return 0;}static int mc(PyObject*m){MS*s=(MS*)"
              "PyModule_GetState(m);if(!s||!s->active)return 0;"
              "s->active=0u;if(mlive!=0u)mlive--;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_CLEAR(s->t[%zu]);", index) < 0) return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_CLEAR(s->sg[%zu]);Py_CLEAR(s->ot[%zu]);",
                    index, index) < 0)
            return -1;
    for (index = 0u; index < fusion_count; index++)
        if (fprintf(file, "Py_CLEAR(s->fd[%zu]);", index) < 0) return -1;
    if (fputs("Py_CLEAR(s->nt);Py_CLEAR(s->wt);", file) < 0) return -1;
    if (has_handle_run &&
        fputs("{size_t i;for(i=0u;i<7u;i++)Py_CLEAR(s->hr[i]);}", file) < 0)
        return -1;
    if (fprintf(file,
                "{size_t i;for(i=0u;i<%zuu;i++){Py_CLEAR(s->od[i]);"
                "Py_CLEAR(s->nd[i]);}}s->invalidation_epoch++;",
                emitted_region_count(program)) < 0)
        return -1;
    for (index = 0u; index < program->record_count; index++)
        if (fprintf(file, "Py_CLEAR(s->rt[%zu]);", index) < 0) return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file, "wrtc_boxed_suite_clear(&r%zu_%zu_suite);"
                              "wrtc_boxed_signature_clear(&r%zu_%zu_sig);",
                        index, region_index,
                        index, region_index) < 0)
                return -1;
        if (program->classes[index].custom_constructor &&
            fprintf(file, "wrtc_boxed_suite_clear(&c%zu_suite);"
                          "wrtc_boxed_signature_clear(&c%zu_sig);",
                    index, index) < 0)
            return -1;
        if (class_has_globals(&program->classes[index]) &&
            fprintf(file, "g%zu_clear_globals();", index) < 0)
            return -1;
    }
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "wrtc_boxed_suite_clear(&f%zu_suite);"
                          "wrtc_boxed_signature_clear(&f%zu_sig);"
                          "fg%zu_clear_globals();", index, index, index) < 0)
            return -1;
    if (fputs("return 0;}static void mf(void*m){(void)mc((PyObject*)m);}"
              "static int me(PyObject*m){MS*s=(MS*)PyModule_GetState(m);"
              "PyObject*constant=NULL,*all=PyTuple_New(", file) < 0 ||
        fprintf(file, "%zu);if(!s||!all)goto error;",
                program->class_count + program->factory_count) < 0)
        return -1;
    if (fputs("if(mlive!=0u){PyErr_SetString(PyExc_RuntimeError,"
              "\"native artifact permits one live module instance; "
              "subinterpreters and concurrent re-exec are unsupported\");"
              "goto error;}mlive++;s->active=1u;", file) < 0)
        return -1;
    if (has_storage && !has_workers &&
        fputs("(void)&wane;(void)&wasp;", file) < 0)
        return -1;
    if (has_storage &&
        fputs("s->nt=PyType_FromModuleAndSpec(m,&nosp,NULL);"
              "if(!s->nt)goto error;", file) < 0)
        return -1;
    if (has_workers &&
        fputs("s->wt=PyType_FromModuleAndSpec(m,&wasp,NULL);"
              "if(!s->wt)goto error;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (class_has_globals(&program->classes[index]) &&
            fprintf(file, "if(g%zu_initialize_globals()<0)goto error;",
                    index) < 0)
            return -1;
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "if(fg%zu_initialize_globals()<0)goto error;",
                    index) < 0)
            return -1;
    for (index = 0u; index < program->record_count; index++) {
        char *record_module =
            wrtc_boxed_module_name(program->records[index].filename);
        if (record_module == NULL) return -1;
        if (fputs("{PyObject*x=PyImport_ImportModule(", file) < 0 ||
            quote(file, record_module) < 0 ||
            fprintf(file, ");if(!x)goto error;s->rt[%zu]="
                          "PyObject_GetAttrString(x,",
                    index) < 0 ||
            quote(file, program->records[index].name) < 0 ||
            fputs(");Py_DECREF(x);if(!s->rt[", file) < 0 ||
            fprintf(file, "%zu]||!PyType_Check(s->rt[%zu]))goto error;}",
                    index, index) < 0) {
            free(record_module);
            return -1;
        }
        free(record_module);
    }
    if (has_handle_run && fputs(
            "{static const char*n[]={\"_run\",\"_callback\",\"_args\",\"_cancelled\",\"_context\"};"
            "PyObject*x=PyImport_ImportModule(\"asyncio.events\");PyObject*d;size_t i;"
            "if(!x)goto error;s->hr[0]=PyObject_GetAttrString(x,\"Handle\");"
            "s->hr[6]=PyObject_GetAttrString(x,\"TimerHandle\");Py_DECREF(x);"
            "if(!s->hr[0]||!PyType_Check(s->hr[0])||!s->hr[6]||!PyType_Check(s->hr[6]))goto error;d=PyType_GetDict((PyTypeObject*)s->hr[0]);"
            "for(i=0u;i<5u;i++){PyObject*v=PyDict_GetItemString(d,n[i]);if(!v){PyErr_Format(PyExc_ImportError,"
            "\"asyncio Handle descriptor %s is unavailable\",n[i]);goto error;}s->hr[i+1u]=Py_NewRef(v);}}",
            file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        if (fprintf(file, "s->sg[%zu]=Py_NewRef(g%zu_globals);"
                          "{PyObject*v=PyDict_GetItemString(s->sg[%zu],",
                    index, index, index) < 0 ||
            quote(file, program->classes[index].name) < 0 ||
            fprintf(file, ");if(!v||!PyType_Check(v)){PyErr_Format("
                          "PyExc_ImportError,\"source class %%s is unavailable "
                          "or was replaced before native module load\",") < 0 ||
            quote(file, program->classes[index].name) < 0 ||
            fprintf(file, ");goto error;}s->ot[%zu]=Py_NewRef(v);}",
                    index) < 0)
            return -1;
    }
    for (index = 0u; index < program->class_count; index++)
        if (class_has_globals(&program->classes[index]) &&
            fprintf(file, "{PyObject*c=PyDict_Copy(g%zu_globals);"
                          "if(!c)goto error;Py_SETREF(g%zu_globals,c);}",
                    index, index) < 0)
            return -1;
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "{PyObject*c=PyDict_Copy(fg%zu_globals);"
                          "if(!c)goto error;Py_SETREF(fg%zu_globals,c);}",
                    index, index) < 0)
            return -1;
    for (index = 0u; index < program->class_count; index++) {
        const char *name = program->classes[index].name;
        const char *base = program->classes[index].base == NULL
                               ? "object" : program->classes[index].base;
        if (fputs("{PyObject*b=rb(", file) < 0 || quote(file, base) < 0 ||
            fprintf(file, "),*bs;if(!b)goto error;bs=PyTuple_Pack(1,b);"
                          "Py_DECREF(b);if(!bs)goto error;"
                          "s->t[%zu]=PyType_FromModuleAndSpec(m,&sp%zu,bs);"
                          "Py_DECREF(bs);"
                          "if(!s->t[%zu])goto error;"
                          "if(pm%zu(s->t[%zu],s->ot[%zu])<0)goto error;"
                          "if(PyModule_AddObjectRef(m,",
                    index, index, index, index, index, index) < 0 ||
            quote(file, name) < 0 ||
            fprintf(file, ",s->t[%zu])<0)goto error;"
                          "if(ta(all,%zu,",
                    index, index) < 0 ||
            quote(file, name) < 0 ||
            fputs(")<0)goto error;}", file) < 0)
            return -1;
    }
    {
        size_t class_index, region_index, manifest_index = 0u;
        for (class_index = 0u; class_index < program->class_count;
             class_index++)
            for (region_index = 0u;
                 region_index < program->classes[class_index].region_count;
                 region_index++, manifest_index++) {
                const char *region_name =
                    program->classes[class_index].regions[region_index].name;
                if (fprintf(file,
                            "{PyObject*source_dict=PyType_GetDict((PyTypeObject*)"
                            "s->ot[%zu]);PyObject*native_dict=PyType_GetDict("
                            "(PyTypeObject*)s->t[%zu]);PyObject*original="
                            "PyDict_GetItemString(source_dict,",
                            class_index, class_index) < 0 ||
                    quote(file, region_name) < 0 ||
                    fputs(");PyObject*installed=PyDict_GetItemString(native_dict,",
                          file) < 0 ||
                    quote(file, region_name) < 0 ||
                    fprintf(file,
                            ");if(!original||!installed){PyErr_SetString("
                            "PyExc_SystemError,\"region descriptor cache is "
                            "incomplete\");goto error;}s->od[%zu]=Py_NewRef("
                            "original);s->nd[%zu]=Py_NewRef(installed);}",
                            manifest_index, manifest_index) < 0)
                    return -1;
            }
    }
    {
        size_t class_index, region_index, call_index, fusion_index = 0u;
        for (class_index = 0u; class_index < program->class_count;
             class_index++)
            for (region_index = 0u;
                 region_index <
                     program->classes[class_index].region_count;
                 region_index++)
                for (call_index = 0u;
                     call_index <
                         program->classes[class_index]
                             .regions[region_index].call_count;
                     call_index++) {
                    const WrtcNativeCallEdgeIR *edge =
                        &program->classes[class_index]
                             .regions[region_index].calls[call_index];
                    const char *method;
                    if (!edge->fused) continue;
                    method = strrchr(edge->target, '.');
                    method = method == NULL ? edge->target : method + 1;
                    if (fprintf(
                            file,
                            "{PyObject*d=PyType_GetDict((PyTypeObject*)"
                            "s->t[%zu]);PyObject*v=PyDict_GetItemString(d,",
                            edge->target_class) < 0 ||
                        quote(file, method) < 0 ||
                        fprintf(file,
                                ");if(!v){PyErr_SetString(PyExc_SystemError,"
                                "\"fused callee descriptor is absent\");"
                                "goto error;}s->fd[%zu]=Py_NewRef(v);}",
                                fusion_index) < 0)
                        return -1;
                    fusion_index++;
                }
    }
    {
        size_t globals_index, class_for_globals;
        for (globals_index = 0u; globals_index < program->class_count;
             globals_index++)
            if (class_has_globals(&program->classes[globals_index]))
                for (class_for_globals = 0u;
                     class_for_globals < program->class_count;
                     class_for_globals++)
                    if (fputs("{PyObject*v=PyDict_GetItemString(s->sg[",
                              file) < 0 ||
                        fprintf(file, "%zu],", globals_index) < 0 ||
                        quote(file,
                              program->classes[class_for_globals].name) < 0 ||
                        fprintf(file, ");if(v==s->ot[%zu])v=s->t[%zu];"
                                      "if(v&&PyDict_SetItemString(g%zu_globals,",
                                class_for_globals, class_for_globals,
                                globals_index) < 0 ||
                        quote(file,
                              program->classes[class_for_globals].name) < 0 ||
                        fputs(",v)<0)goto error;}", file) < 0)
                        return -1;
        for (globals_index = 0u;
             globals_index < program->factory_count; globals_index++)
            for (class_for_globals = 0u;
                 class_for_globals < program->class_count;
                 class_for_globals++)
                if (fputs("if(PyDict_SetItemString(fg", file) < 0 ||
                    fprintf(file, "%zu_globals,", globals_index) < 0 ||
                    quote(file, program->classes[class_for_globals].name) < 0 ||
                    fprintf(file, ",s->t[%zu])<0)goto error;",
                            class_for_globals) < 0)
                    return -1;
    }
    for (index = 0u; index < program->factory_count; index++) {
        if (fprintf(file, "if(ta(all,%zu,",
                    program->class_count + index) < 0 ||
            quote(file, program->factories[index].name) < 0 ||
            fputs(")<0)goto error;", file) < 0)
            return -1;
    }
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file, "if(wrtc_boxed_suite_initialize("
                              "&r%zu_%zu_suite,g%zu_globals)<0)goto error;"
                              "if(wrtc_boxed_signature_initialize("
                              "&r%zu_%zu_sig,g%zu_globals)<0)"
                              "goto error;",
                        index, region_index, index,
                        index, region_index, index) < 0)
                return -1;
        if (program->classes[index].custom_constructor &&
            fprintf(file, "if(wrtc_boxed_suite_initialize(&c%zu_suite,"
                          "g%zu_globals)<0)goto error;"
                          "if(wrtc_boxed_signature_initialize(&c%zu_sig,"
                          "g%zu_globals)<0)goto error;",
                    index, index, index, index) < 0)
            return -1;
    }
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "if(wrtc_boxed_suite_initialize(&f%zu_suite,"
                          "fg%zu_globals)<0)goto error;"
                          "if(wrtc_boxed_signature_initialize(&f%zu_sig,"
                          "fg%zu_globals)<0)goto error;",
                    index, index, index, index) < 0)
            return -1;
    if (fputs("if(PyModule_AddObject(m,\"__all__\",all)<0)goto error;"
              "all=NULL;", file) < 0)
        return -1;
    if (fprintf(file, "{PyObject*x=PyTuple_New(%zu);if(!x)goto error;",
                program->class_count) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "if(ta(x,%zu,", index) < 0 ||
            quote(file, program->classes[index].name) < 0 ||
            fputs(")<0){Py_DECREF(x);goto error;}", file) < 0)
            return -1;
    if (fputs("if(ma(m,\"__pymeta_native_classes__\",x)<0)goto error;}",
              file) < 0 ||
        fprintf(file, "{PyObject*x=PyTuple_New(%zu);size_t q=0u;(void)q;if(!x)goto error;",
                emitted_region_count(program)) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++) {
            const char *class_name = program->classes[index].name;
            const char *region_name =
                program->classes[index].regions[region_index].name;
            size_t length = strlen(class_name) + strlen(region_name) + 2u;
            char *qualified = malloc(length);
            if (qualified == NULL) return -1;
            (void)snprintf(qualified, length, "%s.%s", class_name,
                           region_name);
            if (fputs("if(ta(x,(Py_ssize_t)q++,", file) < 0 ||
                quote(file, qualified) < 0 ||
                fputs(")<0){Py_DECREF(x);goto error;}", file) < 0) {
                free(qualified);
                return -1;
            }
            free(qualified);
        }
    }
    if (fputs("if(ma(m,\"__pymeta_native_regions__\",x)<0)goto error;}",
              file) < 0 ||
        fprintf(file, "{PyObject*x=PyTuple_New(%zu);size_t q=0u;(void)q;if(!x)goto error;",
                emitted_region_count(program)) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++) {
            const char *class_name = program->classes[index].name;
            const char *region_name =
                program->classes[index].regions[region_index].name;
            const char *backend = wrtc_aot_region_direct_supported(
                                      program, operations, index, region_index)
                                      ? "aot_direct_graph"
                                  : wrtc_aot_region_supported(
                                        &program->classes[index]
                                             .regions[region_index])
                                      ? "aot_pyobject" : "boxed_ir";
            size_t length = strlen(class_name) + strlen(region_name) +
                            strlen(backend) + 3u;
            char *entry = malloc(length);
            if (entry == NULL) return -1;
            (void)snprintf(entry, length, "%s.%s=%s", class_name,
                           region_name, backend);
            if (fputs("if(ta(x,(Py_ssize_t)q++,", file) < 0 ||
                quote(file, entry) < 0 ||
                fputs(")<0){Py_DECREF(x);goto error;}", file) < 0) {
                free(entry);
                return -1;
            }
            free(entry);
        }
    }
    if (fputs("if(ma(m,\"__pymeta_native_region_backends__\",x)<0)goto error;}",
              file) < 0 ||
        fprintf(file, "{PyObject*x=PyTuple_New(%zu);size_t q=0u;(void)q;if(!x)goto error;",
                call_graph_manifest_count(program)) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++) {
            const WrtcNativeRegionIR *region =
                &program->classes[index].regions[region_index];
            const char *class_name = program->classes[index].name;
            size_t source_length = strlen(class_name) + strlen(region->name) + 2u;
            char *source = malloc(source_length);
            char *entry;
            size_t call_index, entry_length;
            if (source == NULL) return -1;
            (void)snprintf(source, source_length, "%s.%s", class_name,
                           region->name);
            {
                const char *executor = wrtc_aot_region_direct_supported(
                                           program, operations, index,
                                           region_index)
                                           ? "wrtc_aot_direct_graph"
                                       : wrtc_aot_region_supported(region)
                                           ? "wrtc_aot_pyobject"
                                           : "wrtc_boxed_execute";
                entry_length = strlen(source) + strlen(executor) + 3u;
                entry = malloc(entry_length);
                if (entry == NULL) {
                    free(source);
                    return -1;
                }
                (void)snprintf(entry, entry_length, "%s->%s", source,
                               executor);
            }
            if (fputs("if(ta(x,(Py_ssize_t)q++,", file) < 0 ||
                quote(file, entry) < 0 ||
                fputs(")<0){Py_DECREF(x);goto error;}", file) < 0) {
                free(entry);
                free(source);
                return -1;
            }
            free(entry);
            for (call_index = 0u; call_index < region->call_count;
                 call_index++) {
                const WrtcNativeCallEdgeIR *edge =
                    &region->calls[call_index];
                const char *target = edge->target;
                char *canonical = NULL;
                if (edge->resolved && edge->required_callee &&
                    edge->target_class < program->class_count &&
                    edge->target_region <
                        program->classes[edge->target_class].region_count) {
                    const char *target_class =
                        program->classes[edge->target_class].name;
                    const char *target_region =
                        program->classes[edge->target_class]
                            .regions[edge->target_region].name;
                    size_t canonical_length = strlen(target_class) +
                                              strlen(target_region) + 2u;
                    canonical = malloc(canonical_length);
                    if (canonical == NULL) {
                        free(source);
                        return -1;
                    }
                    (void)snprintf(canonical, canonical_length, "%s.%s",
                                   target_class, target_region);
                    target = canonical;
                }
                entry_length = strlen(source) + strlen(target) + 3u;
                entry = malloc(entry_length);
                if (entry == NULL) {
                    free(canonical);
                    free(source);
                    return -1;
                }
                (void)snprintf(entry, entry_length, "%s->%s", source, target);
                if (fputs("if(ta(x,(Py_ssize_t)q++,", file) < 0 ||
                    quote(file, entry) < 0 ||
                    fputs(")<0){Py_DECREF(x);goto error;}", file) < 0) {
                    free(entry);
                    free(canonical);
                    free(source);
                    return -1;
                }
                free(entry);
                free(canonical);
            }
            free(source);
        }
    }
    if (fputs("if(ma(m,\"__pymeta_native_call_graph__\",x)<0)goto error;}",
              file) < 0 ||
        fprintf(file, "{PyObject*x=PyTuple_New(%zu);if(!x)goto error;",
                program->factory_count) < 0)
        return -1;
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "if(ta(x,%zu,", index) < 0 ||
            quote(file, program->factories[index].name) < 0 ||
            fputs(")<0){Py_DECREF(x);goto error;}", file) < 0)
            return -1;
    if (fputs("if(ma(m,\"__pymeta_native_factories__\",x)<0)goto error;}",
              file) < 0 ||
        emit_module_string(
            file, "__pymeta_native_reactor_hook__",
            has_reactor_hooks
                ? "guarded_cpython_reactor_thread;ordinary_lookup;"
                  "generation_checked;bounded_reschedule"
                : "not_emitted") < 0 ||
        emit_module_string(
            file, "__pymeta_native_reactor_state__",
            has_reactor_storage
                ? "selector_registry;packet_slab;reactor_owned;generation_tagged"
                : "not_emitted") < 0 ||
        emit_module_string(
            file, "__pymeta_module_instance_policy__",
            "single_live_module;subinterpreters_unsupported") < 0 ||
        emit_module_string(
            file, "__pymeta_pyobject_region_backend__",
            program_has_complete_scheduler_graph(program, operations)
                ? "aot_direct_graph"
            : wrtc_aot_program_complete(program)
                ? "aot_pyobject" : "boxed_ir") < 0 ||
        emit_module_string(
            file, "__pymeta_native_operation_abi__",
            "typed_results;ownership;nullability;exception_edges") < 0 ||
        emit_module_string(
            file, "__pymeta_native_guard_policy__",
            "exact_receiver;native_storage;original_descriptor;"
            "installed_descriptor;pre_mutation") < 0 ||
        emit_module_string(
            file, "__pymeta_native_cache_policy__",
            "unbound_descriptors;module_owned;traverse;clear;free") < 0 ||
        emit_module_string(
            file, "__pymeta_native_invalidation_policy__",
            "module_epoch;entry_guard;fallback_before_mutation") < 0 ||
        emit_module_string(file, "__pymeta_source_sha256__", source_hash) < 0 ||
        emit_module_string(file, "__pymeta_semantic_sha256__", semantic_hash) < 0 ||
        emit_module_string(file, "__pymeta_compiler_version__",
                           "wrtc-pymeta-compiler/0.4") < 0 ||
        emit_module_string(file, "__pymeta_cpython_revision__", revision) < 0 ||
        emit_module_string(file, "__pymeta_cpython_source_revision__",
                           "070700ed4d95c16855603cecab3f41f3b587f973") < 0 ||
        emit_module_string(file, "__pymeta_target__", target) < 0 ||
        emit_module_string(file, "__pymeta_architecture__", architecture) < 0 ||
        emit_module_string(file, "__pymeta_extension_suffix__",
                           extension_suffix) < 0 ||
        emit_module_string(file, "__pymeta_optimization__", "release") < 0)
        return -1;
    if (fputs(
            "constant=PySys_GetObject(\"implementation\");"
            "constant=constant?PyObject_GetAttrString(constant,\"cache_tag\"):NULL;"
            "if(constant==Py_None){Py_DECREF(constant);"
            "constant=PyUnicode_FromString(\"\");}"
            "if(!constant)goto error;"
            "if(ma(m,\"__pymeta_cache_tag__\",constant)<0){constant=NULL;goto error;}"
            "constant=NULL;constant=PySys_GetObject(\"abiflags\");"
            "constant=constant?Py_NewRef(constant):PyUnicode_FromString(\"\");"
            "if(!constant)goto error;"
            "if(ma(m,\"__pymeta_abi_flags__\",constant)<0){constant=NULL;goto error;}"
            "constant=NULL;", file) < 0)
        return -1;
    if (artifact_metadata != NULL) {
        while (PyDict_Next(artifact_metadata, &position, &key, &value)) {
            const char *key_text = PyUnicode_AsUTF8(key);
            const char *value_text = PyUnicode_AsUTF8(value);
            char *attribute;
            size_t length;
            if (key_text == NULL || value_text == NULL) return -1;
            length = strlen(key_text) + 12u;
            attribute = malloc(length);
            if (attribute == NULL) return -1;
            (void)snprintf(attribute, length, "__pymeta_%s__", key_text);
            if (emit_module_string(file, attribute, value_text) < 0) {
                free(attribute);
                return -1;
            }
            free(attribute);
        }
    }
    if (fputs("return 0;error:Py_XDECREF(constant);Py_XDECREF(all);"
              "(void)mc(m);return -1;}"
              "static PyModuleDef_Slot ms[]={{Py_mod_exec,(void*)me},"
              "{0,NULL}};static struct PyModuleDef md={PyModuleDef_HEAD_INIT,",
              file) < 0 ||
        quote(file, module) < 0 ||
        fputs(",NULL,sizeof(MS),fm,ms,mt,mc,mf};\n"
              "#if defined(_WIN32)\n__declspec(dllexport)\n#else\n"
              "__attribute__((visibility(\"default\")))\n#endif\n"
              "PyMODINIT_FUNC PyInit_", file) < 0 ||
        fputs(module, file) < 0 ||
        fputs("(void){return PyModuleDef_Init(&md);}\n", file) < 0)
        return -1;
    return ferror(file) ? -1 : 0;
}

int wrtc_emit_native_class_extension(
    FILE *file, const char *module, const WrtcNativeClassProgram *program,
    const char *source_hash, const char *semantic_hash, const char *revision,
    const char *target, const char *architecture,
    const char *extension_suffix, PyObject *artifact_metadata) {
    WrtcNativeOperationTable *operations = NULL;
    int status;
    if (file == NULL || module == NULL ||
        !wrtc_native_class_can_emit(program))
        return -1;
    if (program_has_storage(program) &&
        (wrtc_native_operation_prove(program, &operations) < 0 ||
         operations == NULL || !operations->complete)) {
        wrtc_native_operation_table_free(operations);
        return -1;
    }
    status = emit_native_class_extension(
        file, module, program, operations, source_hash, semantic_hash,
        revision, target, architecture, extension_suffix, artifact_metadata);
    wrtc_native_operation_table_free(operations);
    return status;
}
