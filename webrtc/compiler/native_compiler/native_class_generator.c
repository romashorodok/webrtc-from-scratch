#include "native_class_generator.h"
#include "boxed_codegen.h"
#include "boxed_module.h"
#include "native_operation.h"
#include "native_storage.h"
#include "native_storage_codegen.h"

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
    return base != NULL && strcmp(base, "builtins.object") != 0 &&
           strchr(base, '.') != NULL;
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
            class_ir->weakrefs || class_ir->custom_constructor ||
            !compatible_base(class_ir->base))
            return 0;
        for (field_index = 0u; field_index < class_ir->field_count;
             field_index++) {
            const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
            if (field->name == NULL ||
                (field->storage_kind != WRTC_NATIVE_FIELD_PYOBJECT &&
                 !wrtc_native_storage_field_eligible(field, NULL)))
                return 0;
            if (field->storage_kind != WRTC_NATIVE_FIELD_PYOBJECT)
                has_storage = 1;
        }
        for (field_index = 0u; field_index < class_ir->region_count;
             field_index++) {
            const WrtcNativeRegionIR *region =
                &class_ir->regions[field_index];
            const unsigned unsupported =
                WRTC_REGION_OWNED_SHARD | WRTC_REGION_TYPED_RECORD |
                WRTC_REGION_PACKET_POOL;
            if (region->body == NULL || region->signature == NULL ||
                (region->capabilities & unsupported) != 0u ||
                !mpsc_contract_complete(region) ||
                !spsc_contract_complete(region))
                return 0;
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
                                  factory->body->statement_count))
            return 0;
        module_name = wrtc_boxed_module_name(factory->filename);
        if (module_name == NULL) {
            PyErr_Clear();
            return 0;
        }
        free(module_name);
    }
    if (program->factory_name != NULL && program->factory_count == 0u)
        return 0;
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
        field->storage_kind == WRTC_NATIVE_FIELD_MPSC ? 5 : 6;
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
    } else if ((kind == 4 || kind == 5 || kind == 6) &&
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
                  "if(!o)return -1;*p=o;}return "
                  "wrtc_native_fifo_set_boxed(&o->u.f,v);}", file) < 0)
            return -1;
    } else if (kind == 3 &&
               (fputs("if(wrtc_native_heap_delete(&o->u.h,", file) < 0 ||
               quote(file, field->name) < 0 ||
               fputs(")<0)return -1;Py_CLEAR(*p);return 0;}if(!o){o=no(self,3);"
                     "if(!o)return -1;*p=o;}return "
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
        fputs("){PyObject*recv=NULL,*args=NULL,*kwargs=NULL,*callable=NULL,"
              "*result=NULL,*current,*original;PyTypeObject*expected;size_t i;"
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
        fputs(");if(!callable)goto done", file) < 0 ||
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
                      "args=PyTuple_New((Py_ssize_t)",
                edge->target_class, edge->target_region) < 0 ||
        fputs(
              "e->positional_count);kwargs=PyDict_New();"
              "if(!args||!kwargs)goto done",
              file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs(
              "for(i=0u;i<e->positional_count;i++){PyObject*v="
              "wrtc_boxed_hook_evaluate(&e->children[1u+i],f);"
              "if(!v)goto done",
              file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs("PyTuple_SET_ITEM(args,(Py_ssize_t)i,v);}"
              "for(i=0u;i<e->keyword_count;i++){PyObject*v="
              "wrtc_boxed_hook_evaluate(&e->children[1u+"
              "e->positional_count+i],f);if(!v)goto done",
              file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs(
              "if(PyDict_SetItemString(kwargs,e->keyword_names[i],v)<0){"
              "Py_DECREF(v);goto done",
              file) < 0 ||
        fprintf(file, "%zu;", fusion_index) < 0 ||
        fputs("}Py_DECREF(v);}"
              "if(!direct)result=PyObject_Call(callable,args,kwargs);else "
              "result=w",
              file) < 0 ||
        fprintf(file, "%zu_%zu(recv,args,kwargs);"
                      "done%zu:Py_XDECREF(callable);Py_XDECREF(kwargs);"
                      "Py_XDECREF(args);Py_XDECREF(recv);return result;}",
                edge->target_class, edge->target_region,
                fusion_index) < 0)
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
                "void*f,int*h){(void)c;*h=0;",
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
        if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO &&
            operation->kind != WRTC_NATIVE_OP_TRUTH &&
            operation->kind != WRTC_NATIVE_OP_ITERATE) {
            if (fputs("if(wrtc_native_fifo_try_adopt(&o->u.f)<0)"
                      "return NULL;",
                      file) < 0)
                return -1;
        } else if (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP &&
                   operation->kind != WRTC_NATIVE_OP_TRUTH &&
                   operation->kind != WRTC_NATIVE_OP_ITERATE) {
            if (fputs("if(wrtc_native_heap_try_adopt(&o->u.h)<0)"
                      "return NULL;",
                      file) < 0)
                return -1;
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
                if (fputs(field->storage_kind == WRTC_NATIVE_FIELD_FIFO
                              ? "return wrtc_native_fifo_get(&o->u.f,"
                              : "return wrtc_native_heap_get(&o->u.h,",
                          file) < 0 ||
                    quote(file, field->name) < 0 ||
                    fputs(");}", file) < 0)
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
            default:
                return -1;
        }
    }
    for (operation_index = 0u; operation_index < region->call_count;
         operation_index++)
        if (emit_fused_call_case(
                file, &region->calls[operation_index],
                fused_call_index(program, class_index, region_index,
                                 operation_index)) < 0)
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
            fputs("){PyObject*r=NULL,*q=NULL;NSO**p=NULL;NSO*o;*h=1;",
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
    for (field_index = 0u; field_index < class_ir->field_count; field_index++)
        if (class_ir->fields[field_index].storage_kind !=
                WRTC_NATIVE_FIELD_PYOBJECT &&
            emit_storage_accessor(file, program, class_index,
                                  &class_ir->fields[field_index],
                                  field_index) < 0)
            return -1;
    for (region_index = 0u; region_index < class_ir->region_count;
         region_index++) {
        char hook_argument[64] = "";
        int has_hooks = operations != NULL;
        size_t call_index;
        for (call_index = 0u;
             call_index < class_ir->regions[region_index].call_count;
             call_index++)
            if (class_ir->regions[region_index].calls[call_index].fused)
                has_hooks = 1;
        if (has_hooks &&
            emit_region_hooks(file, program, operations, class_index,
                              region_index) < 0)
            return -1;
        if (has_hooks)
            (void)snprintf(hook_argument, sizeof hook_argument,
                           "&hooks,");
        if (fprintf(file,
                    "static PyObject*w%zu_%zu(PyObject*self,PyObject*args,"
                    "PyObject*kwargs){PyObject*full=NULL,*locals=NULL,*result="
                    "NULL,*globals=g%zu_globals;Py_ssize_t i,n;",
                    class_index, region_index, class_index) < 0)
            return -1;
        if (has_hooks &&
            fprintf(file,
                    "WrtcBoxedNativeHooks hooks=hk%zu_%zu;"
                    "hooks.context=self;",
                    class_index, region_index) < 0)
            return -1;
        if (fprintf(file,
                    "if(!globals)return "
                    "NULL;n=PyTuple_GET_SIZE(args);full=PyTuple_New(n+1);"
                    "if(!full)return NULL;PyTuple_SET_ITEM(full,0,Py_NewRef(self));"
                    "for(i=0;i<n;i++)PyTuple_SET_ITEM(full,i+1,Py_NewRef("
                    "PyTuple_GET_ITEM(args,i)));if(wrtc_boxed_bind(&r%zu_%zu_sig,"
                    "full,kwargs,&locals)<0)goto done;if(%s("
                    "&r%zu_%zu_suite,globals,locals,%s&result)<0)goto done;"
                    "done:Py_XDECREF(locals);Py_DECREF(full);return result;}\n",
                    class_index, region_index,
                    has_hooks ? "wrtc_boxed_execute_with_hooks" :
                                "wrtc_boxed_execute",
                    class_index, region_index,
                    hook_argument) < 0)
            return -1;
    }
    if (fprintf(file, "static PyMethodDef mm%zu[]={", class_index) < 0)
        return -1;
    for (region_index = 0u; region_index < class_ir->region_count;
         region_index++) {
        if (fputc('{', file) == EOF ||
            quote(file, class_ir->regions[region_index].name) < 0 ||
            fprintf(file, ",(PyCFunction)(void(*)(void))w%zu_%zu,"
                          "METH_VARARGS|METH_KEYWORDS,NULL},",
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
            quote(file, field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT
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
        if (field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT) continue;
        if (fputc('{', file) == EOF || quote(file, field->name) < 0 ||
            fprintf(file, ",(getter)ng%zu_%zu,(setter)ns%zu_%zu,NULL,NULL},",
                    class_index, field_index, class_index, field_index) < 0)
            return -1;
    }
    if (fputs("{NULL,NULL,NULL,NULL,NULL}};", file) < 0) return -1;
    if (fprintf(file,
                "static PyType_Slot sl%zu[]={"
                "{Py_tp_new,(void*)PyType_GenericNew},"
                "{Py_tp_members,(void*)mb%zu},{Py_tp_methods,(void*)mm%zu},"
                "{Py_tp_getset,(void*)gs%zu},"
                "{0,NULL}};static PyType_Spec sp%zu={",
                class_index, class_index, class_index, class_index,
                class_index) < 0 ||
        fprintf(file, "\"%s.%s\"", module, class_ir->name) < 0 ||
        fprintf(file, ",-(Py_ssize_t)sizeof(H%zu),0,Py_TPFLAGS_DEFAULT|"
                      "Py_TPFLAGS_BASETYPE,sl%zu};\n",
                class_index, class_index) < 0)
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

static int emit_storage_owner(FILE *file) {
    return fputs(
        "typedef struct{PyObject_HEAD int k;PyTypeObject*rt;"
        "union{WrtcNativeScalar s;"
        "WrtcNativeFifo f;WrtcNativeMinHeap h;WrtcNativeAtomicUint32 a;"
        "WrtcNativeMpsc m;WrtcNativeSpsc p;}u;}NSO;"
        "static void nd(void*i,void*c){(void)c;Py_DECREF((PyObject*)i);}"
        "static int notr(NSO*o,visitproc v,void*a){"
        "if(o->rt){int z=v((PyObject*)o->rt,a);if(z)return z;}"
        "if(o->k==1)return wrtc_native_scalar_traverse(&o->u.s,v,a);"
        "if(o->k==2)return wrtc_native_fifo_traverse(&o->u.f,v,a);"
        "if(o->k==3)return wrtc_native_heap_traverse(&o->u.h,v,a);"
        "if(o->k==5)return wrtc_native_mpsc_traverse(&o->u.m,v,a);"
        "if(o->k==6)return wrtc_native_spsc_traverse(&o->u.p,v,a);return 0;}"
        "static int nocl(NSO*o){if(o->k==1)wrtc_native_scalar_clear(&o->u.s);"
        "else if(o->k==2)wrtc_native_fifo_clear(&o->u.f);"
        "else if(o->k==3)wrtc_native_heap_clear(&o->u.h);"
        "else if(o->k==4)wrtc_native_atomic_uint32_clear(&o->u.a);"
        "else if(o->k==5)wrtc_native_mpsc_clear(&o->u.m,nd,NULL);"
        "else if(o->k==6)wrtc_native_spsc_clear(&o->u.p,nd,NULL);"
        "Py_CLEAR(o->rt);o->k=0;return 0;}"
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
        "if(o->k==5)s=wrtc_native_mpsc_try_pop(&o->u.m,&i);"
        "else s=(WrtcNativeMpscStatus)wrtc_native_spsc_try_pop(&o->u.p,&i);"
        "if(s==WRTC_MPSC_OK)return(PyObject*)i;"
        "(void)nqe(\"Empty\");return NULL;}"
        "static PyObject*nqs(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"qsize requires bounded queue storage\");return NULL;}"
        "return PyLong_FromSize_t(o->k==5?wrtc_native_mpsc_snapshot(&o->u.m):"
        "wrtc_native_spsc_snapshot(&o->u.p));}"
        "static PyObject*nqz(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"empty requires bounded queue storage\");return NULL;}"
        "return PyBool_FromLong((o->k==5?wrtc_native_mpsc_snapshot(&o->u.m):"
        "wrtc_native_spsc_snapshot(&o->u.p))==0u);}"
        "static PyObject*nqc(NSO*o,PyObject*unused){(void)unused;"
        "if(o->k!=5&&o->k!=6){PyErr_SetString(PyExc_TypeError,"
        "\"close requires bounded queue storage\");return NULL;}"
        "if(o->k==5)wrtc_native_mpsc_close(&o->u.m);"
        "else wrtc_native_spsc_close(&o->u.p);return Py_NewRef(Py_None);}"
        "static PyMethodDef nom[]={{\"load\",(PyCFunction)nol,METH_NOARGS,NULL},"
        "{\"compare_exchange\",(PyCFunction)nox,METH_VARARGS,NULL},"
        "{\"put_nowait\",(PyCFunction)nqp,METH_O,NULL},"
        "{\"get_nowait\",(PyCFunction)nqg,METH_NOARGS,NULL},"
        "{\"qsize\",(PyCFunction)nqs,METH_NOARGS,NULL},"
        "{\"empty\",(PyCFunction)nqz,METH_NOARGS,NULL},"
        "{\"close\",(PyCFunction)nqc,METH_NOARGS,NULL},"
        "{NULL,NULL,0,NULL}};"
        "static PyType_Slot nosl[]={{Py_tp_traverse,(void*)notr},"
        "{Py_tp_clear,(void*)nocl},{Py_tp_dealloc,(void*)node},"
        "{Py_tp_methods,(void*)nom},{0,NULL}};"
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
        "static NSO*no(PyObject*self,int k){PyTypeObject*t=nt(self);"
        "(void)nac;(void)nal;(void)nai;"
        "NSO*o;if(!t)return NULL;o=PyObject_GC_New(NSO,t);if(!o)return NULL;"
        "o->k=k;o->rt=NULL;if(k==1)wrtc_native_scalar_init(&o->u.s);"
        "else if(k==2){wrtc_native_fifo_init(&o->u.f);"
        "if(wrtc_native_fifo_activate(&o->u.f,8u)<0){PyObject_GC_Del(o);"
        "return NULL;}}else if(k==3){wrtc_native_heap_init(&o->u.h);"
        "if(wrtc_native_heap_activate(&o->u.h,8u)<0){PyObject_GC_Del(o);"
        "return NULL;}}else if(k==4)wrtc_native_atomic_uint32_init(&o->u.a);"
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
        "if(!o)goto fail;o->k=k;o->rt=(PyTypeObject*)rt;rt=NULL;"
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
    const size_t fusion_count = fused_call_count(program);
    if (file == NULL || module == NULL || program == NULL)
        return -1;
    if (fputs("#define PY_SSIZE_T_CLEAN\n#include <Python.h>\n"
              "#include <structmember.h>\n#include <stddef.h>\n"
              "#include <stdint.h>\n#include <string.h>\n"
              "#if PY_VERSION_HEX < 0x030C0000\n"
              "#error \"native heap data requires CPython 3.12 or newer\"\n"
              "#endif\n"
              "typedef struct MS MS;static struct PyModuleDef md;",
              file) < 0 ||
        ((has_storage || fusion_count != 0u) &&
         fputs("static PyTypeObject*dt(PyObject*,size_t);", file) < 0) ||
        (fusion_count != 0u &&
         fputs("static PyObject*fd(PyObject*,size_t);", file) < 0) ||
        (has_storage &&
         fputs("static PyTypeObject*nt(PyObject*);", file) < 0) ||
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
    if (wrtc_boxed_emit_runtime(file) < 0) return -1;
    if (has_storage &&
        (wrtc_native_storage_emit_runtime(file) < 0 ||
         emit_storage_owner(file) < 0))
        return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file,
                        "static PyObject*w%zu_%zu(PyObject*,PyObject*,"
                        "PyObject*);",
                        index, region_index) < 0)
                return -1;
    }
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        if (program->classes[index].region_count != 0u) {
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
                    "(void)self;if(wrtc_boxed_bind(&f%zu_sig,args,kwargs,"
                    "&locals)<0)return NULL;if(wrtc_boxed_execute(&f%zu_suite,"
                    "fg%zu_globals,locals,&result)<0)result=NULL;"
                    "Py_DECREF(locals);return result;}\n",
                    index, index, index, index) < 0)
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
    if (fputs("{NULL,NULL,0,NULL}};", file) < 0) return -1;
    for (index = 0u; index < program->class_count; index++) {
        if (emit_class(file, module, program, operations,
                       &program->classes[index], index) < 0)
            return -1;
    }
    if (fprintf(file,
                "struct MS{PyObject*t[%zu];PyObject*nt;PyObject*fd[%zu];};",
                program->class_count,
                fusion_count == 0u ? 1u : fusion_count) < 0 ||
        ((has_storage || fusion_count != 0u) &&
         fputs("static MS*sm(PyObject*o){PyObject*m="
               "PyType_GetModuleByDef(Py_TYPE(o),&md);"
               "return m?(MS*)PyModule_GetState(m):NULL;}"
               "static PyTypeObject*dt(PyObject*o,size_t i){"
               "MS*s=sm(o);return s?(PyTypeObject*)s->t[i]:NULL;}",
               file) < 0) ||
        (fusion_count != 0u &&
         fputs("static PyObject*fd(PyObject*o,size_t i){"
               "MS*s=sm(o);return s?s->fd[i]:NULL;}", file) < 0) ||
        (has_storage &&
         fputs("static PyTypeObject*nt(PyObject*o){MS*s=sm(o);"
               "return s?(PyTypeObject*)s->nt:NULL;}", file) < 0) ||
        fputs("static int mt(PyObject*m,visitproc visit,void*arg){MS*s="
              "(MS*)PyModule_GetState(m);if(!s)return 0;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_VISIT(s->t[%zu]);", index) < 0) return -1;
    for (index = 0u; index < fusion_count; index++)
        if (fprintf(file, "Py_VISIT(s->fd[%zu]);", index) < 0) return -1;
    if (fputs("Py_VISIT(s->nt);", file) < 0) return -1;
    if (fputs("return 0;}static int mc(PyObject*m){MS*s=(MS*)"
              "PyModule_GetState(m);if(!s)return 0;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (fprintf(file, "Py_CLEAR(s->t[%zu]);", index) < 0) return -1;
    for (index = 0u; index < fusion_count; index++)
        if (fprintf(file, "Py_CLEAR(s->fd[%zu]);", index) < 0) return -1;
    if (fputs("Py_CLEAR(s->nt);", file) < 0) return -1;
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file, "wrtc_boxed_signature_clear(&r%zu_%zu_sig);",
                        index, region_index) < 0)
                return -1;
        if (program->classes[index].region_count != 0u &&
            fprintf(file, "g%zu_clear_globals();", index) < 0)
            return -1;
    }
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "wrtc_boxed_signature_clear(&f%zu_sig);"
                          "fg%zu_clear_globals();", index, index) < 0)
            return -1;
    if (fputs("return 0;}static void mf(void*m){(void)mc((PyObject*)m);}"
              "static int me(PyObject*m){MS*s=(MS*)PyModule_GetState(m);"
              "PyObject*all=PyTuple_New(", file) < 0 ||
        fprintf(file, "%zu);if(!s||!all)goto error;",
                program->class_count + program->factory_count) < 0)
        return -1;
    if (has_storage &&
        fputs("s->nt=PyType_FromModuleAndSpec(m,&nosp,NULL);"
              "if(!s->nt)goto error;", file) < 0)
        return -1;
    for (index = 0u; index < program->class_count; index++)
        if (program->classes[index].region_count != 0u &&
            fprintf(file, "if(g%zu_initialize_globals()<0)goto error;",
                    index) < 0)
            return -1;
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "if(fg%zu_initialize_globals()<0)goto error;",
                    index) < 0)
            return -1;
    for (index = 0u; index < program->class_count; index++)
        if (program->classes[index].region_count != 0u &&
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
                          "if(PyModule_AddObjectRef(m,",
                    index, index, index) < 0 ||
            quote(file, name) < 0 ||
            fprintf(file, ",s->t[%zu])<0)goto error;"
                          "PyTuple_SET_ITEM(all,%zu,PyUnicode_FromString(",
                    index, index) < 0 ||
            quote(file, name) < 0 ||
            fputs("));}", file) < 0)
            return -1;
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
            if (program->classes[globals_index].region_count != 0u)
                for (class_for_globals = 0u;
                     class_for_globals < program->class_count;
                     class_for_globals++)
                    if (fputs("if(PyDict_SetItemString(g", file) < 0 ||
                        fprintf(file, "%zu_globals,", globals_index) < 0 ||
                        quote(file,
                              program->classes[class_for_globals].name) < 0 ||
                        fprintf(file, ",s->t[%zu])<0)goto error;",
                                class_for_globals) < 0)
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
        if (fprintf(file, "PyTuple_SET_ITEM(all,%zu,PyUnicode_FromString(",
                    program->class_count + index) < 0 ||
            quote(file, program->factories[index].name) < 0 ||
            fputs("));", file) < 0)
            return -1;
    }
    for (index = 0u; index < program->class_count; index++) {
        size_t region_index;
        for (region_index = 0u;
             region_index < program->classes[index].region_count;
             region_index++)
            if (fprintf(file, "if(wrtc_boxed_signature_initialize("
                              "&r%zu_%zu_sig,g%zu_globals)<0)"
                              "goto error;",
                        index, region_index, index) < 0)
                return -1;
    }
    for (index = 0u; index < program->factory_count; index++)
        if (fprintf(file, "if(wrtc_boxed_signature_initialize(&f%zu_sig,"
                          "fg%zu_globals)<0)goto error;", index, index) < 0)
            return -1;
    if (fputs("if(PyModule_AddObject(m,\"__all__\",all)<0)goto error;"
              "all=NULL;", file) < 0 ||
        emit_module_string(file, "__pymeta_source_sha256__", source_hash) < 0 ||
        emit_module_string(file, "__pymeta_semantic_sha256__", semantic_hash) < 0 ||
        emit_module_string(file, "__pymeta_compiler_revision__", revision) < 0 ||
        emit_module_string(file, "__pymeta_target__", target) < 0 ||
        emit_module_string(file, "__pymeta_architecture__", architecture) < 0 ||
        emit_module_string(file, "__pymeta_extension_suffix__",
                           extension_suffix) < 0)
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
    if (fputs("return 0;error:Py_XDECREF(all);return -1;}"
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
