#include <Python.h>

#include <stdlib.h>
#include <string.h>

#include "native_operation.h"

typedef struct {
    char *name;
    size_t proof_index;
} Alias;

typedef struct {
    const WrtcNativeClassProgram *program;
    WrtcNativeOperationTable *table;
    const WrtcNativeClassIR *region_class;
    const WrtcNativeRegionIR *region;
    size_t region_class_index;
    size_t region_index;
    Alias *aliases;
    size_t alias_count;
    size_t next_order;
    size_t control_depth;
} Analyzer;

typedef enum {
    USE_READ = 0,
    USE_TRUTH,
    USE_ITERATE,
    USE_WRITE,
    USE_AUGMENTED,
    USE_ESCAPE
} Use;

static char *copy_text(const char *text) {
    char *copy;
    if (text == NULL) return NULL;
    copy = malloc(strlen(text) + 1u);
    if (copy != NULL) strcpy(copy, text);
    return copy;
}

static const char *final_type_name(const char *annotation,
                                   char *buffer, size_t capacity) {
    const char *start, *end, *dot;
    size_t length;
    if (annotation == NULL || capacity == 0u) return NULL;
    start = annotation;
    while (*start == ' ' || *start == '\'' || *start == '"') start++;
    end = start;
    while (*end != '\0' && *end != '\'' && *end != '"' &&
           *end != '[' && *end != '|' && *end != ' ')
        end++;
    dot = end;
    while (dot > start && dot[-1] != '.') dot--;
    length = (size_t)(end - dot);
    if (length == 0u || length >= capacity) return NULL;
    memcpy(buffer, dot, length);
    buffer[length] = '\0';
    return buffer;
}

static size_t class_for_parameter(const Analyzer *analyzer,
                                  const char *parameter) {
    size_t index;
    if (parameter == NULL) return (size_t)-1;
    if (strcmp(parameter, "self") == 0)
        return analyzer->region_class_index;
    if (analyzer->region->signature == NULL) return (size_t)-1;
    for (index = 0u;
         index < analyzer->region->signature->parameter_count; index++) {
        const WrtcPyParameterIR *item =
            &analyzer->region->signature->parameters[index];
        char type_name[256];
        size_t class_index;
        const char *resolved;
        if (item->name == NULL || strcmp(item->name, parameter) != 0)
            continue;
        resolved = final_type_name(item->annotation, type_name,
                                   sizeof type_name);
        if (resolved == NULL) return (size_t)-1;
        for (class_index = 0u;
             class_index < analyzer->program->class_count; class_index++)
            if (strcmp(analyzer->program->classes[class_index].name,
                       resolved) == 0)
                return class_index;
    }
    return (size_t)-1;
}

static int is_region_parameter(const Analyzer *analyzer,
                               const char *name) {
    size_t index;
    if (analyzer->region->signature == NULL || name == NULL) return 0;
    for (index = 0u;
         index < analyzer->region->signature->parameter_count; index++)
        if (strcmp(analyzer->region->signature->parameters[index].name,
                   name) == 0)
            return 1;
    return 0;
}

static size_t proof_for_field(const Analyzer *analyzer, size_t class_index,
                              const char *field_name) {
    size_t proof_index;
    for (proof_index = 0u; proof_index < analyzer->table->field_count;
         proof_index++) {
        const WrtcNativeFieldOperationProof *proof =
            &analyzer->table->fields[proof_index];
        const WrtcNativeFieldIR *field;
        if (proof->class_index != class_index) continue;
        field = &analyzer->program->classes[class_index]
                     .fields[proof->field_index];
        if (strcmp(field->name, field_name) == 0) return proof_index;
    }
    return (size_t)-1;
}

static size_t alias_lookup(const Analyzer *analyzer, const char *name) {
    size_t index;
    for (index = analyzer->alias_count; index > 0u; index--)
        if (strcmp(analyzer->aliases[index - 1u].name, name) == 0)
            return analyzer->aliases[index - 1u].proof_index;
    return (size_t)-1;
}

static size_t expression_field(const Analyzer *analyzer,
                               const WrtcPyExprIR *expression) {
    size_t class_index;
    if (expression->kind == WRTC_PY_EXPR_NAME)
        return alias_lookup(analyzer, expression->operation);
    if (expression->kind != WRTC_PY_EXPR_ATTRIBUTE ||
        expression->child_count != 1u ||
        expression->children[0].kind != WRTC_PY_EXPR_NAME)
        return (size_t)-1;
    class_index = class_for_parameter(
        analyzer, expression->children[0].operation);
    if (class_index == (size_t)-1) return (size_t)-1;
    return proof_for_field(analyzer, class_index, expression->operation);
}

static int add_operation(Analyzer *analyzer, size_t proof_index,
                         WrtcNativeOperationKind kind, WrtcSourceSpan span,
                         const char *alias_name, const char *detail) {
    WrtcNativeOperationIR *operations;
    WrtcNativeOperationIR *operation;
    WrtcNativeFieldOperationProof *proof;
    operations = realloc(
        analyzer->table->operations,
        (analyzer->table->operation_count + 1u) * sizeof(*operations));
    if (operations == NULL) return PyErr_NoMemory(), -1;
    analyzer->table->operations = operations;
    operation =
        &operations[analyzer->table->operation_count++];
    memset(operation, 0, sizeof(*operation));
    operation->kind = kind;
    operation->span = span;
    operation->evaluation_order = analyzer->next_order++;
    operation->region_class_index = analyzer->region_class_index;
    operation->region_index = analyzer->region_index;
    operation->field_proof_index = proof_index;
    operation->has_exception_edge = 1u;
    switch (kind) {
        case WRTC_NATIVE_OP_ALIAS_BIND:
            operation->result_representation =
                WRTC_NATIVE_REPR_STORAGE_POINTER;
            operation->result_ownership = WRTC_NATIVE_OWNERSHIP_BORROWED;
            break;
        case WRTC_NATIVE_OP_LENGTH:
        case WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED:
        case WRTC_NATIVE_OP_MPSC_QSIZE:
        case WRTC_NATIVE_OP_SPSC_QSIZE:
            operation->result_representation = WRTC_NATIVE_REPR_PY_SSIZE_T;
            break;
        case WRTC_NATIVE_OP_TRUTH:
        case WRTC_NATIVE_OP_MPSC_EMPTY:
        case WRTC_NATIVE_OP_SPSC_EMPTY:
        case WRTC_NATIVE_OP_SELECTOR_IS_CURRENT:
            operation->result_representation = WRTC_NATIVE_REPR_BOOL;
            break;
        case WRTC_NATIVE_OP_SCALAR_READ: {
            const WrtcNativeFieldOperationProof *field_proof =
                &analyzer->table->fields[proof_index];
            const WrtcNativeFieldIR *field =
                &analyzer->program->classes[field_proof->class_index]
                     .fields[field_proof->field_index];
            operation->result_representation =
                field->type == WRTC_TYPE_BOOL ? WRTC_NATIVE_REPR_BOOL :
                field->declared_type != NULL &&
                        strcmp(field->declared_type, "float") == 0
                    ? WRTC_NATIVE_REPR_DOUBLE : WRTC_NATIVE_REPR_INT64;
            break;
        }
        case WRTC_NATIVE_OP_ROOT_READ:
            operation->result_representation =
                WRTC_NATIVE_REPR_BORROWED_PYOBJECT;
            operation->result_ownership = WRTC_NATIVE_OWNERSHIP_BORROWED;
            operation->result_nullable = 1u;
            break;
        case WRTC_NATIVE_OP_FIFO_POPLEFT:
        case WRTC_NATIVE_OP_HEAP_POP:
        case WRTC_NATIVE_OP_MPSC_GET_NOWAIT:
        case WRTC_NATIVE_OP_SPSC_GET_NOWAIT:
            operation->result_representation =
                WRTC_NATIVE_REPR_OWNED_PYOBJECT;
            operation->result_ownership = WRTC_NATIVE_OWNERSHIP_OWNED;
            operation->result_nullable = 1u;
            break;
        case WRTC_NATIVE_OP_ITERATE:
            operation->result_representation =
                WRTC_NATIVE_REPR_BORROWED_PYOBJECT;
            operation->result_ownership = WRTC_NATIVE_OWNERSHIP_BORROWED;
            break;
        default:
            operation->result_representation = WRTC_NATIVE_REPR_VOID;
            break;
    }
    operation->alias_name = copy_text(alias_name);
    operation->detail = copy_text(detail);
    if ((alias_name != NULL && operation->alias_name == NULL) ||
        (detail != NULL && operation->detail == NULL))
        return PyErr_NoMemory(), -1;
    proof = &analyzer->table->fields[proof_index];
    if (!proof->touched)
        proof->first_operation = analyzer->table->operation_count - 1u;
    proof->touched = 1u;
    proof->operation_count++;
    if (kind == WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE) {
        proof->complete = 0u;
        analyzer->table->complete = 0u;
    }
    return 0;
}

static int alias_set(Analyzer *analyzer, const char *name,
                     size_t proof_index, WrtcSourceSpan span) {
    Alias *aliases;
    size_t index;
    if (analyzer->control_depth != 0u)
        return add_operation(
            analyzer, proof_index, WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE, span,
            name, "alias binding inside control flow has no proven join");
    for (index = 0u; index < analyzer->alias_count; index++)
        if (strcmp(analyzer->aliases[index].name, name) == 0) {
            analyzer->aliases[index].proof_index = proof_index;
            return add_operation(analyzer, proof_index,
                                 WRTC_NATIVE_OP_ALIAS_BIND, span, name, NULL);
        }
    aliases = realloc(analyzer->aliases,
                      (analyzer->alias_count + 1u) * sizeof(*aliases));
    if (aliases == NULL) return PyErr_NoMemory(), -1;
    analyzer->aliases = aliases;
    aliases = &analyzer->aliases[analyzer->alias_count++];
    aliases->name = copy_text(name);
    aliases->proof_index = proof_index;
    if (aliases->name == NULL) return PyErr_NoMemory(), -1;
    return add_operation(analyzer, proof_index, WRTC_NATIVE_OP_ALIAS_BIND,
                         span, name, NULL);
}

static void alias_kill(Analyzer *analyzer, const char *name) {
    size_t index;
    for (index = 0u; index < analyzer->alias_count; index++)
        if (strcmp(analyzer->aliases[index].name, name) == 0) {
            free(analyzer->aliases[index].name);
            analyzer->aliases[index] =
                analyzer->aliases[analyzer->alias_count - 1u];
            analyzer->alias_count--;
            return;
        }
}

static const WrtcNativeFieldIR *proof_field(const Analyzer *analyzer,
                                            size_t proof_index) {
    const WrtcNativeFieldOperationProof *proof =
        &analyzer->table->fields[proof_index];
    return &analyzer->program->classes[proof->class_index]
                .fields[proof->field_index];
}

static int record_use(Analyzer *analyzer, size_t proof_index, Use use,
                      WrtcSourceSpan span) {
    const WrtcNativeFieldIR *field = proof_field(analyzer, proof_index);
    WrtcNativeOperationKind kind = WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE;
    const char *detail = "native storage escapes through unsupported use";
    if (field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32) {
        kind = WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE;
        detail = "atomic field only supports proven compare_exchange calls";
    } else if (use == USE_WRITE) {
        kind = field->storage_kind == WRTC_NATIVE_FIELD_SCALAR
                   ? WRTC_NATIVE_OP_SCALAR_WRITE
                   : WRTC_NATIVE_OP_BOXED_WRITE;
        detail = NULL;
    } else if (field->storage_kind == WRTC_NATIVE_FIELD_SCALAR) {
        if (use == USE_READ || use == USE_TRUTH || use == USE_ESCAPE)
            kind = WRTC_NATIVE_OP_SCALAR_READ;
        else if (use == USE_AUGMENTED)
            kind = WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE;
        detail = kind == WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE
                     ? "scalar field escapes through unsupported use" : NULL;
    } else if (use == USE_TRUTH) {
        kind = WRTC_NATIVE_OP_TRUTH;
        detail = NULL;
    } else if (use == USE_ITERATE &&
               field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP) {
        kind = WRTC_NATIVE_OP_ITERATE;
        detail = NULL;
    }
    return add_operation(analyzer, proof_index, kind, span, NULL, detail);
}

static int analyze_expression(Analyzer *analyzer,
                              const WrtcPyExprIR *expression, Use use);

static size_t atomic_compare_exchange_field(
    const Analyzer *analyzer, const WrtcPyExprIR *expression) {
    const WrtcPyExprIR *function;
    size_t proof_index;
    const WrtcNativeFieldIR *field;
    if (expression->kind != WRTC_PY_EXPR_CALL ||
        expression->child_count != 3u ||
        expression->positional_count != 2u ||
        expression->keyword_count != 0u)
        return (size_t)-1;
    function = &expression->children[0];
    if (function->kind != WRTC_PY_EXPR_ATTRIBUTE ||
        function->child_count != 1u ||
        strcmp(function->operation, "compare_exchange") != 0)
        return (size_t)-1;
    proof_index = expression_field(analyzer, &function->children[0]);
    if (proof_index == (size_t)-1) return (size_t)-1;
    field = proof_field(analyzer, proof_index);
    return field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                   field->atomic
               ? proof_index
               : (size_t)-1;
}

static int analyze_call(Analyzer *analyzer,
                        const WrtcPyExprIR *expression) {
    const WrtcPyExprIR *function = &expression->children[0];
    size_t proof_index = (size_t)-1;
    size_t argument;
    WrtcNativeOperationKind kind = WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE;
    if (function->kind == WRTC_PY_EXPR_NAME &&
        strcmp(function->operation, "len") == 0 &&
        expression->positional_count == 1u) {
        proof_index = expression_field(analyzer, &expression->children[1]);
        if (proof_index != (size_t)-1)
            return add_operation(analyzer, proof_index,
                                 WRTC_NATIVE_OP_LENGTH, expression->span,
                                 NULL, NULL);
    }
    if (function->kind == WRTC_PY_EXPR_NAME &&
        strcmp(function->operation, "_compact_cancelled_timers") == 0 &&
        expression->positional_count == 1u &&
        expression->keyword_count == 0u) {
        proof_index = expression_field(analyzer, &expression->children[1]);
        if (proof_index != (size_t)-1 &&
            proof_field(analyzer, proof_index)->storage_kind ==
                WRTC_NATIVE_FIELD_MIN_HEAP)
            return add_operation(analyzer, proof_index,
                                 WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED,
                                 expression->span, NULL, NULL);
    }
    if (function->kind == WRTC_PY_EXPR_ATTRIBUTE) {
        proof_index = expression_field(analyzer, &function->children[0]);
        if (proof_index != (size_t)-1) {
            const WrtcNativeFieldIR *field =
                proof_field(analyzer, proof_index);
            if (field->storage_kind == WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                field->atomic &&
                strcmp(function->operation, "load") == 0 &&
                expression->positional_count == 0u &&
                expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_ATOMIC_LOAD;
            else if (field->storage_kind ==
                         WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                     field->atomic &&
                     strcmp(function->operation, "store") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_ATOMIC_STORE;
            else if (field->storage_kind ==
                         WRTC_NATIVE_FIELD_ATOMIC_UINT32 &&
                field->atomic &&
                strcmp(function->operation, "compare_exchange") == 0 &&
                expression->positional_count == 2u &&
                expression->keyword_count == 0u &&
                field->atomic_width == 32u &&
                field->owner != NULL &&
                strcmp(field->owner, "shared") == 0 &&
                field->atomic_memory_order != NULL &&
                strcmp(field->atomic_memory_order, "seq_cst") == 0 &&
                field->atomic_scope != NULL &&
                strcmp(field->atomic_scope, "process") == 0 &&
                field->atomic_linearization != NULL &&
                strcmp(field->atomic_linearization,
                       "compare_exchange") == 0)
                kind = WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO &&
                strcmp(function->operation, "append") == 0 &&
                expression->positional_count == 1u &&
                expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_FIFO_APPEND;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO &&
                     strcmp(function->operation, "popleft") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_FIFO_POPLEFT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     strcmp(function->operation, "put_nowait") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_MPSC_PUT_NOWAIT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     strcmp(function->operation, "get_nowait") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_MPSC_GET_NOWAIT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     strcmp(function->operation, "qsize") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_MPSC_QSIZE;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     strcmp(function->operation, "empty") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_MPSC_EMPTY;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_MPSC &&
                     strcmp(function->operation, "close") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_MPSC_CLOSE;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC &&
                     strcmp(function->operation, "put_nowait") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SPSC_PUT_NOWAIT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC &&
                     strcmp(function->operation, "get_nowait") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SPSC_GET_NOWAIT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC &&
                     strcmp(function->operation, "qsize") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SPSC_QSIZE;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC &&
                     strcmp(function->operation, "empty") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SPSC_EMPTY;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SPSC &&
                     strcmp(function->operation, "close") == 0 &&
                     expression->positional_count == 0u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SPSC_CLOSE;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR &&
                     strcmp(function->operation, "register") == 0 &&
                     expression->positional_count == 3u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SELECTOR_REGISTER;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR &&
                     strcmp(function->operation, "is_current") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SELECTOR_IS_CURRENT;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR &&
                     strcmp(function->operation, "owner") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SELECTOR_OWNER;
            else if (field->storage_kind == WRTC_NATIVE_FIELD_SELECTOR &&
                     strcmp(function->operation, "remove") == 0 &&
                     expression->positional_count == 1u &&
                     expression->keyword_count == 0u)
                kind = WRTC_NATIVE_OP_SELECTOR_REMOVE;
            if (kind == WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE)
                return add_operation(
                    analyzer, proof_index, kind, expression->span, NULL,
                    field->storage_kind ==
                            WRTC_NATIVE_FIELD_ATOMIC_UINT32
                        ? "atomic operation requires uint[32], "
                          "owned_by('shared'), seq_cst process scope, "
                          "compare_exchange linearization, two positional "
                          "arguments, and no keywords"
                        : "method is not valid for the native field "
                          "representation");
            if (add_operation(analyzer, proof_index, kind, expression->span,
                              NULL, NULL) < 0)
                return -1;
            for (argument = 1u; argument < expression->child_count;
                 argument++)
                if (analyze_expression(
                        analyzer, &expression->children[argument],
                        USE_READ) < 0)
                    return -1;
            return 0;
        }
        if (function->children[0].kind == WRTC_PY_EXPR_NAME &&
            strcmp(function->children[0].operation, "heapq") == 0 &&
            expression->positional_count >= 1u) {
            proof_index =
                expression_field(analyzer, &expression->children[1]);
            if (proof_index != (size_t)-1) {
                const WrtcNativeFieldIR *field =
                    proof_field(analyzer, proof_index);
                if (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP) {
                    if (strcmp(function->operation, "heapify") == 0 &&
                        expression->positional_count == 1u &&
                        expression->keyword_count == 0u)
                        kind = WRTC_NATIVE_OP_HEAPIFY;
                    else if (strcmp(function->operation, "heappop") == 0 &&
                             expression->positional_count == 1u &&
                             expression->keyword_count == 0u)
                        kind = WRTC_NATIVE_OP_HEAP_POP;
                    else if (strcmp(function->operation, "heappush") == 0 &&
                             expression->positional_count == 2u &&
                             expression->keyword_count == 0u)
                        kind = WRTC_NATIVE_OP_HEAP_PUSH;
                }
                if (kind == WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE)
                    return add_operation(
                        analyzer, proof_index, kind, expression->span, NULL,
                        "heap call shape is unsupported");
                if (add_operation(analyzer, proof_index, kind,
                                  expression->span, NULL, NULL) < 0)
                    return -1;
                for (argument = 2u; argument < expression->child_count;
                     argument++)
                    if (analyze_expression(
                            analyzer, &expression->children[argument],
                            USE_READ) < 0)
                        return -1;
                return 0;
            }
        }
    }
    for (argument = 0u; argument < expression->child_count; argument++)
        if (analyze_expression(analyzer, &expression->children[argument],
                               argument == 0u ? USE_READ : USE_ESCAPE) < 0)
            return -1;
    return 0;
}

static int analyze_expression(Analyzer *analyzer,
                              const WrtcPyExprIR *expression, Use use) {
    size_t proof_index = expression_field(analyzer, expression);
    size_t child;
    if (proof_index != (size_t)-1)
        return record_use(analyzer, proof_index, use, expression->span);
    if (expression->kind == WRTC_PY_EXPR_ATTRIBUTE &&
        expression->child_count == 1u &&
        expression->children[0].kind == WRTC_PY_EXPR_NAME &&
        is_region_parameter(analyzer,
                            expression->children[0].operation) &&
        class_for_parameter(analyzer,
                            expression->children[0].operation) ==
            (size_t)-1) {
        int matched = 0;
        for (proof_index = 0u;
             proof_index < analyzer->table->field_count; proof_index++)
            if (strcmp(proof_field(analyzer, proof_index)->name,
                       expression->operation) == 0) {
                if (add_operation(
                        analyzer, proof_index,
                        WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE,
                        expression->span, NULL,
                        "field-like access uses an untyped parameter") < 0)
                    return -1;
                matched = 1;
            }
        if (matched) return 0;
    }
    if (expression->kind == WRTC_PY_EXPR_CALL)
        return analyze_call(analyzer, expression);
    if (expression->kind == WRTC_PY_EXPR_SUBSCRIPT &&
        expression->child_count >= 2u) {
        proof_index =
            expression_field(analyzer, &expression->children[0]);
        if (proof_index != (size_t)-1) {
            const WrtcNativeFieldIR *field =
                proof_field(analyzer, proof_index);
            if (use == USE_WRITE &&
                expression->children[1].kind == WRTC_PY_EXPR_SLICE) {
                if (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP)
                    return add_operation(
                        analyzer, proof_index, WRTC_NATIVE_OP_SLICE_ASSIGN,
                        expression->span, NULL, NULL);
                return add_operation(
                    analyzer, proof_index,
                    WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE, expression->span,
                    NULL, "slice assignment requires a min-heap field");
            }
            if (use != USE_WRITE && use != USE_AUGMENTED &&
                field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP &&
                strcmp(expression->children[1].text, "0") == 0)
                return add_operation(analyzer, proof_index,
                                     WRTC_NATIVE_OP_ROOT_READ,
                                     expression->span, NULL, NULL);
            return add_operation(
                analyzer, proof_index, WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE,
                expression->span, NULL,
                "only heap root read and whole-slice assignment are supported");
        }
    }
    if (expression->kind == WRTC_PY_EXPR_BOOLEAN) {
        for (child = 0u; child < expression->child_count; child++)
            if (analyze_expression(analyzer, &expression->children[child],
                                   USE_TRUTH) < 0)
                return -1;
        return 0;
    }
    if (expression->kind == WRTC_PY_EXPR_UNARY &&
        expression->operation != NULL &&
        strcmp(expression->operation, "Not") == 0)
        use = USE_TRUTH;
    for (child = 0u; child < expression->child_count; child++)
        if (analyze_expression(analyzer, &expression->children[child],
                               use) < 0)
            return -1;
    return 0;
}

static int analyze_statements(Analyzer *analyzer,
                              const WrtcPyStmtIR *statements, size_t count) {
    size_t index, expression_index;
    for (index = 0u; index < count; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        if (statement->kind == WRTC_PY_STMT_ASSIGN &&
            statement->expression_count >= 2u) {
            size_t source =
                expression_field(analyzer, &statement->expressions[0]);
            int aliases_only = source != (size_t)-1;
            if (aliases_only)
                for (expression_index = 1u;
                     expression_index < statement->expression_count;
                     expression_index++)
                    if (statement->expressions[expression_index].kind !=
                        WRTC_PY_EXPR_NAME)
                        aliases_only = 0;
            if (aliases_only) {
                for (expression_index = 1u;
                     expression_index < statement->expression_count;
                     expression_index++)
                    if (alias_set(
                            analyzer,
                            statement->expressions[expression_index].operation,
                            source, statement->expressions[0].span) < 0)
                        return -1;
            } else {
                const size_t atomic_proof = atomic_compare_exchange_field(
                    analyzer, &statement->expressions[0]);
                if (analyze_expression(analyzer, &statement->expressions[0],
                                       USE_READ) < 0)
                    return -1;
                if (atomic_proof != (size_t)-1) {
                    const WrtcPyExprIR *target =
                        statement->expression_count == 2u
                            ? &statement->expressions[1] : NULL;
                    if (target == NULL ||
                        target->kind != WRTC_PY_EXPR_TUPLE ||
                        target->child_count != 2u ||
                        target->children[0].kind != WRTC_PY_EXPR_NAME ||
                        strcmp(target->children[0].operation, "_") != 0 ||
                        target->children[1].kind != WRTC_PY_EXPR_NAME) {
                        if (add_operation(
                                analyzer, atomic_proof,
                                WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE,
                                statement->span, NULL,
                                "native uint32 compare_exchange requires "
                                "discarding the representation-erased "
                                "previous value as (_, changed)") < 0)
                            return -1;
                    }
                }
                for (expression_index = 1u;
                     expression_index < statement->expression_count;
                     expression_index++) {
                    const WrtcPyExprIR *target =
                        &statement->expressions[expression_index];
                    if (target->kind == WRTC_PY_EXPR_NAME) {
                        size_t previous =
                            alias_lookup(analyzer, target->operation);
                        if (previous != (size_t)-1 &&
                            analyzer->control_depth != 0u) {
                            if (add_operation(
                                    analyzer, previous,
                                    WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE,
                                    target->span, target->operation,
                                    "alias rebind inside control flow has "
                                    "no proven join") < 0)
                                return -1;
                        } else {
                            alias_kill(analyzer, target->operation);
                        }
                    }
                    if (analyze_expression(analyzer, target, USE_WRITE) < 0)
                        return -1;
                }
            }
        } else if (statement->kind == WRTC_PY_STMT_AUGMENTED_ASSIGN) {
            if (analyze_expression(analyzer, &statement->expressions[0],
                                   USE_AUGMENTED) < 0 ||
                analyze_expression(analyzer, &statement->expressions[1],
                                   USE_READ) < 0)
                return -1;
        } else if (statement->kind == WRTC_PY_STMT_IF ||
                   statement->kind == WRTC_PY_STMT_WHILE) {
            if (analyze_expression(analyzer, &statement->expressions[0],
                                   USE_TRUTH) < 0)
                return -1;
        } else if (statement->kind == WRTC_PY_STMT_FOR) {
            if (analyze_expression(analyzer, &statement->expressions[1],
                                   USE_ITERATE) < 0)
                return -1;
        } else {
            for (expression_index = 0u;
                 expression_index < statement->expression_count;
                 expression_index++)
                if (analyze_expression(
                        analyzer, &statement->expressions[expression_index],
                        statement->kind == WRTC_PY_STMT_RETURN
                            ? USE_ESCAPE : USE_READ) < 0)
                    return -1;
        }
        analyzer->control_depth++;
        if (analyze_statements(analyzer, statement->body,
                               statement->body_count) < 0 ||
            analyze_statements(analyzer, statement->orelse,
                               statement->orelse_count) < 0 ||
            analyze_statements(analyzer, statement->handlers,
                               statement->handler_count) < 0 ||
            analyze_statements(analyzer, statement->finalbody,
                               statement->finalbody_count) < 0)
            return -1;
        analyzer->control_depth--;
    }
    return 0;
}

int wrtc_native_operation_prove(const WrtcNativeClassProgram *program,
                                WrtcNativeOperationTable **out) {
    WrtcNativeOperationTable *table;
    size_t class_index, field_index, region_index, proof_index = 0u;
    if (program == NULL || out == NULL) {
        PyErr_SetString(PyExc_ValueError,
                        "native operation proof input is absent");
        return -1;
    }
    *out = NULL;
    table = calloc(1u, sizeof(*table));
    if (table == NULL) return PyErr_NoMemory(), -1;
    table->complete = 1u;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (field_index = 0u;
             field_index < program->classes[class_index].field_count;
             field_index++)
            if (program->classes[class_index].fields[field_index]
                    .storage_kind != WRTC_NATIVE_FIELD_PYOBJECT)
                table->field_count++;
    table->fields = calloc(table->field_count, sizeof(*table->fields));
    if (table->field_count != 0u && table->fields == NULL) {
        free(table);
        return PyErr_NoMemory(), -1;
    }
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (field_index = 0u;
             field_index < program->classes[class_index].field_count;
             field_index++)
            if (program->classes[class_index].fields[field_index]
                    .storage_kind != WRTC_NATIVE_FIELD_PYOBJECT) {
                table->fields[proof_index].class_index = class_index;
                table->fields[proof_index].field_index = field_index;
                table->fields[proof_index].complete = 1u;
                if (program->classes[class_index].fields[field_index]
                            .storage_kind == WRTC_NATIVE_FIELD_SELECTOR ||
                    program->classes[class_index].fields[field_index]
                            .storage_kind == WRTC_NATIVE_FIELD_PACKET_POOL)
                    table->fields[proof_index].touched = 1u;
                proof_index++;
            }
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++) {
            const WrtcNativeRegionIR *region =
                &program->classes[class_index].regions[region_index];
            Analyzer analyzer;
            size_t alias;
            if (region->policy != WRTC_REGION_REQUIRED ||
                region->body == NULL)
                continue;
            memset(&analyzer, 0, sizeof(analyzer));
            analyzer.program = program;
            analyzer.table = table;
            analyzer.region_class = &program->classes[class_index];
            analyzer.region = region;
            analyzer.region_class_index = class_index;
            analyzer.region_index = region_index;
            analyzer.next_order = table->operation_count;
            if (analyze_statements(
                    &analyzer, region->body->statements,
                    region->body->statement_count) < 0) {
                for (alias = 0u; alias < analyzer.alias_count; alias++)
                    free(analyzer.aliases[alias].name);
                free(analyzer.aliases);
                wrtc_native_operation_table_free(table);
                return -1;
            }
            for (alias = 0u; alias < analyzer.alias_count; alias++)
                free(analyzer.aliases[alias].name);
            free(analyzer.aliases);
        }
    for (proof_index = 0u; proof_index < table->field_count; proof_index++)
        if (!table->fields[proof_index].touched) {
            table->fields[proof_index].complete = 0u;
            table->complete = 0u;
        }
    *out = table;
    return 0;
}

const char *wrtc_native_operation_kind_name(WrtcNativeOperationKind kind) {
    static const char *const names[] = {
        "alias_bind", "scalar_read", "scalar_write",
        "scalar_augmented_write", "length", "truth", "root_read",
        "iterate", "slice_assign", "fifo_append", "fifo_popleft",
        "heapify", "heap_push", "heap_pop", "heap_compact_cancelled",
        "atomic_load", "atomic_store",
        "atomic_compare_exchange",
        "mpsc_put_nowait", "mpsc_get_nowait", "mpsc_qsize",
        "mpsc_empty", "mpsc_close", "spsc_put_nowait",
        "spsc_get_nowait", "spsc_qsize", "spsc_empty", "spsc_close",
        "selector_register", "selector_is_current", "selector_owner",
        "selector_remove",
        "boxed_write",
        "unsupported_escape"
    };
    return (size_t)kind < sizeof names / sizeof names[0]
               ? names[(size_t)kind] : "unknown";
}

void wrtc_native_operation_table_free(WrtcNativeOperationTable *table) {
    size_t index;
    if (table == NULL) return;
    for (index = 0u; index < table->operation_count; index++) {
        free(table->operations[index].alias_name);
        free(table->operations[index].detail);
    }
    free(table->operations);
    free(table->fields);
    free(table);
}
