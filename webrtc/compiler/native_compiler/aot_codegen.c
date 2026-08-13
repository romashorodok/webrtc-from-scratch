#include "aot_codegen.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define WRTC_AOT_SLOT_LIMIT 64u
#define WRTC_AOT_EXPRESSION_LIMIT 4096u

typedef struct {
    FILE *file;
    const WrtcNativeRegionIR *region;
    const WrtcNativeClassProgram *program;
    const WrtcNativeOperationTable *operations;
    size_t class_index;
    size_t region_index;
    size_t expression_id;
    size_t target_id;
    size_t statement_id;
    size_t suite_id;
    int has_hooks;
    int direct;
    const char *slot_names[WRTC_AOT_SLOT_LIMIT];
    WrtcNativeRepresentation slot_representations[WRTC_AOT_SLOT_LIMIT];
    unsigned char slot_scalar_seen[WRTC_AOT_SLOT_LIMIT];
    unsigned char slot_scalar_conflict[WRTC_AOT_SLOT_LIMIT];
    size_t slot_count;
    const WrtcPyExprIR *expressions[WRTC_AOT_EXPRESSION_LIMIT];
    size_t expression_ids[WRTC_AOT_EXPRESSION_LIMIT];
    size_t expression_count;
} AotEmitter;

static const WrtcNativeOperationIR *direct_operation(
    const AotEmitter *emitter, const WrtcPyExprIR *expression);
static const WrtcNativeCallEdgeIR *call_edge(
    const AotEmitter *emitter, const WrtcPyExprIR *expression);
static size_t slot_index(const AotEmitter *emitter, const char *name);

static const char *aot_final_type_name(const char *annotation,
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

static size_t expression_owner_class(const AotEmitter *emitter,
                                     const WrtcPyExprIR *owner) {
    size_t parameter, class_index;
    if (owner == NULL || owner->kind != WRTC_PY_EXPR_NAME ||
        owner->operation == NULL)
        return (size_t)-1;
    if (strcmp(owner->operation, "self") == 0) return emitter->class_index;
    for (parameter = 0u;
         parameter < emitter->region->signature->parameter_count; parameter++) {
        const WrtcPyParameterIR *item =
            &emitter->region->signature->parameters[parameter];
        char type_name[256];
        const char *resolved;
        if (item->name == NULL || strcmp(item->name, owner->operation) != 0)
            continue;
        resolved = aot_final_type_name(item->annotation, type_name,
                                       sizeof type_name);
        if (resolved == NULL) return (size_t)-1;
        for (class_index = 0u;
             class_index < emitter->program->class_count; class_index++)
            if (strcmp(emitter->program->classes[class_index].name,
                       resolved) == 0)
                return class_index;
    }
    return (size_t)-1;
}

static const WrtcNativeFieldIR *direct_object_field(
    const AotEmitter *emitter, const WrtcPyExprIR *expression,
    size_t *class_index_out, size_t *field_index_out) {
    size_t class_index, field_index;
    const WrtcNativeClassIR *class_ir;
    if (expression == NULL || expression->kind != WRTC_PY_EXPR_ATTRIBUTE ||
        expression->child_count != 1u || expression->operation == NULL)
        return NULL;
    class_index = expression_owner_class(emitter, &expression->children[0]);
    if (class_index == (size_t)-1) return NULL;
    class_ir = &emitter->program->classes[class_index];
    for (field_index = 0u; field_index < class_ir->field_count; field_index++) {
        const WrtcNativeFieldIR *field = &class_ir->fields[field_index];
        if (field->storage_kind == WRTC_NATIVE_FIELD_PYOBJECT &&
            strcmp(field->name, expression->operation) == 0) {
            *class_index_out = class_index;
            *field_index_out = field_index;
            return field;
        }
    }
    return NULL;
}

static size_t first_region_manifest(const WrtcNativeClassProgram *program,
                                    size_t class_index) {
    size_t index, manifest = 0u;
    for (index = 0u; index < class_index; index++)
        manifest += program->classes[index].region_count;
    return manifest;
}

static const WrtcNativeFieldIR *typed_heap_key_expression(
    const AotEmitter *emitter, const WrtcPyExprIR *expression) {
    const WrtcNativeOperationIR *operation;
    const WrtcNativeFieldOperationProof *proof;
    const WrtcNativeFieldIR *field;
    if (expression == NULL || expression->kind != WRTC_PY_EXPR_ATTRIBUTE ||
        expression->child_count != 1u || expression->operation == NULL ||
        expression->children[0].kind != WRTC_PY_EXPR_SUBSCRIPT)
        return NULL;
    operation = direct_operation(emitter, &expression->children[0]);
    if (operation == NULL || operation->kind != WRTC_NATIVE_OP_ROOT_READ)
        return NULL;
    proof = &emitter->operations->fields[operation->field_proof_index];
    field = &emitter->program->classes[proof->class_index]
                 .fields[proof->field_index];
    if (field->storage_kind != WRTC_NATIVE_FIELD_MIN_HEAP ||
        field->heap_key == NULL || field->heap_key_type == NULL ||
        strcmp(field->heap_key, expression->operation) != 0)
        return NULL;
    return field;
}

static WrtcNativeRepresentation constant_scalar_representation(
    const WrtcPyExprIR *expression) {
    char *end = NULL;
    if (expression->operation == NULL || expression->text == NULL)
        return WRTC_NATIVE_REPR_VOID;
    if (strcmp(expression->operation, "bool") == 0 &&
        (strcmp(expression->text, "True") == 0 ||
         strcmp(expression->text, "False") == 0))
        return WRTC_NATIVE_REPR_BOOL;
    if (strcmp(expression->operation, "float") == 0) {
        errno = 0;
        (void)strtod(expression->text, &end);
        return errno == 0 && end != expression->text && *end == '\0'
                   ? WRTC_NATIVE_REPR_DOUBLE : WRTC_NATIVE_REPR_VOID;
    }
    if (strcmp(expression->operation, "int") == 0) {
        errno = 0;
        (void)strtoll(expression->text, &end, 0);
        return errno == 0 && end != expression->text && *end == '\0'
                   ? WRTC_NATIVE_REPR_INT64 : WRTC_NATIVE_REPR_VOID;
    }
    return WRTC_NATIVE_REPR_VOID;
}

static int scalar_representation(WrtcNativeRepresentation representation) {
    return representation == WRTC_NATIVE_REPR_PY_SSIZE_T ||
           representation == WRTC_NATIVE_REPR_INT64 ||
           representation == WRTC_NATIVE_REPR_DOUBLE ||
           representation == WRTC_NATIVE_REPR_BOOL;
}

static WrtcNativeRepresentation expression_scalar_representation(
    const AotEmitter *emitter, const WrtcPyExprIR *expression) {
    const WrtcNativeOperationIR *operation;
    WrtcNativeRepresentation left, right;
    size_t slot, index;
    if (expression == NULL) return WRTC_NATIVE_REPR_VOID;
    operation = direct_operation(emitter, expression);
    if (operation != NULL && scalar_representation(
            operation->result_representation)) {
        if ((operation->kind == WRTC_NATIVE_OP_TRUTH ||
             operation->kind == WRTC_NATIVE_OP_SCALAR_READ) &&
            expression->kind == WRTC_PY_EXPR_ATTRIBUTE &&
            expression->child_count == 1u)
            return operation->result_representation;
        if (operation->kind == WRTC_NATIVE_OP_LENGTH &&
            expression->child_count >= 2u &&
            expression->children[1].kind == WRTC_PY_EXPR_ATTRIBUTE &&
            expression->children[1].child_count == 1u)
            return operation->result_representation;
        return WRTC_NATIVE_REPR_VOID;
    }
    if (typed_heap_key_expression(emitter, expression) != NULL) {
        const WrtcNativeFieldIR *field =
            typed_heap_key_expression(emitter, expression);
        if (strcmp(field->heap_key_type, "float") == 0)
            return WRTC_NATIVE_REPR_DOUBLE;
        if (strcmp(field->heap_key_type, "bool") == 0)
            return WRTC_NATIVE_REPR_BOOL;
        if (strcmp(field->heap_key_type, "int") == 0)
            return WRTC_NATIVE_REPR_INT64;
    }
    switch (expression->kind) {
        case WRTC_PY_EXPR_NAME:
            slot = slot_index(emitter, expression->operation);
            return slot == (size_t)-1 ? WRTC_NATIVE_REPR_VOID
                                      : emitter->slot_representations[slot];
        case WRTC_PY_EXPR_CONSTANT:
            return constant_scalar_representation(expression);
        case WRTC_PY_EXPR_CALL: {
            const WrtcNativeCallEdgeIR *edge = call_edge(emitter, expression);
            if (edge == NULL || !edge->result_contract_proven)
                return WRTC_NATIVE_REPR_VOID;
            if (edge->result_representation == WRTC_CALL_RESULT_DOUBLE)
                return WRTC_NATIVE_REPR_DOUBLE;
            if (edge->result_representation == WRTC_CALL_RESULT_BOOL)
                return WRTC_NATIVE_REPR_BOOL;
            if (edge->result_representation == WRTC_CALL_RESULT_INT64)
                return WRTC_NATIVE_REPR_INT64;
            return WRTC_NATIVE_REPR_VOID;
        }
        case WRTC_PY_EXPR_UNARY:
            left = expression_scalar_representation(
                emitter, &expression->children[0]);
            if (expression->operation != NULL &&
                strcmp(expression->operation, "Not") == 0 &&
                scalar_representation(left))
                return WRTC_NATIVE_REPR_BOOL;
            if (expression->operation != NULL &&
                (strcmp(expression->operation, "USub") == 0 ||
                 strcmp(expression->operation, "UAdd") == 0) &&
                left == WRTC_NATIVE_REPR_DOUBLE)
                return left;
            return WRTC_NATIVE_REPR_VOID;
        case WRTC_PY_EXPR_BINARY:
            if (expression->child_count != 2u)
                return WRTC_NATIVE_REPR_VOID;
            left = expression_scalar_representation(
                emitter, &expression->children[0]);
            right = expression_scalar_representation(
                emitter, &expression->children[1]);
            if (!scalar_representation(left) ||
                !scalar_representation(right))
                return WRTC_NATIVE_REPR_VOID;
            if (expression->binary_operation == WRTC_PY_BINARY_TRUE_DIVIDE)
                return WRTC_NATIVE_REPR_DOUBLE;
            if ((left == WRTC_NATIVE_REPR_DOUBLE ||
                 right == WRTC_NATIVE_REPR_DOUBLE) &&
                (expression->binary_operation == WRTC_PY_BINARY_ADD ||
                 expression->binary_operation == WRTC_PY_BINARY_SUBTRACT ||
                 expression->binary_operation == WRTC_PY_BINARY_MULTIPLY))
                return WRTC_NATIVE_REPR_DOUBLE;
            /* Arbitrary precision integer arithmetic cannot be represented by
             * int64_t without a separately proven range. */
            return WRTC_NATIVE_REPR_VOID;
        case WRTC_PY_EXPR_COMPARE:
            if (expression->operation_count == 0u ||
                expression->child_count != expression->operation_count + 1u)
                return WRTC_NATIVE_REPR_VOID;
            for (index = 0u; index < expression->child_count; index++)
                if (!scalar_representation(expression_scalar_representation(
                        emitter, &expression->children[index])))
                    return WRTC_NATIVE_REPR_VOID;
            for (index = 0u; index < expression->operation_count; index++) {
                left = expression_scalar_representation(
                    emitter, &expression->children[index]);
                right = expression_scalar_representation(
                    emitter, &expression->children[index + 1u]);
                /* CPython compares large ints with floats without first
                 * rounding the integer to double.  Keep mixed comparisons
                 * boxed until a numeric-range proof is available. */
                if ((left == WRTC_NATIVE_REPR_DOUBLE) !=
                    (right == WRTC_NATIVE_REPR_DOUBLE))
                    return WRTC_NATIVE_REPR_VOID;
            }
            for (index = 0u; index < expression->operation_count; index++)
                if (strcmp(expression->operations[index], "Eq") != 0 &&
                    strcmp(expression->operations[index], "NotEq") != 0 &&
                    strcmp(expression->operations[index], "Lt") != 0 &&
                    strcmp(expression->operations[index], "LtE") != 0 &&
                    strcmp(expression->operations[index], "Gt") != 0 &&
                    strcmp(expression->operations[index], "GtE") != 0)
                    return WRTC_NATIVE_REPR_VOID;
            return WRTC_NATIVE_REPR_BOOL;
        default:
            return WRTC_NATIVE_REPR_VOID;
    }
}

static int same_span(WrtcSourceSpan left, WrtcSourceSpan right) {
    return left.line == right.line && left.column == right.column &&
           left.end_line == right.end_line &&
           left.end_column == right.end_column;
}

static const WrtcNativeOperationIR *direct_operation(
    const AotEmitter *emitter, const WrtcPyExprIR *expression) {
    size_t index;
    if (emitter->operations == NULL || emitter->has_hooks) return NULL;
    for (index = 0u; index < emitter->operations->operation_count; index++) {
        const WrtcNativeOperationIR *operation =
            &emitter->operations->operations[index];
        if (operation->region_class_index == emitter->class_index &&
            operation->region_index == emitter->region_index &&
            same_span(operation->span, expression->span) &&
            operation->kind != WRTC_NATIVE_OP_ALIAS_BIND &&
            operation->kind != WRTC_NATIVE_OP_BOXED_WRITE &&
            operation->kind != WRTC_NATIVE_OP_UNSUPPORTED_ESCAPE)
            return operation;
    }
    return NULL;
}

static const WrtcNativeCallEdgeIR *direct_call(
    const AotEmitter *emitter, const WrtcPyExprIR *expression) {
    size_t index;
    if (expression->kind != WRTC_PY_EXPR_CALL) return NULL;
    for (index = 0u; index < emitter->region->call_count; index++) {
        const WrtcNativeCallEdgeIR *edge = &emitter->region->calls[index];
        if (edge->resolved && edge->required_callee &&
            same_span(edge->span, expression->span))
            return edge;
    }
    return NULL;
}

static const WrtcNativeCallEdgeIR *call_edge(
    const AotEmitter *emitter, const WrtcPyExprIR *expression) {
    size_t index;
    if (expression == NULL || expression->kind != WRTC_PY_EXPR_CALL)
        return NULL;
    for (index = 0u; index < emitter->region->call_count; index++)
        if (same_span(emitter->region->calls[index].span, expression->span))
            return &emitter->region->calls[index];
    return NULL;
}

static size_t expression_id(const AotEmitter *emitter,
                            const WrtcPyExprIR *expression) {
    size_t index;
    for (index = 0u; index < emitter->expression_count; index++)
        if (emitter->expressions[index] == expression)
            return emitter->expression_ids[index];
    return (size_t)-1;
}

static int quote(FILE *file, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    if (fputc('"', file) == EOF) return -1;
    while (*cursor != 0u) {
        const unsigned char value = *cursor++;
        if (value == '"' || value == '\\') {
            if (fputc('\\', file) == EOF || fputc((int)value, file) == EOF)
                return -1;
        } else if (value == '\n') {
            if (fputs("\\n", file) < 0) return -1;
        } else if (value == '\r') {
            if (fputs("\\r", file) < 0) return -1;
        } else if (value == '\t') {
            if (fputs("\\t", file) < 0) return -1;
        } else if (value < 32u || value > 126u) {
            if (fprintf(file, "\\x%02x", (unsigned)value) < 0) return -1;
        } else if (fputc((int)value, file) == EOF) {
            return -1;
        }
    }
    return fputc('"', file) == EOF ? -1 : 0;
}

static int target_supported(const WrtcPyExprIR *target) {
    size_t index;
    if (target == NULL) return 0;
    switch (target->kind) {
        case WRTC_PY_EXPR_NAME:
        case WRTC_PY_EXPR_ATTRIBUTE:
        case WRTC_PY_EXPR_SUBSCRIPT:
            return 1;
        case WRTC_PY_EXPR_TUPLE:
        case WRTC_PY_EXPR_LIST:
            for (index = 0u; index < target->child_count; index++)
                if (!target_supported(&target->children[index])) return 0;
            return 1;
        default:
            return 0;
    }
}

static int expression_supported(const WrtcPyExprIR *expression) {
    size_t index;
    if (expression == NULL || expression->kind == WRTC_PY_EXPR_LAMBDA ||
        expression->kind == WRTC_PY_EXPR_JOINED_STRING ||
        expression->kind == WRTC_PY_EXPR_FORMATTED_VALUE)
        return 0;
    for (index = 0u; index < expression->child_count; index++)
        if (!expression_supported(&expression->children[index])) return 0;
    return 1;
}

static int statements_supported(const WrtcPyStmtIR *statements, size_t count) {
    size_t statement_index, expression_index;
    for (statement_index = 0u; statement_index < count; statement_index++) {
        const WrtcPyStmtIR *statement = &statements[statement_index];
        for (expression_index = 0u;
             expression_index < statement->expression_count;
             expression_index++)
            if (!expression_supported(
                    &statement->expressions[expression_index]))
                return 0;
        if (statement->kind == WRTC_PY_STMT_ASSIGN)
            for (expression_index = 1u;
                 expression_index < statement->expression_count;
                 expression_index++)
                if (!target_supported(
                        &statement->expressions[expression_index]))
                    return 0;
        if (statement->kind == WRTC_PY_STMT_FOR &&
            (statement->expression_count < 2u ||
             !target_supported(&statement->expressions[0])))
            return 0;
        if (statement->kind == WRTC_PY_STMT_AUGMENTED_ASSIGN &&
            (statement->expression_count < 2u ||
             statement->expressions[0].kind != WRTC_PY_EXPR_NAME))
            return 0;
        if (!statements_supported(statement->body, statement->body_count) ||
            !statements_supported(statement->orelse, statement->orelse_count) ||
            !statements_supported(statement->finalbody,
                                  statement->finalbody_count) ||
            !statements_supported(statement->handlers,
                                  statement->handler_count))
            return 0;
    }
    return 1;
}

static int expression_uses_name(const WrtcPyExprIR *expression,
                                const char *name) {
    size_t index;
    if (expression == NULL || name == NULL) return 0;
    if (expression->kind == WRTC_PY_EXPR_NAME &&
        expression->operation != NULL &&
        strcmp(expression->operation, name) == 0)
        return 1;
    for (index = 0u; index < expression->child_count; index++)
        if (expression_uses_name(&expression->children[index], name))
            return 1;
    return 0;
}

static int statements_use_name(const WrtcPyStmtIR *statements, size_t count,
                               const char *name) {
    size_t statement_index, expression_index;
    for (statement_index = 0u; statement_index < count; statement_index++) {
        const WrtcPyStmtIR *statement = &statements[statement_index];
        for (expression_index = 0u;
             expression_index < statement->expression_count;
             expression_index++)
            if (expression_uses_name(
                    &statement->expressions[expression_index], name))
                return 1;
        if (statements_use_name(statement->body, statement->body_count, name) ||
            statements_use_name(statement->orelse, statement->orelse_count,
                                name) ||
            statements_use_name(statement->finalbody,
                                statement->finalbody_count, name) ||
            statements_use_name(statement->handlers,
                                statement->handler_count, name))
            return 1;
    }
    return 0;
}

static int signature_supported(const WrtcPySignatureIR *signature) {
    size_t index;
    int saw_varargs = 0;
    if (signature == NULL || signature->parameter_count == 0u ||
        signature->parameter_count > WRTC_AOT_SLOT_LIMIT)
        return 0;
    for (index = 0u; index < signature->parameter_count; index++) {
        const WrtcPyParameterIR *parameter = &signature->parameters[index];
        if (parameter->kind == WRTC_PY_PARAM_VAR_KEYWORD) return 0;
        if (parameter->kind == WRTC_PY_PARAM_VAR_POSITIONAL) {
            if (saw_varargs) return 0;
            saw_varargs = 1;
        } else if (parameter->kind == WRTC_PY_PARAM_KEYWORD_ONLY) {
            if (!saw_varargs || !parameter->has_default) return 0;
        } else if (parameter->kind != WRTC_PY_PARAM_POSITIONAL_ONLY &&
                   parameter->kind != WRTC_PY_PARAM_POSITIONAL_OR_KEYWORD) {
            return 0;
        } else if (parameter->has_default) {
            return 0;
        }
    }
    return strcmp(signature->parameters[0].name, "self") == 0;
}

int wrtc_aot_region_supported(const WrtcNativeRegionIR *region) {
    return region != NULL && region->body != NULL &&
           region->body->local_count <= WRTC_AOT_SLOT_LIMIT &&
           signature_supported(region->signature) &&
           statements_supported(region->body->statements,
                                region->body->statement_count);
}

int wrtc_aot_region_direct_supported(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations, size_t class_index,
    size_t region_index) {
    const WrtcNativeRegionIR *region;
    size_t index;
    int found = 0;
    if (program == NULL || operations == NULL || !operations->complete ||
        class_index >= program->class_count ||
        region_index >= program->classes[class_index].region_count)
        return 0;
    region = &program->classes[class_index].regions[region_index];
    if (!wrtc_aot_region_supported(region))
        return 0;
    /* Direct graph promotion is intentionally scoped to the event-loop
     * scheduling closure.  Other required subsystems keep their independently
     * proven compatibility/kernel tiers until their own graph is complete. */
    if (strcmp(program->classes[class_index].name,
               "WebRTCSelectorEventLoop") != 0 &&
        strcmp(program->classes[class_index].name, "ReactorScheduler") != 0 &&
        strcmp(program->classes[class_index].name, "CommandInbox") != 0 &&
        strcmp(program->classes[class_index].name, "PacketWorkerPool") != 0)
        return 0;
    for (index = 0u; index < operations->operation_count; index++) {
        const WrtcNativeOperationIR *operation = &operations->operations[index];
        const WrtcNativeFieldOperationProof *proof;
        if (operation->region_class_index != class_index ||
            operation->region_index != region_index)
            continue;
        found = 1;
        proof = &operations->fields[operation->field_proof_index];
        if (!proof->complete) return 0;
        switch (operation->kind) {
            case WRTC_NATIVE_OP_SCALAR_READ:
            case WRTC_NATIVE_OP_SCALAR_WRITE:
            case WRTC_NATIVE_OP_SCALAR_AUGMENTED_WRITE:
            case WRTC_NATIVE_OP_LENGTH:
            case WRTC_NATIVE_OP_TRUTH:
            case WRTC_NATIVE_OP_ROOT_READ:
            case WRTC_NATIVE_OP_FIFO_APPEND:
            case WRTC_NATIVE_OP_FIFO_POPLEFT:
            case WRTC_NATIVE_OP_HEAPIFY:
            case WRTC_NATIVE_OP_HEAP_PUSH:
            case WRTC_NATIVE_OP_HEAP_POP:
            case WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED:
            case WRTC_NATIVE_OP_ATOMIC_LOAD:
            case WRTC_NATIVE_OP_ATOMIC_STORE:
            case WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE:
            case WRTC_NATIVE_OP_MPSC_PUT_NOWAIT:
            case WRTC_NATIVE_OP_MPSC_GET_NOWAIT:
            case WRTC_NATIVE_OP_MPSC_QSIZE:
            case WRTC_NATIVE_OP_MPSC_EMPTY:
            case WRTC_NATIVE_OP_MPSC_CLOSE:
                break;
            default:
                return 0;
        }
    }
    /* Regions without storage operations are still direct when their body is
     * fully emitted as C.  This is essential for graph glue such as
     * _run_once, whose only operation is a resolved direct-region call. */
    (void)found;
    return 1;
}

int wrtc_aot_program_complete(const WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    if (program == NULL) return 0;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (!wrtc_aot_region_supported(
                    &program->classes[class_index].regions[region_index]))
                return 0;
    return 1;
}

int wrtc_aot_program_direct_complete(
    const WrtcNativeClassProgram *program,
    const WrtcNativeOperationTable *operations) {
    size_t class_index, region_index;
    if (program == NULL) return 0;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (!wrtc_aot_region_direct_supported(
                    program, operations, class_index, region_index))
                return 0;
    return 1;
}

int wrtc_aot_program_has_regions(const WrtcNativeClassProgram *program) {
    size_t class_index, region_index;
    if (program == NULL) return 0;
    for (class_index = 0u; class_index < program->class_count; class_index++)
        for (region_index = 0u;
             region_index < program->classes[class_index].region_count;
             region_index++)
            if (wrtc_aot_region_supported(
                    &program->classes[class_index].regions[region_index]))
                return 1;
    return 0;
}

int wrtc_aot_emit_runtime(FILE *file) {
    if (file == NULL) return -1;
    return fputs(
        "#if defined(__GNUC__)||defined(__clang__)\n"
        "#define WRTC_AOT_UNUSED __attribute__((unused))\n"
        "#else\n#define WRTC_AOT_UNUSED\n#endif\n"
        "#define WRTC_REGION_SLOT_COUNT 64u\n"
        "typedef struct{PyObject*values[WRTC_REGION_SLOT_COUNT];"
        "int64_t scalar_i[WRTC_REGION_SLOT_COUNT];"
        "double scalar_d[WRTC_REGION_SLOT_COUNT];uint64_t scalar_mask;"
        "uint64_t initialized_mask;uint64_t owned_mask;PyObject*globals;"
        "PyObject*return_value;const WrtcBoxedNativeHooks*hooks;}"
        "WrtcRegionFrame;"
        "void wafc(WrtcRegionFrame*f){size_t i=0u;uint64_t m=f->owned_mask;"
        "while(m){if((m&UINT64_C(1))!=0u)Py_DECREF(f->values[i]);"
        "m>>=1u;i++;}Py_XDECREF(f->return_value);}"
        "int wafb(WrtcRegionFrame*f,size_t i,PyObject*v,int owned){"
        "uint64_t b=UINT64_C(1)<<i;if(i>=WRTC_REGION_SLOT_COUNT){"
        "PyErr_SetString(PyExc_SystemError,\"AOT frame slot overflow\");"
        "return -1;}if((f->owned_mask&b)!=0u)Py_DECREF(f->values[i]);"
        "f->values[i]=v;f->initialized_mask|=b;if(owned)f->owned_mask|=b;"
        "else f->owned_mask&=~b;return 0;}"
        "int wafs(WrtcRegionFrame*f,size_t i,PyObject*v){"
        "Py_INCREF(v);if(wafb(f,i,v,1)<0){Py_DECREF(v);return -1;}return 0;}"
        "PyObject*wafl(WrtcRegionFrame*f,size_t i,const char*n){"
        "uint64_t b=UINT64_C(1)<<i;if((f->initialized_mask&b)==0u){"
        "PyErr_Format(PyExc_UnboundLocalError,\"cannot access local variable "
        "'%s' where it is not associated with a value\",n);return NULL;}"
        "return Py_NewRef(f->values[i]);}"
        "PyObject*wafg(WrtcRegionFrame*f,const char*n){PyObject*v,*b;"
        "v=PyDict_GetItemString(f->globals,n);if(v)return Py_NewRef(v);"
        "if(PyErr_Occurred())return NULL;b=PyDict_GetItemString(f->globals,"
        "\"__builtins__\");if(!b)b=PyEval_GetBuiltins();"
        "if(b&&PyDict_Check(b))v=PyDict_GetItemString(b,n);"
        "else if(b)v=PyObject_GetAttrString(b,n);"
        "if(v)return PyDict_Check(b)?Py_NewRef(v):v;if(PyErr_Occurred())"
        "return NULL;PyErr_Format(PyExc_NameError,\"name '%s' is not defined\","
        "n);return NULL;}\n",
        file) < 0 ? -1 : 0;
}

static int add_slot(AotEmitter *emitter, const char *name) {
    size_t index;
    for (index = 0u; index < emitter->slot_count; index++)
        if (strcmp(emitter->slot_names[index], name) == 0) return 0;
    if (emitter->slot_count == WRTC_AOT_SLOT_LIMIT) return -1;
    emitter->slot_names[emitter->slot_count++] = name;
    return 0;
}

static size_t slot_index(const AotEmitter *emitter, const char *name) {
    size_t index;
    for (index = 0u; index < emitter->slot_count; index++)
        if (strcmp(emitter->slot_names[index], name) == 0) return index;
    return (size_t)-1;
}

static void discover_scalar_locals(AotEmitter *emitter,
                                   const WrtcPyStmtIR *statements,
                                   size_t count) {
    size_t index;
    for (index = 0u; index < count; index++) {
        const WrtcPyStmtIR *statement = &statements[index];
        if (statement->kind == WRTC_PY_STMT_ASSIGN) {
            WrtcNativeRepresentation representation =
                statement->expression_count != 0u
                    ? expression_scalar_representation(
                          emitter, &statement->expressions[0])
                    : WRTC_NATIVE_REPR_VOID;
            size_t target;
            for (target = 1u; target < statement->expression_count; target++) {
                size_t slot;
                if (statement->expressions[target].kind != WRTC_PY_EXPR_NAME)
                    continue;
                slot = slot_index(emitter,
                                  statement->expressions[target].operation);
                if (slot != (size_t)-1) {
                    if (statement->expression_count == 2u &&
                        scalar_representation(representation)) {
                        if (emitter->slot_scalar_seen[slot] &&
                            emitter->slot_representations[slot] !=
                                representation)
                            emitter->slot_scalar_conflict[slot] = 1u;
                        emitter->slot_scalar_seen[slot] = 1u;
                        emitter->slot_representations[slot] = representation;
                    } else {
                        emitter->slot_scalar_conflict[slot] = 1u;
                    }
                }
            }
        }
        if ((statement->kind == WRTC_PY_STMT_AUGMENTED_ASSIGN ||
             statement->kind == WRTC_PY_STMT_FOR) &&
            statement->expression_count != 0u &&
            statement->expressions[0].kind == WRTC_PY_EXPR_NAME) {
            size_t slot = slot_index(
                emitter, statement->expressions[0].operation);
            if (slot != (size_t)-1)
                emitter->slot_scalar_conflict[slot] = 1u;
        }
        discover_scalar_locals(emitter, statement->body,
                               statement->body_count);
        discover_scalar_locals(emitter, statement->orelse,
                               statement->orelse_count);
        discover_scalar_locals(emitter, statement->finalbody,
                               statement->finalbody_count);
    }
}

static void finalize_scalar_locals(AotEmitter *emitter) {
    size_t index;
    for (index = 0u; index < emitter->slot_count; index++)
        if (!emitter->slot_scalar_seen[index] ||
            emitter->slot_scalar_conflict[index])
            emitter->slot_representations[index] = WRTC_NATIVE_REPR_VOID;
}

static int function_prefix(FILE *file, const AotEmitter *emitter,
                           const char *kind, size_t id) {
    return fprintf(file, "%s%zu_%zu_%zu", kind, emitter->class_index,
                   emitter->region_index, id) < 0 ? -1 : 0;
}

static int emit_expression(AotEmitter *emitter,
                           const WrtcPyExprIR *expression, size_t *result_id);

static int emit_expression_children(AotEmitter *emitter,
                                    const WrtcPyExprIR *expression,
                                    size_t **ids_out) {
    size_t *ids = NULL, index;
    if (expression->child_count != 0u) {
        ids = calloc(expression->child_count, sizeof(*ids));
        if (ids == NULL) return -1;
    }
    for (index = 0u; index < expression->child_count; index++)
        if (emit_expression(emitter, &expression->children[index],
                            &ids[index]) < 0) {
            free(ids);
            return -1;
        }
    *ids_out = ids;
    return 0;
}

static int emit_eval_child(FILE *file, const AotEmitter *emitter, size_t id,
                           size_t child_index) {
    if (function_prefix(file, emitter, "wae", id) < 0 ||
        fprintf(file, "(f,&e->children[%zu])", child_index) < 0)
        return -1;
    return 0;
}

static int emit_eval_statement(FILE *file, const AotEmitter *emitter,
                               size_t id, size_t expression_index) {
    if (function_prefix(file, emitter, "wae", id) < 0 ||
        fprintf(file, "(f,&s->expressions[%zu])", expression_index) < 0)
        return -1;
    return 0;
}

/* Emit a proven scalar storage operation directly into a C scalar.  The
 * source expression is used only to locate its already-emitted owner; runtime
 * dispatch is selected exclusively from the native operation table. */
static int emit_direct_scalar_statement(FILE *file, AotEmitter *emitter,
                                        const WrtcPyExprIR *expression,
                                        const char *runtime_root,
                                        const char *target) {
    const WrtcNativeOperationIR *operation =
        direct_operation(emitter, expression);
    const WrtcNativeFieldOperationProof *proof;
    const WrtcNativeFieldIR *field;
    const WrtcPyExprIR *owner = NULL;
    const char *owner_suffix = NULL;
    size_t owner_id;
    const char *kernel;
    char member;
    if (operation == NULL) return 0;
    if ((operation->kind == WRTC_NATIVE_OP_TRUTH ||
         operation->kind == WRTC_NATIVE_OP_SCALAR_READ) &&
        operation->result_representation == WRTC_NATIVE_REPR_BOOL &&
        expression->kind == WRTC_PY_EXPR_ATTRIBUTE &&
        expression->child_count == 1u) {
        owner = &expression->children[0];
        owner_suffix = ".children[0]";
    } else if (operation->kind == WRTC_NATIVE_OP_SCALAR_READ &&
               scalar_representation(operation->result_representation) &&
               expression->kind == WRTC_PY_EXPR_ATTRIBUTE &&
               expression->child_count == 1u) {
        owner = &expression->children[0];
        owner_suffix = ".children[0]";
    } else if (operation->kind == WRTC_NATIVE_OP_LENGTH &&
               operation->result_representation == WRTC_NATIVE_REPR_PY_SSIZE_T &&
               expression->child_count >= 2u &&
               expression->children[1].kind == WRTC_PY_EXPR_ATTRIBUTE) {
        owner = &expression->children[1].children[0];
        owner_suffix = ".children[1].children[0]";
    } else {
        return 0;
    }
    proof = &emitter->operations->fields[operation->field_proof_index];
    field = &emitter->program->classes[proof->class_index]
                 .fields[proof->field_index];
    if (field->storage_kind == WRTC_NATIVE_FIELD_SCALAR) {
        kernel = NULL;
        member = 's';
    } else if (field->storage_kind == WRTC_NATIVE_FIELD_FIFO) {
        kernel = operation->kind == WRTC_NATIVE_OP_TRUTH
                     ? "wrtc_native_fifo_truth"
                     : "wrtc_native_fifo_snapshot";
        member = 'f';
    } else if (field->storage_kind == WRTC_NATIVE_FIELD_MIN_HEAP) {
        kernel = operation->kind == WRTC_NATIVE_OP_TRUTH
                     ? "wrtc_native_heap_truth"
                     : "wrtc_native_heap_snapshot";
        member = 'h';
    } else {
        return 0;
    }
    owner_id = expression_id(emitter, owner);
    if (owner_id == (size_t)-1 || fputs("{PyObject*wo=", file) < 0 ||
        function_prefix(file, emitter, "wae", owner_id) < 0 ||
        fprintf(file, "(f,&%s%s);NSO*wn;if(!wo)return -1;wn=*np%zu_%zu(wo);"
                      "Py_DECREF(wo);if(!wn){PyErr_SetString(PyExc_AttributeError,",
                runtime_root, owner_suffix, proof->class_index,
                proof->field_index) < 0 ||
        quote(file, field->name) < 0 ||
        fputs(");return -1;}", file) < 0)
        return -1;
    if (field->storage_kind == WRTC_NATIVE_FIELD_SCALAR) {
        const char *tag = operation->result_representation ==
                                  WRTC_NATIVE_REPR_DOUBLE
                              ? "WRTC_SCALAR_DOUBLE"
                              : operation->result_representation ==
                                        WRTC_NATIVE_REPR_BOOL
                                    ? "WRTC_SCALAR_BOOL"
                                    : "WRTC_SCALAR_INT64";
        const char *value = operation->result_representation ==
                                    WRTC_NATIVE_REPR_DOUBLE
                                ? "floating"
                                : operation->result_representation ==
                                          WRTC_NATIVE_REPR_BOOL
                                      ? "boolean"
                                      : "integer";
        if (fprintf(file, "if(wn->u.s.tag==%s)%s=wn->u.s.value.%s;"
                          "else if(wn->u.s.tag==WRTC_SCALAR_BOXED){",
                    tag, target, value) < 0)
            return -1;
        if (operation->result_representation == WRTC_NATIVE_REPR_DOUBLE) {
            if (fprintf(file,
                        "if(!PyFloat_CheckExact(wn->u.s.value.boxed)){"
                        "PyErr_SetString(PyExc_TypeError,\"boxed native "
                        "scalar violated float contract\");return -1;}"
                        "%s=PyFloat_AS_DOUBLE(wn->u.s.value.boxed);",
                        target) < 0)
                return -1;
        } else if (operation->result_representation == WRTC_NATIVE_REPR_BOOL) {
            if (fprintf(file,
                        "if(!PyBool_Check(wn->u.s.value.boxed)){"
                        "PyErr_SetString(PyExc_TypeError,\"boxed native "
                        "scalar violated bool contract\");return -1;}"
                        "%s=(wn->u.s.value.boxed==Py_True);",
                        target) < 0)
                return -1;
        } else if (fprintf(file,
                           "if(!PyLong_CheckExact(wn->u.s.value.boxed)){"
                           "PyErr_SetString(PyExc_TypeError,\"boxed native "
                           "scalar violated sint contract\");return -1;}"
                           "{long long ws_boxed=PyLong_AsLongLong("
                           "wn->u.s.value.boxed);if(ws_boxed==-1&&"
                           "PyErr_Occurred())return -1;%s=(int64_t)ws_boxed;}",
                           target) < 0) {
            return -1;
        }
        if (fprintf(file,
                    "}else{PyErr_Format(PyExc_TypeError,\"native scalar "
                    "representation changed for %%s: expected %%d, got %%d\",") < 0 ||
            quote(file, field->name) < 0 ||
            fprintf(file, ",(int)%s,(int)wn->u.s.tag);return -1;}}",
                    tag) < 0)
            return -1;
    } else if (fprintf(file, "%s=%s(&wn->u.%c);if(%s<0)return -1;}",
                       target, kernel, member, target) < 0) {
        return -1;
    }
    return 1;
}

static int emit_scalar_expression(FILE *file, AotEmitter *emitter,
                                  const WrtcPyExprIR *expression,
                                  const char *runtime_root,
                                  const char *target) {
    WrtcNativeRepresentation representation =
        expression_scalar_representation(emitter, expression);
    size_t id = expression_id(emitter, expression), slot, index;
    int direct;
    char left[48], right[48];
    char left_root[256], right_root[256];
    if (!scalar_representation(representation)) return 0;
    direct = emit_direct_scalar_statement(file, emitter, expression,
                                          runtime_root, target);
    if (direct != 0) return direct;
    if (typed_heap_key_expression(emitter, expression) != NULL) {
        const WrtcNativeFieldIR *field =
            typed_heap_key_expression(emitter, expression);
        size_t root_id = expression_id(emitter, &expression->children[0]);
        if (root_id == (size_t)-1 ||
            fputs("{PyObject*wr=", file) < 0 ||
            function_prefix(file, emitter, "wae", root_id) < 0 ||
            fprintf(file,
                    "(f,&%s.children[0]),*wk;if(!wr)return -1;"
                    "if(!%s.cached_attribute_name){Py_DECREF(wr);"
                    "PyErr_SetString(PyExc_SystemError,"
                    "\"heap-key attribute cache is uninitialized\");"
                    "return -1;}wk=PyObject_GetAttr(wr,"
                    "%s.cached_attribute_name);Py_DECREF(wr);if(!wk)"
                    "return -1;",
                    runtime_root, runtime_root, runtime_root) < 0)
            return -1;
        if (strcmp(field->heap_key_type, "float") == 0) {
            if (fprintf(file,
                        "if(!PyFloat_CheckExact(wk)){Py_DECREF(wk);"
                        "PyErr_SetString(PyExc_TypeError,"
                        "\"native heap key violated float contract\");"
                        "return -1;}%s=PyFloat_AS_DOUBLE(wk);",
                        target) < 0)
                return -1;
        } else if (strcmp(field->heap_key_type, "bool") == 0) {
            if (fprintf(file,
                        "if(!PyBool_Check(wk)){Py_DECREF(wk);PyErr_SetString("
                        "PyExc_TypeError,\"native heap key violated bool "
                        "contract\");return -1;}%s=(wk==Py_True);",
                        target) < 0)
                return -1;
        } else if (fprintf(file,
                           "if(!PyLong_CheckExact(wk)){Py_DECREF(wk);"
                           "PyErr_SetString(PyExc_TypeError,"
                           "\"native heap key violated int contract\");"
                           "return -1;}{long long wv=PyLong_AsLongLong(wk);"
                           "if(wv==-1&&PyErr_Occurred()){Py_DECREF(wk);"
                           "return -1;}%s=(int64_t)wv;}",
                           target) < 0) {
            return -1;
        }
        return fputs("Py_DECREF(wk);}", file) < 0 ? -1 : 1;
    }
    switch (expression->kind) {
        case WRTC_PY_EXPR_NAME:
            slot = slot_index(emitter, expression->operation);
            if (slot == (size_t)-1 ||
                !scalar_representation(emitter->slot_representations[slot]))
                return 0;
            return fprintf(
                       file,
                       "if((f->scalar_mask&(UINT64_C(1)<<%zu))==0u){"
                       "PyErr_SetString(PyExc_UnboundLocalError,"
                       "\"uninitialized scalar local\");return -1;}%s=%s[%zu];",
                       slot, target,
                       representation == WRTC_NATIVE_REPR_DOUBLE
                           ? "f->scalar_d" : "f->scalar_i",
                       slot) < 0 ? -1 : 1;
        case WRTC_PY_EXPR_CONSTANT:
            if (representation == WRTC_NATIVE_REPR_DOUBLE) {
                char *end = NULL;
                double value = strtod(expression->text, &end);
                return fprintf(file, "%s=%a;", target, value) < 0 ? -1 : 1;
            }
            if (representation == WRTC_NATIVE_REPR_BOOL)
                return fprintf(file, "%s=%d;", target,
                               strcmp(expression->text, "True") == 0) < 0
                           ? -1 : 1;
            {
                char *end = NULL;
                long long value = strtoll(expression->text, &end, 0);
                return fprintf(file, "%s=INT64_C(%lld);", target,
                               value) < 0 ? -1 : 1;
            }
        case WRTC_PY_EXPR_CALL: {
            const WrtcNativeCallEdgeIR *edge = call_edge(emitter, expression);
            if (edge == NULL || !edge->result_contract_proven ||
                id == (size_t)-1)
                return 0;
            if (edge->call_abi == WRTC_CALL_ABI_MONOTONIC_CLOCK &&
                expression->child_count == 1u &&
                expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
                expression->children[0].child_count == 1u) {
                const WrtcPyExprIR *receiver =
                    &expression->children[0].children[0];
                const size_t receiver_id = expression_id(emitter, receiver);
                const size_t receiver_slot =
                    receiver->kind == WRTC_PY_EXPR_NAME
                        ? slot_index(emitter, receiver->operation)
                        : (size_t)-1;
                if (receiver_id == (size_t)-1 ||
                    fputs("{PyObject*ws_receiver=NULL,*ws_call=NULL,**ws_dict;"
                          "int ws_receiver_owned=0,ws_override=0;",
                          file) < 0)
                    return -1;
                if (receiver_slot != (size_t)-1 &&
                    !scalar_representation(
                        emitter->slot_representations[receiver_slot])) {
                    if (fprintf(file,
                                "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                "==0u){PyErr_SetString(PyExc_UnboundLocalError,"
                                "\"uninitialized pinned-call receiver\");"
                                "return -1;}ws_receiver=f->values[%zu];",
                                receiver_slot, receiver_slot) < 0)
                        return -1;
                } else if (fputs("ws_receiver=", file) < 0 ||
                           function_prefix(file, emitter, "wae",
                                           receiver_id) < 0 ||
                           fputs("(f,&", file) < 0 ||
                           fprintf(file, "%s.children[0].children[0]);"
                                         "if(!ws_receiver)return -1;"
                                         "ws_receiver_owned=1;",
                                   runtime_root) < 0) {
                    return -1;
                }
                if (fprintf(
                        file,
                        "if(!%s.children[0].cached_attribute_name){"
                        "if(ws_receiver_owned)Py_DECREF(ws_receiver);"
                        "PyErr_SetString(PyExc_SystemError,\"pinned-call "
                        "attribute cache is uninitialized\");return -1;}"
                        "ws_dict=_PyObject_GetDictPtr(ws_receiver);"
                        "if(ws_dict&&*ws_dict){PyObject*ws_entry="
                        "PyDict_GetItemWithError(*ws_dict,%s.children[0]."
                        "cached_attribute_name);ws_override=ws_entry!=NULL;"
                        "if(!ws_entry&&PyErr_Occurred()){"
                        "if(ws_receiver_owned)Py_DECREF(ws_receiver);"
                        "return -1;}}if(ws_receiver_owned)"
                        "Py_DECREF(ws_receiver);if(ws_override){ws_call=",
                        runtime_root, runtime_root) < 0 ||
                    function_prefix(file, emitter, "wae", id) < 0 ||
                    fprintf(file,
                            "(f,&%s);if(!ws_call)return -1;"
                            "if(!PyFloat_CheckExact(ws_call)){Py_DECREF("
                            "ws_call);PyErr_SetString(PyExc_TypeError,"
                            "\"external call violated float return "
                            "contract\");return -1;}%s="
                            "PyFloat_AS_DOUBLE(ws_call);Py_DECREF(ws_call);"
                            "}else{PyTime_t ws_time;if(PyTime_Monotonic("
                            "&ws_time)<0)return -1;%s="
                            "PyTime_AsSecondsDouble(ws_time);}}",
                            runtime_root, target, target) < 0)
                    return -1;
                return 1;
            }
            if (edge->call_abi == WRTC_CALL_ABI_FLOAT_ULP) {
                char argument[48], argument_root[256];
                int emitted;
                if (expression->positional_count != 1u ||
                    expression->keyword_count != 0u ||
                    expression->child_count != 2u ||
                    expression_scalar_representation(
                        emitter, &expression->children[1]) !=
                        WRTC_NATIVE_REPR_DOUBLE)
                    return 0;
                (void)snprintf(argument, sizeof argument, "ws_ulp_%zu", id);
                (void)snprintf(argument_root, sizeof argument_root,
                               "%s.children[1]", runtime_root);
                if (fprintf(file, "{double %s;", argument) < 0)
                    return -1;
                emitted = emit_scalar_expression(
                    file, emitter, &expression->children[1], argument_root,
                    argument);
                if (emitted <= 0) return emitted;
                return fprintf(
                           file,
                           "if(isnan(%s))%s=%s;else{double ws_abs=fabs(%s);"
                           "if(isinf(ws_abs))%s=ws_abs;else if(ws_abs==0.0)"
                           "%s=nextafter(0.0,1.0);else{double ws_next="
                           "nextafter(ws_abs,INFINITY);%s=isinf(ws_next)?"
                           "ws_abs-nextafter(ws_abs,-INFINITY):"
                           "ws_next-ws_abs;}}}",
                           argument, target, argument, argument, target,
                           target, target) < 0
                           ? -1
                           : 1;
            }
            if (edge->call_abi == WRTC_CALL_ABI_FLOAT_MIN ||
                edge->call_abi == WRTC_CALL_ABI_FLOAT_MAX) {
                char first[48], second[48];
                char first_root[256], second_root[256];
                int emitted;
                if (expression->positional_count != 2u ||
                    expression->keyword_count != 0u ||
                    expression->child_count != 3u ||
                    expression_scalar_representation(
                        emitter, &expression->children[1]) !=
                        WRTC_NATIVE_REPR_DOUBLE ||
                    expression_scalar_representation(
                        emitter, &expression->children[2]) !=
                        WRTC_NATIVE_REPR_DOUBLE)
                    return 0;
                (void)snprintf(first, sizeof first, "ws_first_%zu", id);
                (void)snprintf(second, sizeof second, "ws_second_%zu", id);
                (void)snprintf(first_root, sizeof first_root,
                               "%s.children[1]", runtime_root);
                (void)snprintf(second_root, sizeof second_root,
                               "%s.children[2]", runtime_root);
                if (fprintf(file, "{double %s,%s;", first, second) < 0)
                    return -1;
                emitted = emit_scalar_expression(
                    file, emitter, &expression->children[1], first_root,
                    first);
                if (emitted <= 0) return emitted;
                emitted = emit_scalar_expression(
                    file, emitter, &expression->children[2], second_root,
                    second);
                if (emitted <= 0) return emitted;
                return fprintf(
                           file, "%s=%s%s%s?%s:%s;}", target, second,
                           edge->call_abi == WRTC_CALL_ABI_FLOAT_MAX ? ">" : "<",
                           first, second, first) < 0
                           ? -1
                           : 1;
            }
            if (fputs("{PyObject*ws_call=", file) < 0 ||
                function_prefix(file, emitter, "wae", id) < 0 ||
                fprintf(file, "(f,&%s);if(!ws_call)return -1;", runtime_root) < 0)
                return -1;
            if (edge->result_representation == WRTC_CALL_RESULT_DOUBLE) {
                if (fprintf(file,
                            "if(!PyFloat_CheckExact(ws_call)){Py_DECREF("
                            "ws_call);PyErr_SetString(PyExc_TypeError,"
                            "\"external call violated float return contract\");"
                            "return -1;}%s=PyFloat_AS_DOUBLE(ws_call);",
                            target) < 0)
                    return -1;
            } else if (edge->result_representation == WRTC_CALL_RESULT_BOOL) {
                if (fprintf(file,
                            "if(!PyBool_Check(ws_call)){Py_DECREF(ws_call);"
                            "PyErr_SetString(PyExc_TypeError,\"external call "
                            "violated bool return contract\");return -1;}"
                            "%s=(ws_call==Py_True);",
                            target) < 0)
                    return -1;
            } else if (edge->result_representation ==
                       WRTC_CALL_RESULT_INT64) {
                if (fprintf(file,
                            "if(!PyLong_CheckExact(ws_call)){Py_DECREF("
                            "ws_call);PyErr_SetString(PyExc_TypeError,"
                            "\"external call violated sint return contract\");"
                            "return -1;}{long long ws_value="
                            "PyLong_AsLongLong(ws_call);if(ws_value==-1&&"
                            "PyErr_Occurred()){Py_DECREF(ws_call);return -1;}"
                            "%s=(int64_t)ws_value;}",
                            target) < 0)
                    return -1;
            } else {
                return 0;
            }
            return fputs("Py_DECREF(ws_call);}", file) < 0 ? -1 : 1;
        }
        case WRTC_PY_EXPR_UNARY:
            if (id == (size_t)-1) return 0;
            (void)snprintf(left, sizeof left, "ws_l_%zu", id);
            if (fprintf(file, "{%s %s;",
                        expression_scalar_representation(
                            emitter, &expression->children[0]) ==
                                WRTC_NATIVE_REPR_DOUBLE ? "double" : "int64_t",
                        left) < 0)
                return -1;
            (void)snprintf(left_root, sizeof left_root, "%s.children[0]",
                           runtime_root);
            direct = emit_scalar_expression(file, emitter,
                                             &expression->children[0],
                                             left_root, left);
            if (direct <= 0) return direct;
            if (strcmp(expression->operation, "Not") == 0) {
                if (fprintf(file, "%s=!%s;}", target, left) < 0) return -1;
            } else if (strcmp(expression->operation, "USub") == 0) {
                if (fprintf(file, "%s=-%s;}", target, left) < 0) return -1;
            } else if (fprintf(file, "%s=%s;}", target, left) < 0) {
                return -1;
            }
            return 1;
        case WRTC_PY_EXPR_BINARY: {
            WrtcNativeRepresentation left_rep =
                expression_scalar_representation(
                    emitter, &expression->children[0]);
            WrtcNativeRepresentation right_rep =
                expression_scalar_representation(
                    emitter, &expression->children[1]);
            const char *operator_text = NULL;
            if (id == (size_t)-1) return 0;
            (void)snprintf(left, sizeof left, "ws_l_%zu", id);
            (void)snprintf(right, sizeof right, "ws_r_%zu", id);
            (void)snprintf(left_root, sizeof left_root, "%s.children[0]",
                           runtime_root);
            (void)snprintf(right_root, sizeof right_root, "%s.children[1]",
                           runtime_root);
            if (fprintf(file, "{%s %s;%s %s;",
                        left_rep == WRTC_NATIVE_REPR_DOUBLE
                            ? "double" : "int64_t", left,
                        right_rep == WRTC_NATIVE_REPR_DOUBLE
                            ? "double" : "int64_t", right) < 0)
                return -1;
            direct = emit_scalar_expression(file, emitter,
                                             &expression->children[0],
                                             left_root, left);
            if (direct <= 0) return direct;
            direct = emit_scalar_expression(file, emitter,
                                             &expression->children[1],
                                             right_root, right);
            if (direct <= 0) return direct;
            switch (expression->binary_operation) {
                case WRTC_PY_BINARY_ADD: operator_text = "+"; break;
                case WRTC_PY_BINARY_SUBTRACT: operator_text = "-"; break;
                case WRTC_PY_BINARY_MULTIPLY: operator_text = "*"; break;
                case WRTC_PY_BINARY_TRUE_DIVIDE: operator_text = "/"; break;
                default: return 0;
            }
            if (expression->binary_operation == WRTC_PY_BINARY_TRUE_DIVIDE &&
                fprintf(file,
                        "if(%s==0){PyErr_SetString(PyExc_ZeroDivisionError,"
                        "\"%s\");return -1;}", right,
                        left_rep == WRTC_NATIVE_REPR_DOUBLE ||
                                right_rep == WRTC_NATIVE_REPR_DOUBLE
                            ? "float division by zero" : "division by zero") < 0)
                return -1;
            if (fprintf(file, "%s=(double)%s%s(double)%s;}", target, left,
                        operator_text, right) < 0)
                return -1;
            return 1;
        }
        case WRTC_PY_EXPR_COMPARE:
            if (id == (size_t)-1) return 0;
            if (fprintf(file, "{%s=1;", target) < 0) return -1;
            for (index = 0u; index < expression->operation_count; index++) {
                WrtcNativeRepresentation left_rep =
                    expression_scalar_representation(
                        emitter, &expression->children[index]);
                WrtcNativeRepresentation right_rep =
                    expression_scalar_representation(
                        emitter, &expression->children[index + 1u]);
                const char *operator_text = NULL;
                (void)snprintf(left, sizeof left, "ws_l_%zu_%zu", id, index);
                (void)snprintf(right, sizeof right, "ws_r_%zu_%zu", id, index);
                (void)snprintf(left_root, sizeof left_root,
                               "%s.children[%zu]", runtime_root, index);
                (void)snprintf(right_root, sizeof right_root,
                               "%s.children[%zu]", runtime_root, index + 1u);
                if (fprintf(file, "%s %s;%s %s;",
                            left_rep == WRTC_NATIVE_REPR_DOUBLE
                                ? "double" : "int64_t", left,
                            right_rep == WRTC_NATIVE_REPR_DOUBLE
                                ? "double" : "int64_t", right) < 0)
                    return -1;
                direct = emit_scalar_expression(
                    file, emitter, &expression->children[index],
                    left_root, left);
                if (direct <= 0) return direct;
                direct = emit_scalar_expression(
                    file, emitter, &expression->children[index + 1u],
                    right_root, right);
                if (direct <= 0) return direct;
                if (strcmp(expression->operations[index], "Eq") == 0)
                    operator_text = "==";
                else if (strcmp(expression->operations[index], "NotEq") == 0)
                    operator_text = "!=";
                else if (strcmp(expression->operations[index], "Lt") == 0)
                    operator_text = "<";
                else if (strcmp(expression->operations[index], "LtE") == 0)
                    operator_text = "<=";
                else if (strcmp(expression->operations[index], "Gt") == 0)
                    operator_text = ">";
                else operator_text = ">=";
                if (fprintf(file, "if(!(%s%s%s))%s=0;", left,
                            operator_text, right, target) < 0)
                    return -1;
            }
            return fputs("}", file) < 0 ? -1 : 1;
        default:
            return 0;
    }
}

static int emit_expression(AotEmitter *emitter,
                           const WrtcPyExprIR *expression, size_t *result_id) {
    FILE *file = emitter->file;
    size_t *children = NULL, id, index, slot;
    const WrtcNativeOperationIR *native_operation;
    const WrtcNativeCallEdgeIR *native_call;
    if (emit_expression_children(emitter, expression, &children) < 0)
        return -1;
    id = emitter->expression_id++;
    if (emitter->expression_count == WRTC_AOT_EXPRESSION_LIMIT) {
        free(children);
        return -1;
    }
    emitter->expressions[emitter->expression_count] = expression;
    emitter->expression_ids[emitter->expression_count++] = id;
    if (fputs(expression->kind == WRTC_PY_EXPR_NAME
                  ? "static inline PyObject*WRTC_AOT_UNUSED "
                  : "static PyObject*WRTC_AOT_UNUSED ", file) < 0 ||
        function_prefix(file, emitter, "wae", id) < 0 ||
        fputs("(WrtcRegionFrame*f,const WrtcPyExprIR*e){(void)f;(void)e;",
              file) < 0) {
        free(children);
        return -1;
    }
    native_operation = direct_operation(emitter, expression);
    if (native_operation != NULL) {
        const WrtcNativeFieldOperationProof *proof =
            &emitter->operations->fields[native_operation->field_proof_index];
        const WrtcPyExprIR *owner_expression = NULL;
        const char *owner_runtime = NULL;
        size_t owner_id = (size_t)-1;
        int field_method = 0, heap_function = 0;
        if ((native_operation->kind == WRTC_NATIVE_OP_TRUTH ||
             native_operation->kind == WRTC_NATIVE_OP_SCALAR_READ) &&
            expression->kind == WRTC_PY_EXPR_ATTRIBUTE &&
            expression->child_count == 1u) {
            owner_expression = &expression->children[0];
            owner_runtime = "&e->children[0]";
        } else if (native_operation->kind == WRTC_NATIVE_OP_LENGTH &&
                   expression->child_count >= 2u &&
                   expression->children[1].kind == WRTC_PY_EXPR_ATTRIBUTE) {
            owner_expression = &expression->children[1].children[0];
            owner_runtime = "&e->children[1].children[0]";
        } else if (native_operation->kind == WRTC_NATIVE_OP_ROOT_READ &&
                   expression->child_count >= 1u &&
                   expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE) {
            owner_expression = &expression->children[0].children[0];
            owner_runtime = "&e->children[0].children[0]";
        } else if (native_operation->kind ==
                       WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED &&
                   expression->child_count >= 2u &&
                   expression->children[1].kind == WRTC_PY_EXPR_ATTRIBUTE) {
            owner_expression = &expression->children[1].children[0];
            owner_runtime = "&e->children[1].children[0]";
        } else if ((native_operation->kind == WRTC_NATIVE_OP_HEAPIFY ||
                    native_operation->kind == WRTC_NATIVE_OP_HEAP_PUSH ||
                    native_operation->kind == WRTC_NATIVE_OP_HEAP_POP) &&
                   expression->child_count >= 2u &&
                   expression->children[1].kind == WRTC_PY_EXPR_ATTRIBUTE) {
            owner_expression = &expression->children[1].children[0];
            owner_runtime = "&e->children[1].children[0]";
            heap_function = 1;
        } else if (expression->kind == WRTC_PY_EXPR_CALL &&
                   expression->child_count >= 1u &&
                   expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
                   expression->children[0].child_count == 1u &&
                   expression->children[0].children[0].kind ==
                       WRTC_PY_EXPR_ATTRIBUTE &&
                   expression->children[0].children[0].child_count == 1u) {
            owner_expression =
                &expression->children[0].children[0].children[0];
            owner_runtime = "&e->children[0].children[0].children[0]";
            field_method = 1;
        }
        owner_id = expression_id(emitter, owner_expression);
        if (owner_id == (size_t)-1 ||
            fputs("PyObject*o=", file) < 0 ||
            function_prefix(file, emitter, "wae", owner_id) < 0 ||
            fprintf(file, "(f,%s),*v=NULL,*q=NULL;NSO**p;NSO*n;"
                          "(void)v;(void)q;if(!o)return NULL;p=np",
                    owner_runtime) < 0 ||
            fprintf(file, "%zu_%zu(o);n=*p;Py_DECREF(o);"
                          "if(!n){PyErr_SetString(PyExc_AttributeError,",
                    proof->class_index, proof->field_index) < 0 ||
            quote(file,
                      emitter->program->classes[proof->class_index]
                          .fields[proof->field_index].name) < 0 ||
            fputs(");return NULL;}", file) < 0) {
            free(children);
            return -1;
        }
        switch (native_operation->kind) {
            case WRTC_NATIVE_OP_LENGTH:
                if (fprintf(file, "{Py_ssize_t z=%s(&n->u.%c);return z<0?"
                                  "NULL:PyLong_FromSsize_t(z);}}",
                            emitter->program->classes[proof->class_index]
                                        .fields[proof->field_index].storage_kind ==
                                    WRTC_NATIVE_FIELD_FIFO
                                ? "wrtc_native_fifo_snapshot"
                                : "wrtc_native_heap_snapshot",
                            emitter->program->classes[proof->class_index]
                                        .fields[proof->field_index].storage_kind ==
                                    WRTC_NATIVE_FIELD_FIFO ? 'f' : 'h') < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_TRUTH:
                if (fprintf(file, "{int z=%s(&n->u.%c);return z<0?NULL:"
                                  "PyBool_FromLong(z);}}",
                            emitter->program->classes[proof->class_index]
                                        .fields[proof->field_index].storage_kind ==
                                    WRTC_NATIVE_FIELD_FIFO
                                ? "wrtc_native_fifo_truth"
                                : "wrtc_native_heap_truth",
                            emitter->program->classes[proof->class_index]
                                        .fields[proof->field_index].storage_kind ==
                                    WRTC_NATIVE_FIELD_FIFO ? 'f' : 'h') < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_ROOT_READ:
                if (fputs("v=wrtc_native_heap_root(&n->u.h);return v?"
                          "Py_NewRef(v):NULL;}", file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_SCALAR_READ:
                if (fputs("return wrtc_native_scalar_get(&n->u.s,", file) < 0 ||
                    quote(file,
                          emitter->program->classes[proof->class_index]
                              .fields[proof->field_index].name) < 0 ||
                    fputs(");}", file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_FIFO_APPEND:
            case WRTC_NATIVE_OP_HEAP_PUSH:
            case WRTC_NATIVE_OP_ATOMIC_STORE:
            case WRTC_NATIVE_OP_MPSC_PUT_NOWAIT: {
                const size_t value_child = heap_function ? 2u : 1u;
                if (value_child >= expression->child_count ||
                    fputs("v=", file) < 0 ||
                    function_prefix(file, emitter, "wae",
                                    children[value_child]) < 0 ||
                    fprintf(file, "(f,&e->children[%zu]);if(!v)return NULL;",
                            value_child) < 0) goto native_fail;
                if (native_operation->kind == WRTC_NATIVE_OP_FIFO_APPEND) {
                    if (fputs("if(wrtc_native_fifo_append(&n->u.f,v)<0){"
                              "Py_DECREF(v);return NULL;}Py_DECREF(v);"
                              "return Py_NewRef(Py_None);}", file) < 0)
                        goto native_fail;
                } else if (native_operation->kind == WRTC_NATIVE_OP_HEAP_PUSH) {
                    if (fputs("if(wrtc_native_heap_push(&n->u.h,v)<0){"
                              "Py_DECREF(v);return NULL;}Py_DECREF(v);"
                              "return Py_NewRef(Py_None);}", file) < 0)
                        goto native_fail;
                } else if (native_operation->kind == WRTC_NATIVE_OP_ATOMIC_STORE) {
                    if (fputs("{uint_least32_t z;if(n32(v,&z)<0){Py_DECREF(v);"
                              "return NULL;}Py_DECREF(v);if("
                              "wrtc_native_atomic_uint32_set(&n->u.a,z)<0)"
                              "return NULL;return Py_NewRef(Py_None);}}", file) < 0)
                        goto native_fail;
                } else if (fputs("{int notify=0;WrtcNativeMpscStatus z;"
                                 "Py_INCREF(v);z=wrtc_native_mpsc_publish("
                                 "&n->u.m,v,&notify);Py_DECREF(v);if(z=="
                                 "WRTC_MPSC_OK)return Py_NewRef(Py_None);"
                                 "Py_DECREF(v);q=wafg(f,\"queue\");if(!q)"
                                 "return NULL;v=PyObject_GetAttrString(q,z=="
                                 "WRTC_MPSC_FULL?\"Full\":\"Empty\");"
                                 "Py_DECREF(q);if(!v)return NULL;PyErr_SetNone(v);"
                                 "Py_DECREF(v);return NULL;}}", file) < 0)
                    goto native_fail;
                break;
            }
            case WRTC_NATIVE_OP_FIFO_POPLEFT:
                if (fputs("return wrtc_native_fifo_popleft(&n->u.f);}", file) < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_HEAPIFY:
                if (fputs("if(wrtc_native_heap_heapify(&n->u.h)<0)return NULL;"
                          "return Py_NewRef(Py_None);}", file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_HEAP_POP:
                if (fputs("return wrtc_native_heap_pop(&n->u.h);}", file) < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_HEAP_COMPACT_CANCELLED:
                if (fputs("{Py_ssize_t z=wrtc_native_heap_compact_cancelled("
                          "&n->u.h);return z<0?NULL:PyLong_FromSsize_t(z);}}",
                          file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_ATOMIC_LOAD:
                if (fputs("{uint_least32_t z;if(wrtc_native_atomic_uint32_load("
                          "&n->u.a,&z)<0)return NULL;return "
                          "PyLong_FromUnsignedLong((unsigned long)z);}}", file) < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_ATOMIC_COMPARE_EXCHANGE:
                if (expression->child_count < 3u ||
                    fputs("v=", file) < 0 ||
                    function_prefix(file, emitter, "wae", children[1]) < 0 ||
                    fputs("(f,&e->children[1]);if(!v)return NULL;q=", file) < 0 ||
                    function_prefix(file, emitter, "wae", children[2]) < 0 ||
                    fputs("(f,&e->children[2]);if(!q){Py_DECREF(v);return NULL;}"
                          "{uint_least32_t a,b,pv;int changed;PyObject*r;"
                          "if(n32(v,&a)<0||n32(q,&b)<0){Py_DECREF(q);"
                          "Py_DECREF(v);return NULL;}Py_DECREF(q);Py_DECREF(v);"
                          "if(wrtc_native_atomic_uint32_compare_exchange("
                          "&n->u.a,a,b,&pv,&changed)<0)return NULL;v="
                          "PyLong_FromUnsignedLong((unsigned long)pv);q="
                          "PyBool_FromLong(changed);if(!v||!q){Py_XDECREF(v);"
                          "Py_XDECREF(q);return NULL;}r=PyTuple_Pack(2,v,q);"
                          "Py_DECREF(q);Py_DECREF(v);return r;}}", file) < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_MPSC_QSIZE:
                if (fputs("return PyLong_FromSize_t(wrtc_native_mpsc_snapshot("
                          "&n->u.m));}", file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_MPSC_EMPTY:
                if (fputs("return PyBool_FromLong(wrtc_native_mpsc_snapshot("
                          "&n->u.m)==0u);}", file) < 0) goto native_fail;
                break;
            case WRTC_NATIVE_OP_MPSC_GET_NOWAIT:
                if (fputs("{void*x=NULL;if(wrtc_native_mpsc_try_pop(&n->u.m,"
                          "&x)==WRTC_MPSC_OK)return (PyObject*)x;q=wafg(f,"
                          "\"queue\");if(!q)return NULL;v=PyObject_GetAttrString("
                          "q,\"Empty\");Py_DECREF(q);if(!v)return NULL;"
                          "PyErr_SetNone(v);Py_DECREF(v);return NULL;}}", file) < 0)
                    goto native_fail;
                break;
            case WRTC_NATIVE_OP_MPSC_CLOSE:
                if (fputs("wrtc_native_mpsc_close(&n->u.m);return "
                          "Py_NewRef(Py_None);}", file) < 0) goto native_fail;
                break;
            default:
                /* Eligibility rejects operations not yet expressible here. */
                goto native_fail;
        }
        free(children);
        *result_id = id;
        return 0;
native_fail:
        (void)field_method;
        free(children);
        return -1;
    }
    native_call = direct_call(emitter, expression);
    if (native_call != NULL && expression->child_count != 0u &&
        expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
        expression->children[0].child_count == 1u) {
        const size_t argc = expression->positional_count +
                            expression->keyword_count;
        const int unchecked_self =
            native_call->target_class == emitter->class_index &&
            native_call->target != NULL &&
            strncmp(native_call->target, "self.", 5u) == 0;
        size_t receiver_id = expression_id(
            emitter, &expression->children[0].children[0]);
        const WrtcPyExprIR *receiver_expression =
            &expression->children[0].children[0];
        size_t receiver_slot = receiver_expression->kind == WRTC_PY_EXPR_NAME
                                   ? slot_index(emitter,
                                                receiver_expression->operation)
                                   : (size_t)-1;
        if (receiver_id == (size_t)-1 ||
            fprintf(file,
                    "PyObject*r=NULL,*recv=NULL,*a[%zu]={0};"
                    "unsigned char own_a[%zu]={0};int recv_owned=0;size_t i;",
                    argc == 0u ? 1u : argc,
                    argc == 0u ? 1u : argc) < 0)
            goto fail;
        if (receiver_slot != (size_t)-1 &&
            !scalar_representation(
                emitter->slot_representations[receiver_slot])) {
            if (fprintf(file,
                        "if((f->initialized_mask&(UINT64_C(1)<<%zu))==0u){"
                        "PyErr_SetString(PyExc_UnboundLocalError,"
                        "\"uninitialized call receiver\");return NULL;}"
                        "recv=f->values[%zu];",
                        receiver_slot, receiver_slot) < 0)
                goto fail;
        } else if (fputs("recv=", file) < 0 ||
                   function_prefix(file, emitter, "wae", receiver_id) < 0 ||
                   fputs("(f,&e->children[0].children[0]);if(!recv)return NULL;"
                         "recv_owned=1;", file) < 0) {
            goto fail;
        }
        for (index = 0u; index < argc; index++) {
            const WrtcPyExprIR *argument = &expression->children[index + 1u];
            size_t argument_slot = argument->kind == WRTC_PY_EXPR_NAME
                                       ? slot_index(emitter,
                                                    argument->operation)
                                       : (size_t)-1;
            if (argument_slot != (size_t)-1 &&
                !scalar_representation(
                    emitter->slot_representations[argument_slot])) {
                if (fprintf(file,
                            "if((f->initialized_mask&(UINT64_C(1)<<%zu))==0u){"
                            "PyErr_SetString(PyExc_UnboundLocalError,"
                            "\"uninitialized call argument\");goto done;}"
                            "a[%zu]=f->values[%zu];",
                            argument_slot, index, argument_slot) < 0)
                    goto fail;
            } else if (fprintf(file, "a[%zu]=", index) < 0 ||
                       function_prefix(file, emitter, "wae",
                                       children[index + 1u]) < 0 ||
                       fprintf(file,
                               "(f,&e->children[%zu]);if(!a[%zu])goto done;"
                               "own_a[%zu]=1u;",
                               index + 1u, index, index) < 0) {
                goto fail;
            }
        }
        if ((unchecked_self
                 ? fprintf(file,
                           "if(wu%zu_%zu(recv,a,%zu,e->cached_keyword_names,"
                           "&r)<0)r=NULL;",
                           native_call->target_class,
                           native_call->target_region,
                           expression->positional_count)
                 : fprintf(file,
                           "r=wi%zu_%zu(recv,a,%zu,e->cached_keyword_names);",
                           native_call->target_class,
                           native_call->target_region,
                           expression->positional_count)) < 0 ||
            (argc != 0u && fputs("done:", file) < 0) ||
            fprintf(file, "for(i=0u;i<%zu;i++)if(own_a[i])Py_DECREF(a[i]);"
                          "if(recv_owned)Py_DECREF(recv);"
                          "return r;}", argc) < 0)
            goto fail;
        free(children);
        *result_id = id;
        return 0;
    }
    if ((emitter->region->capabilities & WRTC_REGION_HANDLE_RUN) != 0u &&
        expression->kind == WRTC_PY_EXPR_CALL &&
        expression->positional_count == 0u &&
        expression->keyword_count == 0u && expression->child_count == 1u &&
        expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
        expression->children[0].operation != NULL &&
        strcmp(expression->children[0].operation, "_run") == 0 &&
        expression->children[0].child_count == 1u) {
        size_t handle_id = expression_id(
            emitter, &expression->children[0].children[0]);
        size_t loop_slot = slot_index(emitter, "loop");
        if (handle_id == (size_t)-1 || loop_slot == (size_t)-1 ||
            fprintf(file, "PyObject*l=wafl(f,%zu,\"loop\"),*h,*r;"
                          "if(!l)return NULL;h=", loop_slot) < 0 ||
            function_prefix(file, emitter, "wae", handle_id) < 0 ||
            fputs("(f,&e->children[0].children[0]);if(!h){Py_DECREF(l);"
                  "return NULL;}r=whr(l,h);Py_DECREF(h);Py_DECREF(l);"
                  "return r;}", file) < 0)
            goto fail;
        free(children);
        *result_id = id;
        return 0;
    }
    if (emitter->has_hooks &&
        (fputs("if(f->hooks&&f->hooks->evaluate){WrtcBoxedFrame b={0};"
               "PyObject*r;int h=0;b.globals=f->globals;b.external_frame=f;"
               "b.external_evaluate=", file) < 0 ||
         function_prefix(file, emitter, "waq", 0u) < 0 ||
         fputs(";b.external_local=", file) < 0 ||
         function_prefix(file, emitter, "wal", 0u) < 0 ||
         fputs(";r=f->hooks->evaluate(f->hooks->context,e,&b,&h);"
               "if(h||(r==NULL&&PyErr_Occurred()))return r;}", file) < 0)) {
        free(children);
        return -1;
    }
    switch (expression->kind) {
        case WRTC_PY_EXPR_NAME:
            slot = slot_index(emitter, expression->operation);
            if (slot != (size_t)-1) {
                const WrtcNativeRepresentation representation =
                    emitter->slot_representations[slot];
                if (scalar_representation(representation)) {
                    if (fprintf(file, "if((f->scalar_mask&(UINT64_C(1)<<%zu))"
                                      "==0u){PyErr_Format(PyExc_UnboundLocalError,"
                                      "\"cannot access uninitialized scalar local\");"
                                      "return NULL;}", slot) < 0)
                        goto fail;
                    if (representation == WRTC_NATIVE_REPR_DOUBLE) {
                        if (fprintf(file, "return PyFloat_FromDouble(f->scalar_d[%zu]);}",
                                    slot) < 0) goto fail;
                    } else if (representation == WRTC_NATIVE_REPR_BOOL) {
                        if (fprintf(file, "return PyBool_FromLong((int)f->scalar_i[%zu]);}",
                                    slot) < 0) goto fail;
                    } else if (fprintf(file, "return PyLong_FromLongLong((long long)"
                                             "f->scalar_i[%zu]);}", slot) < 0) {
                        goto fail;
                    }
                } else if (fprintf(file, "return wafl(f,%zu,", slot) < 0 ||
                           quote(file, expression->operation) < 0 ||
                           fputs(");}", file) < 0) goto fail;
            } else if (fputs("return wafg(f,e->operation);}", file) < 0) {
                goto fail;
            }
            break;
        case WRTC_PY_EXPR_ATTRIBUTE:
        {
            const WrtcPyExprIR *owner_expression = &expression->children[0];
            size_t field_class = (size_t)-1, field_index = (size_t)-1;
            const WrtcNativeFieldIR *object_field =
                emitter->direct
                    ? direct_object_field(emitter, expression, &field_class,
                                          &field_index)
                    : NULL;
            size_t owner_slot = owner_expression->kind == WRTC_PY_EXPR_NAME
                                    ? slot_index(emitter,
                                                 owner_expression->operation)
                                    : (size_t)-1;
            if (object_field != NULL && owner_slot != (size_t)-1 &&
                !scalar_representation(
                    emitter->slot_representations[owner_slot])) {
                const size_t manifest = first_region_manifest(
                    emitter->program, field_class);
                if (fprintf(file,
                            "PyObject*o,*r;WrtcSchedulerContext wc;"
                            "if((f->initialized_mask&(UINT64_C(1)<<%zu))==0u){"
                            "PyErr_SetString(PyExc_UnboundLocalError,"
                            "\"uninitialized native field owner\");"
                            "return NULL;}o=f->values[%zu];if(wg(o,%zu,%zu,"
                            "&wc)){H%zu*d=(H%zu*)PyObject_GetTypeData(o,"
                            "dt(o,%zu));if(!d->f%zu){PyErr_SetString("
                            "PyExc_AttributeError,",
                            owner_slot, owner_slot, field_class, manifest,
                            field_class, field_class, field_class,
                            field_index) < 0 ||
                    quote(file, object_field->name) < 0 ||
                    fputs(");return NULL;}return Py_NewRef(d->f", file) < 0 ||
                    fprintf(file,
                            "%zu);}if(!e->cached_attribute_name){"
                            "PyErr_SetString(PyExc_SystemError,"
                            "\"AOT attribute-name cache is uninitialized\");"
                            "return NULL;}r=PyObject_GetAttr(o,"
                            "e->cached_attribute_name);return r;}",
                            field_index) < 0)
                    goto fail;
                break;
            }
            if (owner_slot != (size_t)-1 &&
                !scalar_representation(
                    emitter->slot_representations[owner_slot])) {
                if (fprintf(file,
                            "PyObject*o,*r;if((f->initialized_mask&"
                            "(UINT64_C(1)<<%zu))==0u){PyErr_SetString("
                            "PyExc_UnboundLocalError,"
                            "\"uninitialized attribute owner\");return NULL;}"
                            "if(!e->cached_attribute_name){PyErr_SetString("
                            "PyExc_SystemError,\"AOT attribute-name cache is "
                            "uninitialized\");return NULL;}o=f->values[%zu];"
                            "r=PyObject_GetAttr(o,e->cached_attribute_name);"
                            "return r;}",
                            owner_slot, owner_slot) < 0)
                    goto fail;
            } else if (fputs("PyObject*o=", file) < 0 ||
                       emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                       fputs(",*r;if(!o)return NULL;if(!e->cached_attribute_name){"
                             "Py_DECREF(o);PyErr_SetString(PyExc_SystemError,"
                             "\"AOT attribute-name cache is uninitialized\");"
                             "return NULL;}r=PyObject_GetAttr(o,"
                             "e->cached_attribute_name);Py_DECREF(o);return r;}",
                             file) < 0) {
                goto fail;
            }
            break;
        }
        case WRTC_PY_EXPR_CONSTANT:
            if (fputs("(void)f;if(!e->cached_constant){PyErr_SetString("
                      "PyExc_SystemError,\"AOT constant cache is "
                      "uninitialized\");return NULL;}return "
                      "Py_NewRef(e->cached_constant);}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_CALL: {
            const size_t count = expression->positional_count +
                                 expression->keyword_count;
            if (expression->child_count != 0u &&
                expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
                expression->children[0].child_count == 1u) {
                const WrtcPyExprIR *owner_expression =
                    &expression->children[0].children[0];
                size_t owner_field_class = (size_t)-1;
                size_t owner_field_index = (size_t)-1;
                const WrtcNativeFieldIR *owner_field =
                    emitter->direct
                        ? direct_object_field(
                              emitter, owner_expression,
                              &owner_field_class, &owner_field_index)
                        : NULL;
                size_t owner_id = expression_id(emitter, owner_expression);
                size_t owner_slot = owner_expression->kind == WRTC_PY_EXPR_NAME
                                        ? slot_index(
                                              emitter,
                                              owner_expression->operation)
                                        : (size_t)-1;
                if (owner_id == (size_t)-1 ||
                    fprintf(file,
                            "PyObject*owner=NULL,*a[%zu]={0},*r=NULL;"
                            "unsigned char own_a[%zu]={0};int owner_owned=0;"
                            "size_t i;if(!e->children[0].cached_attribute_name){"
                            "PyErr_SetString(PyExc_SystemError,"
                            "\"AOT attribute-name cache is uninitialized\");"
                            "return NULL;}",
                            count + 1u, count == 0u ? 1u : count) < 0)
                    goto fail;
                if (owner_field != NULL &&
                    owner_expression->children[0].kind == WRTC_PY_EXPR_NAME) {
                    size_t root_slot = slot_index(
                        emitter,
                        owner_expression->children[0].operation);
                    size_t manifest = first_region_manifest(
                        emitter->program, owner_field_class);
                    if (root_slot == (size_t)-1 ||
                        scalar_representation(
                            emitter->slot_representations[root_slot]) ||
                        fprintf(file,
                                "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                "==0u){PyErr_SetString("
                                "PyExc_UnboundLocalError,"
                                "\"uninitialized component owner\");"
                                "return NULL;}{PyObject*root=f->values[%zu];"
                                "WrtcSchedulerContext wc;if(wg(root,%zu,%zu,"
                                "&wc)){H%zu*d=(H%zu*)PyObject_GetTypeData("
                                "root,dt(root,%zu));if(!d->f%zu){"
                                "PyErr_SetString(PyExc_AttributeError,",
                                root_slot, root_slot, owner_field_class,
                                manifest, owner_field_class,
                                owner_field_class, owner_field_class,
                                owner_field_index) < 0 ||
                        quote(file, owner_field->name) < 0 ||
                        fprintf(file,
                                ");return NULL;}owner=d->f%zu;}else{owner=",
                                owner_field_index) < 0 ||
                        function_prefix(file, emitter, "wae", owner_id) < 0 ||
                        fputs("(f,&e->children[0].children[0]);if(!owner)"
                              "return NULL;owner_owned=1;}}a[0]=owner;",
                              file) < 0)
                        goto fail;
                } else if (owner_slot != (size_t)-1 &&
                    !scalar_representation(
                        emitter->slot_representations[owner_slot])) {
                    if (fprintf(file,
                                "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                "==0u){PyErr_SetString("
                                "PyExc_UnboundLocalError,"
                                "\"uninitialized method receiver\");"
                                "return NULL;}owner=f->values[%zu];a[0]=owner;",
                                owner_slot, owner_slot) < 0)
                        goto fail;
                } else if (fputs("owner=", file) < 0 ||
                           function_prefix(file, emitter, "wae", owner_id) < 0 ||
                           fputs("(f,&e->children[0].children[0]);"
                                 "if(!owner)return NULL;owner_owned=1;a[0]=owner;",
                                 file) < 0) {
                    goto fail;
                }
                for (index = 0u; index < count; index++) {
                    const WrtcPyExprIR *argument =
                        &expression->children[index + 1u];
                    size_t argument_slot =
                        argument->kind == WRTC_PY_EXPR_NAME
                            ? slot_index(emitter, argument->operation)
                            : (size_t)-1;
                    if (argument_slot != (size_t)-1 &&
                        !scalar_representation(
                            emitter->slot_representations[argument_slot])) {
                        if (fprintf(file,
                                    "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                    "==0u){PyErr_SetString("
                                    "PyExc_UnboundLocalError,"
                                    "\"uninitialized method argument\");"
                                    "goto done;}a[%zu]=f->values[%zu];",
                                    argument_slot, index + 1u,
                                    argument_slot) < 0)
                            goto fail;
                    } else if (fprintf(file, "a[%zu]=", index + 1u) < 0 ||
                               emit_eval_child(file, emitter,
                                               children[index + 1u],
                                               index + 1u) < 0 ||
                               fprintf(file,
                                       ";if(!a[%zu])goto done;own_a[%zu]=1u;",
                                       index + 1u, index) < 0) {
                        goto fail;
                    }
                }
                if ((emitter->direct &&
                     fputs("wrtc_native_allocation_pause();", file) < 0) ||
                    fprintf(file,
                            "r=PyObject_VectorcallMethod("
                            "e->children[0].cached_attribute_name,a,%zu,"
                            "e->cached_keyword_names);",
                            expression->positional_count + 1u) < 0 ||
                    (emitter->direct &&
                     fputs("wrtc_native_allocation_resume();", file) < 0) ||
                    (count != 0u && fputs("done:", file) < 0) ||
                    fprintf(file,
                            "for(i=0u;i<%zu;i++)if(own_a[i])"
                            "Py_DECREF(a[i+1u]);if(owner_owned)"
                            "Py_DECREF(owner);return r;}",
                            count) < 0)
                    goto fail;
                break;
            }
            if (fputs("PyObject*c=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fprintf(file, ",*a[%zu]={0},*r=NULL;size_t i;", count == 0u ? 1u : count) < 0 ||
                fputs("if(!c)return NULL;", file) < 0)
                goto fail;
            for (index = 0u; index < count; index++)
                if (fprintf(file, "a[%zu]=", index) < 0 ||
                    emit_eval_child(file, emitter, children[index + 1u],
                                    index + 1u) < 0 ||
                    fprintf(file, ";if(!a[%zu])goto done;", index) < 0)
                    goto fail;
            if ((emitter->direct &&
                 fputs("wrtc_native_allocation_pause();", file) < 0) ||
                fprintf(file,
                        "r=PyObject_Vectorcall(c,a,%zu,e->cached_keyword_names);",
                        expression->positional_count) < 0 ||
                (emitter->direct &&
                 fputs("wrtc_native_allocation_resume();", file) < 0) ||
                (count != 0u && fputs("done:", file) < 0) ||
                fprintf(file,
                        "for(i=0u;i<%zu;i++)Py_XDECREF(a[i]);Py_DECREF(c);"
                        "return r;}", count) < 0)
                goto fail;
            break;
        }
        case WRTC_PY_EXPR_BINARY:
            if (fputs("PyObject*l=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fputs(",*r,*v;if(!l)return NULL;r=", file) < 0 ||
                emit_eval_child(file, emitter, children[1], 1u) < 0 ||
                fputs(";if(!r){Py_DECREF(l);return NULL;}v=binary_operation("
                      "e->binary_operation,l,r,0);Py_DECREF(r);Py_DECREF(l);"
                      "return v;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_UNARY:
            if (fputs("PyObject*v=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fputs(",*r=NULL;if(!v)return NULL;if(strcmp(e->operation,"
                      "\"Not\")==0){int t=PyObject_IsTrue(v);Py_DECREF(v);"
                      "return t<0?NULL:PyBool_FromLong(!t);}if(strcmp("
                      "e->operation,\"USub\")==0)r=PyNumber_Negative(v);"
                      "else if(strcmp(e->operation,\"UAdd\")==0)"
                      "r=PyNumber_Positive(v);else if(strcmp(e->operation,"
                      "\"Invert\")==0)r=PyNumber_Invert(v);else "
                      "PyErr_SetString(PyExc_SystemError,\"unknown AOT unary "
                      "operation\");Py_DECREF(v);return r;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_BOOLEAN:
            if (fputs("PyObject*v=NULL;int t=0;(void)t;", file) < 0) goto fail;
            for (index = 0u; index < expression->child_count; index++) {
                if (fputs("Py_XDECREF(v);v=", file) < 0 ||
                    emit_eval_child(file, emitter, children[index], index) < 0 ||
                    fputs(";if(!v)return NULL;", file) < 0)
                    goto fail;
                if (index + 1u != expression->child_count &&
                    (fputs("t=PyObject_IsTrue(v);if(t<0){Py_DECREF(v);"
                           "return NULL;}if(", file) < 0 ||
                     (strcmp(expression->operation, "And") == 0
                          ? fputs("!t", file) : fputs("t", file)) < 0 ||
                     fputs(")return v;", file) < 0))
                    goto fail;
            }
            if (fputs("return v;}", file) < 0) goto fail;
            break;
        case WRTC_PY_EXPR_COMPARE:
            if (fputs("PyObject*l=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fputs(",*r,*a;int t=0;(void)t;if(!l)return NULL;", file) < 0)
                goto fail;
            for (index = 0u; index < expression->operation_count; index++) {
                if (fputs("r=", file) < 0 ||
                    emit_eval_child(file, emitter, children[index + 1u],
                                    index + 1u) < 0 ||
                    fputs(";if(!r){Py_DECREF(l);return NULL;}a="
                          "compare_operation(e->operations[", file) < 0 ||
                    fprintf(file, "%zu],l,r);Py_DECREF(l);if(!a){"
                                  "Py_DECREF(r);return NULL;}", index) < 0)
                    goto fail;
                if (index + 1u == expression->operation_count) {
                    if (fputs("Py_DECREF(r);return a;", file) < 0) goto fail;
                } else if (fputs("t=PyObject_IsTrue(a);Py_DECREF(a);if(t<0){"
                                 "Py_DECREF(r);return NULL;}if(!t){"
                                 "Py_DECREF(r);return Py_NewRef(Py_False);}"
                                 "l=r;", file) < 0) goto fail;
            }
            if (fputs("Py_DECREF(l);return Py_NewRef(Py_True);}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_TUPLE:
        case WRTC_PY_EXPR_LIST:
            if (fprintf(file, "PyObject*r=%s(%zu);if(!r)return NULL;",
                        expression->kind == WRTC_PY_EXPR_TUPLE
                            ? "PyTuple_New" : "PyList_New",
                        expression->child_count) < 0)
                goto fail;
            for (index = 0u; index < expression->child_count; index++)
                if (fputs("{PyObject*v=", file) < 0 ||
                    emit_eval_child(file, emitter, children[index], index) < 0 ||
                    fprintf(file, ";if(!v){Py_DECREF(r);return NULL;}%s(r,%zu,v);}",
                            expression->kind == WRTC_PY_EXPR_TUPLE
                                ? "PyTuple_SET_ITEM" : "PyList_SET_ITEM",
                            index) < 0)
                    goto fail;
            if (fputs("return r;}", file) < 0) goto fail;
            break;
        case WRTC_PY_EXPR_DICT:
            if (fputs("PyObject*r=PyDict_New();if(!r)return NULL;", file) < 0)
                goto fail;
            for (index = 0u; index < expression->child_count; index += 2u)
                if (fputs("{PyObject*k=", file) < 0 ||
                    emit_eval_child(file, emitter, children[index], index) < 0 ||
                    fputs(",*v=k?", file) < 0 ||
                    emit_eval_child(file, emitter, children[index + 1u],
                                    index + 1u) < 0 ||
                    fputs(":NULL;if(!k||!v||PyDict_SetItem(r,k,v)<0){"
                          "Py_XDECREF(v);Py_XDECREF(k);Py_DECREF(r);"
                          "return NULL;}Py_DECREF(v);Py_DECREF(k);}", file) < 0)
                    goto fail;
            if (fputs("return r;}", file) < 0) goto fail;
            break;
        case WRTC_PY_EXPR_JOINED_STRING:
        case WRTC_PY_EXPR_FORMATTED_VALUE:
            /* Kept boxed until the string-builder ABI is emitted. */
            goto fail;
        case WRTC_PY_EXPR_SUBSCRIPT:
            if (fputs("PyObject*o=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fputs(",*k,*r;if(!o)return NULL;k=", file) < 0 ||
                emit_eval_child(file, emitter, children[1], 1u) < 0 ||
                fputs(";if(!k){Py_DECREF(o);return NULL;}r=PyObject_GetItem("
                      "o,k);Py_DECREF(k);Py_DECREF(o);return r;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_SLICE:
            if (fputs("PyObject*a=", file) < 0 ||
                emit_eval_child(file, emitter, children[0], 0u) < 0 ||
                fputs(",*b,*c,*r;if(!a)return NULL;b=", file) < 0 ||
                emit_eval_child(file, emitter, children[1], 1u) < 0 ||
                fputs(";if(!b){Py_DECREF(a);return NULL;}c=", file) < 0 ||
                emit_eval_child(file, emitter, children[2], 2u) < 0 ||
                fputs(";if(!c){Py_DECREF(b);Py_DECREF(a);return NULL;}"
                      "r=PySlice_New(a,b,c);Py_DECREF(c);Py_DECREF(b);"
                      "Py_DECREF(a);return r;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_LAMBDA:
            goto fail;
    }
    if (emitter->has_hooks) {
        /* Hook dispatch must precede the generated body.  It is inserted as
         * a wrapper after the body-specific function below. */
    }
    free(children);
    *result_id = id;
    return 0;
fail:
    free(children);
    return -1;
}

static int emit_target(AotEmitter *emitter, const WrtcPyExprIR *target,
                       size_t *result_id) {
    FILE *file = emitter->file;
    size_t id = emitter->target_id++, index, slot;
    size_t owner = 0u, key = 0u;
    size_t *children = NULL;
    if (target->kind == WRTC_PY_EXPR_ATTRIBUTE) {
        if (emit_expression(emitter, &target->children[0], &owner) < 0)
            return -1;
    } else if (target->kind == WRTC_PY_EXPR_SUBSCRIPT) {
        if (emit_expression(emitter, &target->children[0], &owner) < 0 ||
            emit_expression(emitter, &target->children[1], &key) < 0)
            return -1;
    } else if (target->kind == WRTC_PY_EXPR_TUPLE ||
               target->kind == WRTC_PY_EXPR_LIST) {
        children = calloc(target->child_count == 0u ? 1u : target->child_count,
                          sizeof(*children));
        if (children == NULL) return -1;
        for (index = 0u; index < target->child_count; index++)
            if (emit_target(emitter, &target->children[index],
                            &children[index]) < 0) {
                free(children);
                return -1;
            }
    }
    if (fputs("static int WRTC_AOT_UNUSED ", file) < 0 ||
        function_prefix(file, emitter, "wat", id) < 0 ||
        fputs("(WrtcRegionFrame*f,const WrtcPyExprIR*t,PyObject*v){"
              "const WrtcPyExprIR*e=t;(void)e;", file) < 0)
        goto fail;
    if (emitter->has_hooks &&
        (fputs("if(f->hooks&&f->hooks->assign){WrtcBoxedFrame b={0};"
               "int h=0,z;b.globals=f->globals;b.external_frame=f;"
               "b.external_evaluate=", file) < 0 ||
         function_prefix(file, emitter, "waq", 0u) < 0 ||
         fputs(";b.external_local=", file) < 0 ||
         function_prefix(file, emitter, "wal", 0u) < 0 ||
         fputs(";z=f->hooks->assign(f->hooks->context,t,v,&b,&h);"
               "if(h||z<0)return z;}", file) < 0))
        goto fail;
    switch (target->kind) {
        case WRTC_PY_EXPR_NAME:
            slot = slot_index(emitter, target->operation);
            if (slot == (size_t)-1 || fprintf(file, "(void)t;return wafs(f,%zu,v);}", slot) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_ATTRIBUTE:
            if (fputs("PyObject*o=", file) < 0 ||
                emit_eval_child(file, emitter, owner, 0u) < 0 ||
                fputs(";int z;if(!o)return -1;if(!t->cached_attribute_name){"
                      "Py_DECREF(o);PyErr_SetString(PyExc_SystemError,"
                      "\"AOT attribute-name cache is uninitialized\");"
                      "return -1;}z=PyObject_SetAttr(o,"
                      "t->cached_attribute_name,v);Py_DECREF(o);return z;}",
                      file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_SUBSCRIPT:
            if (fputs("PyObject*o=", file) < 0 ||
                emit_eval_child(file, emitter, owner, 0u) < 0 ||
                fputs(",*k;int z;if(!o)return -1;k=", file) < 0 ||
                emit_eval_child(file, emitter, key, 1u) < 0 ||
                fputs(";if(!k){Py_DECREF(o);return -1;}z=PyObject_SetItem("
                      "o,k,v);Py_DECREF(k);Py_DECREF(o);return z;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_EXPR_TUPLE:
        case WRTC_PY_EXPR_LIST:
            if (fprintf(file,
                        "PyObject*i=NULL,*x,*extra;size_t n;if((PyTuple_CheckExact(v)"
                        "&&PyTuple_GET_SIZE(v)==%zu)||(PyList_CheckExact(v)&&"
                        "PyList_GET_SIZE(v)==%zu)){",
                        target->child_count, target->child_count) < 0)
                goto fail;
            for (index = 0u; index < target->child_count; index++) {
                if (fputs("x=PyTuple_CheckExact(v)?PyTuple_GET_ITEM(v,", file) < 0 ||
                    fprintf(file, "%zu):PyList_GET_ITEM(v,%zu);if(", index,
                            index) < 0 ||
                    function_prefix(file, emitter, "wat", children[index]) < 0 ||
                    fprintf(file, "(f,&t->children[%zu],x)<0)return -1;",
                            index) < 0)
                    goto fail;
            }
            if (fputs("return 0;}i=PyObject_GetIter(v);if(!i)return -1;",
                      file) < 0)
                goto fail;
            for (index = 0u; index < target->child_count; index++) {
                if (fprintf(file, "x=PyIter_Next(i);if(!x){Py_DECREF(i);"
                                  "if(!PyErr_Occurred())PyErr_Format("
                                  "PyExc_ValueError,\"not enough values to "
                                  "unpack (expected %zu, got %zu)\");return -1;}"
                                  "if(", target->child_count, index) < 0 ||
                    function_prefix(file, emitter, "wat", children[index]) < 0 ||
                    fprintf(file, "(f,&t->children[%zu],x)<0){Py_DECREF(x);"
                                  "Py_DECREF(i);return -1;}Py_DECREF(x);",
                            index) < 0)
                    goto fail;
            }
            if (fprintf(file, "extra=PyIter_Next(i);Py_DECREF(i);if(extra){"
                              "Py_DECREF(extra);PyErr_Format(PyExc_ValueError,"
                              "\"too many values to unpack (expected %zu)\");"
                              "return -1;}if(PyErr_Occurred())return -1;"
                              "(void)n;return 0;}", target->child_count) < 0)
                goto fail;
            break;
        default:
            goto fail;
    }
    free(children);
    *result_id = id;
    return 0;
fail:
    free(children);
    return -1;
}

static int emit_suite(AotEmitter *emitter, const WrtcPyStmtIR *statements,
                      size_t count, size_t *result_id);

static int emit_statement(AotEmitter *emitter,
                          const WrtcPyStmtIR *statement, size_t *result_id) {
    FILE *file = emitter->file;
    size_t *expressions = NULL, *targets = NULL;
    size_t *handler_expressions = NULL, *handler_suites = NULL;
    size_t body = 0u, orelse = 0u, finalbody = 0u, id, index, slot;
    if (statement->expression_count != 0u) {
        expressions = calloc(statement->expression_count,
                             sizeof(*expressions));
        if (expressions == NULL) return -1;
        for (index = 0u; index < statement->expression_count; index++) {
            if ((statement->kind == WRTC_PY_STMT_ASSIGN && index != 0u) ||
                (statement->kind == WRTC_PY_STMT_FOR && index == 0u) ||
                (statement->kind == WRTC_PY_STMT_AUGMENTED_ASSIGN &&
                 index == 0u))
                continue;
            if (emit_expression(emitter, &statement->expressions[index],
                                &expressions[index]) < 0)
                goto fail;
        }
    }
    if (statement->kind == WRTC_PY_STMT_ASSIGN) {
        targets = calloc(statement->expression_count,
                         sizeof(*targets));
        if (targets == NULL) goto fail;
        for (index = 1u; index < statement->expression_count; index++)
            if (emit_target(emitter, &statement->expressions[index],
                            &targets[index]) < 0)
                goto fail;
    } else if (statement->kind == WRTC_PY_STMT_FOR) {
        targets = calloc(1u, sizeof(*targets));
        if (targets == NULL ||
            emit_target(emitter, &statement->expressions[0],
                        &targets[0]) < 0)
            goto fail;
    }
    if ((statement->kind == WRTC_PY_STMT_TRY ||
         statement->kind == WRTC_PY_STMT_TRY_FINALLY) &&
        statement->handler_count != 0u) {
        handler_expressions = calloc(statement->handler_count,
                                     sizeof(*handler_expressions));
        handler_suites = calloc(statement->handler_count,
                                sizeof(*handler_suites));
        if (handler_expressions == NULL || handler_suites == NULL) goto fail;
        for (index = 0u; index < statement->handler_count; index++) {
            const WrtcPyStmtIR *handler = &statement->handlers[index];
            if ((handler->expression_count != 0u &&
                 emit_expression(emitter, &handler->expressions[0],
                                 &handler_expressions[index]) < 0) ||
                emit_suite(emitter, handler->body, handler->body_count,
                           &handler_suites[index]) < 0)
                goto fail;
        }
    }
    if (statement->kind == WRTC_PY_STMT_IF ||
        statement->kind == WRTC_PY_STMT_WHILE ||
        statement->kind == WRTC_PY_STMT_FOR ||
        statement->kind == WRTC_PY_STMT_TRY ||
        statement->kind == WRTC_PY_STMT_TRY_FINALLY) {
        if (emit_suite(emitter, statement->body, statement->body_count,
                       &body) < 0 ||
            emit_suite(emitter, statement->orelse, statement->orelse_count,
                       &orelse) < 0)
            goto fail;
        if (statement->kind == WRTC_PY_STMT_TRY_FINALLY &&
            emit_suite(emitter, statement->finalbody,
                       statement->finalbody_count, &finalbody) < 0)
            goto fail;
    }
    id = emitter->statement_id++;
    if (fputs("static inline int ", file) < 0 ||
        function_prefix(file, emitter, "wax", id) < 0 ||
        fputs("(WrtcRegionFrame*f,const WrtcPyStmtIR*s,WrtcFlow*flow){"
              "PyObject*v=NULL;(void)f;(void)s;(void)v;"
              "*flow=WRTC_FLOW_NORMAL;", file) < 0)
        goto fail;
    switch (statement->kind) {
        case WRTC_PY_STMT_EXPR:
        {
            const WrtcNativeCallEdgeIR *call =
                direct_call(emitter, &statement->expressions[0]);
            const WrtcPyExprIR *expression = &statement->expressions[0];
            if (call != NULL && expression->child_count != 0u &&
                expression->children[0].kind == WRTC_PY_EXPR_ATTRIBUTE &&
                expression->children[0].child_count == 1u) {
                const size_t argc = expression->positional_count +
                                    expression->keyword_count;
                const char *entry =
                    call->target_class == emitter->class_index &&
                            call->target != NULL &&
                            strncmp(call->target, "self.", 5u) == 0
                        ? "wu" : "wv";
                size_t receiver_id = expression_id(
                    emitter, &expression->children[0].children[0]);
                const WrtcPyExprIR *receiver_expression =
                    &expression->children[0].children[0];
                size_t receiver_slot =
                    receiver_expression->kind == WRTC_PY_EXPR_NAME
                        ? slot_index(emitter, receiver_expression->operation)
                        : (size_t)-1;
                if (receiver_id == (size_t)-1 ||
                    fprintf(file,
                            "{int z=-1;PyObject*recv=NULL,*a[%zu]={0};"
                            "unsigned char own_a[%zu]={0};int recv_owned=0;"
                            "size_t i;",
                            argc == 0u ? 1u : argc,
                            argc == 0u ? 1u : argc) < 0)
                    goto fail;
                if (receiver_slot != (size_t)-1 &&
                    !scalar_representation(
                        emitter->slot_representations[receiver_slot])) {
                    if (fprintf(file,
                                "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                "==0u){PyErr_SetString(PyExc_UnboundLocalError,"
                                "\"uninitialized call receiver\");return -1;}"
                                "recv=f->values[%zu];",
                                receiver_slot, receiver_slot) < 0)
                        goto fail;
                } else if (fputs("recv=", file) < 0 ||
                           function_prefix(file, emitter, "wae", receiver_id) < 0 ||
                           fputs("(f,&s->expressions[0].children[0].children[0]);"
                                 "if(!recv)return -1;recv_owned=1;",
                                 file) < 0) {
                    goto fail;
                }
                for (index = 0u; index < argc; index++) {
                    const WrtcPyExprIR *argument =
                        &expression->children[index + 1u];
                    size_t argument_id = expression_id(emitter, argument);
                    size_t argument_slot =
                        argument->kind == WRTC_PY_EXPR_NAME
                            ? slot_index(emitter, argument->operation)
                            : (size_t)-1;
                    if (argument_id == (size_t)-1) goto fail;
                    if (argument_slot != (size_t)-1 &&
                        !scalar_representation(
                            emitter->slot_representations[argument_slot])) {
                        if (fprintf(file,
                                    "if((f->initialized_mask&(UINT64_C(1)<<%zu))"
                                    "==0u){PyErr_SetString("
                                    "PyExc_UnboundLocalError,"
                                    "\"uninitialized call argument\");"
                                    "goto done;}a[%zu]=f->values[%zu];",
                                    argument_slot, index, argument_slot) < 0)
                            goto fail;
                    } else if (fprintf(file, "a[%zu]=", index) < 0 ||
                               function_prefix(file, emitter, "wae",
                                               argument_id) < 0 ||
                               fprintf(file,
                                       "(f,&s->expressions[0].children[%zu]);"
                                       "if(!a[%zu])goto done;own_a[%zu]=1u;",
                                       index + 1u, index, index) < 0) {
                        goto fail;
                    }
                }
                if (fprintf(file,
                            "if(%s%zu_%zu(recv,a,%zu,"
                            "s->expressions[0].cached_keyword_names,NULL)<0)"
                            "goto done;z=0;done:for(i=0u;i<%zu;i++)"
                            "if(own_a[i])Py_DECREF(a[i]);"
                            "if(recv_owned)Py_DECREF(recv);"
                            "return z;}}",
                            entry, call->target_class, call->target_region,
                            expression->positional_count, argc) < 0)
                    goto fail;
                break;
            }
            if (fputs("v=", file) < 0 ||
                emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                fputs(";if(!v)return -1;Py_DECREF(v);return 0;}", file) < 0)
                goto fail;
            break;
        }
        case WRTC_PY_STMT_ASSIGN:
            if (statement->expression_count == 2u &&
                statement->expressions[1].kind == WRTC_PY_EXPR_NAME) {
                char target[64];
                int typed;
                slot = slot_index(emitter,
                                  statement->expressions[1].operation);
                if (slot != (size_t)-1 && scalar_representation(
                        emitter->slot_representations[slot])) {
                    (void)snprintf(
                        target, sizeof target,
                        emitter->slot_representations[slot] ==
                                WRTC_NATIVE_REPR_DOUBLE
                            ? "f->scalar_d[%zu]" : "f->scalar_i[%zu]",
                        slot);
                    typed = emit_scalar_expression(
                        file, emitter, &statement->expressions[0],
                        "s->expressions[0]", target);
                    if (typed < 0) goto fail;
                    if (typed) {
                        if (fprintf(file, "f->scalar_mask|=UINT64_C(1)<<%zu;"
                                          "return 0;}", slot) < 0)
                            goto fail;
                        break;
                    }
                }
            }
            if (fputs("v=", file) < 0 ||
                emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                fputs(";if(!v)return -1;", file) < 0)
                goto fail;
            for (index = 1u; index < statement->expression_count; index++)
                if (fputs("if(", file) < 0 ||
                    function_prefix(file, emitter, "wat", targets[index]) < 0 ||
                    fprintf(file, "(f,&s->expressions[%zu],v)<0){Py_DECREF(v);"
                                  "return -1;}", index) < 0)
                    goto fail;
            if (fputs("Py_DECREF(v);return 0;}", file) < 0) goto fail;
            break;
        case WRTC_PY_STMT_AUGMENTED_ASSIGN:
            slot = slot_index(emitter, statement->expressions[0].operation);
            if (slot == (size_t)-1 ||
                fprintf(file, "{PyObject*l=wafl(f,%zu,", slot) < 0 ||
                quote(file, statement->expressions[0].operation) < 0 ||
                fputs("),*r,*u;if(!l)return -1;r=", file) < 0 ||
                emit_eval_statement(file, emitter, expressions[1], 1u) < 0 ||
                fprintf(file, ";if(!r){Py_DECREF(l);return -1;}u="
                              "binary_operation((WrtcPyBinaryOp)%d,l,r,1);"
                              "Py_DECREF(r);Py_DECREF(l);if(!u)return -1;"
                              "if(wafs(f,%zu,u)<0){Py_DECREF(u);return -1;}"
                              "Py_DECREF(u);return 0;}}",
                        (int)statement->binary_operation, slot) < 0)
                goto fail;
            break;
        case WRTC_PY_STMT_IF:
        {
            int typed;
            if (fputs("{int t;", file) < 0) goto fail;
            typed = emit_scalar_expression(
                file, emitter, &statement->expressions[0],
                "s->expressions[0]", "t");
            if (typed < 0) goto fail;
            if (!typed &&
                (fputs("v=", file) < 0 ||
                 emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                 fputs(";if(!v)return -1;t=PyObject_IsTrue(v);"
                       "Py_DECREF(v);if(t<0)return -1;", file) < 0))
                goto fail;
            if (fputs("if(t)return ", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,flow);return ", file) < 0 ||
                function_prefix(file, emitter, "was", orelse) < 0 ||
                fputs("(f,s->orelse,flow);}}", file) < 0)
                goto fail;
            break;
        }
        case WRTC_PY_STMT_WHILE:
        {
            int typed;
            if (fputs("for(;;){int t;", file) < 0) goto fail;
            typed = emit_scalar_expression(
                file, emitter, &statement->expressions[0],
                "s->expressions[0]", "t");
            if (typed < 0) goto fail;
            if (!typed &&
                (fputs("v=", file) < 0 ||
                 emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                 fputs(";if(!v)return -1;t=PyObject_IsTrue(v);Py_DECREF(v);"
                       "if(t<0)return -1;", file) < 0))
                goto fail;
            if (fputs("if(!t)return ", file) < 0 ||
                function_prefix(file, emitter, "was", orelse) < 0 ||
                fputs("(f,s->orelse,flow);if(", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,flow)<0)return -1;if(*flow==WRTC_FLOW_BREAK){"
                      "*flow=WRTC_FLOW_NORMAL;return 0;}if(*flow==WRTC_FLOW_RETURN)"
                      "return 0;*flow=WRTC_FLOW_NORMAL;}}", file) < 0)
                goto fail;
            break;
        }
        case WRTC_PY_STMT_FOR:
            if (statement->iterator_is_range &&
                statement->expressions[0].kind == WRTC_PY_EXPR_NAME &&
                !statements_use_name(statement->body, statement->body_count,
                                     statement->expressions[0].operation) &&
                statement->expressions[1].kind == WRTC_PY_EXPR_CALL &&
                statement->expressions[1].positional_count == 1u &&
                statement->expressions[1].keyword_count == 0u &&
                statement->expressions[1].child_count == 2u) {
                const size_t count_id = expression_id(
                    emitter, &statement->expressions[1].children[1]);
                int typed;
                if (count_id == (size_t)-1 ||
                    fputs("{Py_ssize_t wi,wn;int broke=0;", file) < 0)
                    goto fail;
                typed = emit_scalar_expression(
                    file, emitter, &statement->expressions[1].children[1],
                    "s->expressions[1].children[1]", "wn");
                if (typed < 0) goto fail;
                if (!typed &&
                    statement->expressions[1].children[1].kind ==
                        WRTC_PY_EXPR_NAME) {
                    size_t scalar_slot = slot_index(
                        emitter,
                        statement->expressions[1].children[1].operation);
                    if (scalar_slot != (size_t)-1 &&
                        scalar_representation(
                            emitter->slot_representations[scalar_slot]) &&
                        emitter->slot_representations[scalar_slot] !=
                            WRTC_NATIVE_REPR_DOUBLE) {
                        if (fprintf(file,
                                    "if((f->scalar_mask&(UINT64_C(1)<<%zu))"
                                    "==0u){PyErr_SetString("
                                    "PyExc_UnboundLocalError,"
                                    "\"uninitialized scalar loop bound\");"
                                    "return -1;}wn=(Py_ssize_t)f->scalar_i[%zu];",
                                    scalar_slot, scalar_slot) < 0)
                            goto fail;
                        typed = 1;
                    }
                }
                if (!typed &&
                    (fputs("v=", file) < 0 ||
                     function_prefix(file, emitter, "wae", count_id) < 0 ||
                     fputs("(f,&s->expressions[1].children[1]);if(!v)return -1;"
                           "wn=PyNumber_AsSsize_t(v,PyExc_OverflowError);"
                           "Py_DECREF(v);if(wn==-1&&PyErr_Occurred())return -1;",
                           file) < 0))
                    goto fail;
                if (fputs("for(wi=0;wi<wn;wi++){if(", file) < 0 ||
                    function_prefix(file, emitter, "was", body) < 0 ||
                    fputs("(f,s->body,flow)<0)return -1;"
                          "if(*flow==WRTC_FLOW_BREAK){*flow=WRTC_FLOW_NORMAL;"
                          "broke=1;break;}if(*flow==WRTC_FLOW_RETURN)return 0;"
                          "*flow=WRTC_FLOW_NORMAL;}if(!broke)return ", file) < 0 ||
                    function_prefix(file, emitter, "was", orelse) < 0 ||
                    fputs("(f,s->orelse,flow);return 0;}}", file) < 0)
                    goto fail;
                break;
            }
            if (fputs("{PyObject*i,*x;Py_ssize_t wi;int broke=0;v=", file) < 0 ||
                emit_eval_statement(file, emitter, expressions[1], 1u) < 0 ||
                fputs(";if(!v)return -1;if(PyList_CheckExact(v)){"
                      "for(wi=0;wi<PyList_GET_SIZE(v);wi++){"
                      "x=Py_NewRef(PyList_GET_ITEM(v,wi));if(", file) < 0 ||
                function_prefix(file, emitter, "wat", targets[0]) < 0 ||
                fputs("(f,&s->expressions[0],x)<0){Py_DECREF(x);Py_DECREF(v);"
                      "return -1;}Py_DECREF(x);if(", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,flow)<0){Py_DECREF(v);return -1;}"
                      "if(*flow==WRTC_FLOW_BREAK){*flow=WRTC_FLOW_NORMAL;"
                      "broke=1;break;}if(*flow==WRTC_FLOW_RETURN){Py_DECREF(v);"
                      "return 0;}*flow=WRTC_FLOW_NORMAL;}Py_DECREF(v);"
                      "if(!broke)return ", file) < 0 ||
                function_prefix(file, emitter, "was", orelse) < 0 ||
                fputs("(f,s->orelse,flow);return 0;}"
                      "i=PyObject_GetIter(v);Py_DECREF(v);"
                      "if(!i)return -1;for(;;){x=PyIter_Next(i);if(!x){"
                      "Py_DECREF(i);if(PyErr_Occurred())return -1;break;}if(",
                      file) < 0 ||
                function_prefix(file, emitter, "wat", targets[0]) < 0 ||
                fputs("(f,&s->expressions[0],x)<0){Py_DECREF(x);Py_DECREF(i);"
                      "return -1;}Py_DECREF(x);if(", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,flow)<0){Py_DECREF(i);return -1;}"
                      "if(*flow==WRTC_FLOW_BREAK){*flow=WRTC_FLOW_NORMAL;"
                      "broke=1;Py_DECREF(i);break;}if(*flow==WRTC_FLOW_RETURN){"
                      "Py_DECREF(i);return 0;}*flow=WRTC_FLOW_NORMAL;}"
                      "if(!broke)return ", file) < 0 ||
                function_prefix(file, emitter, "was", orelse) < 0 ||
                fputs("(f,s->orelse,flow);return 0;}}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_STMT_TRY_FINALLY:
            if (fputs("{PyObject*et=NULL,*ev=NULL,*eb=NULL;WrtcFlow pending="
                      "WRTC_FLOW_NORMAL,fin=WRTC_FLOW_NORMAL;int z=", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,&pending);if(z<0)PyErr_Fetch(&et,&ev,&eb);"
                      "z=", file) < 0 ||
                function_prefix(file, emitter, "was", finalbody) < 0 ||
                fputs("(f,s->finalbody,&fin);if(z<0){Py_XDECREF(et);"
                      "Py_XDECREF(ev);Py_XDECREF(eb);return -1;}if(fin!="
                      "WRTC_FLOW_NORMAL){Py_XDECREF(et);Py_XDECREF(ev);"
                      "Py_XDECREF(eb);pending=fin;}else if(et){PyErr_Restore("
                      "et,ev,eb);return -1;}*flow=pending;return 0;}}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_STMT_TRY:
            if (fputs("{PyObject*et=NULL,*ev=NULL,*eb=NULL;WrtcFlow pending="
                      "WRTC_FLOW_NORMAL;int z=", file) < 0 ||
                function_prefix(file, emitter, "was", body) < 0 ||
                fputs("(f,s->body,&pending);if(z<0){PyErr_Fetch(&et,&ev,&eb);"
                      "PyErr_NormalizeException(&et,&ev,&eb);", file) < 0)
                goto fail;
            for (index = 0u; index < statement->handler_count; index++) {
                const WrtcPyStmtIR *handler = &statement->handlers[index];
                if (fputs("if(et){int matches=1;PyObject*mt=NULL;", file) < 0)
                    goto fail;
                if (handler->expression_count != 0u &&
                    (fputs("mt=", file) < 0 ||
                     function_prefix(file, emitter, "wae",
                                     handler_expressions[index]) < 0 ||
                     fprintf(file, "(f,&s->handlers[%zu].expressions[0]);"
                                   "if(!mt){Py_XDECREF(eb);Py_XDECREF(ev);"
                                   "Py_XDECREF(et);return -1;}matches="
                                   "PyErr_GivenExceptionMatches(ev,mt);"
                                   "Py_DECREF(mt);", index) < 0))
                    goto fail;
                if (fputs("if(matches){PyObject*previous="
                          "PyErr_GetHandledException();PyErr_SetHandledException("
                          "Py_NewRef(ev));", file) < 0)
                    goto fail;
                if (handler->operation != NULL) {
                    slot = slot_index(emitter, handler->operation);
                    if (slot == (size_t)-1 ||
                        fprintf(file, "if(wafs(f,%zu,ev)<0){"
                                      "PyErr_SetHandledException(previous);"
                                      "Py_XDECREF(eb);Py_DECREF(ev);"
                                      "Py_DECREF(et);return -1;}", slot) < 0)
                        goto fail;
                }
                if (fputs("z=", file) < 0 ||
                    function_prefix(file, emitter, "was",
                                    handler_suites[index]) < 0 ||
                    fprintf(file, "(f,s->handlers[%zu].body,&pending);",
                            index) < 0)
                    goto fail;
                if (handler->operation != NULL &&
                    fprintf(file, "if((f->owned_mask&(UINT64_C(1)<<%zu))!=0u)"
                                  "Py_DECREF(f->values[%zu]);f->values[%zu]="
                                  "NULL;f->owned_mask&=~(UINT64_C(1)<<%zu);"
                                  "f->initialized_mask&=~(UINT64_C(1)<<%zu);",
                            slot, slot, slot, slot, slot) < 0)
                    goto fail;
                if (fputs("PyErr_SetHandledException(previous);Py_XDECREF(eb);"
                          "Py_DECREF(ev);Py_DECREF(et);et=ev=eb=NULL;}}",
                          file) < 0)
                    goto fail;
            }
            if (fputs("if(et){PyErr_Restore(et,ev,eb);return -1;}}"
                      "else if(pending==WRTC_FLOW_NORMAL){z=", file) < 0 ||
                function_prefix(file, emitter, "was", orelse) < 0 ||
                fputs("(f,s->orelse,&pending);}if(z<0)return -1;*flow=pending;"
                      "return 0;}}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_STMT_RETURN:
            if (statement->expression_count == 0u) {
                if (fputs("v=Py_NewRef(Py_None);", file) < 0) goto fail;
            } else if (fputs("v=", file) < 0 ||
                       emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                       fputs(";", file) < 0) goto fail;
            if (fputs("if(!v)return -1;Py_XSETREF(f->return_value,v);"
                      "*flow=WRTC_FLOW_RETURN;return 0;}", file) < 0)
                goto fail;
            break;
        case WRTC_PY_STMT_RAISE:
            if (statement->expression_count == 0u) {
                if (fputs("(void)raise_value(NULL,NULL);return -1;}", file) < 0)
                    goto fail;
            } else if (fputs("{PyObject*c=NULL;v=", file) < 0 ||
                       emit_eval_statement(file, emitter, expressions[0], 0u) < 0 ||
                       fputs(";if(!v)return -1;", file) < 0)
                goto fail;
            else {
                if (statement->expression_count > 1u &&
                    (fputs("c=", file) < 0 ||
                     emit_eval_statement(file, emitter, expressions[1], 1u) < 0 ||
                     fputs(";if(!c){Py_DECREF(v);return -1;}", file) < 0))
                    goto fail;
                if (fputs("(void)raise_value(v,c);Py_XDECREF(c);Py_DECREF(v);"
                          "return -1;}}", file) < 0) goto fail;
            }
            break;
        case WRTC_PY_STMT_BREAK:
            if (fputs("*flow=WRTC_FLOW_BREAK;return 0;}", file) < 0) goto fail;
            break;
        case WRTC_PY_STMT_CONTINUE:
            if (fputs("*flow=WRTC_FLOW_CONTINUE;return 0;}", file) < 0) goto fail;
            break;
        case WRTC_PY_STMT_PASS:
            if (fputs("return 0;}", file) < 0) goto fail;
            break;
        default:
            goto fail;
    }
    free(handler_suites);
    free(handler_expressions);
    free(targets);
    free(expressions);
    *result_id = id;
    return 0;
fail:
    free(handler_suites);
    free(handler_expressions);
    free(targets);
    free(expressions);
    return -1;
}

static int emit_suite(AotEmitter *emitter, const WrtcPyStmtIR *statements,
                      size_t count, size_t *result_id) {
    size_t *ids = calloc(count == 0u ? 1u : count, sizeof(*ids));
    size_t id, index;
    FILE *file = emitter->file;
    if (ids == NULL) return -1;
    for (index = 0u; index < count; index++)
        if (emit_statement(emitter, &statements[index], &ids[index]) < 0) {
            free(ids);
            return -1;
        }
    id = emitter->suite_id++;
    if (fputs("static inline int WRTC_AOT_UNUSED ", file) < 0 ||
        function_prefix(file, emitter, "was", id) < 0 ||
        fputs("(WrtcRegionFrame*f,const WrtcPyStmtIR*s,WrtcFlow*flow){"
              "(void)f;(void)s;",
              file) < 0) {
        free(ids);
        return -1;
    }
    for (index = 0u; index < count; index++)
        if (fputs("if(", file) < 0 ||
            function_prefix(file, emitter, "wax", ids[index]) < 0 ||
            fprintf(file, "(f,&s[%zu],flow)<0)return -1;"
                          "if(*flow!=WRTC_FLOW_NORMAL)return 0;", index) < 0) {
            free(ids);
            return -1;
        }
    if (fputs("*flow=WRTC_FLOW_NORMAL;return 0;}", file) < 0) {
        free(ids);
        return -1;
    }
    free(ids);
    *result_id = id;
    return 0;
}

int wrtc_aot_emit_region(FILE *file, size_t class_index, size_t region_index,
                         const WrtcNativeRegionIR *region,
                         const WrtcNativeClassProgram *program,
                         const WrtcNativeOperationTable *operations,
                         const char *globals_symbol, int has_hooks) {
    AotEmitter emitter;
    size_t index, root, vararg = (size_t)-1, keyword_only = (size_t)-1;
    if (file == NULL || !wrtc_aot_region_supported(region)) return -1;
    memset(&emitter, 0, sizeof emitter);
    emitter.file = file;
    emitter.region = region;
    emitter.program = program;
    emitter.operations = operations;
    emitter.class_index = class_index;
    emitter.region_index = region_index;
    emitter.has_hooks = has_hooks;
    emitter.direct = wrtc_aot_region_direct_supported(
        program, operations, class_index, region_index);
    if (has_hooks &&
        (fputs("static PyObject*", file) < 0 ||
         function_prefix(file, &emitter, "waq", 0u) < 0 ||
         fputs("(void*,const WrtcPyExprIR*);static PyObject*", file) < 0 ||
         function_prefix(file, &emitter, "wal", 0u) < 0 ||
         fputs("(void*,const char*);", file) < 0))
        return -1;
    for (index = 0u; index < region->signature->parameter_count; index++)
        if (add_slot(&emitter,
                     region->signature->parameters[index].name) < 0)
            return -1;
        else if (region->signature->parameters[index].kind ==
                 WRTC_PY_PARAM_VAR_POSITIONAL)
            vararg = index;
        else if (region->signature->parameters[index].kind ==
                 WRTC_PY_PARAM_KEYWORD_ONLY)
            keyword_only = index;
    for (index = 0u; index < region->body->local_count; index++)
        if (add_slot(&emitter, region->body->local_names[index]) < 0)
            return -1;
    discover_scalar_locals(&emitter, region->body->statements,
                           region->body->statement_count);
    finalize_scalar_locals(&emitter);
    if (emit_suite(&emitter, region->body->statements,
                   region->body->statement_count, &root) < 0)
        return -1;
    if (has_hooks) {
        if (fputs("static PyObject*", file) < 0 ||
            function_prefix(file, &emitter, "waq", 0u) < 0 ||
            fputs("(void*x,const WrtcPyExprIR*e){WrtcRegionFrame*f=x;", file) < 0)
            return -1;
        for (index = 0u; index < emitter.expression_count; index++) {
            const WrtcPyExprIR *expression = emitter.expressions[index];
            if (fprintf(file,
                        "if(e->kind==%d&&e->span.line==%d&&"
                        "e->span.column==%d&&e->span.end_line==%d&&"
                        "e->span.end_column==%d)return ",
                        (int)expression->kind,
                        expression->span.line,
                        expression->span.column,
                        expression->span.end_line,
                        expression->span.end_column) < 0 ||
                function_prefix(file, &emitter, "wae",
                                emitter.expression_ids[index]) < 0 ||
                fputs("(f,e);", file) < 0)
                return -1;
        }
        if (fputs("PyErr_SetString(PyExc_SystemError,\"AOT expression "
                  "dispatcher missed IR node\");return NULL;}"
                  "static PyObject*", file) < 0 ||
            function_prefix(file, &emitter, "wal", 0u) < 0 ||
            fputs("(void*x,const char*n){WrtcRegionFrame*f=x;", file) < 0)
            return -1;
        for (index = 0u; index < emitter.slot_count; index++)
            if (fputs("if(strcmp(n,", file) < 0 ||
                quote(file, emitter.slot_names[index]) < 0 ||
                fprintf(file, ")==0)return wafl(f,%zu,n);", index) < 0)
                return -1;
        if (fputs("return wafg(f,n);}", file) < 0) return -1;
    }
    if (fputs("static inline int ", file) < 0 ||
        function_prefix(file, &emitter, "wad", 0u) < 0 ||
        fputs("(PyObject*self,PyObject*const*args,Py_ssize_t nargs,"
              "PyObject*kwnames,const WrtcBoxedNativeHooks*hooks,"
              "PyObject**out){WrtcRegionFrame f;"
              "WrtcFlow flow=WRTC_FLOW_NORMAL;int z=-1;(void)args;", file) < 0 ||
        fprintf(file, "f.globals=%s;", globals_symbol) < 0 ||
        fputs("f.scalar_mask=0u;f.initialized_mask=0u;f.owned_mask=0u;"
              "f.return_value=NULL;f.hooks=hooks;", file) < 0 ||
        fputs("if(!f.globals){PyErr_SetString(PyExc_SystemError,"
              "\"AOT globals are unavailable\");return -1;}"
              "if(wafb(&f,0u,self,0)<0)goto done;", file) < 0)
        return -1;
    if (vararg == (size_t)-1) {
        if (fprintf(file, "if(kwnames||nargs!=%zu){z=1;goto done;}",
                    region->signature->parameter_count - 1u) < 0)
            return -1;
        for (index = 1u; index < region->signature->parameter_count; index++)
            if (fprintf(file, "if(wafb(&f,%zu,args[%zu],0)<0)goto done;",
                        index, index - 1u) < 0)
                return -1;
    } else {
        const size_t required = vararg - 1u;
        if (fprintf(file, "if(nargs<%zu){z=1;goto done;}", required) < 0)
            return -1;
        for (index = 1u; index < vararg; index++)
            if (fprintf(file, "if(wafb(&f,%zu,args[%zu],0)<0)goto done;",
                        index, index - 1u) < 0)
                return -1;
        if (fprintf(file,
                    "{Py_ssize_t i,n=nargs-%zu;PyObject*t=PyTuple_New(n);"
                    "if(!t)goto done;for(i=0;i<n;i++)PyTuple_SET_ITEM(t,i,"
                    "Py_NewRef(args[%zu+i]));if(wafb(&f,%zu,t,1)<0){"
                    "Py_DECREF(t);goto done;}}",
                    required, required, vararg) < 0)
            return -1;
        if (keyword_only != (size_t)-1) {
            if (fprintf(file,
                        "{PyObject*v=Py_None;Py_ssize_t i,kn=kwnames?"
                        "PyTuple_GET_SIZE(kwnames):0;for(i=0;i<kn;i++){"
                        "PyObject*n=PyTuple_GET_ITEM(kwnames,i);int eq="
                        "PyUnicode_Check(n)?PyUnicode_CompareWithASCIIString(n,") < 0 ||
                quote(file, region->signature->parameters[keyword_only].name) < 0 ||
                fprintf(file,
                        "):1;if(eq<0)goto done;if(eq!=0){z=1;goto done;}"
                        "v=args[nargs+i];}"
                        "if(wafb(&f,%zu,v,0)<0)goto done;}", keyword_only) < 0)
                return -1;
        } else if (fputs("if(kwnames){z=1;goto done;}", file) < 0) {
            return -1;
        }
    }
    if (fputs("if(", file) < 0 ||
        function_prefix(file, &emitter, "was", root) < 0 ||
        fprintf(file, "(&f,r%zu_%zu_suite.statements,&flow)<0)goto done;",
                class_index, region_index) < 0 ||
        fputs("if(flow==WRTC_FLOW_BREAK||flow==WRTC_FLOW_CONTINUE){"
              "PyErr_SetString(PyExc_SyntaxError,\"loop control escaped AOT "
              "region\");goto done;}if(out){*out=f.return_value?f.return_value:"
              "Py_NewRef(Py_None);f.return_value=NULL;}else{"
              "Py_CLEAR(f.return_value);}z=0;done:wafc(&f);"
              "return z;}", file) < 0)
        return -1;
    return 0;
}
