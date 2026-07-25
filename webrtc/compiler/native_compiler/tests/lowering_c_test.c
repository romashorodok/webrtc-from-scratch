#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler_core.h"
#include "lowering.h"

#ifndef WRTC_KERNEL_E_SOURCE
#error "WRTC_KERNEL_E_SOURCE is required"
#endif

#define CHECK(value) do { if (!(value)) { (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #value); if (PyErr_Occurred()) PyErr_Print(); return 1; } } while (0)

static char *read_source(size_t *length) {
    FILE *file = fopen(WRTC_KERNEL_E_SOURCE, "rb"); long end; char *source;
    if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (end = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) return NULL;
    source = malloc((size_t)end + 1u); if (source == NULL) { (void)fclose(file); return NULL; }
    if (fread(source, 1, (size_t)end, file) != (size_t)end) { free(source); (void)fclose(file); return NULL; }
    source[end] = '\0'; *length = (size_t)end; (void)fclose(file); return source;
}

int main(void) {
    WrtcCompilerCore *core = NULL; WrtcLoweringProgram *program = NULL;
    const WrtcLoweredFunction *entry; char *source; size_t length, f, n;
    int saw_branch = 0, saw_loop = 0, saw_call = 0, saw_raise = 0;
    int saw_any = 0, saw_record = 0, saw_collection = 0, saw_endian = 0;
    int saw_literal = 0, saw_operator = 0, saw_assignment_target = 0;
    int saw_slice_bound = 0;
    Py_Initialize(); source = read_source(&length); CHECK(source != NULL);
    CHECK(wrtc_compiler_core_analyze(source, length, WRTC_KERNEL_E_SOURCE, &core) == 0);
    CHECK(wrtc_lowering_build(core, &program) == 0 && program != NULL);
    CHECK(program->function_count == core->function_count);
    CHECK(program->record_count == 2u);
    CHECK(program->constant_count == 7u);
    CHECK(strcmp(program->constants[0].name, "_MAX_FRAME_SIZE") == 0);
    CHECK(strcmp(program->constants[0].literal, "16777216") == 0);
    CHECK(strcmp(program->records[1].fields[1].default_literal, "0") == 0);
    CHECK(program->records[0].property_count == 2u);
    CHECK(strcmp(program->records[0].properties[0].name, "header_size") == 0);
    CHECK(program->records[0].properties[0].operation_count != 0u);
    entry = wrtc_lowering_find_function(program, "packetize_av1_frame");
    CHECK(entry != NULL && entry->is_public && entry->parameter_count == 6u);
    CHECK(entry->return_type == WRTC_TYPE_TUPLE);
    CHECK(strcmp(entry->return_annotation,
                 "tuple[tuple[bytes, ...], int, int]") == 0);
    CHECK(entry->return_shape.kind == WRTC_TYPE_TUPLE);
    CHECK(entry->return_shape.item_count == 3u);
    CHECK(entry->return_shape.items[0].kind == WRTC_TYPE_TUPLE);
    CHECK(entry->return_shape.items[0].variadic);
    CHECK(entry->return_shape.items[0].item_count == 1u);
    CHECK(entry->return_shape.items[0].items[0].kind == WRTC_TYPE_BYTES);
    CHECK(entry->return_shape.items[1].kind == WRTC_TYPE_INT);
    CHECK(entry->return_shape.items[2].kind == WRTC_TYPE_INT);
    CHECK(strstr(entry->docstring, "Return complete RTP packets") != NULL);
    CHECK(strcmp(entry->parameters[0].annotation, "bytes") == 0);
    CHECK(strcmp(entry->parameters[0].name, "frame") == 0);
    CHECK(entry->parameters[0].boxed_type == WRTC_TYPE_BYTES);
    CHECK(entry->parameters[0].refined_type == WRTC_TYPE_BUFFER);
    CHECK(entry->parameters[0].storage == WRTC_STORAGE_BYTE_SPAN);
    CHECK(entry->parameters[0].ownership == WRTC_OWNERSHIP_BOUNDARY_OWNED);
    CHECK(entry->parameters[0].maximum_length == 16u * 1024u * 1024u);
    CHECK(entry->parameters[1].bit_width == 16u && entry->parameters[1].has_range);
    CHECK(entry->parameters[2].bit_width == 32u && entry->parameters[2].has_range);
    CHECK(entry->parameters[4].bit_width == 16u && entry->parameters[4].wraps);
    CHECK(strcmp(entry->parameters[5].name, "current_twcc_sequence") == 0);
    CHECK(entry->local_count != 0u);
    {
        int found_wrapped_sequence = 0;
        for (n = 0u; n < entry->local_count; n++)
            if (strcmp(entry->locals[n].name, "rtp_sequence") == 0) {
                CHECK(entry->locals[n].type == WRTC_TYPE_INT);
                CHECK(entry->locals[n].bit_width == 16u);
                CHECK(entry->locals[n].wraps);
                found_wrapped_sequence = 1;
            }
        CHECK(found_wrapped_sequence);
    }
    {
        const WrtcLoweredFunction *entry =
            wrtc_lowering_find_function(program, "packetize_av1_frame");
        int found_typed_call = 0;
        CHECK(entry != NULL);
        for (n = 0u; n < entry->operation_count; n++) {
            const WrtcLoweringOp *operation = &entry->operations[n];
            if (operation->kind == WRTC_LOWER_OP_DIRECT_CALL &&
                operation->symbol != NULL &&
                strcmp(operation->symbol, "_parse_obus") == 0) {
                CHECK(operation->type == WRTC_TYPE_TUPLE);
                CHECK(operation->element_type == WRTC_TYPE_RECORD);
                CHECK(operation->element_record_index == 0u);
                found_typed_call = 1;
            }
        }
        CHECK(found_typed_call);
    }
    {
        const WrtcLoweredFunction *parse =
            wrtc_lowering_find_function(program, "_parse_obus");
        int found_typed_obus = 0;
        CHECK(parse != NULL && parse->return_type == WRTC_TYPE_TUPLE);
        for (n = 0u; n < parse->local_count; n++) {
            const WrtcLoweredLocal *local = &parse->locals[n];
            if (strcmp(local->name, "obus") == 0) {
                CHECK(local->type == WRTC_TYPE_LIST);
                CHECK(local->element_type == WRTC_TYPE_RECORD);
                CHECK(local->element_record_index == 0u);
                CHECK(local->storage == WRTC_STORAGE_TYPED_VECTOR);
                CHECK(local->ownership == WRTC_OWNERSHIP_OWNED);
                found_typed_obus = 1;
            }
        }
        CHECK(found_typed_obus);
    }
    {
        const WrtcLoweredFunction *additional = wrtc_lowering_find_function(
            program, "_additional_bytes_for_previous_obu");
        int resolved_packet_size = 0;
        CHECK(additional != NULL && additional->parameter_count == 1u);
        CHECK(additional->parameters[0].boxed_type == WRTC_TYPE_RECORD);
        CHECK(additional->parameters[0].record_index == 1u);
        for (n = 0u; n < additional->operation_count; n++)
            if (additional->operations[n].kind == WRTC_LOWER_OP_ATTRIBUTE &&
                additional->operations[n].symbol != NULL &&
                strcmp(additional->operations[n].symbol, "packet_size") == 0) {
                CHECK(additional->operations[n].type == WRTC_TYPE_INT);
                CHECK(additional->operations[n].record_index == 1u);
                resolved_packet_size = 1;
            }
        CHECK(resolved_packet_size);
    }
    {
        const WrtcLoweredFunction *packetize =
            wrtc_lowering_find_function(program, "_packetize_obus");
        int found_record_store = 0;
        CHECK(packetize != NULL);
        for (n = 0u; n < packetize->operation_count; n++) {
            const WrtcLoweringOp *assignment = &packetize->operations[n];
            size_t operand;
            if (assignment->kind != WRTC_LOWER_OP_ASSIGN ||
                strcmp(assignment->syntax_kind, "AugAssign") != 0) continue;
            for (operand = 0u; operand < assignment->operand_count; operand++) {
                const WrtcLoweringOp *target =
                    &packetize->operations[assignment->operands[operand]];
                if (target->role != NULL && strcmp(target->role, "target") == 0 &&
                    target->kind == WRTC_LOWER_OP_ATTRIBUTE &&
                    target->record_index == 1u) found_record_store = 1;
            }
        }
        CHECK(found_record_store);
    }
    {
        const WrtcLoweredFunction *serialize = wrtc_lowering_find_function(
            program, "_serialize_rtp_packet");
        int found_mutable_output = 0;
        CHECK(serialize != NULL);
        for (n = 0u; n < serialize->local_count; n++)
            if (strcmp(serialize->locals[n].name, "output") == 0) {
                CHECK(serialize->locals[n].type == WRTC_TYPE_BYTE_VECTOR);
                CHECK(serialize->locals[n].owns_value);
                CHECK(serialize->locals[n].storage == WRTC_STORAGE_BYTE_BUILDER);
                found_mutable_output = 1;
            }
        CHECK(found_mutable_output);
    }
    for (f = 0u; f < program->function_count; f++) {
        const WrtcLoweredFunction *function = &program->functions[f];
        CHECK(function->operation_count != 0u);
        CHECK(function->operations[0].kind == WRTC_LOWER_OP_FUNCTION);
        CHECK(function->operations[0].parent == SIZE_MAX);
        CHECK(function->operations[0].subtree_end == function->operation_count);
        for (n = 0u; n < function->operation_count; n++) {
            const WrtcLoweringOp *op = &function->operations[n];
            size_t operand_index;
            CHECK(op->syntax_kind != NULL && op->span.line > 0);
            CHECK(op->symbol == NULL || strstr(op->symbol, "pymeta") == NULL);
            CHECK(op->subtree_end > n && op->subtree_end <= function->operation_count);
            if (op->kind == WRTC_LOWER_OP_FOR) CHECK(op->direct_loop);
            if (op->owns_value) {
                CHECK(op->ownership == WRTC_OWNERSHIP_OWNED);
                CHECK(op->cleanup_on_error);
            }
            for (operand_index = 0u; operand_index < op->operand_count; operand_index++) {
                size_t child = op->operands[operand_index];
                CHECK(child > n && child < op->subtree_end);
                CHECK(function->operations[child].parent == n);
                CHECK(function->operations[child].role != NULL);
            }
            saw_branch |= op->kind == WRTC_LOWER_OP_BRANCH;
            saw_loop |= op->kind == WRTC_LOWER_OP_FOR || op->kind == WRTC_LOWER_OP_WHILE;
            saw_call |= op->kind == WRTC_LOWER_OP_DIRECT_CALL;
            if (op->kind == WRTC_LOWER_OP_DIRECT_CALL) {
                CHECK(op->target_function < program->function_count);
                CHECK(strcmp(program->functions[op->target_function].name,
                             op->symbol) == 0);
            }
            saw_raise |= op->kind == WRTC_LOWER_OP_RAISE;
            saw_any |= op->kind == WRTC_LOWER_OP_ANY_GENERATOR;
            saw_record |= op->kind == WRTC_LOWER_OP_RECORD_CONSTRUCT;
            saw_collection |= op->kind == WRTC_LOWER_OP_COLLECTION_APPEND || op->kind == WRTC_LOWER_OP_COLLECTION_EXTEND || op->kind == WRTC_LOWER_OP_COLLECTION_POP;
            saw_endian |= op->kind == WRTC_LOWER_OP_ENDIAN_WRITE;
            saw_literal |= op->literal != NULL;
            saw_operator |= strcmp(op->syntax_kind, "Add") == 0 ||
                            strcmp(op->syntax_kind, "BitAnd") == 0;
            saw_assignment_target |= op->role != NULL &&
                                     strcmp(op->role, "targets") == 0;
            saw_slice_bound |= op->parent != SIZE_MAX && op->role != NULL &&
                               (strcmp(op->role, "lower") == 0 ||
                                strcmp(op->role, "upper") == 0);
            if (op->kind == WRTC_LOWER_OP_DIRECT_CALL && op->symbol != NULL &&
                strcmp(op->symbol, "_validate_range") == 0) {
                CHECK(op->operand_count == 5u);
                CHECK(strcmp(function->operations[op->operands[1]].role, "args") == 0);
                CHECK(function->operations[op->operands[1]].role_index == 0u);
                CHECK(function->operations[op->operands[1]].literal != NULL);
            }
            if (op->kind == WRTC_LOWER_OP_RETURN) {
                CHECK(op->operand_count <= 1u);
                if (op->operand_count == 1u)
                    CHECK(strcmp(function->operations[op->operands[0]].role, "value") == 0);
            }
        }
    }
    CHECK(saw_branch && saw_loop && saw_call && saw_raise && saw_any);
    CHECK(saw_record && saw_collection && saw_endian);
    CHECK(saw_literal && saw_operator && saw_assignment_target && saw_slice_bound);
    wrtc_lowering_free(program); wrtc_compiler_core_free(core); free(source);
    {
        static const char bad_source[] =
            "import pymeta\n__all__ = ['bad']\n"
            "@pymeta.required\n@pymeta.region('bad', value=pymeta.u16)\n"
            "def bad(value: int) -> int:\n    return arbitrary_callback(value)\n";
        core = NULL; program = NULL;
        CHECK(wrtc_compiler_core_analyze(bad_source, sizeof(bad_source) - 1u,
                                         "bad.py", &core) == 0);
        CHECK(wrtc_lowering_build(core, &program) < 0 && program == NULL);
        CHECK(PyErr_ExceptionMatches(PyExc_ValueError)); PyErr_Clear();
        wrtc_compiler_core_free(core);
    }
    {
        static const char incomplete_source[] =
            "import pymeta\n__all__ = ['incomplete']\n"
            "@pymeta.required\n@pymeta.region('incomplete', value=pymeta.u16)\n"
            "def incomplete(value: int, missing: int) -> int:\n    return value + missing\n";
        core = NULL; program = NULL;
        CHECK(wrtc_compiler_core_analyze(incomplete_source,
                                         sizeof(incomplete_source) - 1u,
                                         "incomplete.py", &core) == 0);
        CHECK(wrtc_lowering_build(core, &program) < 0 && program == NULL);
        CHECK(PyErr_ExceptionMatches(PyExc_ValueError)); PyErr_Clear();
        wrtc_compiler_core_free(core);
    }
    CHECK(Py_FinalizeEx() == 0); return 0;
}
