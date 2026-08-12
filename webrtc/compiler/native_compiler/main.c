#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler_core.h"
#include "generator.h"
#include "lowering.h"
#include "native_class.h"
#include "native_class_generator.h"

#ifndef WRTC_PYTHON_EXECUTABLE
#error "WRTC_PYTHON_EXECUTABLE is required"
#endif
#ifndef WRTC_PYTHON_VERSION
#error "WRTC_PYTHON_VERSION is required"
#endif

typedef struct {
    const char *source;
    const char *output;
    const char *metadata;
    int json;
} Options;

static int usage(const char *p, const char *error) {
    if (error != NULL) (void)fprintf(stderr, "%s: %s\n", p, error);
    (void)fprintf(stderr, "usage: %s --source <module.py> --output <directory>\n", p);
    return error == NULL ? 0 : 2;
}

static int options(int argc, char **argv, Options *o) {
    int i; o->source = NULL; o->output = NULL; o->metadata = NULL; o->json = 0;
    for (i = 1; i < argc; i++) {
        const int source = strcmp(argv[i], "--source") == 0;
        const int output = strcmp(argv[i], "--output") == 0;
        const int metadata = strcmp(argv[i], "--metadata-json") == 0;
        if (strcmp(argv[i], "--help") == 0) return usage(argv[0], NULL);
        if (strcmp(argv[i], "--result-json") == 0) { o->json = 1; continue; }
        if (!source && !output && !metadata) return usage(argv[0], "unknown argument");
        if (++i >= argc) return usage(argv[0], "path argument is missing");
        if (source) { if (o->source != NULL) return usage(argv[0], "duplicate --source"); o->source = argv[i]; }
        if (output) { if (o->output != NULL) return usage(argv[0], "duplicate --output"); o->output = argv[i]; }
        if (metadata) { if (o->metadata != NULL) return usage(argv[0], "duplicate --metadata-json"); o->metadata = argv[i]; }
    }
    if (o->source == NULL || o->output == NULL) return usage(argv[0], "--source and --output are required");
    return -1;
}

static char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb"); long end; char *data;
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0 || (end = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return NULL; }
    data = malloc((size_t)end + 1u);
    if (data == NULL) { fclose(file); return NULL; }
    if (fread(data, 1, (size_t)end, file) != (size_t)end) { free(data); fclose(file); return NULL; }
    data[end] = '\0'; *length = (size_t)end; fclose(file); return data;
}

static PyObject *read_metadata(const char *path) {
    char *source;
    size_t length;
    PyObject *json = NULL, *loads = NULL, *text = NULL, *result = NULL;
    PyObject *key, *value;
    Py_ssize_t position = 0;
    if (path == NULL) return PyDict_New();
    source = read_file(path, &length);
    if (source == NULL) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
        return NULL;
    }
    json = PyImport_ImportModule("json");
    loads = json == NULL ? NULL : PyObject_GetAttrString(json, "loads");
    text = PyUnicode_DecodeUTF8(source, (Py_ssize_t)length, "strict");
    free(source);
    if (loads != NULL && text != NULL) result = PyObject_CallOneArg(loads, text);
    Py_XDECREF(text);
    Py_XDECREF(loads);
    Py_XDECREF(json);
    if (result == NULL) return NULL;
    if (!PyDict_CheckExact(result)) {
        Py_DECREF(result);
        PyErr_SetString(PyExc_ValueError,
                        "--metadata-json must contain a JSON object");
        return NULL;
    }
    while (PyDict_Next(result, &position, &key, &value))
        if (!PyUnicode_CheckExact(key) || !PyUnicode_CheckExact(value)) {
            Py_DECREF(result);
            PyErr_SetString(
                PyExc_ValueError,
                "--metadata-json keys and values must all be strings");
            return NULL;
        }
    return result;
}

static int write_file(const char *path, const char *data) {
    FILE *file = fopen(path, "wb"); size_t length = strlen(data); int ok;
    if (file == NULL) return -1;
    ok = fwrite(data, 1, length, file) == length && fclose(file) == 0;
    return ok ? 0 : -1;
}

static char *copy_utf8(PyObject *object) {
    const char *value = PyUnicode_AsUTF8(object); char *copy;
    if (value == NULL) return NULL;
    copy = malloc(strlen(value) + 1u); if (copy != NULL) strcpy(copy, value); return copy;
}

static char *hash_bytes(const char *data, size_t length) {
    PyObject *hashlib = PyImport_ImportModule("hashlib"); PyObject *sha = NULL, *digest = NULL; char *result = NULL;
    if (hashlib == NULL) goto done;
    sha = PyObject_CallMethod(hashlib, "sha256", "y#", data, (Py_ssize_t)length); if (sha == NULL) goto done;
    digest = PyObject_CallMethod(sha, "hexdigest", NULL); if (digest != NULL) result = copy_utf8(digest);
done: Py_XDECREF(digest); Py_XDECREF(sha); Py_XDECREF(hashlib); return result;
}

static char *semantic_hash(const char *source, size_t length, const char *filename) {
    PyObject *ast = NULL, *parse = NULL, *dump = NULL, *text = NULL, *name = NULL, *tree = NULL;
    PyObject *args = NULL, *kwargs = NULL, *normalized = NULL, *encoded = NULL; char *result = NULL;
    ast = PyImport_ImportModule("ast"); if (ast == NULL) goto done;
    parse = PyObject_GetAttrString(ast, "parse"); dump = PyObject_GetAttrString(ast, "dump");
    text = PyUnicode_DecodeUTF8(source, (Py_ssize_t)length, "strict"); name = PyUnicode_DecodeFSDefault(filename);
    if (parse == NULL || dump == NULL || text == NULL || name == NULL) goto done;
    tree = PyObject_CallFunctionObjArgs(parse, text, name, NULL); if (tree == NULL) goto done;
    args = PyTuple_Pack(1, tree); kwargs = Py_BuildValue("{s:O,s:O}", "annotate_fields", Py_True, "include_attributes", Py_False);
    if (args == NULL || kwargs == NULL) goto done;
    normalized = PyObject_Call(dump, args, kwargs); if (normalized == NULL) goto done;
    encoded = PyUnicode_AsUTF8String(normalized); if (encoded == NULL) goto done;
    result = hash_bytes(PyBytes_AS_STRING(encoded), (size_t)PyBytes_GET_SIZE(encoded));
done:
    Py_XDECREF(encoded); Py_XDECREF(normalized); Py_XDECREF(kwargs); Py_XDECREF(args); Py_XDECREF(tree);
    Py_XDECREF(name); Py_XDECREF(text); Py_XDECREF(dump); Py_XDECREF(parse); Py_XDECREF(ast); return result;
}

static char *module_stem(const char *path) {
    const char *base = strrchr(path, '/'); const char *back = strrchr(path, '\\'); const char *dot; size_t n; char *stem;
    if (back != NULL && (base == NULL || back > base)) base = back; base = base == NULL ? path : base + 1;
    dot = strrchr(base, '.'); n = dot == NULL ? strlen(base) : (size_t)(dot - base);
    stem = malloc(n + 1u); if (stem == NULL) return NULL; memcpy(stem, base, n); stem[n] = '\0'; return stem;
}

static int valid_identifier(const char *stem) {
    PyObject *value = PyUnicode_FromString(stem), *keyword = NULL, *iskeyword = NULL, *answer = NULL; int valid = 0;
    size_t index;
    if (stem[0] == '\0' || (stem[0] >= '0' && stem[0] <= '9')) return 0;
    for (index = 0; stem[index] != '\0'; index++) {
        const unsigned char c = (unsigned char)stem[index];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    if (value == NULL || !PyUnicode_IsIdentifier(value)) goto done;
    keyword = PyImport_ImportModule("keyword"); if (keyword == NULL) goto done;
    iskeyword = PyObject_GetAttrString(keyword, "iskeyword"); if (iskeyword == NULL) goto done;
    answer = PyObject_CallOneArg(iskeyword, value); if (answer != NULL) valid = PyObject_IsTrue(answer) == 0;
done: Py_XDECREF(answer); Py_XDECREF(iskeyword); Py_XDECREF(keyword); Py_XDECREF(value); return valid;
}

static char *python_fact(const char *module_name, const char *attribute, int call) {
    PyObject *module = PyImport_ImportModule(module_name), *value = NULL, *result = NULL; char *copy = NULL;
    if (module == NULL) return NULL; value = PyObject_GetAttrString(module, attribute); if (value == NULL) goto done;
    result = call ? PyObject_CallNoArgs(value) : Py_NewRef(value); if (result != NULL) copy = copy_utf8(result);
done: Py_XDECREF(result); Py_XDECREF(value); Py_DECREF(module); return copy;
}

static PyObject *project_source_set(const char *entry) {
    static const char discovery[] =
        "import ast as _a\n"
        "from pathlib import Path as _P\n"
        "def _wrtc_sources(entry):\n"
        "    pending=[_P(entry).resolve()]; seen=set(); result=[]\n"
        "    while pending:\n"
        "        path=pending.pop()\n"
        "        if path in seen: continue\n"
        "        seen.add(path); result.append(str(path))\n"
        "        tree=_a.parse(path.read_text(encoding='utf-8'), filename=str(path))\n"
        "        for node in _a.walk(tree):\n"
        "            if not isinstance(node, _a.ImportFrom): continue\n"
        "            names=[]\n"
        "            if node.module: names.append(node.module)\n"
        "            elif node.level: names.extend(x.name for x in node.names)\n"
        "            for name in names:\n"
        "                parts=name.split('.') if name else []\n"
        "                candidates=[]\n"
        "                if node.level:\n"
        "                    base=path.parent\n"
        "                    for _ in range(node.level-1): base=base.parent\n"
        "                    candidates.append(base.joinpath(*parts).with_suffix('.py'))\n"
        "                    candidates.append(base.joinpath(*parts,'__init__.py'))\n"
        "                else:\n"
        "                    for base in path.parents:\n"
        "                        candidates.append(base.joinpath(*parts).with_suffix('.py'))\n"
        "                        candidates.append(base.joinpath(*parts,'__init__.py'))\n"
        "                for candidate in candidates:\n"
        "                    if candidate.is_file(): pending.append(candidate.resolve()); break\n"
        "    return tuple(result)\n";
    PyObject *globals = PyDict_New();
    PyObject *result = NULL, *function = NULL, *argument = NULL;
    if (globals == NULL ||
        PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins()) < 0)
        goto done;
    result = PyRun_String(discovery, Py_file_input, globals, globals);
    if (result == NULL) goto done;
    Py_CLEAR(result);
    function = PyDict_GetItemString(globals, "_wrtc_sources");
    argument = PyUnicode_DecodeFSDefault(entry);
    if (function != NULL && argument != NULL)
        result = PyObject_CallOneArg(function, argument);
done:
    Py_XDECREF(argument);
    Py_XDECREF(globals);
    return result;
}

static int py_call(const char *module_name, const char *name, PyObject *args, PyObject *kwargs, PyObject **out) {
    PyObject *module = PyImport_ImportModule(module_name), *function = NULL, *result = NULL;
    if (module == NULL) return -1; function = PyObject_GetAttrString(module, name);
    if (function != NULL) result = PyObject_Call(function, args, kwargs);
    Py_XDECREF(function); Py_DECREF(module); if (result == NULL) return -1;
    if (out != NULL) *out = result; else Py_DECREF(result); return 0;
}

static int run_command(const char *const *items) {
    PyObject *list = PyList_New(0), *args = NULL, *kwargs = NULL, *completed = NULL; int i, status = -1;
    if (list == NULL) return -1;
    for (i = 0; items[i] != NULL; i++) { PyObject *item = PyUnicode_DecodeFSDefault(items[i]); if (item == NULL || PyList_Append(list, item) < 0) { Py_XDECREF(item); goto done; } Py_DECREF(item); }
    args = PyTuple_Pack(1, list); kwargs = Py_BuildValue("{s:O,s:O}", "check", Py_True, "capture_output", Py_True);
    if (args != NULL && kwargs != NULL &&
        py_call("subprocess", "run", args, kwargs, &completed) == 0) {
        status = 0;
    } else if (PyErr_Occurred()) {
        PyObject *type = NULL, *value = NULL, *traceback = NULL;
        PyObject *stderr_value = NULL;
        PyErr_Fetch(&type, &value, &traceback);
        if (value != NULL)
            stderr_value = PyObject_GetAttrString(value, "stderr");
        if (stderr_value != NULL && PyBytes_Check(stderr_value))
            PySys_WriteStderr("%s", PyBytes_AS_STRING(stderr_value));
        Py_XDECREF(stderr_value);
        PyErr_Clear();
        PyErr_Restore(type, value, traceback);
    }
done: Py_XDECREF(completed); Py_XDECREF(kwargs); Py_XDECREF(args); Py_DECREF(list); return status;
}

static char *run_command_output(const char *const *items) {
    PyObject *list = PyList_New(0), *args = NULL, *kwargs = NULL, *completed = NULL, *stdout_value = NULL;
    char *output = NULL; int i;
    if (list == NULL) return NULL;
    for (i = 0; items[i] != NULL; i++) { PyObject *item = PyUnicode_DecodeFSDefault(items[i]); if (item == NULL || PyList_Append(list, item) < 0) { Py_XDECREF(item); goto done; } Py_DECREF(item); }
    args = PyTuple_Pack(1, list); kwargs = Py_BuildValue("{s:O,s:O,s:O}", "check", Py_True, "capture_output", Py_True, "text", Py_True);
    if (args == NULL || kwargs == NULL || py_call("subprocess", "run", args, kwargs, &completed) < 0) goto done;
    stdout_value = PyObject_GetAttrString(completed, "stdout"); if (stdout_value != NULL) output = copy_utf8(stdout_value);
done: Py_XDECREF(stdout_value); Py_XDECREF(completed); Py_XDECREF(kwargs); Py_XDECREF(args); Py_DECREF(list); return output;
}

static char *absolute_path(const char *path) {
    PyObject *value = PyUnicode_DecodeFSDefault(path), *args = NULL, *result = NULL; char *copy = NULL;
    if (value == NULL) return NULL; args = PyTuple_Pack(1, value);
    if (args != NULL && py_call("os.path", "abspath", args, NULL, &result) == 0) copy = copy_utf8(result);
    Py_XDECREF(result); Py_XDECREF(args); Py_DECREF(value); return copy;
}

static int audit_exports(const char *artifact, const char *module) {
#if defined(__APPLE__)
    const char *command[] = {"nm", "-gU", artifact, NULL}; const char *prefix = "_PyInit_";
#elif defined(__linux__)
    const char *command[] = {"nm", "-D", "--defined-only", artifact, NULL}; const char *prefix = "PyInit_";
#else
    (void)artifact; (void)module; return 0;
#endif
#if defined(__APPLE__) || defined(__linux__)
    char expected[512]; char *output = run_command_output(command), *line, *save = NULL; int count = 0, valid = 1;
    if (output == NULL) return -1; (void)snprintf(expected, sizeof expected, "%s%s", prefix, module);
    line = strtok_r(output, "\n", &save);
    while (line != NULL) { char *symbol = strrchr(line, ' '); if (symbol == NULL) symbol = strrchr(line, '\t'); symbol = symbol == NULL ? line : symbol + 1; if (strcmp(symbol, expected) != 0) valid = 0; count++; line = strtok_r(NULL, "\n", &save); }
    free(output); if (!valid || count != 1) { PyErr_SetString(PyExc_RuntimeError, "native extension exported symbols other than its CPython initializer"); return -1; } return 0;
#endif
}

static int make_dirs(const char *path) {
    PyObject *p = PyUnicode_DecodeFSDefault(path), *args = NULL, *kwargs = NULL; int status = -1;
    if (p == NULL) return -1; args = PyTuple_Pack(1, p); kwargs = Py_BuildValue("{s:O}", "exist_ok", Py_True);
    if (args != NULL && kwargs != NULL) status = py_call("os", "makedirs", args, kwargs, NULL);
    Py_XDECREF(kwargs); Py_XDECREF(args); Py_DECREF(p); return status;
}

static char *make_temp(const char *output, const char *module) {
    PyObject *prefix = PyUnicode_FromFormat(".%s-", module), *dir = PyUnicode_DecodeFSDefault(output), *args = PyTuple_New(0);
    PyObject *kwargs = NULL, *result = NULL; char *copy = NULL;
    if (prefix == NULL || dir == NULL || args == NULL) goto done;
    kwargs = Py_BuildValue("{s:O,s:O}", "prefix", prefix, "dir", dir);
    if (kwargs != NULL && py_call("tempfile", "mkdtemp", args, kwargs, &result) == 0) copy = copy_utf8(result);
done: Py_XDECREF(result); Py_XDECREF(kwargs); Py_XDECREF(args); Py_XDECREF(dir); Py_XDECREF(prefix); return copy;
}

static void cleanup(const char *path) {
    PyObject *p, *args, *kwargs;
    if (path == NULL) return; p = PyUnicode_DecodeFSDefault(path); if (p == NULL) { PyErr_Clear(); return; }
    args = PyTuple_Pack(1, p); kwargs = Py_BuildValue("{s:O}", "ignore_errors", Py_True);
    if (args != NULL && kwargs != NULL && py_call("shutil", "rmtree", args, kwargs, NULL) < 0) PyErr_Clear();
    Py_XDECREF(kwargs); Py_XDECREF(args); Py_DECREF(p);
}

static int replace_path(const char *source, const char *destination) {
    PyObject *a = PyUnicode_DecodeFSDefault(source), *b = PyUnicode_DecodeFSDefault(destination), *args; int status = -1;
    if (a == NULL || b == NULL) goto done; args = PyTuple_Pack(2, a, b); if (args != NULL) { status = py_call("os", "replace", args, NULL, NULL); Py_DECREF(args); }
done: Py_XDECREF(b); Py_XDECREF(a); return status;
}

static int emit_json(const char *artifact, const char *source, const char *source_hash,
                     const char *semantic, const char *module, PyObject *exports) {
    PyObject *mapping = PyDict_New(), *functions = NULL, *json = NULL, *dumps = NULL, *serialized = NULL;
    PyObject *value = NULL; const char *text; int status = -1;
    if (mapping == NULL) goto done;
#define PUT_STRING(key, raw) do { value = PyUnicode_DecodeFSDefault(raw); if (value == NULL || PyDict_SetItemString(mapping, key, value) < 0) goto done; Py_CLEAR(value); } while (0)
    PUT_STRING("artifact_path", artifact); PUT_STRING("source_path", source);
    PUT_STRING("source_sha256", source_hash); PUT_STRING("semantic_sha256", semantic); PUT_STRING("module_name", module);
#undef PUT_STRING
    functions = PySequence_List(exports); if (functions == NULL || PyDict_SetItemString(mapping, "public_functions", functions) < 0) goto done;
    json = PyImport_ImportModule("json"); if (json == NULL) goto done;
    dumps = PyObject_GetAttrString(json, "dumps"); if (dumps == NULL) goto done;
    serialized = PyObject_CallOneArg(dumps, mapping); if (serialized == NULL) goto done;
    text = PyUnicode_AsUTF8(serialized); if (text != NULL && printf("%s\n", text) >= 0) status = 0;
done: Py_XDECREF(value); Py_XDECREF(serialized); Py_XDECREF(dumps); Py_XDECREF(json); Py_XDECREF(functions); Py_XDECREF(mapping); return status;
}

static int compile_module(const Options *o) {
    char *source = NULL, *semantic = NULL, *source_hash = NULL, *stem = NULL, *module = NULL, *suffix = NULL;
    char *revision = NULL, *target = NULL, *arch = NULL, *temp = NULL;
    char *absolute_source = NULL, *absolute_output = NULL;
    char c_path[4096], cmake_path[4096], build_path[4096], built[4096], destination[4096], python_option[4096];
    size_t source_n = 0; int status = -1, native_emit = 0; const char *configure[11], *build[7]; PyObject *exports = NULL, *capability_report = NULL, *source_set = NULL, *artifact_metadata = NULL; WrtcCompilerCore *core = NULL; WrtcLoweringProgram *program = NULL; WrtcNativeClassProgram *native_classes = NULL; FILE *generated = NULL;
    static const char *cmake_format = "cmake_minimum_required(VERSION 3.25)\nproject(pymeta_extension LANGUAGES C)\nif(CMAKE_CROSSCOMPILING)\n message(FATAL_ERROR \"native extension cross-compiling is unsupported\")\nendif()\nfind_package(Python3 %s EXACT REQUIRED COMPONENTS Interpreter Development.Module)\nfind_package(Threads REQUIRED)\nadd_library(native MODULE generated.c)\ntarget_compile_features(native PRIVATE c_std_17)\ntarget_link_libraries(native PRIVATE Python3::Module Threads::Threads)\nset_target_properties(native PROPERTIES PREFIX \"\" OUTPUT_NAME \"%s\" SUFFIX \"%s\" C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO C_VISIBILITY_PRESET hidden)\nif(MSVC)\n target_compile_options(native PRIVATE /W4 /WX)\nelse()\n target_compile_options(native PRIVATE -O3 -fvisibility=hidden -Wall -Wextra -Wconversion -Werror)\nendif()\n";
    char *cmake_text = NULL;
    absolute_source = absolute_path(o->source); absolute_output = absolute_path(o->output); if (absolute_source == NULL || absolute_output == NULL) goto done;
    if (strchr(absolute_source, '"') != NULL || strchr(absolute_output, '"') != NULL) {
        PyErr_SetString(PyExc_ValueError, "source and output paths must not contain a double quote"); goto done;
    }
    if (strlen(absolute_source) > 3000u || strlen(absolute_output) > 3000u) {
        PyErr_SetString(PyExc_ValueError, "source or output path exceeds the bounded compiler path limit"); goto done;
    }
    source = read_file(absolute_source, &source_n); if (source == NULL) { PyErr_SetFromErrnoWithFilename(PyExc_OSError, absolute_source); goto done; }
    artifact_metadata = read_metadata(o->metadata);
    if (artifact_metadata == NULL) goto done;
    semantic = semantic_hash(source, source_n, absolute_source); source_hash = hash_bytes(source, source_n);
    if (semantic == NULL || source_hash == NULL) goto done;
    stem = module_stem(absolute_source); if (stem == NULL || !valid_identifier(stem)) { PyErr_SetString(PyExc_ValueError, "source stem must be a valid non-keyword Python identifier"); goto done; }
    if (wrtc_native_class_analyze(source, source_n, absolute_source,
                                  &native_classes) < 0) goto done;
    source_set = project_source_set(absolute_source);
    if (source_set == NULL) goto done;
    {
        Py_ssize_t dependency_index;
        const Py_ssize_t dependency_count = PySequence_Size(source_set);
        for (dependency_index = 0; dependency_index < dependency_count;
             dependency_index++) {
            PyObject *dependency =
                PySequence_GetItem(source_set, dependency_index);
            const char *dependency_path =
                dependency == NULL ? NULL : PyUnicode_AsUTF8(dependency);
            char *dependency_source = NULL;
            size_t dependency_length = 0u;
            WrtcNativeClassProgram *dependency_program = NULL;
            if (dependency_path == NULL) {
                Py_XDECREF(dependency);
                goto done;
            }
            if (strcmp(dependency_path, absolute_source) != 0) {
                dependency_source =
                    read_file(dependency_path, &dependency_length);
                if (dependency_source == NULL ||
                    wrtc_native_class_analyze(
                        dependency_source, dependency_length, dependency_path,
                        &dependency_program) < 0 ||
                    wrtc_native_class_merge(
                        native_classes, dependency_program) < 0) {
                    free(dependency_source);
                    wrtc_native_class_free(dependency_program);
                    Py_DECREF(dependency);
                    goto done;
                }
                free(dependency_source);
                wrtc_native_class_free(dependency_program);
            }
            Py_DECREF(dependency);
        }
    }
    wrtc_native_class_resolve_calls(native_classes);
    native_emit = wrtc_native_class_can_emit(native_classes);
    if (wrtc_native_class_requires_lowering(native_classes) && !native_emit) {
        PyObject *rendered;
        const char *report_text;
        capability_report = wrtc_native_class_capability_report(
            native_classes, absolute_source);
        rendered = capability_report == NULL ? NULL : PyObject_Repr(capability_report);
        report_text = rendered == NULL ? NULL : PyUnicode_AsUTF8(rendered);
        PyErr_Format(
            PyExc_NotImplementedError,
            "%s:%d:%d: error: native-class lowering requested for %s; "
            "this backend cannot completely lower this native class set; "
            "capability_report=%s",
            absolute_source, native_classes->classes[0].span.line,
            native_classes->classes[0].span.column,
            native_classes->classes[0].name,
            report_text == NULL ? "<unavailable>" : report_text);
        Py_XDECREF(rendered);
        goto done;
    }
    if (native_emit) {
        size_t export_index;
        exports = PyTuple_New((Py_ssize_t)(
            native_classes->class_count + native_classes->factory_count));
        if (exports == NULL) goto done;
        for (export_index = 0u; export_index < native_classes->class_count;
             export_index++) {
            PyObject *name = PyUnicode_FromString(
                native_classes->classes[export_index].name);
            if (name == NULL) goto done;
            PyTuple_SET_ITEM(exports, (Py_ssize_t)export_index, name);
        }
        for (export_index = 0u;
             export_index < native_classes->factory_count; export_index++) {
            PyObject *name = PyUnicode_FromString(
                native_classes->factories[export_index].name);
            if (name == NULL) goto done;
            PyTuple_SET_ITEM(
                exports,
                (Py_ssize_t)(native_classes->class_count + export_index),
                name);
        }
    } else {
        if (wrtc_compiler_core_analyze(source, source_n, absolute_source,
                                       &core) < 0) goto done;
        exports = Py_NewRef(core->exports);
        if (exports == NULL || wrtc_lowering_build(core, &program) < 0)
            goto done;
    }
    { size_t module_size = strlen(stem) + 8u; module = malloc(module_size); if (module == NULL) goto done; (void)snprintf(module, module_size, "%s_native", stem); }
    { PyObject *sc = PyImport_ImportModule("sysconfig"), *v = NULL; if (sc != NULL) v = PyObject_CallMethod(sc, "get_config_var", "s", "EXT_SUFFIX"); if (v != NULL && v != Py_None) suffix = copy_utf8(v); Py_XDECREF(v); Py_XDECREF(sc); }
    revision = python_fact("sys", "version", 0); target = python_fact("sysconfig", "get_platform", 1); arch = python_fact("platform", "machine", 1);
    if (suffix == NULL || revision == NULL || target == NULL || arch == NULL) goto done;
    if (make_dirs(absolute_output) < 0) goto done; temp = make_temp(absolute_output, module); if (temp == NULL) goto done;
    (void)snprintf(c_path, sizeof c_path, "%s/generated.c", temp); (void)snprintf(cmake_path, sizeof cmake_path, "%s/CMakeLists.txt", temp);
    (void)snprintf(build_path, sizeof build_path, "%s/build", temp); (void)snprintf(built, sizeof built, "%s/%s%s", build_path, module, suffix);
    (void)snprintf(destination, sizeof destination, "%s/%s%s", absolute_output, module, suffix); (void)snprintf(python_option, sizeof python_option, "-DPython3_EXECUTABLE=%s", WRTC_PYTHON_EXECUTABLE);
    cmake_text = malloc(strlen(cmake_format) + strlen(WRTC_PYTHON_VERSION) + strlen(module) + strlen(suffix) + 1u); if (cmake_text == NULL) goto done;
    (void)snprintf(cmake_text, strlen(cmake_format) + strlen(WRTC_PYTHON_VERSION) + strlen(module) + strlen(suffix) + 1u, cmake_format, WRTC_PYTHON_VERSION, module, suffix);
    generated = fopen(c_path, "wb");
    if (generated == NULL) { PyErr_SetFromErrnoWithFilename(PyExc_OSError, c_path); goto done; }
    if ((native_emit
             ? wrtc_emit_native_class_extension(
                   generated, module, native_classes, source_hash, semantic,
                   revision, target, arch, suffix, artifact_metadata)
             : wrtc_emit_extension(generated, module, program, source_hash,
                                   semantic, revision, target, arch,
                                   suffix, artifact_metadata)) < 0) {
        (void)fclose(generated); generated = NULL; PyErr_SetString(PyExc_OSError, "could not emit generated C17 source"); goto done;
    }
    if (fclose(generated) != 0) { generated = NULL; PyErr_SetFromErrnoWithFilename(PyExc_OSError, c_path); goto done; }
    generated = NULL;
    if (write_file(cmake_path, cmake_text) < 0) { PyErr_SetFromErrno(PyExc_OSError); goto done; }
    configure[0]="cmake"; configure[1]="-S"; configure[2]=temp; configure[3]="-B"; configure[4]=build_path; configure[5]="-DCMAKE_BUILD_TYPE=Release"; configure[6]=python_option; configure[7]=NULL;
    build[0]="cmake"; build[1]="--build"; build[2]=build_path; build[3]="--config"; build[4]="Release"; build[5]=NULL;
    if (run_command(configure) < 0 || run_command(build) < 0 || audit_exports(built, module) < 0 || replace_path(built, destination) < 0) goto done;
    if (o->json) { if (emit_json(destination, absolute_source, source_hash, semantic, module, exports) < 0) goto done; }
    else (void)printf("%s\n", destination);
    status = 0;
done:
    if (generated != NULL) fclose(generated);
    { PyObject *type = NULL, *value = NULL, *traceback = NULL; if (status < 0) PyErr_Fetch(&type, &value, &traceback); cleanup(temp); if (status < 0) PyErr_Restore(type, value, traceback); }
    Py_XDECREF(artifact_metadata); Py_XDECREF(source_set); Py_XDECREF(capability_report); Py_XDECREF(exports); wrtc_native_class_free(native_classes); wrtc_lowering_free(program); wrtc_compiler_core_free(core); free(cmake_text); free(temp); free(arch); free(target); free(revision); free(suffix); free(module); free(stem); free(source_hash); free(semantic); free(source); free(absolute_output); free(absolute_source); return status;
}

static void print_error(void) {
    PyObject *type = NULL, *value = NULL, *traceback = NULL, *text = NULL;
    const char *message = NULL;
    PyErr_Fetch(&type, &value, &traceback); PyErr_NormalizeException(&type, &value, &traceback);
    if (value != NULL) text = PyObject_Str(value);
    if (text != NULL) message = PyUnicode_AsUTF8(text);
    if (message != NULL) (void)fprintf(stderr, "%s\n", message);
    else { PyErr_Restore(type, value, traceback); type = value = traceback = NULL; PyErr_Print(); }
    Py_XDECREF(text); Py_XDECREF(traceback); Py_XDECREF(value); Py_XDECREF(type);
}

int main(int argc, char **argv) {
    Options o; PyConfig config; PyStatus init; int parsed = options(argc, argv, &o), result;
    if (parsed >= 0) return parsed;
    PyConfig_InitPythonConfig(&config); config.parse_argv = 0;
    init = PyConfig_SetBytesString(&config, &config.program_name, WRTC_PYTHON_EXECUTABLE);
    if (!PyStatus_Exception(init)) init = Py_InitializeFromConfig(&config); PyConfig_Clear(&config);
    if (PyStatus_Exception(init)) Py_ExitStatusException(init);
    result = compile_module(&o); if (result < 0) print_error(); if (Py_FinalizeEx() < 0) return 120; return result < 0 ? 1 : 0;
}
