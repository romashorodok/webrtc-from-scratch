#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boxed_module.h"

static char *copy_range(const char *begin, size_t count) {
    char *result = malloc(count + 1u);
    if (result != NULL) {
        memcpy(result, begin, count);
        result[count] = '\0';
    }
    return result;
}

static char *last_separator(char *value) {
    char *slash = strrchr(value, '/');
    char *backslash = strrchr(value, '\\');
    return backslash != NULL && (slash == NULL || backslash > slash)
               ? backslash : slash;
}

static int package_marker(const char *directory) {
    const size_t count = strlen(directory);
    char *path = malloc(count + 13u);
    FILE *file;
    if (path == NULL) return -1;
    (void)snprintf(path, count + 13u, "%s/%s", directory, "__init__.py");
    file = fopen(path, "rb");
    free(path);
    if (file == NULL) return 0;
    (void)fclose(file);
    return 1;
}

char *wrtc_boxed_module_name(const char *filename) {
    char *path, *separator, *stem, *module, *directory;
    size_t stem_length;
    if (filename == NULL || filename[0] == '\0') {
        PyErr_SetString(PyExc_ValueError, "source filename is absent");
        return NULL;
    }
    path = copy_range(filename, strlen(filename));
    if (path == NULL) return PyErr_NoMemory(), NULL;
    separator = last_separator(path);
    stem = separator == NULL ? path : separator + 1;
    stem_length = strlen(stem);
    if (stem_length > 3u && strcmp(stem + stem_length - 3u, ".py") == 0)
        stem_length -= 3u;
    if (stem_length == 0u || (stem_length == 8u &&
                              strncmp(stem, "__init__", 8u) == 0)) {
        free(path);
        PyErr_SetString(PyExc_ValueError,
                        "source module filename has no importable stem");
        return NULL;
    }
    module = copy_range(stem, stem_length);
    if (module == NULL) {
        free(path);
        return PyErr_NoMemory(), NULL;
    }
    if (separator == NULL) {
        free(path);
        free(module);
        PyErr_Format(PyExc_ValueError,
                     "%s: source is not inside a Python package", filename);
        return NULL;
    }
    *separator = '\0';
    directory = path;
    {
        size_t package_count = 0u;
        for (;;) {
            char *parent_separator;
            char *component;
            char *combined;
            size_t component_length, module_length;
            const int marker = package_marker(directory);
            if (marker < 0) {
                free(module);
                free(path);
                return PyErr_NoMemory(), NULL;
            }
            if (!marker) break;
            parent_separator = last_separator(directory);
            component =
                parent_separator == NULL ? directory : parent_separator + 1;
            component_length = strlen(component);
            module_length = strlen(module);
            combined =
                malloc(component_length + module_length + 2u);
            if (combined == NULL) {
                free(module);
                free(path);
                return PyErr_NoMemory(), NULL;
            }
            memcpy(combined, component, component_length);
            combined[component_length] = '.';
            memcpy(combined + component_length + 1u, module,
                   module_length + 1u);
            free(module);
            module = combined;
            package_count++;
            if (parent_separator == NULL) break;
            *parent_separator = '\0';
        }
        if (package_count == 0u) {
            PyErr_Format(PyExc_ValueError,
                         "%s: source is not inside a Python package",
                         filename);
            free(module);
            module = NULL;
        }
    }
    free(path);
    return module;
}
