#ifndef WRTC_BOXED_MODULE_H
#define WRTC_BOXED_MODULE_H

/* Return a newly allocated package-qualified module name, or NULL with a
 * Python exception when filename is not inside an importable package. */
char *wrtc_boxed_module_name(const char *filename);

#endif
