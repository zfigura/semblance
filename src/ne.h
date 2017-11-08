#ifndef __NE_H
#define __NE_H

#include "semblance.h"

typedef struct _entry {
    byte flags;
    byte segment;
    word offset;
    char *name;     /* may be NULL */
} entry;

typedef struct _export {
    word ordinal;
    char *name;
} export;

typedef struct _import_module {
    char *name;
    export *exports;
    unsigned export_count;
} import_module;

/* per-file globals */
byte *import_name_table;
entry *entry_table;
unsigned entry_count;
import_module *import_module_table;

extern void print_rsrc(long start); /* in ne_resource.c */
extern void print_ne_segments(word count, word align, word entry_cs, word entry_ip); /* in ne_segment.c */

#endif /* __NE_H */
