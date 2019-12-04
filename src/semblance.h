#ifndef __SEMBLANCE_H
#define __SEMBLANCE_H

/* Common functions */

#include <stdint.h>
#include <stdio.h>
#include "config.h"

#define STATIC_ASSERT(e) extern void STATIC_ASSERT_(int [(e)?1:-1])

typedef uint8_t byte;
typedef uint16_t word;
typedef uint32_t dword;
typedef uint64_t qword;

FILE *f;

static inline byte read_byte(){
    return getc(f);
}

static inline word read_word(){
    word w;
    fread(&w,2,1,f);
    return w;
}

static inline dword read_dword(){
    dword d;
    fread(&d,4,1,f);
    return d;
}

static inline dword read_qword(){
    qword q;
    fread(&q,8,1,f);
    return q;
}

static inline void skip_padding(char bytes){
    fseek(f, ((bytes-1) & (bytes-(ftell(f)%bytes)))*sizeof(byte), SEEK_CUR);
}

#define min(a,b) (((a)<(b))?(a):(b))

#ifdef USE_WARN
#define warn(...)       fprintf(stderr, "Warning: " __VA_ARGS__)
#else
#define warn(...)
#endif

/* Common globals */

#define DUMPHEADER      0x01
#define DUMPRSRC        0x02
#define DUMPEXPORT      0x04
#define DUMPIMPORTMOD   0x08
#define DISASSEMBLE     0x10
#define SPECFILE        0x80
word mode; /* what to dump */

#define DISASSEMBLE_ALL     0x01
#define DEMANGLE            0x02
#define NO_SHOW_RAW_INSN    0x04
#define NO_SHOW_ADDRESSES   0x08
#define COMPILABLE          0x10
#define FULL_CONTENTS       0x20
word opts; /* additional options */

enum {
    GAS,
    NASM,
    MASM,
} asm_syntax;

extern const char *const rsrc_types[];
extern const size_t rsrc_types_count;

char **resource_filters;
unsigned resource_filters_count;

/* Whether to print addresses relative to the image base for PE files. */
extern int pe_rel_addr;

/* Entry points */
void dumpmz(void);
void dumpne(long offset_ne);
void dumppe(long offset_pe);

#endif /* SEMBLANCE_H */
