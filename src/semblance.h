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

static inline void skip_padding(char bytes){
    fseek(f, ((bytes-1) & (bytes-(ftell(f)%bytes)))*sizeof(byte), SEEK_CUR);
}

/* Common globals */

#define DUMPHEADER      0x01
#define DUMPRSRC        0x02
#define DUMPEXPORT      0x04
#define DUMPIMPORTMOD   0x08
#define DISASSEMBLE     0x10
#define SPECFILE        0x80
word mode; /* what to dump */

#define DISASSEMBLE_ALL 0x01
#define DEMANGLE        0x02
word opts; /* additional options */

#define MAXARGS		256

enum {
    GAS,
    NASM,
    MASM,
} asm_syntax;

extern const char *const rsrc_types[];
extern const size_t rsrc_types_count;

extern word resource_type[MAXARGS];
extern word resource_id[MAXARGS];
extern word resource_count;

/* Entry points */
void dumpne(long offset_ne);

#endif /* SEMBLANCE_H */
