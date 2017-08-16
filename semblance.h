#ifndef __SEMBLANCE_H
#define __SEMBLANCE_H

/* Common functions */

#include <stdint.h>
#include <stdio.h>

#pragma pack(1)

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

#define USE_WARN        1

#ifdef USE_WARN
#define warn(...)       fprintf(stderr, "Warning: " __VA_ARGS__)
#else
#define warn(...)
#endif

word mode; /* program options */

#define DUMPHEADER      0x01
#define DUMPRSRC        0x02
#define DUMPEXPORT      0x04
#define DUMPIMPORTMOD   0x08
#define DISASSEMBLE     0x10
#define DISASSEMBLE_ALL 0x20
#define SPECFILE        0x80

#define GAS     1
#define NASM    2
#define MASM    3
word asm_syntax;

#endif /* SEMBLANCE_H */
