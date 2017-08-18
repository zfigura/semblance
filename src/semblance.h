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

#endif /* SEMBLANCE_H */
