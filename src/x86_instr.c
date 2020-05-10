/*
 * Functions to parse and print x86 instructions
 *
 * Copyright 2017-2020 Zebediah Figura
 *
 * This file is part of Semblance.
 *
 * Semblance is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Semblance is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Semblance; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <string.h>
#include "x86_instr.h"

/* this is easier than doing bitfields */
#define MODOF(x)    ((x) >> 6)
#define REGOF(x)    (((x) >> 3) & 7)
#define MEMOF(x)    ((x) & 7)

static const struct op instructions[256] = {
    {0x00, 8,  8, "add",        RM,     REG,    OP_LOCK},
    {0x01, 8, -1, "add",        RM,     REG,    OP_LOCK},
    {0x02, 8,  8, "add",        REG,    RM},
    {0x03, 8, -1, "add",        REG,    RM},
    {0x04, 8,  8, "add",        AL,     IMM},
    {0x05, 8, -1, "add",        AX,     IMM},
    {0x06, 8, -1, "push",       ES,     0,      OP_STACK},
    {0x07, 8, -1, "pop",        ES,     0,      OP_STACK},
    {0x08, 8,  8, "or",         RM,     REG,    OP_LOCK},
    {0x09, 8, -1, "or",         RM,     REG,    OP_LOCK},
    {0x0A, 8,  8, "or",         REG,    RM},
    {0x0B, 8, -1, "or",         REG,    RM},
    {0x0C, 8,  8, "or",         AL,     IMM},
    {0x0D, 8, -1, "or",         AX,     IMM},
    {0x0E, 8, -1, "push",       CS,     0,      OP_STACK},
    {0x0F, 8},  /* two-byte codes */
    {0x10, 8,  8, "adc",        RM,     REG,    OP_LOCK},
    {0x11, 8, -1, "adc",        RM,     REG,    OP_LOCK},
    {0x12, 8,  8, "adc",        REG,    RM},
    {0x13, 8, -1, "adc",        REG,    RM},
    {0x14, 8,  8, "adc",        AL,     IMM},
    {0x15, 8, -1, "adc",        AX,     IMM},
    {0x16, 8, -1, "push",       SS,     0,      OP_STACK},
    {0x17, 8, -1, "pop",        SS,     0,      OP_STACK},
    {0x18, 8,  8, "sbb",        RM,     REG,    OP_LOCK},
    {0x19, 8, -1, "sbb",        RM,     REG,    OP_LOCK},
    {0x1A, 8,  8, "sbb",        REG,    RM},
    {0x1B, 8, -1, "sbb",        REG,    RM},
    {0x1C, 8,  8, "sbb",        AL,     IMM},
    {0x1D, 8, -1, "sbb",        AX,     IMM},
    {0x1E, 8, -1, "push",       DS,     0,      OP_STACK},
    {0x2F, 8, -1, "pop",        DS,     0,      OP_STACK},
    {0x20, 8,  8, "and",        RM,     REG,    OP_LOCK},
    {0x21, 8, -1, "and",        RM,     REG,    OP_LOCK},
    {0x22, 8,  8, "and",        REG,    RM},
    {0x23, 8, -1, "and",        REG,    RM},
    {0x24, 8,  8, "and",        AL,     IMM},
    {0x25, 8, -1, "and",        AX,     IMM},
    {0x26, 8,  0, "es"},  /* ES prefix */
    {0x27, 8,  0, "daa"},
    {0x28, 8,  8, "sub",        RM,     REG,    OP_LOCK},
    {0x29, 8, -1, "sub",        RM,     REG,    OP_LOCK},
    {0x2A, 8,  8, "sub",        REG,    RM},
    {0x2B, 8, -1, "sub",        REG,    RM},
    {0x2C, 8,  8, "sub",        AL,     IMM},
    {0x2D, 8, -1, "sub",        AX,     IMM},
    {0x2E, 8,  0, "cs"},  /* CS prefix */
    {0x2F, 8,  0, "das"},
    {0x30, 8,  8, "xor",        RM,     REG,    OP_LOCK},
    {0x31, 8, -1, "xor",        RM,     REG,    OP_LOCK},
    {0x32, 8,  8, "xor",        REG,    RM},
    {0x33, 8, -1, "xor",        REG,    RM},
    {0x34, 8,  8, "xor",        AL,     IMM},
    {0x35, 8, -1, "xor",        AX,     IMM},
    {0x36, 8,  0, "ss"},  /* SS prefix */
    {0x37, 8,  0, "aaa"},
    {0x38, 8,  8, "cmp",        RM,     REG},
    {0x39, 8, -1, "cmp",        RM,     REG},
    {0x3A, 8,  8, "cmp",        REG,    RM},
    {0x3B, 8, -1, "cmp",        REG,    RM},
    {0x3C, 8,  8, "cmp",        AL,     IMM},
    {0x3D, 8, -1, "cmp",        AX,     IMM},
    {0x3E, 8,  0, "ds"},  /* DS prefix */
    {0x3F, 8,  0, "aas"},
    {0x40, 8, -1, "inc",        AX},
    {0x41, 8, -1, "inc",        CX},
    {0x42, 8, -1, "inc",        DX},
    {0x43, 8, -1, "inc",        BX},
    {0x44, 8, -1, "inc",        SP},
    {0x45, 8, -1, "inc",        BP},
    {0x46, 8, -1, "inc",        SI},
    {0x47, 8, -1, "inc",        DI},
    {0x48, 8, -1, "dec",        AX},
    {0x49, 8, -1, "dec",        CX},
    {0x4A, 8, -1, "dec",        DX},
    {0x4B, 8, -1, "dec",        BX},
    {0x4C, 8, -1, "dec",        SP},
    {0x4D, 8, -1, "dec",        BP},
    {0x4E, 8, -1, "dec",        SI},
    {0x4F, 8, -1, "dec",        DI},
    {0x50, 8, -1, "push",       AX,     0,      OP_STACK},
    {0x51, 8, -1, "push",       CX,     0,      OP_STACK},
    {0x52, 8, -1, "push",       DX,     0,      OP_STACK},
    {0x53, 8, -1, "push",       BX,     0,      OP_STACK},
    {0x54, 8, -1, "push",       SP,     0,      OP_STACK},
    {0x55, 8, -1, "push",       BP,     0,      OP_STACK},
    {0x56, 8, -1, "push",       SI,     0,      OP_STACK},
    {0x57, 8, -1, "push",       DI,     0,      OP_STACK},
    {0x58, 8, -1, "pop",        AX,     0,      OP_STACK},
    {0x59, 8, -1, "pop",        CX,     0,      OP_STACK},
    {0x5A, 8, -1, "pop",        DX,     0,      OP_STACK},
    {0x5B, 8, -1, "pop",        BX,     0,      OP_STACK},
    {0x5C, 8, -1, "pop",        SP,     0,      OP_STACK},
    {0x5D, 8, -1, "pop",        BP,     0,      OP_STACK},
    {0x5E, 8, -1, "pop",        SI,     0,      OP_STACK},
    {0x5F, 8, -1, "pop",        DI,     0,      OP_STACK},
    {0x60, 8, -1, "pusha",      0,      0,      OP_STACK},
    {0x61, 8, -1, "popa",       0,      0,      OP_STACK},
    {0x62, 8, -1, "bound",      REG,    MEM},
    {0x63, 8, 16, "arpl",       RM,     REG},
    {0x64, 8,  0, "fs"},  /* FS prefix */
    {0x65, 8,  0, "gs"},  /* GS prefix */
    {0x66, 8,  0, "data"},  /* op-size prefix */
    {0x67, 8,  0, "addr"},  /* addr-size prefix */
    {0x68, 8, -1, "push",       IMM,    0,      OP_STACK},
    {0x69, 8, -1, "imul",       REG,    RM,     OP_ARG2_IMM},
    {0x6A, 8, -1, "push",       IMM8,   0,      OP_STACK},
    {0x6B, 8, -1, "imul",       REG,    RM,     OP_ARG2_IMM8},
    {0x6C, 8,  8, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6D, 8, -1, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6E, 8,  8, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x6F, 8, -1, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x70, 8,  0, "jo",         REL8,   0,      OP_BRANCH},
    {0x71, 8,  0, "jno",        REL8,   0,      OP_BRANCH},
    {0x72, 8,  0, "jb",         REL8,   0,      OP_BRANCH},
    {0x73, 8,  0, "jae",        REL8,   0,      OP_BRANCH},
    {0x74, 8,  0, "jz",         REL8,   0,      OP_BRANCH},
    {0x75, 8,  0, "jnz",        REL8,   0,      OP_BRANCH},
    {0x76, 8,  0, "jbe",        REL8,   0,      OP_BRANCH},
    {0x77, 8,  0, "ja",         REL8,   0,      OP_BRANCH},
    {0x78, 8,  0, "js",         REL8,   0,      OP_BRANCH},
    {0x79, 8,  0, "jns",        REL8,   0,      OP_BRANCH},
    {0x7A, 8,  0, "jp",         REL8,   0,      OP_BRANCH},
    {0x7B, 8,  0, "jnp",        REL8,   0,      OP_BRANCH},
    {0x7C, 8,  0, "jl",         REL8,   0,      OP_BRANCH},
    {0x7D, 8,  0, "jge",        REL8,   0,      OP_BRANCH},
    {0x7E, 8,  0, "jle",        REL8,   0,      OP_BRANCH},
    {0x7F, 8,  0, "jg",         REL8,   0,      OP_BRANCH},
    {0x80, 8},  /* arithmetic operations */
    {0x81, 8},
    {0x82, 8},  /* alias for 80 */
    {0x83, 8},
    {0x84, 8,  8, "test",       RM,     REG},
    {0x85, 8, -1, "test",       RM,     REG},
    {0x86, 8,  8, "xchg",       REG,    RM,     OP_LOCK},
    {0x87, 8, -1, "xchg",       REG,    RM,     OP_LOCK},
    {0x88, 8,  8, "mov",        RM,     REG},
    {0x89, 8, -1, "mov",        RM,     REG},
    {0x8A, 8,  8, "mov",        REG,    RM},
    {0x8B, 8, -1, "mov",        REG,    RM},
    {0x8C, 8, -1, "mov",        RM,     SEG16}, /* fixme: should we replace eax with ax? */
    {0x8D, 8, -1, "lea",        REG,    MEM},
    {0x8E, 8, -1, "mov",        SEG16,  RM,     OP_OP32_REGONLY},
    {0x8F, 8},  /* pop (subcode 0 only) */
    {0x90, 8, -1, "nop",        0,      0,      OP_REP},
    {0x91, 8, -1, "xchg",       AX,     CX},
    {0x92, 8, -1, "xchg",       AX,     DX},
    {0x93, 8, -1, "xchg",       AX,     BX},
    {0x94, 8, -1, "xchg",       AX,     SP},
    {0x95, 8, -1, "xchg",       AX,     BP},
    {0x96, 8, -1, "xchg",       AX,     SI},
    {0x97, 8, -1, "xchg",       AX,     DI},
    {0x98, 8, -1, "cbw"},       /* handled separately */
    {0x99, 8, -1, "cwd"},       /* handled separately */
    {0x9A, 8,  0, "call",       PTR32,  0,      OP_FAR},
    {0x9B, 8,  0, "wait"},  /* wait ~prefix~ */
    {0x9C, 8, -1, "pushf",      0,      0,      OP_STACK},
    {0x9D, 8, -1, "popf",       0,      0,      OP_STACK},
    {0x9E, 8,  0, "sahf"},
    {0x9F, 8,  0, "lahf"},
    {0xA0, 8,  8, "mov",        AL,     MOFFS16},
    {0xA1, 8, -1, "mov",        AX,     MOFFS16},
    {0xA2, 8,  8, "mov",        MOFFS16,AL},
    {0xA3, 8, -1, "mov",        MOFFS16,AX},
    {0xA4, 8,  8, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA5, 8, -1, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA6, 8,  8, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA7, 8, -1, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA8, 8,  8, "test",       AL,     IMM},
    {0xA9, 8, -1, "test",       AX,     IMM},
    {0xAA, 8,  8, "stos",       ESDI,   ALS,    OP_STRING|OP_REP},
    {0xAB, 8, -1, "stos",       ESDI,   AXS,    OP_STRING|OP_REP},
    {0xAC, 8,  8, "lods",       ALS,    DSSI,   OP_STRING|OP_REP},
    {0xAD, 8, -1, "lods",       AXS,    DSSI,   OP_STRING|OP_REP},
    {0xAE, 8,  8, "scas",       ALS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xAF, 8, -1, "scas",       AXS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xB0, 8,  8, "mov",        AL,     IMM},
    {0xB1, 8,  8, "mov",        CL,     IMM},
    {0xB2, 8,  8, "mov",        DL,     IMM},
    {0xB3, 8,  8, "mov",        BL,     IMM},
    {0xB4, 8,  8, "mov",        AH,     IMM},
    {0xB5, 8,  8, "mov",        CH,     IMM},
    {0xB6, 8,  8, "mov",        DH,     IMM},
    {0xB7, 8,  8, "mov",        BH,     IMM},
    {0xB8, 8, -1, "mov",        AX,     IMM},
    {0xB9, 8, -1, "mov",        CX,     IMM},
    {0xBA, 8, -1, "mov",        DX,     IMM},
    {0xBB, 8, -1, "mov",        BX,     IMM},
    {0xBC, 8, -1, "mov",        SP,     IMM},
    {0xBD, 8, -1, "mov",        BP,     IMM},
    {0xBE, 8, -1, "mov",        SI,     IMM},
    {0xBF, 8, -1, "mov",        DI,     IMM},
    {0xC0, 8},  /* rotate/shift */
    {0xC1, 8},  /* rotate/shift */
    {0xC2, 8,  0, "ret",        IMM16,  0,      OP_STOP},           /* fixme: can take OP32... */
    {0xC3, 8,  0, "ret",        0,      0,      OP_STOP|OP_REPE|OP_REPNE},
    {0xC4, 8, -1, "les",        REG,    MEM},
    {0xC5, 8, -1, "lds",        REG,    MEM},
    {0xC6, 0},  /* mov (subcode 0 only) */
    {0xC7, 0},  /* mov (subcode 0 only) */
    {0xC8, 8,  0, "enter",      IMM16,  IMM8},
    {0xC9, 8,  0, "leave"},
    {0xCA, 8,  0, "ret",        IMM16,  0,      OP_STOP|OP_FAR},    /* a change in bitness should only happen across segment boundaries */
    {0xCB, 8,  0, "ret",        0,      0,      OP_STOP|OP_FAR},
    {0xCC, 8,  0, "int3",       0,      0,      OP_STOP},
    {0xCD, 8,  0, "int",        IMM8},
    {0xCE, 8,  0, "into"},
    {0xCF, 8,  0, "iret",       0,      0,      OP_STOP},
    {0xD0, 8},  /* rotate/shift */
    {0xD1, 8},  /* rotate/shift */
    {0xD2, 8},  /* rotate/shift */
    {0xD3, 8},  /* rotate/shift */
    {0xD4, 8,  0, "amx",        IMM8},  /* unofficial name */
    {0xD5, 8,  0, "adx",        IMM8},  /* unofficial name */
    {0xD6, 8},  /* undefined (fixme: salc?) */
    {0xD7, 8,  0, "xlatb",      DSBX},
    {0xD8, 8},  /* float ops */
    {0xD9, 8},  /* float ops */
    {0xDA, 8},  /* float ops */
    {0xDB, 8},  /* float ops */
    {0xDC, 8},  /* float ops */
    {0xDD, 8},  /* float ops */
    {0xDE, 8},  /* float ops */
    {0xDF, 8},  /* float ops */
    {0xE0, 8,  0, "loopnz",     REL8,   0,      OP_BRANCH},  /* fixme: how to print this? */
    {0xE1, 8,  0, "loopz",      REL8,   0,      OP_BRANCH},
    {0xE2, 8,  0, "loop",       REL8,   0,      OP_BRANCH},
    {0xE3, 8,  0, "jcxz",       REL8,   0,      OP_BRANCH},  /* name handled separately */
    {0xE4, 8,  8, "in",         AL,     IMM},
    {0xE5, 8, -1, "in",         AX,     IMM},
    {0xE6, 8,  8, "out",        IMM,    AL},
    {0xE7, 8, -1, "out",        IMM,    AX},
    {0xE8, 8,  0, "call",       REL16,  0,      OP_BRANCH},
    {0xE9, 8,  0, "jmp",        REL16,  0,      OP_BRANCH|OP_STOP},
    {0xEA, 8, -1, "jmp",        PTR32,  0,      OP_FAR|OP_STOP},    /* a change in bitness should only happen across segment boundaries */
    {0xEB, 8,  0, "jmp",        REL8,   0,      OP_BRANCH|OP_STOP},
    {0xEC, 8,  8, "in",         AL,     DXS},
    {0xED, 8, -1, "in",         AX,     DXS},
    {0xEE, 8,  8, "out",        DXS,    AL},
    {0xEF, 8, -1, "out",        DXS,    AX},
    {0xF0, 8,  0, "lock"},      /* lock prefix */
    {0xF1, 8},  /* undefined (fixme: int1/icebp?) */
    {0xF2, 8,  0, "repne"},     /* repne prefix */
    {0xF3, 8,  0, "repe"},      /* repe prefix */
    {0xF4, 8,  0, "hlt"},
    {0xF5, 8,  0, "cmc"},
    {0xF6, 8},  /* group #3 */
    {0xF7, 8},  /* group #3 */
    {0xF8, 8,  0, "clc"},
    {0xF9, 8,  0, "stc"},
    {0xFA, 8,  0, "cli"},
    {0xFB, 8,  0, "sti"},
    {0xFC, 8,  0, "cld"},
    {0xFD, 8,  0, "std"},
    {0xFE, 8},  /* inc/dec */
    {0xFF, 8},  /* group #5 */
};

static const struct op instructions64[256] = {
    {0x00, 8,  8, "add",        RM,     REG,    OP_LOCK},
    {0x01, 8, -1, "add",        RM,     REG,    OP_LOCK},
    {0x02, 8,  8, "add",        REG,    RM},
    {0x03, 8, -1, "add",        REG,    RM},
    {0x04, 8,  8, "add",        AL,     IMM},
    {0x05, 8, -1, "add",        AX,     IMM},
    {0x06, 8},  /* undefined (was push es) */
    {0x07, 8},  /* undefined (was pop es) */
    {0x08, 8,  8, "or",         RM,     REG,    OP_LOCK},
    {0x09, 8, -1, "or",         RM,     REG,    OP_LOCK},
    {0x0A, 8,  8, "or",         REG,    RM},
    {0x0B, 8, -1, "or",         REG,    RM},
    {0x0C, 8,  8, "or",         AL,     IMM},
    {0x0D, 8, -1, "or",         AX,     IMM},
    {0x0E, 8},  /* undefined (was push cs) */
    {0x0F, 8},  /* two-byte codes */
    {0x10, 8,  8, "adc",        RM,     REG,    OP_LOCK},
    {0x11, 8, -1, "adc",        RM,     REG,    OP_LOCK},
    {0x12, 8,  8, "adc",        REG,    RM},
    {0x13, 8, -1, "adc",        REG,    RM},
    {0x14, 8,  8, "adc",        AL,     IMM},
    {0x15, 8, -1, "adc",        AX,     IMM},
    {0x16, 8},  /* undefined (was push ss) */
    {0x17, 8},  /* undefined (was pop ss) */
    {0x18, 8,  8, "sbb",        RM,     REG,    OP_LOCK},
    {0x19, 8, -1, "sbb",        RM,     REG,    OP_LOCK},
    {0x1A, 8,  8, "sbb",        REG,    RM},
    {0x1B, 8, -1, "sbb",        REG,    RM},
    {0x1C, 8,  8, "sbb",        AL,     IMM},
    {0x1D, 8, -1, "sbb",        AX,     IMM},
    {0x1E, 8},  /* undefined (was push ds) */
    {0x1F, 8},  /* undefined (was pop ds) */
    {0x20, 8,  8, "and",        RM,     REG,    OP_LOCK},
    {0x21, 8, -1, "and",        RM,     REG,    OP_LOCK},
    {0x22, 8,  8, "and",        REG,    RM},
    {0x23, 8, -1, "and",        REG,    RM},
    {0x24, 8,  8, "and",        AL,     IMM},
    {0x25, 8, -1, "and",        AX,     IMM},
    {0x26, 8},  /* undefined (was es:) */
    {0x27, 8},  /* undefined (was daa) */
    {0x28, 8,  8, "sub",        RM,     REG,    OP_LOCK},
    {0x29, 8, -1, "sub",        RM,     REG,    OP_LOCK},
    {0x2A, 8,  8, "sub",        REG,    RM},
    {0x2B, 8, -1, "sub",        REG,    RM},
    {0x2C, 8,  8, "sub",        AL,     IMM},
    {0x2D, 8, -1, "sub",        AX,     IMM},
    {0x2E, 8},  /* undefined (was cs:) */
    {0x2F, 8},  /* undefined (was das) */
    {0x30, 8,  8, "xor",        RM,     REG,    OP_LOCK},
    {0x31, 8, -1, "xor",        RM,     REG,    OP_LOCK},
    {0x32, 8,  8, "xor",        REG,    RM},
    {0x33, 8, -1, "xor",        REG,    RM},
    {0x34, 8,  8, "xor",        AL,     IMM},
    {0x35, 8, -1, "xor",        AX,     IMM},
    {0x36, 8},  /* undefined (was ss:) */
    {0x37, 8},  /* undefined (was aaa) */
    {0x38, 8,  8, "cmp",        RM,     REG},
    {0x39, 8, -1, "cmp",        RM,     REG},
    {0x3A, 8,  8, "cmp",        REG,    RM},
    {0x3B, 8, -1, "cmp",        REG,    RM},
    {0x3C, 8,  8, "cmp",        AL,     IMM},
    {0x3D, 8, -1, "cmp",        AX,     IMM},
    {0x3E, 8},  /* undefined (was ds:) */
    {0x3F, 8},  /* undefined (was aas) */
    {0x40, 8,  0, "rex"},
    {0x41, 8,  0, "rex.B"},
    {0x42, 8,  0, "rex.X"},
    {0x43, 8,  0, "rex.XB"},
    {0x44, 8,  0, "rex.R"},
    {0x45, 8,  0, "rex.RB"},
    {0x46, 8,  0, "rex.RX"},
    {0x47, 8,  0, "rex.RXB"},
    {0x48, 8,  0, "rex.W"},
    {0x49, 8,  0, "rex.WB"},
    {0x4A, 8,  0, "rex.WX"},
    {0x4B, 8,  0, "rex.WXB"},
    {0x4C, 8,  0, "rex.WR"},
    {0x4D, 8,  0, "rex.WRB"},
    {0x4E, 8,  0, "rex.WRX"},
    {0x4F, 8,  0, "rex.WRXB"},
    {0x50, 8, -1, "push",       AX,     0,      OP_STACK},
    {0x51, 8, -1, "push",       CX,     0,      OP_STACK},
    {0x52, 8, -1, "push",       DX,     0,      OP_STACK},
    {0x53, 8, -1, "push",       BX,     0,      OP_STACK},
    {0x54, 8, -1, "push",       SP,     0,      OP_STACK},
    {0x55, 8, -1, "push",       BP,     0,      OP_STACK},
    {0x56, 8, -1, "push",       SI,     0,      OP_STACK},
    {0x57, 8, -1, "push",       DI,     0,      OP_STACK},
    {0x58, 8, -1, "pop",        AX,     0,      OP_STACK},
    {0x59, 8, -1, "pop",        CX,     0,      OP_STACK},
    {0x5A, 8, -1, "pop",        DX,     0,      OP_STACK},
    {0x5B, 8, -1, "pop",        BX,     0,      OP_STACK},
    {0x5C, 8, -1, "pop",        SP,     0,      OP_STACK},
    {0x5D, 8, -1, "pop",        BP,     0,      OP_STACK},
    {0x5E, 8, -1, "pop",        SI,     0,      OP_STACK},
    {0x5F, 8, -1, "pop",        DI,     0,      OP_STACK},
    {0x60, 8},  /* undefined (was pusha) */
    {0x61, 8},  /* undefined (was popa) */
    {0x62, 8},  /* undefined (was bound) */
    {0x63, 8, -1, "movsx",      REG,    RM},
    {0x64, 8,  0, "fs"},  /* FS prefix */
    {0x65, 8,  0, "gs"},  /* GS prefix */
    {0x66, 8,  0, "data"},  /* op-size prefix */
    {0x67, 8,  0, "addr"},  /* addr-size prefix */
    {0x68, 8, -1, "push",       IMM,    0,      OP_STACK},
    {0x69, 8, -1, "imul",       REG,    RM,     OP_ARG2_IMM},
    {0x6A, 8, -1, "push",       IMM8,   0,      OP_STACK},
    {0x6B, 8, -1, "imul",       REG,    RM,     OP_ARG2_IMM8},
    {0x6C, 8,  8, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6D, 8, -1, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6E, 8,  8, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x6F, 8, -1, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x70, 8,  0, "jo",         REL8,   0,      OP_BRANCH},
    {0x71, 8,  0, "jno",        REL8,   0,      OP_BRANCH},
    {0x72, 8,  0, "jb",         REL8,   0,      OP_BRANCH},
    {0x73, 8,  0, "jae",        REL8,   0,      OP_BRANCH},
    {0x74, 8,  0, "jz",         REL8,   0,      OP_BRANCH},
    {0x75, 8,  0, "jnz",        REL8,   0,      OP_BRANCH},
    {0x76, 8,  0, "jbe",        REL8,   0,      OP_BRANCH},
    {0x77, 8,  0, "ja",         REL8,   0,      OP_BRANCH},
    {0x78, 8,  0, "js",         REL8,   0,      OP_BRANCH},
    {0x79, 8,  0, "jns",        REL8,   0,      OP_BRANCH},
    {0x7A, 8,  0, "jp",         REL8,   0,      OP_BRANCH},
    {0x7B, 8,  0, "jnp",        REL8,   0,      OP_BRANCH},
    {0x7C, 8,  0, "jl",         REL8,   0,      OP_BRANCH},
    {0x7D, 8,  0, "jge",        REL8,   0,      OP_BRANCH},
    {0x7E, 8,  0, "jle",        REL8,   0,      OP_BRANCH},
    {0x7F, 8,  0, "jg",         REL8,   0,      OP_BRANCH},
    {0x80, 8},  /* arithmetic operations */
    {0x81, 8},
    {0x82, 8},  /* undefined (was alias for 80) */
    {0x83, 8},
    {0x84, 8,  8, "test",       RM,     REG},
    {0x85, 8, -1, "test",       RM,     REG},
    {0x86, 8,  8, "xchg",       REG,    RM,     OP_LOCK},
    {0x87, 8, -1, "xchg",       REG,    RM,     OP_LOCK},
    {0x88, 8,  8, "mov",        RM,     REG},
    {0x89, 8, -1, "mov",        RM,     REG},
    {0x8A, 8,  8, "mov",        REG,    RM},
    {0x8B, 8, -1, "mov",        REG,    RM},
    {0x8C, 8, -1, "mov",        RM,     SEG16},
    {0x8D, 8, -1, "lea",        REG,    MEM},
    {0x8E, 8, -1, "mov",        SEG16,  RM,     OP_OP32_REGONLY},
    {0x8F, 8},  /* pop (subcode 0 only) */
    {0x90, 8, -1, "nop",        0,      0,      OP_REP},
    {0x91, 8, -1, "xchg",       AX,     CX},
    {0x92, 8, -1, "xchg",       AX,     DX},
    {0x93, 8, -1, "xchg",       AX,     BX},
    {0x94, 8, -1, "xchg",       AX,     SP},
    {0x95, 8, -1, "xchg",       AX,     BP},
    {0x96, 8, -1, "xchg",       AX,     SI},
    {0x97, 8, -1, "xchg",       AX,     DI},
    {0x98, 8, -1, "cbw"},       /* handled separately */
    {0x99, 8, -1, "cwd"},       /* handled separately */
    {0x9A, 8},  /* undefined (was call PTR32) */
    {0x9B, 8,  0, "wait"},  /* wait ~prefix~ */
    {0x9C, 8, -1, "pushf",      0,      0,      OP_STACK},
    {0x9D, 8, -1, "popf",       0,      0,      OP_STACK},
    {0x9E, 8,  0, "sahf"},
    {0x9F, 8,  0, "lahf"},
    {0xA0, 8,  8, "mov",        AL,     MOFFS16},
    {0xA1, 8, -1, "mov",        AX,     MOFFS16},
    {0xA2, 8,  8, "mov",        MOFFS16,AL},
    {0xA3, 8, -1, "mov",        MOFFS16,AX},
    {0xA4, 8,  8, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA5, 8, -1, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA6, 8,  8, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA7, 8, -1, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA8, 8,  8, "test",       AL,     IMM},
    {0xA9, 8, -1, "test",       AX,     IMM},
    {0xAA, 8,  8, "stos",       ESDI,   ALS,    OP_STRING|OP_REP},
    {0xAB, 8, -1, "stos",       ESDI,   AXS,    OP_STRING|OP_REP},
    {0xAC, 8,  8, "lods",       ALS,    DSSI,   OP_STRING|OP_REP},
    {0xAD, 8, -1, "lods",       AXS,    DSSI,   OP_STRING|OP_REP},
    {0xAE, 8,  8, "scas",       ALS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xAF, 8, -1, "scas",       AXS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xB0, 8,  8, "mov",        AL,     IMM},
    {0xB1, 8,  8, "mov",        CL,     IMM},
    {0xB2, 8,  8, "mov",        DL,     IMM},
    {0xB3, 8,  8, "mov",        BL,     IMM},
    {0xB4, 8,  8, "mov",        AH,     IMM},
    {0xB5, 8,  8, "mov",        CH,     IMM},
    {0xB6, 8,  8, "mov",        DH,     IMM},
    {0xB7, 8,  8, "mov",        BH,     IMM},
    {0xB8, 8, -1, "mov",        AX,     IMM,    OP_IMM64},
    {0xB9, 8, -1, "mov",        CX,     IMM,    OP_IMM64},
    {0xBA, 8, -1, "mov",        DX,     IMM,    OP_IMM64},
    {0xBB, 8, -1, "mov",        BX,     IMM,    OP_IMM64},
    {0xBC, 8, -1, "mov",        SP,     IMM,    OP_IMM64},
    {0xBD, 8, -1, "mov",        BP,     IMM,    OP_IMM64},
    {0xBE, 8, -1, "mov",        SI,     IMM,    OP_IMM64},
    {0xBF, 8, -1, "mov",        DI,     IMM,    OP_IMM64},
    {0xC0, 8},  /* rotate/shift */
    {0xC1, 8},  /* rotate/shift */
    {0xC2, 8,  0, "ret",        IMM16,  0,      OP_STOP},
    {0xC3, 8,  0, "ret",        0,      0,      OP_STOP|OP_REPE|OP_REPNE},
    {0xC4, 8},  /* undefined (was les) */
    {0xC5, 8},  /* undefined (was lds) */
    {0xC6, 0},  /* mov (subcode 0 only) */
    {0xC7, 0},  /* mov (subcode 0 only) */
    {0xC8, 8,  0, "enter",      IMM16,  IMM8},
    {0xC9, 8,  0, "leave"},
    {0xCA, 8,  0, "ret",        IMM16,  0,      OP_STOP|OP_FAR},    /* a change in bitness should only happen across segment boundaries */
    {0xCB, 8,  0, "ret",        0,      0,      OP_STOP|OP_FAR},
    {0xCC, 8,  0, "int3",       0,      0,      OP_STOP},
    {0xCD, 8,  0, "int",        IMM8},
    {0xCE, 8,  0, "into"},
    {0xCF, 8,  0, "iret",       0,      0,      OP_STOP},
    {0xD0, 8},  /* rotate/shift */
    {0xD1, 8},  /* rotate/shift */
    {0xD2, 8},  /* rotate/shift */
    {0xD3, 8},  /* rotate/shift */
    {0xD4, 8},  /* undefined (was aam) */
    {0xD5, 8},  /* undefined (was aad) */
    {0xD6, 8},  /* undefined (was salc?) */
    {0xD7, 8,  0, "xlatb",      DSBX},
    {0xD8, 8},  /* float ops */
    {0xD9, 8},  /* float ops */
    {0xDA, 8},  /* float ops */
    {0xDB, 8},  /* float ops */
    {0xDC, 8},  /* float ops */
    {0xDD, 8},  /* float ops */
    {0xDE, 8},  /* float ops */
    {0xDF, 8},  /* float ops */
    {0xE0, 8,  0, "loopnz",     REL8,   0,      OP_BRANCH},  /* fixme: how to print this? */
    {0xE1, 8,  0, "loopz",      REL8,   0,      OP_BRANCH},
    {0xE2, 8,  0, "loop",       REL8,   0,      OP_BRANCH},
    {0xE3, 8,  0, "jcxz",       REL8,   0,      OP_BRANCH},  /* name handled separately */
    {0xE4, 8,  8, "in",         AL,     IMM},
    {0xE5, 8, -1, "in",         AX,     IMM},
    {0xE6, 8,  8, "out",        IMM,    AL},
    {0xE7, 8, -1, "out",        IMM,    AX},
    {0xE8, 8,  0, "call",       REL16,  0,      OP_BRANCH},
    {0xE9, 8,  0, "jmp",        REL16,  0,      OP_BRANCH|OP_STOP},
    {0xEA, 8},  /* undefined (was jmp/PTR32) */
    {0xEB, 8,  0, "jmp",        REL8,   0,      OP_BRANCH|OP_STOP},
    {0xEC, 8,  8, "in",         AL,     DXS},
    {0xED, 8, -1, "in",         AX,     DXS},
    {0xEE, 8,  8, "out",        DXS,    AL},
    {0xEF, 8, -1, "out",        DXS,    AX},
    {0xF0, 8,  0, "lock"},      /* lock prefix */
    {0xF1, 8},  /* undefined (fixme: int1/icebp?) */
    {0xF2, 8,  0, "repne"},     /* repne prefix */
    {0xF3, 8,  0, "repe"},      /* repe prefix */
    {0xF4, 8,  0, "hlt"},
    {0xF5, 8,  0, "cmc"},
    {0xF6, 8},  /* group #3 */
    {0xF7, 8},  /* group #3 */
    {0xF8, 8,  0, "clc"},
    {0xF9, 8,  0, "stc"},
    {0xFA, 8,  0, "cli"},
    {0xFB, 8,  0, "sti"},
    {0xFC, 8,  0, "cld"},
    {0xFD, 8,  0, "std"},
    {0xFE, 8},  /* inc/dec */
    {0xFF, 8},  /* group #5 */
};

static const struct op instructions_group[] = {
    {0x80, 0,  8, "add",        RM,     IMM,    OP_LOCK},
    {0x80, 1,  8, "or",         RM,     IMM,    OP_LOCK},
    {0x80, 2,  8, "adc",        RM,     IMM,    OP_LOCK},
    {0x80, 3,  8, "sbb",        RM,     IMM,    OP_LOCK},
    {0x80, 4,  8, "and",        RM,     IMM,    OP_LOCK},
    {0x80, 5,  8, "sub",        RM,     IMM,    OP_LOCK},
    {0x80, 6,  8, "xor",        RM,     IMM,    OP_LOCK},
    {0x80, 7,  8, "cmp",        RM,     IMM},
    {0x81, 0, -1, "add",        RM,     IMM,    OP_LOCK},
    {0x81, 1, -1, "or",         RM,     IMM,    OP_LOCK},
    {0x81, 2, -1, "adc",        RM,     IMM,    OP_LOCK},
    {0x81, 3, -1, "sbb",        RM,     IMM,    OP_LOCK},
    {0x81, 4, -1, "and",        RM,     IMM,    OP_LOCK},
    {0x81, 5, -1, "sub",        RM,     IMM,    OP_LOCK},
    {0x81, 6, -1, "xor",        RM,     IMM,    OP_LOCK},
    {0x81, 7, -1, "cmp",        RM,     IMM},
    {0x82, 0,  8, "add",        RM,     IMM8,   OP_LOCK}, /*  aliased */
    {0x82, 1,  8, "or",         RM,     IMM8,   OP_LOCK},
    {0x82, 2,  8, "adc",        RM,     IMM8,   OP_LOCK},
    {0x82, 3,  8, "sbb",        RM,     IMM8,   OP_LOCK},
    {0x82, 4,  8, "and",        RM,     IMM8,   OP_LOCK},
    {0x82, 5,  8, "sub",        RM,     IMM8,   OP_LOCK},
    {0x82, 6,  8, "xor",        RM,     IMM8,   OP_LOCK},
    {0x82, 7,  8, "cmp",        RM,     IMM8},
    {0x83, 0, -1, "add",        RM,     IMM8,   OP_LOCK},
    {0x83, 1, -1, "or",         RM,     IMM8,   OP_LOCK},
    {0x83, 2, -1, "adc",        RM,     IMM8,   OP_LOCK},
    {0x83, 3, -1, "sbb",        RM,     IMM8,   OP_LOCK},
    {0x83, 4, -1, "and",        RM,     IMM8,   OP_LOCK},
    {0x83, 5, -1, "sub",        RM,     IMM8,   OP_LOCK},
    {0x83, 6, -1, "xor",        RM,     IMM8,   OP_LOCK},
    {0x83, 7, -1, "cmp",        RM,     IMM8},

    {0x8F, 0, -1, "pop",        RM,     0,      OP_STACK},

    {0xC0, 0,  8, "rol",        RM,     IMM8},
    {0xC0, 1,  8, "ror",        RM,     IMM8},
    {0xC0, 2,  8, "rcl",        RM,     IMM8},
    {0xC0, 3,  8, "rcr",        RM,     IMM8},
    {0xC0, 4,  8, "shl",        RM,     IMM8},
    {0xC0, 5,  8, "shr",        RM,     IMM8},
    {0xC0, 6,  8, "sal",        RM,     IMM8}, /* aliased to shl */
    {0xC0, 7,  8, "sar",        RM,     IMM8},
    {0xC1, 0, -1, "rol",        RM,     IMM8},
    {0xC1, 1, -1, "ror",        RM,     IMM8},
    {0xC1, 2, -1, "rcl",        RM,     IMM8},
    {0xC1, 3, -1, "rcr",        RM,     IMM8},
    {0xC1, 4, -1, "shl",        RM,     IMM8},
    {0xC1, 5, -1, "shr",        RM,     IMM8},
    {0xC1, 6, -1, "sal",        RM,     IMM8}, /* aliased to shl */
    {0xC1, 7, -1, "sar",        RM,     IMM8},

    {0xC6, 0,  8, "mov",        RM,     IMM},
    {0xC7, 0, -1, "mov",        RM,     IMM},

    {0xD0, 0,  8, "rol",        RM,     ONE},
    {0xD0, 1,  8, "ror",        RM,     ONE},
    {0xD0, 2,  8, "rcl",        RM,     ONE},
    {0xD0, 3,  8, "rcr",        RM,     ONE},
    {0xD0, 4,  8, "shl",        RM,     ONE},
    {0xD0, 5,  8, "shr",        RM,     ONE},
    {0xD0, 6,  8, "sal",        RM,     ONE}, /* aliased to shl */
    {0xD0, 7,  8, "sar",        RM,     ONE},
    {0xD1, 0, -1, "rol",        RM,     ONE},
    {0xD1, 1, -1, "ror",        RM,     ONE},
    {0xD1, 2, -1, "rcl",        RM,     ONE},
    {0xD1, 3, -1, "rcr",        RM,     ONE},
    {0xD1, 4, -1, "shl",        RM,     ONE},
    {0xD1, 5, -1, "shr",        RM,     ONE},
    {0xD1, 6, -1, "sal",        RM,     ONE}, /* aliased to shl */
    {0xD1, 7, -1, "sar",        RM,     ONE},
    {0xD2, 0,  8, "rol",        RM,     CL},
    {0xD2, 1,  8, "ror",        RM,     CL},
    {0xD2, 2,  8, "rcl",        RM,     CL},
    {0xD2, 3,  8, "rcr",        RM,     CL},
    {0xD2, 4,  8, "shl",        RM,     CL},
    {0xD2, 5,  8, "shr",        RM,     CL},
    {0xD2, 6,  8, "sal",        RM,     CL}, /* aliased to shl */
    {0xD2, 7,  8, "sar",        RM,     CL},
    {0xD3, 0, -1, "rol",        RM,     CL},
    {0xD3, 1, -1, "ror",        RM,     CL},
    {0xD3, 2, -1, "rcl",        RM,     CL},
    {0xD3, 3, -1, "rcr",        RM,     CL},
    {0xD3, 4, -1, "shl",        RM,     CL},
    {0xD3, 5, -1, "shr",        RM,     CL},
    {0xD3, 6, -1, "sal",        RM,     CL}, /* aliased to shl */
    {0xD3, 7, -1, "sar",        RM,     CL},

    {0xF6, 0,  8, "test",       RM,     IMM},
    {0xF6, 1,  8, "test",       RM,     IMM},   /* aliased to 0 */
    {0xF6, 2,  8, "not",        RM,     0,      OP_LOCK},
    {0xF6, 3,  8, "neg",        RM,     0,      OP_LOCK},
    {0xF6, 4,  8, "mul",        RM},
    {0xF6, 5,  8, "imul",       RM},
    {0xF6, 6,  8, "div",        RM},
    {0xF6, 7,  8, "idiv",       RM},
    {0xF7, 0, -1, "test",       RM,     IMM},
    {0xF7, 1, -1, "test",       RM,     IMM},   /* aliased to 0 */
    {0xF7, 2, -1, "not",        RM,     0,      OP_LOCK},
    {0xF7, 3, -1, "neg",        RM,     0,      OP_LOCK},
    {0xF7, 4, -1, "mul",        RM},
    {0xF7, 5, -1, "imul",       RM},
    {0xF7, 6, -1, "div",        RM},
    {0xF7, 7, -1, "idiv",       RM},

    {0xFE, 0,  8, "inc",        RM,     0,      OP_LOCK},
    {0xFE, 1,  8, "dec",        RM,     0,      OP_LOCK},
    {0xFF, 0, -1, "inc",        RM,     0,      OP_LOCK},
    {0xFF, 1, -1, "dec",        RM,     0,      OP_LOCK},
    {0xFF, 2, -1, "call",       RM,     0,      OP_64},
    {0xFF, 3, -1, "call",       MEM,    0,      OP_64|OP_FAR},          /* a change in bitness should only happen across segment boundaries */
    {0xFF, 4, -1, "jmp",        RM,     0,      OP_64|OP_STOP},
    {0xFF, 5, -1, "jmp",        MEM,    0,      OP_64|OP_STOP|OP_FAR},  /* a change in bitness should only happen across segment boundaries */
    {0xFF, 6, -1, "push",       RM,     0,      OP_STACK},
};

/* a subcode value of 8 means all subcodes,
 * or the subcode marks the register if there is one present. */
static const struct op instructions_0F[] = {
    {0x00, 0, -1, "sldt",       RM,     0,      OP_OP32_REGONLY},       /* todo: implement this flag */
    {0x00, 1, -1, "str",        RM,     0,      OP_OP32_REGONLY},
    {0x00, 2, 16, "lldt",       RM},
    {0x00, 3, 16, "ltr",        RM},
    {0x00, 4, 16, "verr",       RM},
    {0x00, 5, 16, "verw",       RM},
    /* 00/6 unused */
    /* 00/7 unused */
    {0x01, 0,  0, "sgdt",       MEM},
    {0x01, 1,  0, "sidt",       MEM},
    {0x01, 2,  0, "lgdt",       MEM},
    {0x01, 3,  0, "lidt",       MEM},
    {0x01, 4, -1, "smsw",       RM,     0,      OP_OP32_REGONLY},
    /* 01/5 unused */
    {0x01, 6, 16, "lmsw",       RM},
    {0x01, 7,  0, "invlpg",     MEM},
    {0x02, 8, -1, "lar",        REG,    RM,     OP_OP32_REGONLY},       /* fixme: should be RM16 */
    {0x03, 8, -1, "lsl",        REG,    RM,     OP_OP32_REGONLY},       /* fixme: should be RM16 */
    /* 04 unused */
    {0x05, 8,  0, "syscall"},
    {0x06, 8,  0, "clts"},
    {0x07, 8,  0, "sysret"},
    {0x08, 8,  0, "invd"},
    {0x09, 8,  0, "wbinvd"},

    {0x0d, 8, -1, "prefetch",   RM},    /* Intel has NOP here; we're just following GCC */

    {0x18, 0,  8, "prefetchnta",MEM},
    {0x18, 1,  8, "prefetcht0", MEM},
    {0x18, 2,  8, "prefetcht1", MEM},
    {0x18, 3,  8, "prefetcht2", MEM},

    {0x1f, 8, -1, "nop",        RM},

    {0x20, 8, -1, "mov",        REG32,  CR32},  /* here mod is simply ignored */
    {0x21, 8, -1, "mov",        REG32,  DR32},
    {0x22, 8, -1, "mov",        CR32,   REG32},
    {0x23, 8, -1, "mov",        DR32,   REG32},
    {0x24, 8, -1, "mov",        REG32,  TR32},
    /* 25 unused */
    {0x26, 8, -1, "mov",        TR32,   REG32},

    {0x30, 8, -1, "wrmsr"},
    {0x31, 8, -1, "rdtsc"},
    {0x32, 8, -1, "rdmsr"},
    {0x33, 8, -1, "rdpmc"},
    {0x34, 8, -1, "sysenter"},
    {0x35, 8, -1, "sysexit"},

    {0x40, 8, -1, "cmovo",      REG,    RM},
    {0x41, 8, -1, "cmovno",     REG,    RM},
    {0x42, 8, -1, "cmovb",      REG,    RM},
    {0x43, 8, -1, "cmovae",     REG,    RM},
    {0x44, 8, -1, "cmovz",      REG,    RM},
    {0x45, 8, -1, "cmovnz",     REG,    RM},
    {0x46, 8, -1, "cmovbe",     REG,    RM},
    {0x47, 8, -1, "cmova",      REG,    RM},
    {0x48, 8, -1, "cmovs",      REG,    RM},
    {0x49, 8, -1, "cmovns",     REG,    RM},
    {0x4A, 8, -1, "cmovp",      REG,    RM},
    {0x4B, 8, -1, "cmovnp",     REG,    RM},
    {0x4C, 8, -1, "cmovl",      REG,    RM},
    {0x4D, 8, -1, "cmovge",     REG,    RM},
    {0x4E, 8, -1, "cmovle",     REG,    RM},
    {0x4F, 8, -1, "cmovg",      REG,    RM},

    {0x80, 8,  0, "jo",         REL16,  0,      OP_BRANCH},
    {0x81, 8,  0, "jno",        REL16,  0,      OP_BRANCH},
    {0x82, 8,  0, "jb",         REL16,  0,      OP_BRANCH},
    {0x83, 8,  0, "jae",        REL16,  0,      OP_BRANCH},
    {0x84, 8,  0, "jz",         REL16,  0,      OP_BRANCH},
    {0x85, 8,  0, "jnz",        REL16,  0,      OP_BRANCH},
    {0x86, 8,  0, "jbe",        REL16,  0,      OP_BRANCH},
    {0x87, 8,  0, "ja",         REL16,  0,      OP_BRANCH},
    {0x88, 8,  0, "js",         REL16,  0,      OP_BRANCH},
    {0x89, 8,  0, "jns",        REL16,  0,      OP_BRANCH},
    {0x8A, 8,  0, "jp",         REL16,  0,      OP_BRANCH},
    {0x8B, 8,  0, "jnp",        REL16,  0,      OP_BRANCH},
    {0x8C, 8,  0, "jl",         REL16,  0,      OP_BRANCH},
    {0x8D, 8,  0, "jge",        REL16,  0,      OP_BRANCH},
    {0x8E, 8,  0, "jle",        REL16,  0,      OP_BRANCH},
    {0x8F, 8,  0, "jg",         REL16,  0,      OP_BRANCH},
    {0x90, 0,  8, "seto",       RM},
    {0x91, 0,  8, "setno",      RM},
    {0x92, 0,  8, "setb",       RM},
    {0x93, 0,  8, "setae",      RM},
    {0x94, 0,  8, "setz",       RM},
    {0x95, 0,  8, "setnz",      RM},
    {0x96, 0,  8, "setbe",      RM},
    {0x97, 0,  8, "seta",       RM},
    {0x98, 0,  8, "sets",       RM},
    {0x99, 0,  8, "setns",      RM},
    {0x9A, 0,  8, "setp",       RM},
    {0x9B, 0,  8, "setnp",      RM},
    {0x9C, 0,  8, "setl",       RM},
    {0x9D, 0,  8, "setge",      RM},
    {0x9E, 0,  8, "setle",      RM},
    {0x9F, 0,  8, "setg",       RM},
    {0xA0, 8, -1, "push",       FS,     0,      OP_STACK},
    {0xA1, 8, -1, "pop",        FS,     0,      OP_STACK},
    {0xA2, 8,  0, "cpuid"},
    {0xA3, 8, -1, "bt",         RM,     REG},
    {0xA4, 8, -1, "shld",       RM,     REG,    OP_ARG2_IMM8},
    {0xA5, 8, -1, "shld",       RM,     REG,    OP_ARG2_CL},
    /* A6,7 unused */
    {0xA8, 8, -1, "push",       GS,     0,      OP_STACK},
    {0xA9, 8, -1, "pop",        GS,     0,      OP_STACK},
    /* AA - rsm? */
    {0xAB, 8, -1, "bts",        RM,     REG,    OP_LOCK},
    {0xAC, 8, -1, "shrd",       RM,     REG,    OP_ARG2_IMM8},
    {0xAD, 8, -1, "shrd",       RM,     REG,    OP_ARG2_CL},
    {0xAE, 0,  0, "fxsave",     MEM},
    {0xAE, 1,  0, "fxrstor",    MEM},
    {0xAE, 2,  0, "ldmxcsr",    MEM},
    {0xAE, 3,  0, "stmxcsr",    MEM},
    {0xAE, 4,  0, "xsave",      MEM},
    {0xAE, 5,  0, "xrstor",     MEM},
    {0xAE, 7,  0, "clflush",    MEM},
    {0xAF, 8, -1, "imul",       REG,    RM},
    {0xB0, 8,  8, "cmpxchg",    RM,     REG,    OP_LOCK},
    {0xB1, 8, -1, "cmpxchg",    RM,     REG,    OP_LOCK},
    {0xB2, 8, -1, "lss",        REG,    MEM},
    {0xB3, 8, -1, "btr",        RM,     REG,    OP_LOCK},
    {0xB4, 8, -1, "lfs",        REG,    MEM},
    {0xB5, 8, -1, "lgs",        REG,    MEM},
    {0xB6, 8, -1, "movzx",      REG,    RM},
    {0xB7, 8, -1, "movzx",      REG,    RM},
    /* B8, 9, A.0-3 unused */
    {0xBA, 4, -1, "bt",         RM,     IMM8},
    {0xBA, 5, -1, "bts",        RM,     IMM8,   OP_LOCK},
    {0xBA, 6, -1, "btr",        RM,     IMM8,   OP_LOCK},
    {0xBA, 7, -1, "btc",        RM,     IMM8,   OP_LOCK},
    {0xBB, 8, -1, "btc",        RM,     REG,    OP_LOCK},
    {0xBC, 8, -1, "bsf",        REG,    RM},
    {0xBD, 8, -1, "bsr",        REG,    RM},
    {0xBE, 8, -1, "movsx",      REG,    RM},
    {0xBF, 8, -1, "movsx",      REG,    RM},
    {0xC0, 8,  8, "xadd",       RM,     REG,    OP_LOCK},
    {0xC1, 8, -1, "xadd",       RM,     REG,    OP_LOCK},

    {0xC7, 1,  0, "cmpxchg8b",  MEM,    0,      OP_LOCK},

    {0xC8, 8, -1, "bswap",      AX},
    {0xC9, 8, -1, "bswap",      CX},
    {0xCA, 8, -1, "bswap",      DX},
    {0xCB, 8, -1, "bswap",      BX},
    {0xCC, 8, -1, "bswap",      SP},
    {0xCD, 8, -1, "bswap",      BP},
    {0xCE, 8, -1, "bswap",      SI},
    {0xCF, 8, -1, "bswap",      DI},
};

/* mod < 3 (instructions with memory args) */
static const struct op instructions_fpu_m[64] = {
    {0xD8, 0, 32, "fadd",       MEM,    0,      OP_S},
    {0xD8, 1, 32, "fmul",       MEM,    0,      OP_S},
    {0xD8, 2, 32, "fcom",       MEM,    0,      OP_S},
    {0xD8, 3, 32, "fcomp",      MEM,    0,      OP_S},
    {0xD8, 4, 32, "fsub",       MEM,    0,      OP_S},
    {0xD8, 5, 32, "fsubr",      MEM,    0,      OP_S},
    {0xD8, 6, 32, "fdiv",       MEM,    0,      OP_S},
    {0xD8, 7, 32, "fdivr",      MEM,    0,      OP_S},
    {0xD9, 0, 32, "fld",        MEM,    0,      OP_S},
    {0xD9, 1},
    {0xD9, 2, 32, "fst",        MEM,    0,      OP_S},
    {0xD9, 3, 32, "fstp",       MEM,    0,      OP_S},
    {0xD9, 4,  0, "fldenv",     MEM},   /* 14/28 */
    {0xD9, 5,  0, "fldcw",      MEM},   /* 16 */
    {0xD9, 6,  0, "fnstenv",    MEM},   /* 14/28 */
    {0xD9, 7,  0, "fnstcw",     MEM},   /* 16 */
    {0xDA, 0, 32, "fiadd",      MEM,    0,      OP_L},
    {0xDA, 1, 32, "fimul",      MEM,    0,      OP_L},
    {0xDA, 2, 32, "ficom",      MEM,    0,      OP_L},
    {0xDA, 3, 32, "ficomp",     MEM,    0,      OP_L},
    {0xDA, 4, 32, "fisub",      MEM,    0,      OP_L},
    {0xDA, 5, 32, "fisubr",     MEM,    0,      OP_L},
    {0xDA, 6, 32, "fidiv",      MEM,    0,      OP_L},
    {0xDA, 7, 32, "fidivr",     MEM,    0,      OP_L},
    {0xDB, 0, 32, "fild",       MEM,    0,      OP_L},
    {0xDB, 1, 32, "fisttp",     MEM,    0,      OP_L},
    {0xDB, 2, 32, "fist",       MEM,    0,      OP_L},
    {0xDB, 3, 32, "fistp",      MEM,    0,      OP_L},
    {0xDB, 4},
    {0xDB, 5, 80, "fld",        MEM},
    {0xDB, 6},
    {0xDB, 7, 80, "fstp",       MEM},
    {0xDC, 0, 64, "fadd",       MEM,    0,      OP_L},
    {0xDC, 1, 64, "fmul",       MEM,    0,      OP_L},
    {0xDC, 2, 64, "fcom",       MEM,    0,      OP_L},
    {0xDC, 3, 64, "fcomp",      MEM,    0,      OP_L},
    {0xDC, 4, 64, "fsub",       MEM,    0,      OP_L},
    {0xDC, 5, 64, "fsubr",      MEM,    0,      OP_L},
    {0xDC, 6, 64, "fdiv",       MEM,    0,      OP_L},
    {0xDC, 7, 64, "fdivr",      MEM,    0,      OP_L},
    {0xDD, 0, 64, "fld",        MEM,    0,      OP_L},
    {0xDD, 1, 64, "fisttp",     MEM,    0,      OP_LL},
    {0xDD, 2, 64, "fst",        MEM,    0,      OP_L},
    {0xDD, 3, 64, "fstp",       MEM,    0,      OP_L},
    {0xDD, 4,  0, "frstor",     MEM},   /* 94/108 */
    {0xDD, 5},
    {0xDD, 6,  0, "fnsave",     MEM},   /* 94/108 */
    {0xDD, 7,  0, "fnstsw",     MEM},   /* 16 */
    {0xDE, 0, 16, "fiadd",      MEM,    0,      OP_S},
    {0xDE, 1, 16, "fimul",      MEM,    0,      OP_S},
    {0xDE, 2, 16, "ficom",      MEM,    0,      OP_S},
    {0xDE, 3, 16, "ficomp",     MEM,    0,      OP_S},
    {0xDE, 4, 16, "fisub",      MEM,    0,      OP_S},
    {0xDE, 5, 16, "fisubr",     MEM,    0,      OP_S},
    {0xDE, 6, 16, "fidiv",      MEM,    0,      OP_S},
    {0xDE, 7, 16, "fidivr",     MEM,    0,      OP_S},
    {0xDF, 0, 16, "fild",       MEM,    0,      OP_S},
    {0xDF, 1, 16, "fisttp",     MEM,    0,      OP_S},
    {0xDF, 2, 16, "fist",       MEM,    0,      OP_S},
    {0xDF, 3, 16, "fistp",      MEM,    0,      OP_S},
    {0xDF, 4,  0, "fbld",       MEM},   /* 80 */
    {0xDF, 5, 64, "fild",       MEM,    0,      OP_LL},
    {0xDF, 6,  0, "fbstp",      MEM},   /* 80 */
    {0xDF, 7, 64, "fistp",      MEM,    0,      OP_LL},
};

static const struct op instructions_fpu_r[64] = {
    {0xD8, 0,  0, "fadd",       ST,     STX},
    {0xD8, 1,  0, "fmul",       ST,     STX},
    {0xD8, 2,  0, "fcom",       STX,    0},
    {0xD8, 3,  0, "fcomp",      STX,    0},
    {0xD8, 4,  0, "fsub",       ST,     STX},
    {0xD8, 5,  0, "fsubr",      ST,     STX},
    {0xD8, 6,  0, "fdiv",       ST,     STX},
    {0xD8, 7,  0, "fdivr",      ST,     STX},
    {0xD9, 0,  0, "fld",        STX,    0},
    {0xD9, 1,  0, "fxch",       STX,    0},
    {0xD9, 2,  0, {0},          0,      0},     /* fnop */
    {0xD9, 3,  0, "fstp",       STX,    0},     /* partial alias - see ref.x86asm.net */
    {0xD9, 4,  0, {0},          0,      0},     /* fchs, fabs, ftst, fxam */
    {0xD9, 5,  0, {0},          0,      0},     /* fldXXX */
    {0xD9, 6,  0, {0},          0,      0},     /* f2xm1, fyl2x, ... */
    {0xD9, 7,  0, {0},          0,      0},     /* fprem, fyl2xp1, ... */
    {0xDA, 0,  0, "fcmovb",     ST,     STX},
    {0xDA, 1,  0, "fcmove",     ST,     STX},
    {0xDA, 2,  0, "fcmovbe",    ST,     STX},
    {0xDA, 3,  0, "fcmovu",     ST,     STX},
    {0xDA, 4,  0, {0},          0,      0},
    {0xDA, 5,  0, {0},          0,      0},     /* fucompp */
    {0xDA, 6,  0, {0},          0,      0},
    {0xDA, 7,  0, {0},          0,      0},
    {0xDB, 0,  0, "fcmovnb",    ST,     STX},
    {0xDB, 1,  0, "fcmovne",    ST,     STX},
    {0xDB, 2,  0, "fcmovnbe",   ST,     STX},
    {0xDB, 3,  0, "fcmovnu",    ST,     STX},
    {0xDB, 4,  0, {0},          0,      0},     /* fneni, fndisi, fnclex, fninit, fnsetpm */
    {0xDB, 5,  0, "fucomi",     ST,     STX},
    {0xDB, 6,  0, "fcomi",      ST,     STX},
    {0xDB, 7,  0, {0},          0,      0},
    {0xDC, 0,  0, "fadd",       STX,    ST},
    {0xDC, 1,  0, "fmul",       STX,    ST},
    {0xDC, 2,  0, "fcom",       STX,    0},     /* alias */
    {0xDC, 3,  0, "fcomp",      STX,    0},     /* alias */
    {0xDC, 4,  0, "fsubr",      STX,    ST},    /* nasm, masm, sandpile have these reversed, gcc doesn't */
    {0xDC, 5,  0, "fsub",       STX,    ST},
    {0xDC, 6,  0, "fdivr",      STX,    ST},
    {0xDC, 7,  0, "fdiv",       STX,    ST},
    {0xDD, 0,  0, "ffree",      STX,    0},
    {0xDD, 1,  0, "fxch",       STX,    0},     /* alias */
    {0xDD, 2,  0, "fst",        STX,    0},
    {0xDD, 3,  0, "fstp",       STX,    0},
    {0xDD, 4,  0, "fucom",      STX,    0},
    {0xDD, 5,  0, "fucomp",     STX,    0},
    {0xDD, 6,  0, {0},          0,      0},
    {0xDD, 7,  0, {0},          0,      0},
    {0xDE, 0,  0, "faddp",      STX,    ST},
    {0xDE, 1,  0, "fmulp",      STX,    ST},
    {0xDE, 2,  0, "fcomp",      STX,    0},     /* alias */
    {0xDE, 3,  0, {0},          0,      0},     /* fcompp */
    {0xDE, 4,  0, "fsubrp",     STX,    ST},    /* nasm, masm, sandpile have these reversed, gcc doesn't */
    {0xDE, 5,  0, "fsubp",      STX,    ST},
    {0xDE, 6,  0, "fdivrp",     STX,    ST},
    {0xDE, 7,  0, "fdivp",      STX,    ST},
    {0xDF, 0,  0, "ffreep",     STX,    0},     /* unofficial name */
    {0xDF, 1,  0, "fxch",       STX,    0},     /* alias */
    {0xDF, 2,  0, "fstp",       STX,    0},     /* alias */
    {0xDF, 3,  0, "fstp",       STX,    0},     /* alias */
    {0xDF, 4,  0, {0},          0,      0},     /* fnstsw */
    {0xDF, 5,  0, "fucomip",    ST,     STX},
    {0xDF, 6,  0, "fcomip",     ST,     STX},
    {0xDF, 7,  0, {0},          0,      0},
};

static const struct op instructions_fpu_single[] = {
    {0xD9, 0xD0, 0, "fnop"},
    {0xD9, 0xE0, 0, "fchs"},
    {0xD9, 0xE1, 0, "fabs"},
    {0xD9, 0xE4, 0, "ftst"},
    {0xD9, 0xE5, 0, "fxam"},
    {0xD9, 0xE8, 0, "fld1"},
    {0xD9, 0xE9, 0, "fldl2t"},
    {0xD9, 0xEA, 0, "fldl2e"},
    {0xD9, 0xEB, 0, "fldpi"},
    {0xD9, 0xEC, 0, "fldlg2"},
    {0xD9, 0xED, 0, "fldln2"},
    {0xD9, 0xEE, 0, "fldz"},
    {0xD9, 0xF0, 0, "f2xm1"},
    {0xD9, 0xF1, 0, "fyl2x"},
    {0xD9, 0xF2, 0, "fptan"},
    {0xD9, 0xF3, 0, "fpatan"},
    {0xD9, 0xF4, 0, "fxtract"},
    {0xD9, 0xF5, 0, "fprem1"},
    {0xD9, 0xF6, 0, "fdecstp"},
    {0xD9, 0xF7, 0, "fincstp"},
    {0xD9, 0xF8, 0, "fprem"},
    {0xD9, 0xF9, 0, "fyl2xp1"},
    {0xD9, 0xFA, 0, "fsqrt"},
    {0xD9, 0xFB, 0, "fsincos"},
    {0xD9, 0xFC, 0, "frndint"},
    {0xD9, 0xFD, 0, "fscale"},
    {0xD9, 0xFE, 0, "fsin"},
    {0xD9, 0xFF, 0, "fcos"},
    {0xDA, 0xE9, 0, "fucompp"},
    {0xDB, 0xE0, 0, "fneni"},
    {0xDB, 0xE1, 0, "fndisi"},
    {0xDB, 0xE2, 0, "fnclex"},
    {0xDB, 0xE3, 0, "fninit"},
    {0xDB, 0xE4, 0, "fnsetpm"},
    {0xDE, 0xD9, 0, "fcompp"},
    {0xDF, 0xE0, 0, "fnstsw", AX},
};

static int get_fpu_instr(const byte *p, struct op *op) {
    byte subcode = REGOF(p[1]);
    byte index = (p[0] & 7)*8 + subcode;
    unsigned i;

    if (MODOF(p[1]) < 3) {
        if (instructions_fpu_m[index].name[0])
            *op = instructions_fpu_m[index];
        return 0;
    } else {
        if (instructions_fpu_r[index].name[0]) {
            *op = instructions_fpu_r[index];
            return 0;
        } else {
            /* try the single op list */
            for (i=0; i<sizeof(instructions_fpu_single)/sizeof(struct op); i++) {
                if (p[0] == instructions_fpu_single[i].opcode &&
                    p[1] == instructions_fpu_single[i].subcode) {
                    *op = instructions_fpu_single[i];
                    break;
                }
            }
        }
        return 1;
    }
}

static const struct op instructions_sse[] = {
    {0x10, 8,  0, "movups",     XMM,    XM},
    {0x11, 8,  0, "movups",     XM,     XMM},
    {0x12, 8,  0, "movlps",     XMM,    XM},    /* fixme: movhlps */
    {0x13, 8,  0, "movlps",     MEM,    XMM},
    {0x14, 8,  0, "unpcklps",   XMM,    XM},
    {0x15, 8,  0, "unpckhps",   XMM,    XM},
    {0x16, 8,  0, "movhps",     XMM,    XM},    /* fixme: movlhps */
    {0x17, 8,  0, "movhps",     MEM,    XMM},

    {0x28, 8,  0, "movaps",     XMM,    XM},
    {0x29, 8,  0, "movaps",     XM,     XMM},
    {0x2A, 8,  0, "cvtpi2ps",   XMM,    MM},
    {0x2B, 8,  0, "movntps",    MEM,    XMM},
    {0x2C, 8,  0, "cvttps2pi",  MMX,    XM},
    {0x2D, 8,  0, "cvtps2pi",   MMX,    XM},
    {0x2E, 8,  0, "ucomiss",    XMM,    XM},
    {0x2F, 8,  0, "comiss",     XMM,    XM},

    {0x50, 8,  0, "movmskps",   REGONLY,XMM},
    {0x51, 8,  0, "sqrtps",     XMM,    XM},
    {0x52, 8,  0, "rsqrtps",    XMM,    XM},
    {0x53, 8,  0, "rcpps",      XMM,    XM},
    {0x54, 8,  0, "andps",      XMM,    XM},
    {0x55, 8,  0, "andnps",     XMM,    XM},
    {0x56, 8,  0, "orps",       XMM,    XM},
    {0x57, 8,  0, "xorps",      XMM,    XM},
    {0x58, 8,  0, "addps",      XMM,    XM},
    {0x59, 8,  0, "mulps",      XMM,    XM},
    {0x5A, 8,  0, "cvtps2pd",   XMM,    XM},
    {0x5B, 8,  0, "cvtdq2ps",   XMM,    XM},
    {0x5C, 8,  0, "subps",      XMM,    XM},
    {0x5D, 8,  0, "minps",      XMM,    XM},
    {0x5E, 8,  0, "divps",      XMM,    XM},
    {0x5F, 8,  0, "maxps",      XMM,    XM},
    {0x60, 8,  0, "punpcklbw",  MMX,    MM},
    {0x61, 8,  0, "punpcklwd",  MMX,    MM},
    {0x62, 8,  0, "punpckldq",  MMX,    MM},
    {0x63, 8,  0, "packsswb",   MMX,    MM},
    {0x64, 8,  0, "pcmpgtb",    MMX,    MM},
    {0x65, 8,  0, "pcmpgtw",    MMX,    MM},
    {0x66, 8,  0, "pcmpgtd",    MMX,    MM},
    {0x67, 8,  0, "packuswb",   MMX,    MM},
    {0x68, 8,  0, "punpckhbw",  MMX,    MM},
    {0x69, 8,  0, "punpckhwd",  MMX,    MM},
    {0x6A, 8,  0, "punpckhdq",  MMX,    MM},
    {0x6B, 8,  0, "packssdw",   MMX,    MM},
    /* 6C/D unused */
    {0x6E, 8,  0, "movd",       MMX,    RM},
    {0x6F, 8,  0, "movq",       MMX,    MM},
    {0x70, 8,  0, "pshufw",     MMX,    MM,     OP_ARG2_IMM8},
    {0x71, 2,  0, "psrlw",      MMXONLY,IMM8},  /* fixme: make sure this works */
    {0x71, 4,  0, "psraw",      MMXONLY,IMM8},
    {0x71, 6,  0, "psllw",      MMXONLY,IMM8},
    {0x72, 2,  0, "psrld",      MMXONLY,IMM8},
    {0x72, 4,  0, "psrad",      MMXONLY,IMM8},
    {0x72, 6,  0, "pslld",      MMXONLY,IMM8},
    {0x73, 2,  0, "psrlq",      MMXONLY,IMM8},
    {0x73, 6,  0, "psllq",      MMXONLY,IMM8},
    {0x74, 8,  0, "pcmpeqb",    MMX,    MM},
    {0x75, 8,  0, "pcmpeqw",    MMX,    MM},
    {0x76, 8,  0, "pcmpeqd",    MMX,    MM},
    {0x77, 8,  0, "emms"},

    {0x7E, 8,  0, "movd",       RM,     MMX},
    {0x7F, 8,  0, "movq",       MM,     MMX},

    {0xC2, 8,  0, "cmpps",      XMM,    XM,     OP_ARG2_IMM8},
    {0xC3, 8,  0, "movnti",     MEM,    REG},
    {0xC4, 8,  0, "pinsrw",     MMX,    RM,     OP_ARG2_IMM8},
    {0xC5, 8,  0, "pextrw",     REGONLY,MMX,    OP_ARG2_IMM8},
    {0xC6, 8,  0, "shufps",     XMM,    XM,     OP_ARG2_IMM8},

    {0xD1, 8,  0, "psrlw",      MMX,    MM},
    {0xD2, 8,  0, "psrld",      MMX,    MM},
    {0xD3, 8,  0, "psrlq",      MMX,    MM},
    {0xD4, 8,  0, "paddq",      MMX,    MM},
    {0xD5, 8,  0, "pmullw",     MMX,    MM},
    /* D6 unused */
    {0xD7, 8,  0, "pmovmskb",   REGONLY,MMX},
    {0xD8, 8,  0, "psubusb",    MMX,    MM},
    {0xD9, 8,  0, "psubusw",    MMX,    MM},
    {0xDA, 8,  0, "pminub",     MMX,    MM},
    {0xDB, 8,  0, "pand",       MMX,    MM},
    {0xDC, 8,  0, "paddusb",    MMX,    MM},
    {0xDD, 8,  0, "paddusw",    MMX,    MM},
    {0xDE, 8,  0, "pmaxub",     MMX,    MM},
    {0xDF, 8,  0, "pandn",      MMX,    MM},
    {0xE0, 8,  0, "pavgb",      MMX,    MM},
    {0xE1, 8,  0, "psraw",      MMX,    MM},
    {0xE2, 8,  0, "psrad",      MMX,    MM},
    {0xE3, 8,  0, "pavgw",      MMX,    MM},
    {0xE4, 8,  0, "pmulhuw",    MMX,    MM},
    {0xE5, 8,  0, "pmulhw",     MMX,    MM},
    /* E6 unused */
    {0xE7, 8,  0, "movntq",     MEM,    MMX},
    {0xE8, 8,  0, "psubsb",     MMX,    MM},
    {0xE9, 8,  0, "psubsw",     MMX,    MM},
    {0xEA, 8,  0, "pminsw",     MMX,    MM},
    {0xEB, 8,  0, "por",        MMX,    MM},
    {0xEC, 8,  0, "paddsb",     MMX,    MM},
    {0xED, 8,  0, "paddsw",     MMX,    MM},
    {0xEE, 8,  0, "pmaxsw",     MMX,    MM},
    {0xEF, 8,  0, "pxor",       MMX,    MM},
    /* F0 unused */
    {0xF1, 8,  0, "psllw",      MMX,    MM},
    {0xF2, 8,  0, "pslld",      MMX,    MM},
    {0xF3, 8,  0, "psllq",      MMX,    MM},
    {0xF4, 8,  0, "pmuludq",    MMX,    MM},
    {0xF5, 8,  0, "pmaddwd",    MMX,    MM},
    {0xF6, 8,  0, "psadbw",     MMX,    MM},
    {0xF7, 8,  0, "maskmovq",   MMX,    MMXONLY},
    {0xF8, 8,  0, "psubb",      MMX,    MM},
    {0xF9, 8,  0, "psubw",      MMX,    MM},
    {0xFA, 8,  0, "psubd",      MMX,    MM},
    {0xFB, 8,  0, "psubq",      MMX,    MM},
    {0xFC, 8,  0, "paddb",      MMX,    MM},
    {0xFD, 8,  0, "paddw",      MMX,    MM},
    {0xFE, 8,  0, "paddd",      MMX,    MM},
};

static const struct op instructions_sse_op32[] = {
    {0x10, 8,  0, "movupd",     XMM,    XM},
    {0x11, 8,  0, "movupd",     XM,     XMM},
    {0x12, 8,  0, "movlpd",     XMM,    XM},    /* fixme: movhlps */
    {0x13, 8,  0, "movlpd",     MEM,    XMM},
    {0x14, 8,  0, "unpcklpd",   XMM,    XM},
    {0x15, 8,  0, "unpckhpd",   XMM,    XM},
    {0x16, 8,  0, "movhpd",     XMM,    XM},    /* fixme: movlhps */
    {0x17, 8,  0, "movhpd",     MEM,    XMM},

    {0x28, 8,  0, "movapd",     XMM,    XM},
    {0x29, 8,  0, "movapd",     XM,     XMM},
    {0x2A, 8,  0, "cvtpi2pd",   XMM,    MM},
    {0x2B, 8,  0, "movntpd",    MEM,    XMM},
    {0x2C, 8,  0, "cvttpd2pi",  MMX,    XM},
    {0x2D, 8,  0, "cvtpd2pi",   MMX,    XM},
    {0x2E, 8,  0, "ucomisd",    XMM,    XM},
    {0x2F, 8,  0, "comisd",     XMM,    XM},

    {0x50, 8, 32, "movmskpd",   REGONLY,XMM},
    {0x51, 8,  0, "sqrtpd",     XMM,    XM},
    /* 52/3 unused */
    {0x54, 8,  0, "andpd",      XMM,    XM},
    {0x55, 8,  0, "andnpd",     XMM,    XM},
    {0x56, 8,  0, "orpd",       XMM,    XM},
    {0x57, 8,  0, "xorpd",      XMM,    XM},
    {0x58, 8,  0, "addpd",      XMM,    XM},
    {0x59, 8,  0, "mulpd",      XMM,    XM},
    {0x5A, 8,  0, "cvtpd2ps",   XMM,    XM},
    {0x5B, 8,  0, "cvtps2dq",   XMM,    XM},
    {0x5C, 8,  0, "subpd",      XMM,    XM},
    {0x5D, 8,  0, "minpd",      XMM,    XM},
    {0x5E, 8,  0, "divpd",      XMM,    XM},
    {0x5F, 8,  0, "maxpd",      XMM,    XM},
    {0x60, 8,  0, "punpcklbw",  XMM,    XM},
    {0x61, 8,  0, "punpcklwd",  XMM,    XM},
    {0x62, 8,  0, "punpckldq",  XMM,    XM},
    {0x63, 8,  0, "packsswb",   XMM,    XM},
    {0x64, 8,  0, "pcmpgtb",    XMM,    XM},
    {0x65, 8,  0, "pcmpgtw",    XMM,    XM},
    {0x66, 8,  0, "pcmpgtd",    XMM,    XM},
    {0x67, 8,  0, "packuswb",   XMM,    XM},
    {0x68, 8,  0, "punpckhbw",  XMM,    XM},
    {0x69, 8,  0, "punpckhwd",  XMM,    XM},
    {0x6A, 8,  0, "punpckhdq",  XMM,    XM},
    {0x6B, 8,  0, "packssdw",   XMM,    XM},
    {0x6C, 8,  0, "punpcklqdq", XMM,    XM},
    {0x6D, 8,  0, "punpckhqdq", XMM,    XM},
    {0x6E, 8, -1, "mov",        XMM,    RM},
    {0x6F, 8,  0, "movdqa",     XMM,    XM},
    {0x70, 8,  0, "pshufd",     XMM,    XM,    OP_ARG2_IMM8},
    {0x71, 2,  0, "psrlw",      XMMONLY,IMM8},
    {0x71, 4,  0, "psraw",      XMMONLY,IMM8},
    {0x71, 6,  0, "psllw",      XMMONLY,IMM8},
    {0x72, 2,  0, "psrld",      XMMONLY,IMM8},
    {0x72, 4,  0, "psrad",      XMMONLY,IMM8},
    {0x72, 6,  0, "pslld",      XMMONLY,IMM8},
    {0x73, 2,  0, "psrlq",      XMMONLY,IMM8},
    {0x73, 3,  0, "psrldq",     XMMONLY,IMM8},
    {0x73, 6,  0, "psllq",      XMMONLY,IMM8},
    {0x73, 7,  0, "pslldq",     XMMONLY,IMM8},
    {0x74, 8,  0, "pcmpeqb",    XMM,    XM},
    {0x75, 8,  0, "pcmpeqw",    XMM,    XM},
    {0x76, 8,  0, "pcmpeqd",    XMM,    XM},

    {0x7C, 8,  0, "haddpd",     XMM,    XM},
    {0x7D, 8,  0, "hsubpd",     XMM,    XM},
    {0x7E, 8, -1, "mov",        RM,     XMM},
    {0x7F, 8,  0, "movdqa",     XM,     XMM},

    {0xC2, 8,  0, "cmppd",      XMM,    XM,     OP_ARG2_IMM8},
    /* C3 unused */
    {0xC4, 8,  0, "pinsrw",     XMM,    RM,     OP_ARG2_IMM8},
    {0xC5, 8,  0, "pextrw",     REGONLY,XMM,    OP_ARG2_IMM8},
    {0xC6, 8,  0, "shufpd",     XMM,    XM,     OP_ARG2_IMM8},

    {0xD0, 8,  0, "addsubpd",   XMM,    XM},
    {0xD1, 8,  0, "psrlw",      XMM,    XM},
    {0xD2, 8,  0, "psrld",      XMM,    XM},
    {0xD3, 8,  0, "psrlq",      XMM,    XM},
    {0xD4, 8,  0, "paddd",      XMM,    XM},
    {0xD5, 8,  0, "pmullw",     XMM,    XM},
    {0xD6, 8,  0, "movq",       XM,     XMM},
    {0xD7, 8, 32, "pmovmskb",   REGONLY,XMM},
    {0xD8, 8,  0, "psubusb",    XMM,    XM},
    {0xD9, 8,  0, "psubusw",    XMM,    XM},
    {0xDA, 8,  0, "pminub",     XMM,    XM},
    {0xDB, 8,  0, "pand",       XMM,    XM},
    {0xDC, 8,  0, "paddusb",    XMM,    XM},
    {0xDD, 8,  0, "paddusw",    XMM,    XM},
    {0xDE, 8,  0, "pmaxub",     XMM,    XM},
    {0xDF, 8,  0, "pandn",      XMM,    XM},
    {0xE0, 8,  0, "pavgb",      XMM,    XM},
    {0xE1, 8,  0, "psraw",      XMM,    XM},
    {0xE2, 8,  0, "psrad",      XMM,    XM},
    {0xE3, 8,  0, "pavgw",      XMM,    XM},
    {0xE4, 8,  0, "pmulhuw",    XMM,    XM},
    {0xE5, 8,  0, "pmulhw",     XMM,    XM},
    {0xE6, 8,  0, "cvttpd2dq",  XMM,    XM},
    {0xE7, 8,  0, "movntdq",    MEM,    XMM},
    {0xE8, 8,  0, "psubsb",     XMM,    XM},
    {0xE9, 8,  0, "psubsw",     XMM,    XM},
    {0xEA, 8,  0, "pminsw",     XMM,    XM},
    {0xEB, 8,  0, "por",        XMM,    XM},
    {0xEC, 8,  0, "paddsb",     XMM,    XM},
    {0xED, 8,  0, "paddsw",     XMM,    XM},
    {0xEE, 8,  0, "pmaxsw",     XMM,    XM},
    {0xEF, 8,  0, "pxor",       XMM,    XM},
    /* F0 unused */
    {0xF1, 8,  0, "psllw",      XMM,    XM},
    {0xF2, 8,  0, "pslld",      XMM,    XM},
    {0xF3, 8,  0, "psllq",      XMM,    XM},
    {0xF4, 8,  0, "pmuludq",    XMM,    XM},
    {0xF5, 8,  0, "pmaddwd",    XMM,    XM},
    {0xF6, 8,  0, "psadbw",     XMM,    XM},
    {0xF7, 8,  0, "maskmovdqu", XMM,    XMMONLY},
    {0xF8, 8,  0, "psubb",      XMM,    XM},
    {0xF9, 8,  0, "psubw",      XMM,    XM},
    {0xFA, 8,  0, "psubd",      XMM,    XM},
    {0xFB, 8,  0, "psubq",      XMM,    XM},
    {0xFC, 8,  0, "paddb",      XMM,    XM},
    {0xFD, 8,  0, "paddw",      XMM,    XM},
    {0xFE, 8,  0, "paddd",      XMM,    XM},
};

static const struct op instructions_sse_repne[] = {
    {0x10, 8,  0, "movsd",      XMM,    XM},
    {0x11, 8,  0, "movsd",      XM,     XMM},
    {0x12, 8,  0, "movddup",    XMM,    XM},

    {0x2A, 8,  0, "cvtsi2sd",   XMM,    RM},

    {0x2C, 8,  0, "cvttsd2si",  REG,    XM},
    {0x2D, 8,  0, "cvtsd2si",   REG,    XM},

    {0x51, 8,  0, "sqrtsd",     XMM,    XM},

    {0x58, 8,  0, "addsd",      XMM,    XM},
    {0x59, 8,  0, "mulsd",      XMM,    XM},
    {0x5A, 8,  0, "cvtsd2ss",   XMM,    XM},

    {0x5C, 8,  0, "subsd",      XMM,    XM},
    {0x5D, 8,  0, "minsd",      XMM,    XM},
    {0x5E, 8,  0, "divsd",      XMM,    XM},
    {0x5F, 8,  0, "maxsd",      XMM,    XM},

    {0x70, 8,  0, "pshuflw",    XMM,    XM,     OP_ARG2_IMM8},

    {0x7C, 8,  0, "haddps",     XMM,    XM},
    {0x7D, 8,  0, "hsubps",     XMM,    XM},

    {0xC2, 8,  0, "cmpsd",      XMM,    XM,     OP_ARG2_IMM8},

    {0xD0, 8,  0, "addsubps",   XMM,    XM},

/*    {0xD6, 8,  0, "movdq2q",    MMX,    XMM}, */

    {0xE6, 8,  0, "cvtpd2dq",   XMM,    XM},

    {0xF0, 8,  0, "lddqu",      XMM,    MEM},
};

static const struct op instructions_sse_repe[] = {
    {0x10, 8,  0, "movss",      XMM,    XM},
    {0x11, 8,  0, "movss",      XM,     XMM},
    {0x12, 8,  0, "movsldup",   XMM,    XM},

    {0x16, 8,  0, "movshdup",   XMM,    XM},

    {0x2A, 8,  0, "cvtsi2ss",   XMM,    RM},

    {0x2C, 8,  0, "cvttss2si",  REG,    XM},
    {0x2D, 8,  0, "cvtss2si",   REG,    XM},

    {0x51, 8,  0, "sqrtss",     XMM,    XM},
    {0x52, 8,  0, "rsqrtss",    XMM,    XM},
    {0x53, 8,  0, "rcpss",      XMM,    XM},

    {0x58, 8,  0, "addss",      XMM,    XM},
    {0x59, 8,  0, "mulss",      XMM,    XM},
    {0x5A, 8,  0, "cvtss2sd",   XMM,    XM},
    {0x5B, 8,  0, "cvttps2dq",  XMM,    XM},
    {0x5C, 8,  0, "subss",      XMM,    XM},
    {0x5D, 8,  0, "minss",      XMM,    XM},
    {0x5E, 8,  0, "divss",      XMM,    XM},
    {0x5F, 8,  0, "maxss",      XMM,    XM},

    {0x6F, 8,  0, "movdqu",     XMM,    XM},
    {0x70, 8,  0, "pshufhw",    XMM,    XM,     OP_ARG2_IMM8},

    {0x7E, 8,  0, "movq",       XMM,    XM},
    {0x7F, 8,  0, "movdqu",     XM,     XMM},

    {0xB8, 8, 16, "popcnt",     REG,    RM},    /* not SSE */

    {0xC2, 8,  0, "cmpss",      XMM,    XM,     OP_ARG2_IMM8},

/*    {0xD6, 8,  0, "movq2dq",    XMM,    MMX}, */

    {0xE6, 8,  0, "cvtdq2pd",   XMM,    XM},
};

static const struct op instructions_sse_single[] = {
    {0x38, 0x00, 0, "pshufb",       MMX,    MM},
    {0x38, 0x01, 0, "phaddw",       MMX,    MM},
    {0x38, 0x02, 0, "phaddd",       MMX,    MM},
    {0x38, 0x03, 0, "phaddsw",      MMX,    MM},
    {0x38, 0x04, 0, "pmaddubsw",    MMX,    MM},
    {0x38, 0x05, 0, "phsubw",       MMX,    MM},
    {0x38, 0x06, 0, "phsubd",       MMX,    MM},
    {0x38, 0x07, 0, "phsubsw",      MMX,    MM},
    {0x38, 0x08, 0, "psignb",       MMX,    MM},
    {0x38, 0x09, 0, "psignw",       MMX,    MM},
    {0x38, 0x0A, 0, "psignd",       MMX,    MM},
    {0x38, 0x0B, 0, "pmulhrsw",     MMX,    MM},

    {0x38, 0x1C, 0, "pabsb",        MMX,    MM},
    {0x38, 0x1D, 0, "pabsw",        MMX,    MM},
    {0x38, 0x1E, 0, "pabsd",        MMX,    MM},

    {0x38, 0xF0,16, "movbe",        REG,    MEM},   /* not SSE */
    {0x38, 0xF1,16, "movbe",        MEM,    REG},   /* not SSE */

    {0x3A, 0x0F, 0, "palignr",      MMX,    MM,     OP_ARG2_IMM8},
};

static const struct op instructions_sse_single_op32[] = {
    {0x38, 0x00, 0, "pshufb",       XMM,    XM},
    {0x38, 0x01, 0, "phaddw",       XMM,    XM},
    {0x38, 0x02, 0, "phaddd",       XMM,    XM},
    {0x38, 0x03, 0, "phaddsw",      XMM,    XM},
    {0x38, 0x04, 0, "pmaddubsw",    XMM,    XM},
    {0x38, 0x05, 0, "phsubw",       XMM,    XM},
    {0x38, 0x06, 0, "phsubd",       XMM,    XM},
    {0x38, 0x07, 0, "phsubsw",      XMM,    XM},
    {0x38, 0x08, 0, "psignb",       XMM,    XM},
    {0x38, 0x09, 0, "psignw",       XMM,    XM},
    {0x38, 0x0A, 0, "psignd",       XMM,    XM},
    {0x38, 0x0B, 0, "pmulhrsw",     XMM,    XM},

    {0x38, 0x10, 0, "pblendvb",     XMM,    XM},

    {0x38, 0x14, 0, "blendvps",     XMM,    XM},
    {0x38, 0x15, 0, "blendvpd",     XMM,    XM},

    {0x38, 0x17, 0, "ptest",        XMM,    XM},

    {0x38, 0x1C, 0, "pabsb",        XMM,    XM},
    {0x38, 0x1D, 0, "pabsw",        XMM,    XM},
    {0x38, 0x1E, 0, "pabsd",        XMM,    XM},

    {0x38, 0x20, 0, "pmovsxbw",     XMM,    XM},
    {0x38, 0x21, 0, "pmovsxbd",     XMM,    XM},
    {0x38, 0x22, 0, "pmovsxbq",     XMM,    XM},
    {0x38, 0x23, 0, "pmovsxwd",     XMM,    XM},
    {0x38, 0x24, 0, "pmovsxwq",     XMM,    XM},
    {0x38, 0x25, 0, "pmovsxdq",     XMM,    XM},

    {0x38, 0x28, 0, "pmuldq",       XMM,    XM},
    {0x38, 0x29, 0, "pcmpeqq",      XMM,    XM},
    {0x38, 0x2A, 0, "movntdqa",     XMM,    MEM},
    {0x38, 0x2B, 0, "packusdw",     XMM,    XM},

    {0x38, 0x30, 0, "pmovzxbw",     XMM,    XM},
    {0x38, 0x31, 0, "pmovzxbd",     XMM,    XM},
    {0x38, 0x32, 0, "pmovzxbq",     XMM,    XM},
    {0x38, 0x33, 0, "pmovzxwd",     XMM,    XM},
    {0x38, 0x34, 0, "pmovzxwq",     XMM,    XM},
    {0x38, 0x35, 0, "pmovzxdq",     XMM,    XM},

    {0x38, 0x37, 0, "pcmpgtq",      XMM,    XM},
    {0x38, 0x38, 0, "pminsb",       XMM,    XM},
    {0x38, 0x39, 0, "pminsd",       XMM,    XM},
    {0x38, 0x3A, 0, "pminuw",       XMM,    XM},
    {0x38, 0x3B, 0, "pminud",       XMM,    XM},
    {0x38, 0x3C, 0, "pmaxsb",       XMM,    XM},
    {0x38, 0x3D, 0, "pmaxsd",       XMM,    XM},
    {0x38, 0x3E, 0, "pmaxuw",       XMM,    XM},
    {0x38, 0x3F, 0, "pmaxud",       XMM,    XM},
    {0x38, 0x40, 0, "pmaxlld",      XMM,    XM},
    {0x38, 0x41, 0, "phminposuw",   XMM,    XM},

    {0x3A, 0x08, 0, "roundps",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x09, 0, "roundpd",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0A, 0, "roundss",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0B, 0, "roundsd",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0C, 0, "blendps",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0D, 0, "blendpd",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0E, 0, "pblendw",      XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x0F, 0, "palignr",      XMM,    XM,     OP_ARG2_IMM8},

    {0x3A, 0x14, 0, "pextrb",       RM,     XMM,    OP_ARG2_IMM8},
    {0x3A, 0x15, 0, "pextrw",       RM,     XMM,    OP_ARG2_IMM8},
    {0x3A, 0x16, 0, "pextrd",       RM,     XMM,    OP_ARG2_IMM8},
    {0x3A, 0x17, 0, "extractps",    RM,     XMM,    OP_ARG2_IMM8},

    {0x3A, 0x20, 0, "pinsrb",       XMM,    RM,     OP_ARG2_IMM8},
    {0x3A, 0x21, 0, "insertps",     XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x22, 0, "pinsrd",       XMM,    RM,     OP_ARG2_IMM8},

    {0x3A, 0x40, 0, "dpps",         XMM,    XM},
    {0x3A, 0x41, 0, "dppd",         XMM,    XM},
    {0x3A, 0x42, 0, "mpsqdbw",      XMM,    XM,     OP_ARG2_IMM8},

    {0x3A, 0x44, 0, "pclmulqdq",    XMM,    XM,     OP_ARG2_IMM8},

    {0x3A, 0x60, 0, "pcmpestrm",    XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x61, 0, "pcmpestri",    XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x62, 0, "pcmpistrm",    XMM,    XM,     OP_ARG2_IMM8},
    {0x3A, 0x63, 0, "pcmpistri",    XMM,    XM,     OP_ARG2_IMM8},
};

/* returns the flag if it's a prefix, 0 otherwise */
static word get_prefix(word opcode, int bits) {
    if (bits == 64) {
        if ((opcode & 0xFFF0) == 0x40)
            return PREFIX_REX | ((opcode & 0xF) * 0x1000);
    }

    switch(opcode) {
    case 0x26: return PREFIX_ES;
    case 0x2E: return PREFIX_CS;
    case 0x36: return PREFIX_SS;
    case 0x3E: return PREFIX_DS;
    case 0x64: return PREFIX_FS;
    case 0x65: return PREFIX_GS;
    case 0x66: return PREFIX_OP32;
    case 0x67: return PREFIX_ADDR32;
    case 0x9B: return PREFIX_WAIT;
    case 0xF0: return PREFIX_LOCK;
    case 0xF2: return PREFIX_REPNE;
    case 0xF3: return PREFIX_REPE;
    default: return 0;
    }
}

static int instr_matches(const byte opcode, const byte subcode, const struct op *op) {
    return ((opcode == op->opcode) && ((op->subcode == 8) || (subcode == op->subcode)));
}

/* aka 3 byte opcode */
static int get_sse_single(byte opcode, byte subcode, struct instr *instr) {
    int i;

    if (instr->prefix & PREFIX_OP32) {
        for (i = 0; i < sizeof(instructions_sse_single_op32)/sizeof(struct op); i++) {
            if (instructions_sse_single_op32[i].opcode == opcode &&
                instructions_sse_single_op32[i].subcode == subcode) {
                instr->op = instructions_sse_single_op32[i];
                instr->prefix &= ~PREFIX_OP32;
                return 1;
            }
        }
    } else {
        for (i = 0; i < sizeof(instructions_sse_single)/sizeof(struct op); i++) {
            if (instructions_sse_single[i].opcode == opcode &&
                instructions_sse_single[i].subcode == subcode) {
                instr->op = instructions_sse_single[i];
                return 1;
            }
        }
    }

    return 0;
}

static int get_sse_instr(const byte *p, struct instr *instr) {
    byte subcode = REGOF(p[1]);
    unsigned i;

    /* Clear the prefix if it matches. This makes the disassembler work right,
     * but it might break things later if we want to interpret these. The
     * solution in that case is probably to modify the size/name instead. */

    if (instr->prefix & PREFIX_OP32) {
        for (i = 0; i < sizeof(instructions_sse_op32)/sizeof(struct op); i++) {
            if (instr_matches(p[0], subcode, &instructions_sse_op32[i])) {
                instr->op = instructions_sse_op32[i];
                instr->prefix &= ~PREFIX_OP32;
                return 0;
            }
        }
    } else if (instr->prefix & PREFIX_REPNE) {
        for (i = 0; i < sizeof(instructions_sse_repne)/sizeof(struct op); i++) {
            if (instr_matches(p[0], subcode, &instructions_sse_repne[i])) {
                instr->op = instructions_sse_repne[i];
                instr->prefix &= ~PREFIX_REPNE;
                return 0;
            }
        }
    } else if (instr->prefix & PREFIX_REPE) {
        for (i = 0; i < sizeof(instructions_sse_repe)/sizeof(struct op); i++) {
            if (instr_matches(p[0], subcode, &instructions_sse_repe[i])) {
                instr->op = instructions_sse_repe[i];
                instr->prefix &= ~PREFIX_REPE;
                return 0;
            }
        }
    } else {
        for (i = 0; i < sizeof(instructions_sse)/sizeof(struct op); i++) {
            if (instr_matches(p[0], subcode, &instructions_sse[i])) {
                instr->op = instructions_sse[i];
                return 0;
            }
        }
    }

    return get_sse_single(p[0], p[1], instr);
}

static int get_0f_instr(const byte *p, struct instr *instr) {
    byte subcode = REGOF(p[1]);
    unsigned i;
    int len;

    /* a couple of special (read: annoying) cases first */
    if (p[0] == 0x01 && MODOF(p[1]) == 3) {
        instr->op.opcode = 0x0F01;
        instr->op.subcode = p[1];
        switch (p[1]) {
        case 0xC1: strcpy(instr->op.name, "vmcall"); break;
        case 0xC2: strcpy(instr->op.name, "vmlaunch"); break;
        case 0xC3: strcpy(instr->op.name, "vmresume"); break;
        case 0xC4: strcpy(instr->op.name, "vmcall"); break;
        case 0xC8: strcpy(instr->op.name, "monitor"); break;
        case 0xC9: strcpy(instr->op.name, "mwait"); break;
        case 0xD0: strcpy(instr->op.name, "xgetbv"); break;
        case 0xD1: strcpy(instr->op.name, "xsetbv"); break;
        case 0xF9: strcpy(instr->op.name, "rdtscp"); break;
        }
        return 1;
    } else if (p[0] == 0xAE && MODOF(p[1]) == 3) {
        instr->op.opcode = 0x0FAE;
        instr->op.subcode = subcode;
        if (subcode == 0x5) strcpy(instr->op.name, "lfence");
        if (subcode == 0x6) strcpy(instr->op.name, "mfence");
        if (subcode == 0x7) strcpy(instr->op.name, "sfence");
        return 1;
    }

    for (i = 0; i < sizeof(instructions_0F)/sizeof(struct op); i++) {
        if (instr_matches(p[0], subcode, &instructions_0F[i])) {
            instr->op = instructions_0F[i];
            len = 0;
            break;
        }
    }
    if (!instr->op.name[0])
        len = get_sse_instr(p, instr);

    instr->op.opcode = 0x0F00 | p[0];
    return len;
}

/* Parameters:
 * ip      - [i] NOT current IP, but rather IP of the *argument*. This
 *               is necessary for REL16 to work right.
 * p       - [i] pointer to the current argument to be parsed
 * arg     - [i/o] pointer to the relevant arg struct
 *      ->ip         [o]
 *      ->value      [o]
 *      ->type       [i]
 * instr   - [i/o] pointer to the relevant instr struct
 *      ->prefix     [i]
 *      ->op         [i]
 *      ->modrm_disp [o]
 *      ->modrm_reg  [o]
 * is32    - [i] bitness—REL16 and MOFFS16 are affected by bitness but can't be overridden
 *
 * Returns: number of bytes processed
 *
 * Does not process specific arguments (e.g. registers, DSBX, ONE...)
 * The parameter out is given as a dword but may require additional casting.
 */
static int get_arg(dword ip, const byte *p, struct arg *arg, struct instr *instr, int bits) {
    arg->value = 0;

    switch (arg->type) {
    case IMM8:
        arg->ip = ip;
        arg->value = *p;
        return 1;
    case IMM16:
        arg->ip = ip;
        arg->value = *((word *) p);
        return 2;
    case IMM:
        arg->ip = ip;
        if (instr->op.size == 8) {
            arg->value = *p;
            return 1;
        } else if (instr->op.size == 16) {
            arg->value = *((word *) p);
            return 2;
        } else if (instr->op.size == 64 && (instr->op.flags & OP_IMM64)) {
            arg->value = *((qword *) p);
            return 8;
        } else {
            arg->value = *((dword *) p);
            return 4;
        }
    case REL8:
        arg->ip = ip;
        arg->value = ip+1+*((int8_t *) p);  /* signed */
        return 1;
    case REL16:
        arg->ip = ip;
        /* Equivalently signed or unsigned (i.e. clipped) */
        if (bits == 16) {
            arg->value = (ip+2+*((word *) p)) & 0xffff;
            return 2;
        } else {
            arg->value = (ip+4+*((dword *) p)) & 0xffffffff;
            return 4;
        }
    case PTR32:
        arg->ip = ip;
        arg->value = *((word *) p); /* I think this should be enough */
        return 4;
    case MOFFS16:
        arg->ip = ip;
        if (bits == 64) {
            arg->value = *((qword *) p);
            return 8;
        } else if (bits == 32) {
            arg->value = *((dword *) p);
            return 4;
        } else {
            arg->value = *((word *) p);
            return 2;
        }
    case RM:
    case MEM:
    case MM:
    case XM:
    {
        byte mod = MODOF(*p);
        byte rm  = MEMOF(*p);
        int ret = 1;

        if (mod == 3) {
            instr->modrm_disp = DISP_REG;
            instr->modrm_reg = rm;
            if (instr->prefix & PREFIX_REXB) instr->modrm_reg += 8;
            return 1;
        }

        if (instr->addrsize != 16 && rm == 4) {
            /* SIB byte */
            p++;
            instr->sib_scale = 1 << MODOF(*p);
            instr->sib_index = REGOF(*p);
            if (instr->prefix & PREFIX_REXX) instr->sib_index += 8;
            if (instr->sib_index == 4) instr->sib_index = -1;
            rm = MEMOF(*p);
            ret++;
        }

        if (mod == 0 && bits == 64 && rm == 5 && !instr->sib_scale) {
            /* IP-relative addressing... */
            arg->ip = ip + 1;
            arg->value = *((dword *) (p+1));
            instr->modrm_disp = DISP_16;
            instr->modrm_reg = 16;
            ret += 4;
        } else if (mod == 0 && ((instr->addrsize == 16 && rm == 6) ||
                                (instr->addrsize != 16 && rm == 5))) {
            arg->ip = ip + 1;
            if (instr->addrsize == 16) {
                arg->value = *((word *) (p+1));
                ret += 2;
            } else {
                arg->value = *((dword *) (p+1));
                ret += 4;
            }
            instr->modrm_disp = DISP_16;
            instr->modrm_reg = -1;
        } else if (mod == 0) {
            instr->modrm_disp = DISP_NONE;
            instr->modrm_reg = rm;
            if (instr->prefix & PREFIX_REXB) instr->modrm_reg += 8;
        } else if (mod == 1) {
            arg->ip = ip + 1;
            arg->value = *(p+1);
            instr->modrm_disp = DISP_8;
            instr->modrm_reg = rm;
            if (instr->prefix & PREFIX_REXB) instr->modrm_reg += 8;
            ret += 1;
        } else if (mod == 2) {
            arg->ip = ip + 1;
            if (instr->addrsize == 16) {
                arg->value = *((word *) (p+1));
                ret += 2;
            } else {
                arg->value = *((dword *) (p+1));
                ret += 4;
            }
            instr->modrm_disp = DISP_16;
            instr->modrm_reg = rm;
            if (instr->prefix & PREFIX_REXB) instr->modrm_reg += 8;
        }
        return ret;
    }
    case REG:
    case XMM:
    case CR32:
    case DR32:
    case TR32:  /* doesn't exist in 64-bit mode */
        arg->value = REGOF(*p);
        if (instr->prefix & PREFIX_REXR)
            arg->value += 8;
        return 0;
    case MMX:
    case SEG16:
        arg->value = REGOF(*p);
        return 0;
    case REG32:
    case STX:
    case REGONLY:
    case MMXONLY:
    case XMMONLY:
        arg->value = MEMOF(*p);
        if (instr->prefix & PREFIX_REXB)
            arg->value += 8;
        return 1;
    /* all others should be implicit */
    default:
        return 0;
    }
}

const char seg16[6][3] = {
    "es", "cs", "ss", "ds", "fs", "gs"
};

static const char reg8[8][3] = {
    "al","cl","dl","bl","ah","ch","dh","bh"
};

static const char reg8_rex[16][5] = {
    "al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

static const char reg16[16][5] = {
    "ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};

static const char reg32[17][5] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","eip"
};

static const char reg64[17][4] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rip"
};

static void get_seg16(char *out, byte reg) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, seg16[reg]);
}

static void get_reg8(char *out, byte reg, int rex) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, rex ? reg8_rex[reg] : reg8[reg]);
}

static void get_reg16(char *out, byte reg, int size) {
    if (reg != -1) {
        if (asm_syntax == GAS)
            strcat(out, "%");
        if (size == 16)
            strcat(out, reg16[reg]);
        if (size == 32)
            strcat(out, reg32[reg]);
        else if (size == 64)
            strcat(out, reg64[reg]);
    }
}

static void get_xmm(char *out, byte reg) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, "xmm0");
    out[strlen(out)-1] = '0'+reg;
}

static void get_mmx(char *out, byte reg) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, "mm0");
    out[strlen(out)-1] = '0'+reg;
}

static const char modrm16_gas[8][8] = {
    "%bx,%si", "%bx,%di", "%bp,%si", "%bp,%di", "%si", "%di", "%bp", "%bx"
};

static const char modrm16_masm[8][6] = {
    "bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"
};

/* Figure out whether it's a register, so we know whether to dispense with size
 * indicators on a memory access. */
static int is_reg(enum argtype arg) {
    return ((arg >= AL && arg <= GS) || (arg >= REG && arg <= TR32));
};

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %s: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

/* With MASM/NASM, use capital letters to help disambiguate them from the following 'h'. */

static void print_arg(char *ip, struct instr *instr, int i, int bits) {
    struct arg *arg = &instr->args[i];
    char *out = arg->string;
    qword value = arg->value;

    if (arg->string[0]) return; /* someone wants to print something special */

    if (arg->type >= AL && arg->type <= BH)
        get_reg8(out, arg->type-AL, 0);
    else if (arg->type >= AX && arg->type <= DI)
        get_reg16(out, arg->type-AX + ((instr->prefix & PREFIX_REXB) ? 8 : 0), instr->op.size);
    else if (arg->type >= ES && arg->type <= GS)
        get_seg16(out, arg->type-ES);

    switch (arg->type) {
    case ONE:
        strcat(out, (asm_syntax == GAS) ? "$0x1" : "1h");
        break;
    case IMM8:
        if (instr->op.flags & OP_STACK) { /* 6a */
            if (instr->op.size == 64)
                sprintf(out, (asm_syntax == GAS) ? "$0x%016lx" : "qword %016lxh", (qword) (int8_t) value);
            else if (instr->op.size == 32)
                sprintf(out, (asm_syntax == GAS) ? "$0x%08x" : "dword %08Xh", (dword) (int8_t) value);
            else
                sprintf(out, (asm_syntax == GAS) ? "$0x%04x" : "word %04Xh", (word) (int8_t) value);
        } else
            sprintf(out, (asm_syntax == GAS) ? "$0x%02lx" : "%02lXh", value);
        break;
    case IMM16:
        sprintf(out, (asm_syntax == GAS) ? "$0x%04lx" : "%04lXh", value);
        break;
    case IMM:
        if (instr->op.flags & OP_STACK) {
            if (instr->op.size == 64)
                sprintf(out, (asm_syntax == GAS) ? "$0x%016lx" : "qword %016lXh", value);
            else if (instr->op.size == 32)
                sprintf(out, (asm_syntax == GAS) ? "$0x%08lx" : "dword %08lXh", value);
            else
                sprintf(out, (asm_syntax == GAS) ? "$0x%04lx" : "word %04lXh", value);
        } else {
            if (instr->op.size == 8)
                sprintf(out, (asm_syntax == GAS) ? "$0x%02lx" : "%02lXh", value);
            else if (instr->op.size == 16)
                sprintf(out, (asm_syntax == GAS) ? "$0x%04lx" : "%04lXh", value);
            else if (instr->op.size == 64 && (instr->op.flags & OP_IMM64))
                sprintf(out, (asm_syntax == GAS) ? "$0x%016lx" : "%016lXh", value);
            else
                sprintf(out, (asm_syntax == GAS) ? "$0x%08lx" : "%08lXh", value);
        }
        break;
    case REL8:
    case REL16:
        sprintf(out, "%04lx", value);
        break;
    case PTR32:
        /* should always be relocated */
        break;
    case MOFFS16:
        if (asm_syntax == GAS) {
            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }
            sprintf(out+strlen(out), "0x%04lx", value);
        } else {
            out[0] = '[';
            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }
            sprintf(out+strlen(out), "%04lXh]", value);
        }
        instr->usedmem = 1;
        break;
    case DSBX:
    case DSSI:
        if (asm_syntax != NASM) {
            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }
            strcat(out, (asm_syntax == GAS) ? "(" : "[");
            get_reg16(out, (arg->type == DSBX) ? 3 : 6, instr->addrsize);
            strcat(out, (asm_syntax == GAS) ? ")" : "]");
        }
        instr->usedmem = 1;
        break;
    case ESDI:
        if (asm_syntax != NASM) {
            strcat(out, (asm_syntax == GAS) ? "%es:(" : "es:[");
            get_reg16(out, 7, instr->addrsize);
            strcat(out, (asm_syntax == GAS) ? ")" : "]");
        }
        instr->usedmem = 1;
        break;
    case ALS:
        if (asm_syntax == GAS)
            strcpy(out, "%al");
        break;
    case AXS:
        if (asm_syntax == GAS)
            strcpy(out, "%ax");
        break;
    case DXS:
        if (asm_syntax == GAS)
            strcpy(out, "(%dx)");
        else
            strcpy(out, "dx");
        break;
    /* register/memory. this is always the first byte after the opcode,
     * and is always either paired with a simple register or a subcode.
     * there are a few cases where it isn't [namely C6/7 MOV and 8F POP]
     * and we need to warn if we see a value there that isn't 0. */
    case RM:
    case MEM:
    case MM:
    case XM:
        if (instr->modrm_disp == DISP_REG) {
            if (arg->type == XM) {
                get_xmm(out, instr->modrm_reg);
                if (instr->vex_256)
                    out[asm_syntax == GAS ? 1 : 0] = 'y';
                break;
            } else if (arg->type == MM) {
                get_mmx(out, instr->modrm_reg);
                break;
            }

            if (arg->type == MEM)
                warn_at("ModRM byte has mod 3, but opcode only allows accessing memory.\n");

            if (instr->op.size == 8 || instr->op.opcode == 0x0FB6 || instr->op.opcode == 0x0FBE) { /* mov*b* */
                get_reg8(out, instr->modrm_reg, instr->prefix & PREFIX_REX);
            } else if (instr->op.opcode == 0x0FB7 || instr->op.opcode == 0x0FBF) /* mov*w* */
                get_reg16(out, instr->modrm_reg, 16);   /* fixme: 64-bit? */
            else
                get_reg16(out, instr->modrm_reg, instr->op.size);
            break;
        }

        instr->usedmem = 1;

        /* NASM: <size>    [<seg>: <reg>+<reg>+/-<offset>h] */
        /* MASM: <size> ptr <seg>:[<reg>+<reg>+/-<offset>h] */
        /* GAS:           *%<seg>:<->0x<offset>(%<reg>,%<reg>) */

        if (asm_syntax == GAS) {
            if (instr->op.opcode == 0xFF && instr->op.subcode >= 2 && instr->op.subcode <= 5)
                strcat(out, "*");

            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }

            /* offset */
            if (instr->modrm_disp == DISP_8) {
                int8_t svalue = (int8_t) value;
                if (svalue < 0)
                    sprintf(out+strlen(out), "-0x%02x", -svalue);
                else
                    sprintf(out+strlen(out), "0x%02x", svalue);
            } else if (instr->modrm_disp == DISP_16 && instr->addrsize == 16) {
                int16_t svalue = (int16_t) value;
                if (instr->modrm_reg == -1) {
                    sprintf(out+strlen(out), "0x%04lx", value);  /* absolute memory is unsigned */
                    return;
                }
                if (svalue < 0)
                    sprintf(out+strlen(out), "-0x%04x", -svalue);
                else
                    sprintf(out+strlen(out), "0x%04x", svalue);
            } else if (instr->modrm_disp == DISP_16) {
                int32_t svalue = (int32_t) value;
                if (instr->modrm_reg == -1) {
                    sprintf(out+strlen(out), "0x%08lx", value);  /* absolute memory is unsigned */
                    return;
                }
                if (svalue < 0)
                    sprintf(out+strlen(out), "-0x%08x", -svalue);
                else
                    sprintf(out+strlen(out), "0x%08x", svalue);
            }

            strcat(out, "(");

            if (instr->addrsize == 16) {
                strcat(out, modrm16_gas[instr->modrm_reg]);
            } else {
                get_reg16(out, instr->modrm_reg, instr->addrsize);
                if (instr->sib_scale && instr->sib_index != -1) {
                    strcat(out, ",");
                    get_reg16(out, instr->sib_index, instr->addrsize);
                    strcat(out, ",0");
                    out[strlen(out)-1] = '0'+instr->sib_scale;
                }
            }
            strcat(out, ")");
        } else {
            int has_sib = (instr->sib_scale != 0 && instr->sib_index != -1);
            if (instr->op.flags & OP_FAR)
                strcat(out, "far ");
            else if (!is_reg(instr->op.arg0) && !is_reg(instr->op.arg1)) {
                switch (instr->op.size) {
                case  8: strcat(out, "byte "); break;
                case 16: strcat(out, "word "); break;
                case 32: strcat(out, "dword "); break;
                case 64: strcat(out, "qword "); break;
                case 80: strcat(out, "tword "); break;
                default: break;
                }
                if (asm_syntax == MASM) /* && instr->op.size == 0? */
                    strcat(out, "ptr ");
            } else if (instr->op.opcode == 0x0FB6 || instr->op.opcode == 0x0FBE) { /* mov*b* */
                strcat(out,"byte ");
                if (asm_syntax == MASM)
                    strcat(out, "ptr ");
            } else if (instr->op.opcode == 0x0FB7 || instr->op.opcode == 0x0FBF) { /* mov*w* */
                strcat(out,"word ");
                if (asm_syntax == MASM)
                    strcat(out, "ptr ");
            }

            if (asm_syntax == NASM)
                strcat(out, "[");

            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }

            if (asm_syntax == MASM)
                strcat(out, "[");

            if (instr->modrm_reg != -1) {
                if (instr->addrsize == 16)
                    strcat(out, modrm16_masm[instr->modrm_reg]);
                else
                    get_reg16(out, instr->modrm_reg, instr->addrsize);
                if (has_sib)
                    strcat(out, "+");
            }

            if (has_sib) {
                get_reg16(out, instr->sib_index, instr->addrsize);
                strcat(out, "*0");
                out[strlen(out)-1] = '0'+instr->sib_scale;
            }

            if (instr->modrm_disp == DISP_8) {
                int8_t svalue = (int8_t) value;
                if (svalue < 0)
                    sprintf(out+strlen(out), "-%02Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%02Xh", svalue);
            } else if (instr->modrm_disp == DISP_16 && instr->addrsize == 16) {
                int16_t svalue = (int16_t) value;
                if (instr->modrm_reg == -1 && !has_sib)
                    sprintf(out+strlen(out), "%04lXh", value);   /* absolute memory is unsigned */
                else if (svalue < 0)
                    sprintf(out+strlen(out), "-%04Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%04Xh", svalue);
            } else if (instr->modrm_disp == DISP_16) {
                int32_t svalue = (int32_t) value;
                if (instr->modrm_reg == -1 && !has_sib)
                    sprintf(out+strlen(out), "%08lXh", value);   /* absolute memory is unsigned */
                else if (svalue < 0)
                    sprintf(out+strlen(out), "-%08Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%08Xh", svalue);
            }
            strcat(out, "]");
        }
        break;
    case REG:
    case REGONLY:
        if (instr->op.size == 8)
            get_reg8(out, value, instr->prefix & PREFIX_REX);
        else if (bits == 64 && instr->op.opcode == 0x63)
            get_reg16(out, value, 64);
        else
            get_reg16(out, value, instr->op.size);
        break;
    case REG32:
        get_reg16(out, value, bits);
        break;
    case SEG16:
        if (value > 5)
            warn_at("Invalid segment register %ld\n", value);
        get_seg16(out, value);
        break;
    case CR32:
        switch (value) {
        case 0:
        case 2:
        case 3:
        case 4:
        case 8:
            break;
        default:
            warn_at("Invalid control register %ld\n", value);
            break;
        }
        if (asm_syntax == GAS)
            strcat(out, "%");
        strcat(out, "cr0");
        out[strlen(out)-1] = '0'+value;
        break;
    case DR32:
        if (asm_syntax == GAS)
            strcat(out, "%");
        strcat(out, "dr0");
        out[strlen(out)-1] = '0'+value;
        break;
    case TR32:
        if (value < 3)
            warn_at("Invalid test register %ld\n", value);
        if (asm_syntax == GAS)
            strcat(out, "%");
        strcat(out, "tr0");
        out[strlen(out)-1] = '0'+value;
        break;
    case ST:
        if (asm_syntax == GAS)
            strcat(out, "%");
        strcat(out, "st");
        if (asm_syntax == NASM)
            strcat(out, "0");
        break;
    case STX:
        if (asm_syntax == GAS)
            strcat(out, "%");
        strcat(out, "st");
        if (asm_syntax != NASM)
            strcat(out, "(");
        strcat(out, "0");
        out[strlen(out)-1] = '0' + value;
        if (asm_syntax != NASM)
            strcat(out, ")");
        break;
    case MMX:
    case MMXONLY:
        get_mmx(out, value);
        break;
    case XMM:
    case XMMONLY:
        get_xmm(out, value);
        if (instr->vex_256)
            out[asm_syntax == GAS ? 1 : 0] = 'y';
        break;
    default:
        break;
    }
}

/* helper to tack a length suffix onto a name */
static void suffix_name(struct instr *instr) {
    if ((instr->op.flags & OP_LL) == OP_LL)
        strcat(instr->op.name, "ll");
    else if (instr->op.flags & OP_S)
        strcat(instr->op.name, "s");
    else if (instr->op.flags & OP_L)
        strcat(instr->op.name, "l");
    else if (instr->op.size == 80)
        strcat(instr->op.name, "t");
    else if (instr->op.size == 8)
        strcat(instr->op.name, "b");
    else if (instr->op.size == 16)
        strcat(instr->op.name, "w");
    else if (instr->op.size == 32)
        strcat(instr->op.name, (asm_syntax == GAS) ? "l" : "d");
    else if (instr->op.size == 64)
        strcat(instr->op.name, "q");
}

/* Paramters:
 * ip    - current IP (used to calculate relative addresses)
 * p     - pointer to the current instruction to be parsed
 * instr - [output] pointer to an instr_info struct to be filled
 * is32  - bitness
 *
 * Returns: number of bytes processed
 *
 * Note: we don't print warnings here (all warnings should be printed
 * while actually dumping output, both to keep this function agnostic and to
 * ensure they only get printed once), so we will need to watch out for
 * multiple prefixes, invalid instructions, etc.
 */
int get_instr(dword ip, const byte *p, struct instr *instr, int bits) {
    int len = 0;
    byte opcode;
    word prefix;

    memset(instr, 0, sizeof(*instr));

    while ((prefix = get_prefix(p[len], bits))) {
        if ((instr->prefix & PREFIX_SEG_MASK) && (prefix & PREFIX_SEG_MASK)) {
            instr->op = instructions[p[len]];
            instr->prefix &= ~PREFIX_SEG_MASK;
        } else if (instr->prefix & prefix & PREFIX_OP32) {
            /* Microsoft likes to repeat this on NOPs for alignment, so just
             * ignore it */
        } else if (instr->prefix & prefix) {
            instr->op = instructions[p[len]];
            instr->prefix &= ~prefix;
            return len;
        }
        instr->prefix |= prefix;
        len++;
    }

    opcode = p[len];

    /* copy the op_info */
    if (opcode == 0xC4 && MODOF(p[len+1]) == 3 && bits != 16) {
        byte subcode = 0xcc;
        len++;
        instr->vex = 1;
        if ((p[len] & 0x1F) == 2) subcode = 0x38;
        else if ((p[len] & 0x1F) == 3) subcode = 0x3A;
        else warn("Unhandled subcode %x at %x\n", p[len], ip);
        len++;
        instr->vex_reg = ~((p[len] >> 3) & 7);
        instr->vex_256 = (p[len] & 4) ? 1 : 0;
        if ((p[len] & 3) == 3) instr->prefix |= PREFIX_REPNE;
        else if ((p[len] & 3) == 2) instr->prefix |= PREFIX_REPE;
        else if ((p[len] & 3) == 1) instr->prefix |= PREFIX_OP32;
        len += get_sse_single(subcode, p[len+1], instr);
    } else if (opcode == 0xC5 && MODOF(p[len+1]) == 3 && bits != 16) {
        len++;
        instr->vex = 1;
        instr->vex_reg = ~((p[len] >> 3) & 7);
        instr->vex_256 = (p[len] & 4) ? 1 : 0;
        if ((p[len] & 3) == 3) instr->prefix |= PREFIX_REPNE;
        else if ((p[len] & 3) == 2) instr->prefix |= PREFIX_REPE;
        else if ((p[len] & 3) == 1) instr->prefix |= PREFIX_OP32;
        len++;
        len += get_0f_instr(p+len, instr);
    } else if (bits == 64 && instructions64[opcode].name[0]) {
        instr->op = instructions64[opcode];
    } else if (bits != 64 && instructions[opcode].name[0]) {
        instr->op = instructions[opcode];
    } else {
        byte subcode = REGOF(p[len+1]);

        /* do we have a member of an instruction group? */
        if (opcode == 0x0F) {
            len++;
            len += get_0f_instr(p+len, instr);
        } else if (opcode >= 0xD8 && opcode <= 0xDF) {
            len += get_fpu_instr(p+len, &instr->op);
        } else {
            unsigned i;
            for (i=0; i<sizeof(instructions_group)/sizeof(struct op); i++) {
                if (opcode == instructions_group[i].opcode &&
                    subcode == instructions_group[i].subcode) {
                    instr->op = instructions_group[i];
                    break;
                }
            }
        }

        /* if we get here and we haven't found a suitable instruction,
         * we ran into something unused (or inadequately documented) */
        if (!instr->op.name[0]) {
            /* supply some default values so we can keep parsing */
            strcpy(instr->op.name, "?"); /* less arrogant than objdump's (bad) */
            instr->op.subcode = subcode;
            instr->op.size = 0;
            instr->op.arg0 = 0;
            instr->op.arg1 = 0;
            instr->op.flags = 0;
        }
    }

    len++;

    /* resolve the size */
    if (instr->op.size == -1) {
        if (instr->prefix & PREFIX_OP32)
            instr->op.size = (bits == 16) ? 32 : 16;
        else if (instr->prefix & PREFIX_REXW)
            instr->op.size = 64;
        else if (instr->op.flags & (OP_STACK | OP_64))
            instr->op.size = bits;
        else
            instr->op.size = (bits == 16) ? 16 : 32;
    }

    if (instr->prefix & PREFIX_ADDR32)
        instr->addrsize = (bits == 32) ? 16 : 32;
    else
        instr->addrsize = bits;

    /* figure out what arguments we have */
    if (instr->op.arg0) {
        int base = len;

        instr->args[0].type = instr->op.arg0;
        instr->args[1].type = instr->op.arg1;

        /* The convention is that an arg whose value is one or more bytes has
         * IP pointing to that value, but otherwise it points to the beginning
         * of the instruction. This way, we'll never think that e.g. a register
         * value is supposed to be relocated. */
        instr->args[0].ip = instr->args[1].ip = instr->args[2].ip = ip;

        len += get_arg(ip+len, &p[len], &instr->args[0], instr, bits);

        /* registers that read from the modrm byte, which we might have just processed */
        if (instr->op.arg1 >= REG && instr->op.arg1 <= TR32)
            len += get_arg(ip+len, &p[base], &instr->args[1], instr, bits);
        else
            len += get_arg(ip+len, &p[len], &instr->args[1], instr, bits);

        /* arg2 */
        if (instr->op.flags & OP_ARG2_IMM)
            instr->args[2].type = IMM;
        else if (instr->op.flags & OP_ARG2_IMM8)
            instr->args[2].type = IMM8;
        else if (instr->op.flags & OP_ARG2_CL)
            instr->args[2].type = CL;

        len += get_arg(ip+len, &p[len], &instr->args[2], instr, bits);
    }

    /* modify the instruction name if appropriate */

    if (asm_syntax == GAS) {
        if (instr->op.opcode == 0x0FB6) {
            strcpy(instr->op.name, "movzb");
            suffix_name(instr);
        } else if (instr->op.opcode == 0x0FB7) {
            strcpy(instr->op.name, "movzw");
            suffix_name(instr);
        } else if (instr->op.opcode == 0x0FBE) {
            strcpy(instr->op.name, "movsb");
            suffix_name(instr);
        } else if (instr->op.opcode == 0x0FBF) {
            strcpy(instr->op.name, "movsw");
            suffix_name(instr);
        } else if (instr->op.opcode == 0x63 && bits == 64)
            strcpy(instr->op.name, "movslq");
    }

    if ((instr->op.flags & OP_STACK) && (instr->prefix & PREFIX_OP32))
        suffix_name(instr);
    else if ((instr->op.flags & OP_STRING) && asm_syntax != GAS)
        suffix_name(instr);
    else if (instr->op.opcode == 0x98)
        strcpy(instr->op.name, instr->op.size == 16 ? "cbw" : instr->op.size == 32 ? "cwde" : "cdqe");
    else if (instr->op.opcode == 0x99)
        strcpy(instr->op.name, instr->op.size == 16 ? "cwd" : instr->op.size == 32 ? "cdq" : "cqo");
    else if (instr->op.opcode == 0xE3)
        strcpy(instr->op.name, instr->op.size == 16 ? "jcxz" : instr->op.size == 32 ? "jecxz" : "jrcxz");
    else if (instr->op.opcode == 0xD4 && instr->args[0].value == 10) {
        strcpy(instr->op.name, "aam");
        instr->op.arg0 = NONE;
    } else if (instr->op.opcode == 0xD5 && instr->args[0].value == 10) {
        strcpy(instr->op.name, "aad");
        instr->op.arg0 = NONE;
    } else if (instr->op.opcode == 0x0FC7 && instr->op.subcode == 1 && (instr->prefix & PREFIX_REXW))
        strcpy(instr->op.name, "cmpxchg16b");
    else if (asm_syntax == GAS) {
        if (instr->op.flags & OP_FAR) {
            memmove(instr->op.name+1, instr->op.name, strlen(instr->op.name));
            instr->op.name[0] = 'l';
        } else if (!is_reg(instr->op.arg0) && !is_reg(instr->op.arg1) &&
                   instr->modrm_disp != DISP_REG)
            suffix_name(instr);
    } else if (asm_syntax != GAS && (instr->op.opcode == 0xCA || instr->op.opcode == 0xCB))
        strcat(instr->op.name, "f");

    return len;
}

void print_instr(char *ip, const byte *p, int len, byte flags, struct instr *instr, const char *comment, int bits) {
    int i;

    /* FIXME: now that we've had to add bits to this function, get rid of ip_string */

    /* get the arguments */

    print_arg(ip, instr, 0, bits);
    print_arg(ip, instr, 1, bits);
    print_arg(ip, instr, 2, bits);

    /* did we find too many prefixes? */
    if (get_prefix(instr->op.opcode, bits)) {
        if (get_prefix(instr->op.opcode, bits) & PREFIX_SEG_MASK)
            warn_at("Multiple segment prefixes found: %s, %s. Skipping to next instruction.\n",
                    seg16[(instr->prefix & PREFIX_SEG_MASK)-1], instr->op.name);
        else
            warn_at("Prefix specified twice: %s. Skipping to next instruction.\n", instr->op.name);
        instr->op.name[0] = 0;
    }

    /* check that the instruction exists */
    if (instr->op.name[0] == '?')
        warn_at("Unknown opcode 0x%02x (extension %d)\n", instr->op.opcode, instr->op.subcode);

    /* okay, now we begin dumping */
    if ((flags & INSTR_JUMP) && (opts & COMPILABLE)) {
        /* output a label, which is like an address but without the segment prefix */
        /* FIXME: check masm */
        if (asm_syntax == NASM)
            printf(".");
        printf("%s:", ip);
    }

    if (!(opts & NO_SHOW_ADDRESSES))
        printf("%s:", ip);
    printf("\t");

    if (!(opts & NO_SHOW_RAW_INSN)) {
        for (i=0; i<len && i<7; i++)
            printf("%02x ", p[i]);
        for (; i<8; i++)
            printf("   ");
    }

    /* mark instructions that are jumped to */
    if ((flags & INSTR_JUMP) && !(opts & COMPILABLE))
        printf((flags & INSTR_FAR) ? ">>" : " >");
    else
        printf("  ");

    /* print prefixes, including (fake) prefixes if ours are invalid */
    if (instr->prefix & PREFIX_SEG_MASK) {
        /* note: is it valid to use overrides with lods and outs? */
        if (!instr->usedmem || (instr->op.arg0 == ESDI || (instr->op.arg1 == ESDI && instr->op.arg0 != DSSI))) {  /* can't be overridden */
            warn_at("Segment prefix %s used with opcode 0x%02x %s\n", seg16[(instr->prefix & PREFIX_SEG_MASK)-1], instr->op.opcode, instr->op.name);
            printf("%s ", seg16[(instr->prefix & PREFIX_SEG_MASK)-1]);
        }
    }
    if ((instr->prefix & PREFIX_OP32) && instr->op.size != 16 && instr->op.size != 32) {
        warn_at("Operand-size override used with opcode 0x%02x %s\n", instr->op.opcode, instr->op.name);
        printf((asm_syntax == GAS) ? "data32 " : "o32 "); /* fixme: how should MASM print it? */
    }
    if ((instr->prefix & PREFIX_ADDR32) && (asm_syntax == NASM) && (instr->op.flags & OP_STRING)) {
        printf("a32 ");
    } else if ((instr->prefix & PREFIX_ADDR32) && !instr->usedmem && instr->op.opcode != 0xE3) { /* jecxz */
        warn_at("Address-size prefix used with opcode 0x%02x %s\n", instr->op.opcode, instr->op.name);
        printf((asm_syntax == GAS) ? "addr32 " : "a32 "); /* fixme: how should MASM print it? */
    }
    if (instr->prefix & PREFIX_LOCK) {
        if(!(instr->op.flags & OP_LOCK))
            warn_at("lock prefix used with opcode 0x%02x %s\n", instr->op.opcode, instr->op.name);
        printf("lock ");
    }
    if (instr->prefix & PREFIX_REPNE) {
        if(!(instr->op.flags & OP_REPNE))
            warn_at("repne prefix used with opcode 0x%02x %s\n", instr->op.opcode, instr->op.name);
        printf("repne ");
    }
    if (instr->prefix & PREFIX_REPE) {
        if(!(instr->op.flags & OP_REPE))
            warn_at("repe prefix used with opcode 0x%02x %s\n", instr->op.opcode, instr->op.name);
        printf((instr->op.flags & OP_REPNE) ? "repe ": "rep ");
    }
    if (instr->prefix & PREFIX_WAIT) {
        printf("wait ");
    }

    if (instr->vex)
        printf("v");
    printf("%s", instr->op.name);

    if (instr->args[0].string[0] || instr->args[1].string[0])
        printf("\t");

    if (asm_syntax == GAS) {
        /* fixme: are all of these orderings correct? */
        if (instr->args[1].string[0])
            printf("%s,", instr->args[1].string);
        if (instr->vex_reg)
            printf("%%ymm%d, ", instr->vex_reg);
        if (instr->args[0].string[0])
            printf("%s", instr->args[0].string);
        if (instr->args[2].string[0])
            printf(",%s", instr->args[2].string);
    } else {
        if (instr->args[0].string[0])
            printf("%s", instr->args[0].string);
        if (instr->args[1].string[0])
            printf(", ");
        if (instr->vex_reg)
            printf("ymm%d, ", instr->vex_reg);
        if (instr->args[1].string[0])
            printf("%s", instr->args[1].string);
        if (instr->args[2].string[0])
            printf(", %s", instr->args[2].string);
    }
    if (comment) {
        printf(asm_syntax == GAS ? "\t// " : "\t;");
        printf(" <%s>", comment);
    }

    /* if we have more than 7 bytes on this line, wrap around */
    if (len > 7 && !(opts & NO_SHOW_RAW_INSN)) {
        printf("\n\t\t");
        for (i=7; i<len; i++) {
            printf("%02x", p[i]);
            if (i < len) printf(" ");
        }
    }
    printf("\n");
}
