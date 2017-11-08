/* Functions to parse x86 instructions */

#include <string.h>
#include "x86_instr.h"

static const op_info instructions[256] = {
    {0x00, 8,  8, "add",        RM,     REG,    OP_LOCK},
    {0x01, 8, 16, "add",        RM,     REG,    OP_LOCK},
    {0x02, 8,  8, "add",        REG,    RM},
    {0x03, 8, 16, "add",        REG,    RM},
    {0x04, 8,  8, "add",        AL,     IMM},
    {0x05, 8, 16, "add",        AX,     IMM},
    {0x06, 8,  0, "push",       ES},
    {0x07, 8,  0, "pop",        ES},
    {0x08, 8,  8, "or",         RM,     REG,    OP_LOCK},
    {0x09, 8, 16, "or",         RM,     REG,    OP_LOCK},
    {0x0A, 8,  8, "or",         REG,    RM},
    {0x0B, 8, 16, "or",         REG,    RM},
    {0x0C, 8,  8, "or",         AL,     IMM},
    {0x0D, 8, 16, "or",         AX,     IMM},
    {0x0E, 8,  0, "push",       CS},
    {0x0F, 8},  /* two-byte codes */
    {0x10, 8,  8, "adc",        RM,     REG,    OP_LOCK},
    {0x11, 8, 16, "adc",        RM,     REG,    OP_LOCK},
    {0x12, 8,  8, "adc",        REG,    RM},
    {0x13, 8, 16, "adc",        REG,    RM},
    {0x14, 8,  8, "adc",        AL,     IMM},
    {0x15, 8, 16, "adc",        AX,     IMM},
    {0x16, 8,  0, "push",       SS},
    {0x17, 8,  0, "pop",        SS},
    {0x18, 8,  8, "sbb",        RM,     REG,    OP_LOCK},
    {0x19, 8, 16, "sbb",        RM,     REG,    OP_LOCK},
    {0x1A, 8,  8, "sbb",        REG,    RM},
    {0x1B, 8, 16, "sbb",        REG,    RM},
    {0x1C, 8,  8, "sbb",        AL,     IMM},
    {0x1D, 8, 16, "sbb",        AX,     IMM},
    {0x1E, 8,  0, "push",       DS},
    {0x2F, 8,  0, "pop",        DS},
    {0x20, 8,  8, "and",        RM,     REG,    OP_LOCK},
    {0x21, 8, 16, "and",        RM,     REG,    OP_LOCK},
    {0x22, 8,  8, "and",        REG,    RM},
    {0x23, 8, 16, "and",        REG,    RM},
    {0x24, 8,  8, "and",        AL,     IMM},
    {0x25, 8, 16, "and",        AX,     IMM},
    {0x26, 8,  0, "es"},  /* ES prefix */
    {0x27, 8,  0, "daa"},
    {0x28, 8,  8, "sub",        RM,     REG,    OP_LOCK},
    {0x29, 8, 16, "sub",        RM,     REG,    OP_LOCK},
    {0x2A, 8,  8, "sub",        REG,    RM},
    {0x2B, 8, 16, "sub",        REG,    RM},
    {0x2C, 8,  8, "sub",        AL,     IMM},
    {0x2D, 8, 16, "sub",        AX,     IMM},
    {0x2E, 8,  0, "cs"},  /* CS prefix */
    {0x2F, 8,  0, "das"},
    {0x30, 8,  8, "xor",        RM,     REG,    OP_LOCK},
    {0x31, 8, 16, "xor",        RM,     REG,    OP_LOCK},
    {0x32, 8,  8, "xor",        REG,    RM},
    {0x33, 8, 16, "xor",        REG,    RM},
    {0x34, 8,  8, "xor",        AL,     IMM},
    {0x35, 8, 16, "xor",        AX,     IMM},
    {0x36, 8,  0, "ss"},  /* SS prefix */
    {0x37, 8,  0, "aaa"},
    {0x38, 8,  8, "cmp",        RM,     REG},
    {0x39, 8, 16, "cmp",        RM,     REG},
    {0x3A, 8,  8, "cmp",        REG,    RM},
    {0x3B, 8, 16, "cmp",        REG,    RM},
    {0x3C, 8,  8, "cmp",        AL,     IMM},
    {0x3D, 8, 16, "cmp",        AX,     IMM},
    {0x3E, 8,  0, "ds"},  /* DS prefix */
    {0x3F, 8,  0, "aas"},
    {0x40, 8, 16, "inc",        AX},
    {0x41, 8, 16, "inc",        CX},
    {0x42, 8, 16, "inc",        DX},
    {0x43, 8, 16, "inc",        BX},
    {0x44, 8, 16, "inc",        SP},
    {0x45, 8, 16, "inc",        BP},
    {0x46, 8, 16, "inc",        SI},
    {0x47, 8, 16, "inc",        DI},
    {0x48, 8, 16, "dec",        AX},
    {0x49, 8, 16, "dec",        CX},
    {0x4A, 8, 16, "dec",        DX},
    {0x4B, 8, 16, "dec",        BX},
    {0x4C, 8, 16, "dec",        SP},
    {0x4D, 8, 16, "dec",        BP},
    {0x4E, 8, 16, "dec",        SI},
    {0x4F, 8, 16, "dec",        DI},
    {0x50, 8, 16, "push",       AX},
    {0x51, 8, 16, "push",       CX},
    {0x52, 8, 16, "push",       DX},
    {0x53, 8, 16, "push",       BX},
    {0x54, 8, 16, "push",       SP},
    {0x55, 8, 16, "push",       BP},
    {0x56, 8, 16, "push",       SI},
    {0x57, 8, 16, "push",       DI},
    {0x58, 8, 16, "pop",        AX},
    {0x59, 8, 16, "pop",        CX},
    {0x5A, 8, 16, "pop",        DX},
    {0x5B, 8, 16, "pop",        BX},
    {0x5C, 8, 16, "pop",        SP},
    {0x5D, 8, 16, "pop",        BP},
    {0x5E, 8, 16, "pop",        SI},
    {0x5F, 8, 16, "pop",        DI},
    {0x60, 8, 16, "pusha",      0,      0,      OP_STACK},
    {0x61, 8, 16, "popa",       0,      0,      OP_STACK},
    {0x62, 8, 16, "bound",      REG,    MEM},
    {0x63, 8,  0, "arpl",       RM,     REG},
    {0x64, 8,  0, "fs"},  /* FS prefix */
    {0x65, 8,  0, "gs"},  /* GS prefix */
    {0x66, 8,  0, "data"},  /* op-size prefix */
    {0x67, 8,  0, "addr"},  /* addr-size prefix */
    {0x68, 8, 16, "push",       IMM,    0,      OP_STACK},
    {0x69, 8, 16, "imul",       REG,    RM,     OP_ARG2_IMM},
    {0x6A, 8, 16, "push",       IMM8,   0,      OP_STACK},
    {0x6B, 8, 16, "imul",       REG,    RM,     OP_ARG2_IMM8},
    {0x6C, 8,  8, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6D, 8, 16, "ins",        ESDI,   DXS,    OP_STRING|OP_REP},
    {0x6E, 8,  8, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x6F, 8, 16, "outs",       DXS,    DSSI,   OP_STRING|OP_REP},
    {0x70, 8,  0, "jo",         REL8},
    {0x71, 8,  0, "jno",        REL8},
    {0x72, 8,  0, "jb",         REL8},
    {0x73, 8,  0, "jae",        REL8},
    {0x74, 8,  0, "jz",         REL8},
    {0x75, 8,  0, "jnz",        REL8},
    {0x76, 8,  0, "jbe",        REL8},
    {0x77, 8,  0, "ja",         REL8},
    {0x78, 8,  0, "js",         REL8},
    {0x79, 8,  0, "jns",        REL8},
    {0x7A, 8,  0, "jp",         REL8},
    {0x7B, 8,  0, "jnp",        REL8},
    {0x7C, 8,  0, "jl",         REL8},
    {0x7D, 8,  0, "jge",        REL8},
    {0x7E, 8,  0, "jle",        REL8},
    {0x7F, 8,  0, "jg",         REL8},
    {0x80, 8},  /* arithmetic operations */
    {0x81, 8},
    {0x82, 8},  /* alias for 80 */
    {0x83, 8},
    {0x84, 8,  8, "test",       RM,     REG},
    {0x85, 8, 16, "test",       RM,     REG},
    {0x86, 8,  8, "xchg",       REG,    RM,     OP_LOCK},
    {0x87, 8, 16, "xchg",       REG,    RM,     OP_LOCK},
    {0x88, 8,  8, "mov",        RM,     REG},
    {0x89, 8, 16, "mov",        RM,     REG},
    {0x8A, 8,  8, "mov",        REG,    RM},
    {0x8B, 8, 16, "mov",        REG,    RM},
    {0x8C, 8,  0, "mov",        RM,     SEG16},
    {0x8D, 8, 16, "lea",        REG,    MEM},
    {0x8E, 8,  0, "mov",        SEG16,  RM,     OP_OP32_REGONLY},
    {0x8F, 8},  /* pop (subcode 0 only) */
    {0x90, 8,  0, "nop"},
    {0x91, 8, 16, "xchg",       AX,     CX},
    {0x92, 8, 16, "xchg",       AX,     DX},
    {0x93, 8, 16, "xchg",       AX,     BX},
    {0x94, 8, 16, "xchg",       AX,     SP},
    {0x95, 8, 16, "xchg",       AX,     BP},
    {0x96, 8, 16, "xchg",       AX,     SI},
    {0x97, 8, 16, "xchg",       AX,     DI},
    {0x98, 8, 16, "cbw"},       /* handled separately */
    {0x99, 8, 16, "cwd"},       /* handled separately */
    {0x9A, 8,  0, "call",       PTR32,  0,      OP_FAR},
    {0x9B, 8,  0, "wait"},  /* wait ~prefix~ */
    {0x9C, 8, 16, "pushf",      0,      0,      OP_STACK},
    {0x9D, 8, 16, "popf",       0,      0,      OP_STACK},
    {0x9E, 8,  0, "sahf"},
    {0x9F, 8,  0, "lahf"},
    {0xA0, 8,  8, "mov",        AL,     MOFFS16},
    {0xA1, 8, 16, "mov",        AX,     MOFFS16},
    {0xA2, 8,  8, "mov",        MOFFS16,AL},
    {0xA3, 8, 16, "mov",        MOFFS16,AX},
    {0xA4, 8,  8, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA5, 8, 16, "movs",       DSSI,   ESDI,   OP_STRING|OP_REP},
    {0xA6, 8,  8, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA7, 8, 16, "cmps",       DSSI,   ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xA8, 8,  8, "test",       AL,     IMM},
    {0xA9, 8, 16, "test",       AX,     IMM},
    {0xAA, 8,  8, "stos",       ESDI,   ALS,    OP_STRING|OP_REP},
    {0xAB, 8, 16, "stos",       ESDI,   AXS,    OP_STRING|OP_REP},
    {0xAC, 8,  8, "lods",       ALS,    DSSI,   OP_STRING|OP_REP},
    {0xAD, 8, 16, "lods",       AXS,    DSSI,   OP_STRING|OP_REP},
    {0xAE, 8,  8, "scas",       ALS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xAF, 8, 16, "scas",       AXS,    ESDI,   OP_STRING|OP_REPNE|OP_REPE},
    {0xB0, 8,  8, "mov",        AL,     IMM},
    {0xB1, 8,  8, "mov",        CL,     IMM},
    {0xB2, 8,  8, "mov",        DL,     IMM},
    {0xB3, 8,  8, "mov",        BL,     IMM},
    {0xB4, 8,  8, "mov",        AH,     IMM},
    {0xB5, 8,  8, "mov",        CH,     IMM},
    {0xB6, 8,  8, "mov",        DH,     IMM},
    {0xB7, 8,  8, "mov",        BH,     IMM},
    {0xB8, 8, 16, "mov",        AX,     IMM},
    {0xB9, 8, 16, "mov",        CX,     IMM},
    {0xBA, 8, 16, "mov",        DX,     IMM},
    {0xBB, 8, 16, "mov",        BX,     IMM},
    {0xBC, 8, 16, "mov",        SP,     IMM},
    {0xBD, 8, 16, "mov",        BP,     IMM},
    {0xBE, 8, 16, "mov",        SI,     IMM},
    {0xBF, 8, 16, "mov",        DI,     IMM},
    {0xC0, 8},  /* rotate/shift */
    {0xC1, 8},  /* rotate/shift */
    {0xC2, 8,  0, "ret",        IMM16},
    {0xC3, 8,  0, "ret"},       /* fixme: rep? */
    {0xC4, 8, 16, "les",        REG,    MEM},
    {0xC5, 8, 16, "lds",        REG,    MEM},
    {0xC6, 0},  /* mov (subcode 0 only) */
    {0xC7, 0},  /* mov (subcode 0 only) */
    {0xC8, 8,  0, "enter",      IMM16,  IMM8},
    {0xC9, 8,  0, "leave"},
    {0xCA, 8, 16, "ret",        IMM16,  0,      OP_FAR},        /* a change in bitness should only happen across segment boundaries */
    {0xCB, 8, 16, "ret",        0,      0,      OP_FAR},
    {0xCC, 8,  0, "int3"},
    {0xCD, 8,  0, "int",        IMM8},
    {0xCE, 8,  0, "into"},
    {0xCF, 8,  0, "iret"},
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
    {0xE0, 8,  0, "loopnz",     REL8},  /* fixme: how to print this? */
    {0xE1, 8,  0, "loopz",      REL8},
    {0xE2, 8,  0, "loop",       REL8},
    {0xE3, 8,  0, "jcxz",       REL8},  /* handled separately */
    {0xE4, 8,  8, "in",         AL,     IMM},
    {0xE5, 8, 16, "in",         AX,     IMM},
    {0xE6, 8,  8, "out",        IMM,    AL},
    {0xE7, 8, 16, "out",        IMM,    AX},
    {0xE8, 8,  0, "call",       REL16},
    {0xE9, 8,  0, "jmp",        REL16},
    {0xEA, 8, 16, "jmp",        PTR32,  0,      OP_FAR},        /* a change in bitness should only happen across segment boundaries */
    {0xEB, 8,  0, "jmp",        REL8},
    {0xEC, 8,  0, "in",         AL,     DX},
    {0xED, 8,  0, "in",         AX,     DX},
    {0xEE, 8,  0, "out",        DX,     AL},
    {0xEF, 8,  0, "out",        DX,     AX},
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

static const op_info instructions_group[] = {
    {0x80, 0,  8, "add",        RM,     IMM,    OP_LOCK},
    {0x80, 1,  8, "or",         RM,     IMM,    OP_LOCK},
    {0x80, 2,  8, "adc",        RM,     IMM,    OP_LOCK},
    {0x80, 3,  8, "sbb",        RM,     IMM,    OP_LOCK},
    {0x80, 4,  8, "and",        RM,     IMM,    OP_LOCK},
    {0x80, 5,  8, "sub",        RM,     IMM,    OP_LOCK},
    {0x80, 6,  8, "xor",        RM,     IMM,    OP_LOCK},
    {0x80, 7,  8, "cmp",        RM,     IMM},
    {0x81, 0, 16, "add",        RM,     IMM,    OP_LOCK},
    {0x81, 1, 16, "or",         RM,     IMM,    OP_LOCK},
    {0x81, 2, 16, "adc",        RM,     IMM,    OP_LOCK},
    {0x81, 3, 16, "sbb",        RM,     IMM,    OP_LOCK},
    {0x81, 4, 16, "and",        RM,     IMM,    OP_LOCK},
    {0x81, 5, 16, "sub",        RM,     IMM,    OP_LOCK},
    {0x81, 6, 16, "xor",        RM,     IMM,    OP_LOCK},
    {0x81, 7, 16, "cmp",        RM,     IMM},
    {0x82, 0,  8, "add",        RM,     IMM8,   OP_LOCK}, /*  aliased */
    {0x82, 1,  8, "or",         RM,     IMM8,   OP_LOCK},
    {0x82, 2,  8, "adc",        RM,     IMM8,   OP_LOCK},
    {0x82, 3,  8, "sbb",        RM,     IMM8,   OP_LOCK},
    {0x82, 4,  8, "and",        RM,     IMM8,   OP_LOCK},
    {0x82, 5,  8, "sub",        RM,     IMM8,   OP_LOCK},
    {0x82, 6,  8, "xor",        RM,     IMM8,   OP_LOCK},
    {0x82, 7,  8, "cmp",        RM,     IMM8},
    {0x83, 0, 16, "add",        RM,     IMM8,   OP_LOCK},
    {0x83, 1, 16, "or",         RM,     IMM8,   OP_LOCK},
    {0x83, 2, 16, "adc",        RM,     IMM8,   OP_LOCK},
    {0x83, 3, 16, "sbb",        RM,     IMM8,   OP_LOCK},
    {0x83, 4, 16, "and",        RM,     IMM8,   OP_LOCK},
    {0x83, 5, 16, "sub",        RM,     IMM8,   OP_LOCK},
    {0x83, 6, 16, "xor",        RM,     IMM8,   OP_LOCK},
    {0x83, 7, 16, "cmp",        RM,     IMM8},

    {0x8F, 0, 16, "pop",        RM},

    {0xC0, 0,  8, "rol",        RM,     IMM8},
    {0xC0, 1,  8, "ror",        RM,     IMM8},
    {0xC0, 2,  8, "rcl",        RM,     IMM8},
    {0xC0, 3,  8, "rcr",        RM,     IMM8},
    {0xC0, 4,  8, "shl",        RM,     IMM8},
    {0xC0, 5,  8, "shr",        RM,     IMM8},
    {0xC0, 6,  8, "sal",        RM,     IMM8}, /* aliased to shl */
    {0xC0, 7,  8, "sar",        RM,     IMM8},
    {0xC1, 0, 16, "rol",        RM,     IMM8},
    {0xC1, 1, 16, "ror",        RM,     IMM8},
    {0xC1, 2, 16, "rcl",        RM,     IMM8},
    {0xC1, 3, 16, "rcr",        RM,     IMM8},
    {0xC1, 4, 16, "shl",        RM,     IMM8},
    {0xC1, 5, 16, "shr",        RM,     IMM8},
    {0xC1, 6, 16, "sal",        RM,     IMM8}, /* aliased to shl */
    {0xC1, 7, 16, "sar",        RM,     IMM8},

    {0xC6, 0,  8, "mov",        RM,     IMM},
    {0xC7, 0, 16, "mov",        RM,     IMM},

    {0xD0, 0,  8, "rol",        RM,     ONE},
    {0xD0, 1,  8, "ror",        RM,     ONE},
    {0xD0, 2,  8, "rcl",        RM,     ONE},
    {0xD0, 3,  8, "rcr",        RM,     ONE},
    {0xD0, 4,  8, "shl",        RM,     ONE},
    {0xD0, 5,  8, "shr",        RM,     ONE},
    {0xD0, 6,  8, "sal",        RM,     ONE}, /* aliased to shl */
    {0xD0, 7,  8, "sar",        RM,     ONE},
    {0xD1, 0, 16, "rol",        RM,     ONE},
    {0xD1, 1, 16, "ror",        RM,     ONE},
    {0xD1, 2, 16, "rcl",        RM,     ONE},
    {0xD1, 3, 16, "rcr",        RM,     ONE},
    {0xD1, 4, 16, "shl",        RM,     ONE},
    {0xD1, 5, 16, "shr",        RM,     ONE},
    {0xD1, 6, 16, "sal",        RM,     ONE}, /* aliased to shl */
    {0xD1, 7, 16, "sar",        RM,     ONE},
    {0xD2, 0,  8, "rol",        RM,     CL},
    {0xD2, 1,  8, "ror",        RM,     CL},
    {0xD2, 2,  8, "rcl",        RM,     CL},
    {0xD2, 3,  8, "rcr",        RM,     CL},
    {0xD2, 4,  8, "shl",        RM,     CL},
    {0xD2, 5,  8, "shr",        RM,     CL},
    {0xD2, 6,  8, "sal",        RM,     CL}, /* aliased to shl */
    {0xD2, 7,  8, "sar",        RM,     CL},
    {0xD3, 0, 16, "rol",        RM,     CL},
    {0xD3, 1, 16, "ror",        RM,     CL},
    {0xD3, 2, 16, "rcl",        RM,     CL},
    {0xD3, 3, 16, "rcr",        RM,     CL},
    {0xD3, 4, 16, "shl",        RM,     CL},
    {0xD3, 5, 16, "shr",        RM,     CL},
    {0xD3, 6, 16, "sal",        RM,     CL}, /* aliased to shl */
    {0xD3, 7, 16, "sar",        RM,     CL},

    {0xF6, 0,  8, "test",       RM,     IMM},
    {0xF6, 1,  8, "test",       RM,     IMM},   /* aliased to 0 */
    {0xF6, 2,  8, "not",        RM,     0,      OP_LOCK},
    {0xF6, 3,  8, "neg",        RM,     0,      OP_LOCK},
    {0xF6, 4,  8, "mul",        RM},
    {0xF6, 5,  8, "imul",       RM},
    {0xF6, 6,  8, "div",        RM},
    {0xF6, 7,  8, "idiv",       RM},
    {0xF7, 0, 16, "test",       RM,     IMM},
    {0xF7, 1, 16, "test",       RM,     IMM},   /* aliased to 0 */
    {0xF7, 2, 16, "not",        RM,     0,      OP_LOCK},
    {0xF7, 3, 16, "neg",        RM,     0,      OP_LOCK},
    {0xF7, 4, 16, "mul",        RM},
    {0xF7, 5, 16, "imul",       RM},
    {0xF7, 6, 16, "div",        RM},
    {0xF7, 7, 16, "idiv",       RM},

    {0xFE, 0,  8, "inc",        RM,     0,      OP_LOCK},
    {0xFE, 1,  8, "dec",        RM,     0,      OP_LOCK},
    {0xFF, 0, 16, "inc",        RM,     0,      OP_LOCK},
    {0xFF, 1, 16, "dec",        RM,     0,      OP_LOCK},
    {0xFF, 2,  0, "call",       RM},
    {0xFF, 3, 16, "call",       MEM,    0,      OP_FAR},        /* a change in bitness should only happen across segment boundaries */
    {0xFF, 4,  0, "jmp",        RM},
    {0xFF, 5, 16, "jmp",        MEM,    0,      OP_FAR},        /* a change in bitness should only happen across segment boundaries */
    {0xFF, 6, 16, "push",       RM},
};

/* a subcode value of 8 means all subcodes,
 * or the subcode marks the register if there is one present. */
static const op_info instructions_0F[] = {
    {0x00, 0, 16, "sldt",       RM,     0,      OP_OP32_REGONLY},       /* todo: implement this flag */
    {0x00, 1, 16, "str",        RM,     0,      OP_OP32_REGONLY},
    {0x00, 2,  0, "lldt",       RM},
    {0x00, 3,  0, "ltr",        RM},
    {0x00, 4,  0, "verr",       RM},
    {0x00, 5,  0, "verw",       RM},
    /* 00/6 unused */
    /* 00/7 unused */
    {0x01, 0,  0, "sgdt",       MEM},
    {0x01, 1,  0, "sidt",       MEM},
    {0x01, 2,  0, "lgdt",       MEM},
    {0x01, 3,  0, "lidt",       MEM},
    {0x01, 4, 16, "smsw",       RM,     0,      OP_OP32_REGONLY},
    /* 01/5 unused */
    {0x01, 6,  0, "lmsw",       RM},
    {0x01, 7,  0, "invlpg",     MEM},
    {0x02, 8, 16, "lar",        REG,    RM,     OP_OP32_REGONLY},       /* fixme: the first reg should always be ax? */
    {0x03, 8, 16, "lsl",        REG,    RM,     OP_OP32_REGONLY},       /* fixme: the first reg should always be ax? */
    /* 04 unused */
    /* 05 unused (fixme: loadall? syscall?) */
    {0x06, 8,  0, "clts"},
    /* 07 unused (fixme: loadall? sysret?) */
    {0x08, 8,  0, "invd"},
    {0x09, 8,  0, "wbinvd"},

    {0x20, 8,  0, "mov",        REG32,  CR32},  /* here mod is simply ignored */
    {0x21, 8,  0, "mov",        REG32,  DR32},
    {0x22, 8,  0, "mov",        CR32,   REG32},
    {0x23, 8,  0, "mov",        DR32,   REG32},
    {0x24, 8,  0, "mov",        REG32,  TR32},
    /* 25 unused */
    {0x26, 8,  0, "mov",        TR32,   REG32},

    {0x80, 8,  0, "jo",         REL16},
    {0x81, 8,  0, "jno",        REL16},
    {0x82, 8,  0, "jb",         REL16},
    {0x83, 8,  0, "jae",        REL16},
    {0x84, 8,  0, "jz",         REL16},
    {0x85, 8,  0, "jnz",        REL16},
    {0x86, 8,  0, "jbe",        REL16},
    {0x87, 8,  0, "ja",         REL16},
    {0x88, 8,  0, "js",         REL16},
    {0x89, 8,  0, "jns",        REL16},
    {0x8A, 8,  0, "jp",         REL16},
    {0x8B, 8,  0, "jnp",        REL16},
    {0x8C, 8,  0, "jl",         REL16},
    {0x8D, 8,  0, "jge",        REL16},
    {0x8E, 8,  0, "jle",        REL16},
    {0x8F, 8,  0, "jg",         REL16},
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
    {0xA0, 8,  0, "push",       FS},
    {0xA1, 8,  0, "pop",        FS},
    /* A2 - cpuid? */
    {0xA3, 8, 16, "bt",         RM,     REG},
    {0xA4, 8, 16, "shld",       RM,     REG,    OP_ARG2_IMM8},
    {0xA5, 8, 16, "shld",       RM,     REG,    OP_ARG2_CL},
    /* A6,7 unused */
    {0xA8, 8,  0, "push",       GS},
    {0xA9, 8,  0, "pop",        GS},
    /* AA - rsm? */
    {0xAB, 8, 16, "bts",        RM,     REG,    OP_LOCK},
    {0xAC, 8, 16, "shrd",       RM,     REG,    OP_ARG2_IMM8},
    {0xAD, 8, 16, "shrd",       RM,     REG,    OP_ARG2_CL},
    /* AE unused */
    {0xAF, 8, 16, "imul",       REG,    RM},
    {0xB0, 8,  8, "cmpxchg",    RM,     REG,    OP_LOCK},
    {0xB1, 8, 16, "cmpxchg",    RM,     REG,    OP_LOCK},
    {0xB2, 8, 16, "lss",        REG,    MEM},
    {0xB3, 8, 16, "btr",        RM,     REG,    OP_LOCK},
    {0xB4, 8, 16, "lfs",        REG,    MEM},
    {0xB5, 8, 16, "lgs",        REG,    MEM},
    {0xB6, 8, 16, "movzx",      REG,    RM},
    {0xB7, 8, 16, "movzx",      REG,    RM},
    /* B8, 9, A.0-3 unused */
    {0xBA, 4, 16, "bt",         RM,     IMM8},
    {0xBA, 5, 16, "bts",        RM,     IMM8,   OP_LOCK},
    {0xBA, 6, 16, "btr",        RM,     IMM8,   OP_LOCK},
    {0xBA, 7, 16, "btc",        RM,     IMM8,   OP_LOCK},
    {0xBB, 8, 16, "btc",        RM,     REG,    OP_LOCK},
    {0xBC, 8, 16, "bsf",        REG,    RM},
    {0xBD, 8, 16, "bsr",        REG,    RM},
    {0xBE, 8, 16, "movsx",      REG,    RM},
    {0xBF, 8, 16, "movsx",      REG,    RM},
    /* C0/1 - xadd? */

    {0xC8, 0, 16, "bswap",      AX},
    {0xC9, 0, 16, "bswap",      CX},
    {0xCA, 0, 16, "bswap",      DX},
    {0xCB, 0, 16, "bswap",      BX},
    {0xCC, 0, 16, "bswap",      SP},
    {0xCD, 0, 16, "bswap",      BP},
    {0xCE, 0, 16, "bswap",      SI},
    {0xCF, 0, 16, "bswap",      DI},
};

/* mod < 3 (instructions with memory args) */
static const op_info instructions_fpu_m[64] = {
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
    {0xDB, 1},
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
    {0xDD, 1},
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
    {0xDF, 1},
    {0xDF, 2, 16, "fist",       MEM,    0,      OP_S},
    {0xDF, 3, 16, "fistp",      MEM,    0,      OP_S},
    {0xDF, 4,  0, "fbld",       MEM},   /* 80 */
    {0xDF, 5, 64, "fild",       MEM,    0,      OP_LL},
    {0xDF, 6,  0, "fbstp",      MEM},   /* 80 */
    {0xDF, 7, 64, "fistp",      MEM,    0,      OP_LL},
};

static const op_info instructions_fpu_r[64] = {
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
    {0xDA, 0,  0, {0},          0,      0},
    {0xDA, 1,  0, {0},          0,      0},
    {0xDA, 2,  0, {0},          0,      0},
    {0xDA, 3,  0, {0},          0,      0},
    {0xDA, 4,  0, {0},          0,      0},
    {0xDA, 5,  0, {0},          0,      0},     /* fucompp */
    {0xDA, 6,  0, {0},          0,      0},
    {0xDA, 7,  0, {0},          0,      0},
    {0xDB, 0,  0, {0},          0,      0},
    {0xDB, 1,  0, {0},          0,      0},
    {0xDB, 2,  0, {0},          0,      0},
    {0xDB, 3,  0, {0},          0,      0},
    {0xDB, 4,  0, {0},          0,      0},     /* fneni, fndisi, fnclex, fninit, fnsetpm */
    {0xDB, 5,  0, {0},          0,      0},
    {0xDB, 6,  0, {0},          0,      0},
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
    {0xDF, 5,  0, {0},          0,      0},
    {0xDF, 6,  0, {0},          0,      0},
    {0xDF, 7,  0, {0},          0,      0},
};

static const op_info instructions_fpu_single[] = {
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

/* returns the flag if it's a prefix, 0 otherwise */
word get_prefix(byte opcode) {
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

/* Parameters:
 * ip      - [i] NOT current IP, but rather IP of the *argument*. This
 *               is necessary for REL16 to work right.
 * p       - [i] pointer to the current argument to be parsed
 * value   - [o] pointer to the output value
 * argtype - [i] type of argument being processed
 * instr   - [i/o] pointer to the relevant instr_info
 *      ->prefix     [i]
 *      ->op_info    [i]
 *      ->modrm_disp [o]
 *      ->modrm_reg  [o]
 * is32    - [i] bitness—REL16 and MOFFS16 are affected by bitness but can't be overridden
 *
 * Returns: number of bytes processed
 *
 * Does not process specific arguments (e.g. registers, DSBX, ONE...)
 * The parameter out is given as a dword but may require additional casting.
 */
int get_arg(word ip, const byte *p, dword *value, enum arg argtype, instr_info *instr, int is32) {
    *value = 0;

    switch (argtype) {
    case IMM8:
        *value = *p;
        return 1;
    case IMM16:
        *value = *((word *) p);
        return 2;
    case IMM:
        if (instr->op.size == 8)
            *value = *p;
        else if (instr->op.size == 16)
            *value = *((word *) p);
        else if (instr->op.size == 32)
            *value = *((dword *) p);
        return instr->op.size / 8;
    case REL8:
        *value = ip+1+*((int8_t *) p);  /* signed */
        return 1;
    case REL16:
        /* Equivalently signed or unsigned (i.e. clipped) */
        if (is32) {
            *value = (ip+4+*((dword *) p)) & 0xffffffff;
            return 4;
        } else {
            *value = (ip+2+*((word *) p)) & 0xffff;
            return 2;
        }
    case PTR32:
        *value = *((word *) p); /* I think this should be enough */
        return 4;
    case MOFFS16:
        if (is32) {
            *value = *((dword *) p);
            return 4;
        } else {
            *value = *((word *) p);
            return 2;
        }
    case RM:
    case MEM:
    {
        byte mod = *p >> 6;
        byte rm  = *p & 7;
        int ret = 1;

        if (mod == 3) {
            instr->modrm_disp = DISP_REG;
            instr->modrm_reg = rm;
            return 1;
        }

        if (instr->addrsize == 32 && rm == 4) {
            /* SIB byte */
            p++;
            instr->sib_scale = 1 << (*p >> 6);
            instr->sib_index = (*p >> 3) & 7;
            rm = *p & 7;
            ret++;
        }

        if (mod == 0 && ((instr->addrsize == 16 && rm == 6) ||
                         (instr->addrsize == 32 && rm == 5))) {
            if (instr->addrsize == 32) {
                *value = *((dword *) (p+1));
                ret += 4;
            } else {
                *value = *((word *) (p+1));
                ret += 2;
            }
            instr->modrm_disp = DISP_16;
            instr->modrm_reg = 8;
        } else if (mod == 0) {
            instr->modrm_disp = DISP_NONE;
            instr->modrm_reg = rm;
        } else if (mod == 1) {
            *value = *(p+1);
            instr->modrm_disp = DISP_8;
            instr->modrm_reg = rm;
            ret += 1;
        } else if (mod == 2) {
            if (instr->addrsize == 32) {
                *value = *((dword *) (p+1));
                ret += 4;
            } else {
                *value = *((word *) (p+1));
                ret += 2;
            }
            instr->modrm_disp = DISP_16;
            instr->modrm_reg = rm;
        }
        return ret;
    }
    case REG:
    case SEG16:
    case CR32:
    case DR32:
    case TR32:
        *value = (*p >> 3) & 7;
        return 0;
    case REG32:
    case STX:
        *value = *p & 7;
        return 1;
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

static const char reg16[9][3] = {
    "ax","cx","dx","bx","sp","bp","si","di",""
};

static void get_seg16(char *out, byte reg) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, seg16[reg]);
}

static void get_reg8(char *out, byte reg) {
    if (asm_syntax == GAS)
        strcat(out, "%");
    strcat(out, reg8[reg]);
}

static void get_reg16(char *out, byte reg, word is32) {
    if (reg <= 7) {
        if (asm_syntax == GAS)
            strcat(out, "%");
        if (is32)
            strcat(out, "e");
        strcat(out, reg16[reg]);
    }
}

static const char modrm16_gas[8][8] = {
    "%bx,%si", "%bx,%di", "%bp,%si", "%bp,%di", "%si", "%di", "%bp", "%bx"
};

static const char modrm16_masm[8][6] = {
    "bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"
};

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %s: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

/* With MASM/NASM, use capital letters to help disambiguate them from the following 'h'. */

/* Parameters:
 * ip      - [i] current instruction (used for printing warn string)
 * out     - [o] pointer to the output (string) buffer
 * value   - [i] value of argument being processed
 * argtype - [i] type of argument being processed
 * instr   - [i] pointer to the relevant instr_info
 * usedmem - [o] did we use a memory argument (needed for sanity checks)
 */
void print_arg(char *ip, char *out, dword value, enum arg argtype, instr_info *instr, byte *usedmem) {
    *out = '\0';

    if (argtype >= AL && argtype <= BH)
        get_reg8(out, argtype-AL);
    else if (argtype >= AX && argtype <= DI)
        get_reg16(out, argtype-AX, (instr->op.size == 32));
    else if (argtype >= ES && argtype <= GS)
        get_seg16(out, argtype-ES);

    switch (argtype) {
    case ONE:
        strcat(out, (asm_syntax == GAS) ? "$0x1" : "1h");
        break;
    case IMM8:
        if (instr->op.flags & OP_STACK) { /* 6a */
            if (instr->op.size == 32)
                sprintf(out, (asm_syntax == GAS) ? "$0x%08x" : "dword %08Xh", (dword) (int8_t) value);
            else
                sprintf(out, (asm_syntax == GAS) ? "$0x%04x" : "word %04Xh", (word) (int8_t) value);
        } else
            sprintf(out, (asm_syntax == GAS) ? "$0x%02x" : "%02Xh", value);
        break;
    case IMM16:
        sprintf(out, (asm_syntax == GAS) ? "$0x%04x" : "%04Xh", value);
        break;
    case IMM:
        if (instr->op.flags & OP_STACK) {
            if (instr->op.size == 32)
                sprintf(out, (asm_syntax == GAS) ? "$0x%08x" : "dword %08Xh", value);
            else
                sprintf(out, (asm_syntax == GAS) ? "$0x%04x" : "word %04Xh", value);
        } else {
            if (instr->op.size == 8)
                sprintf(out, (asm_syntax == GAS) ? "$0x%02x" : "%02Xh", value);
            else if (instr->op.size == 16)
                sprintf(out, (asm_syntax == GAS) ? "$0x%04x" : "%04Xh", value);
            else if (instr->op.size == 32)
                sprintf(out, (asm_syntax == GAS) ? "$0x%08x" : "%08Xh", value);
        }
        break;
    case REL8:
    case REL16:
        sprintf(out, "%04x", value);
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
            sprintf(out+strlen(out), "0x%04x", value);
        } else {
            out[0] = '[';
            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }
            sprintf(out+strlen(out), "%04Xh]", value);
        }
        *usedmem = 1;
        break;
    case DSBX:
    case DSSI:
        if (asm_syntax != NASM) {
            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }
            strcat(out, (asm_syntax == GAS) ? "(%" : "[");
            if (instr->prefix & PREFIX_ADDR32)
                strcat(out, "e");
            strcat(out, (argtype == DSBX) ? "bx" : "si");
            strcat(out, (asm_syntax == GAS) ? ")" : "]");
        }
        *usedmem = 1;
        break;
    case ESDI:
        if (asm_syntax != NASM) {
            strcat(out, (asm_syntax == GAS) ? "%es:(%" : "es:[");
            if (instr->prefix & PREFIX_ADDR32)
                strcat(out, "e");
            strcat(out, "di");
            strcat(out, (asm_syntax == GAS) ? ")" : "]");
        }
        *usedmem = 1;
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
        else if (asm_syntax == MASM)
            strcpy(out, "dx");
        break;
    /* register/memory. this is always the first byte after the opcode,
     * and is always either paired with a simple register or a subcode.
     * there are a few cases where it isn't [namely C6/7 MOV and 8F POP]
     * and we need to warn if we see a value there that isn't 0. */
    case RM:
    case MEM:
        if (instr->modrm_disp == DISP_REG) {
            if (argtype == MEM)
                warn_at("ModRM byte has mod 3, but opcode only allows accessing memory.\n");

            if (instr->op.size == 8)
                get_reg8(out, instr->modrm_reg);
            else
                /* note: return a 16-bit register if the size is 0 */
                get_reg16(out, instr->modrm_reg, (instr->op.size == 32));
            break;
        }

        *usedmem = 1;

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
                if (instr->modrm_reg == 8) {
                    sprintf(out+strlen(out), "0x%04x", value);  /* absolute memory is unsigned */
                    return;
                }
                if (svalue < 0)
                    sprintf(out+strlen(out), "-0x%04x", -svalue);
                else
                    sprintf(out+strlen(out), "0x%04x", svalue);
            } else if (instr->modrm_disp == DISP_16 && instr->addrsize == 32) {
                int32_t svalue = (int32_t) value;
                if (instr->modrm_reg == 8) {
                    sprintf(out+strlen(out), "0x%08x", value);  /* absolute memory is unsigned */
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
                get_reg16(out, instr->modrm_reg, 1);
                if (instr->sib_index) {
                    strcat(out, ",");
                    get_reg16(out, instr->sib_index, 1);
                    strcat(out, ",0");
                    out[strlen(out)-1] = '0'+instr->sib_scale;
                }
            }
            strcat(out, ")");
        } else {
            int has_sib = (instr->sib_scale != 0 && instr->sib_index < 8);
            if (instr->op.flags & OP_FAR)
                strcat(out, "far ");
            else if (instr->op.arg0 != REG && instr->op.arg1 != REG) {
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
            }

            if (asm_syntax == NASM)
                strcat(out, "[");

            if (instr->prefix & PREFIX_SEG_MASK) {
                get_seg16(out, (instr->prefix & PREFIX_SEG_MASK)-1);
                strcat(out, ":");
            }

            if (asm_syntax == MASM)
                strcat(out, "[");

            if (has_sib) {
                get_reg16(out, instr->sib_index, 1);
                strcat(out, "*0");
                out[strlen(out)-1] = '0'+instr->sib_scale;
            }

            if (instr->modrm_reg < 8) {
                if (has_sib)
                    strcat(out, "+");
                if (instr->addrsize == 16)
                    strcat(out, modrm16_masm[instr->modrm_reg]);
                else
                    get_reg16(out, instr->modrm_reg, 1);
            }

            if (instr->modrm_disp == DISP_8) {
                int8_t svalue = (int8_t) value;
                if (svalue < 0)
                    sprintf(out+strlen(out), "-%02Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%02Xh", svalue);
            } else if (instr->modrm_disp == DISP_16 && instr->addrsize == 16) {
                int16_t svalue = (int16_t) value;
                if (instr->modrm_reg == 8 && !has_sib)
                    sprintf(out+strlen(out), "%04Xh", value);   /* absolute memory is unsigned */
                else if (svalue < 0)
                    sprintf(out+strlen(out), "-%04Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%04Xh", svalue);
            } else if (instr->modrm_disp == DISP_16 && instr->addrsize == 32) {
                int32_t svalue = (int32_t) value;
                if (instr->modrm_reg == 8 && !has_sib)
                    sprintf(out+strlen(out), "%08Xh", value);   /* absolute memory is unsigned */
                else if (svalue < 0)
                    sprintf(out+strlen(out), "-%08Xh", -svalue);
                else
                    sprintf(out+strlen(out), "+%08Xh", svalue);
            }
            strcat(out, "]");
        }
        break;
    case REG:
        if (instr->op.size == 8 || instr->op.opcode == 0x0FB6 || instr->op.opcode == 0x0FBE) /* mov*x */
            get_reg8(out, value);
        else if (instr->op.opcode == 0x0FB7 || instr->op.opcode == 0x0FBF)
            get_reg16(out, value, 0);
        else
            /* note: return a 16-bit register if the size is 0 */
            get_reg16(out, value, (instr->op.size == 32));
        break;
    case REG32:
        get_reg16(out, value, 1);
        break;
    case SEG16:
        if (value > 5)
            warn_at("Invalid segment register %d\n", value);
        get_seg16(out, value);
        break;
    case CR32:
        if (value == 1 || value > 4)
            warn_at("Invalid control register %d\n", value);
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
            warn_at("Invalid test register %d\n", value);
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
    default:
        break;
    }
}

static int get_fpu_instr(const byte *p, op_info *op) {
    byte opcode = *p;
    byte nextcode = *(p+1);
    byte subcode = (nextcode >> 3) & 7;
    byte index = (opcode & 7)*8 + subcode;
    unsigned i;
    
    if ((*(p+1) >> 6) < 3) {
        if (instructions_fpu_m[index].name[0])
            *op = instructions_fpu_m[index];
        return 0;
    } else {
        if (instructions_fpu_r[index].name[0]) {
            *op = instructions_fpu_r[index];
            return 0;
        } else {
            /* try the single op list */
            for (i=0; i<sizeof(instructions_fpu_single)/sizeof(op_info); i++) {
                if (opcode == instructions_fpu_single[i].opcode &&
                    nextcode == instructions_fpu_single[i].subcode) {
                    *op = instructions_fpu_single[i];
                    break;
                }
            }
        }
        return 1;
    }
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
 * while actually dumping output, both to keep this file agnostic and to
 * ensure they only get printed once), so you will need to watch out for
 * multiple prefixes, invalid instructions, etc.
 */
int get_instr(word ip, const byte *p, instr_info *instr, int is32) {
    int len = 0;
    byte opcode;
    word prefix;

    memset(instr, 0, sizeof(instr_info));

    /* first iterate through prefixes until we find a real opcode */
    while ((prefix = get_prefix(p[len]))) {
        if (((instr->prefix & PREFIX_SEG_MASK) && (prefix & PREFIX_SEG_MASK)) ||
            (instr->prefix & prefix)) {
            instr->op = instructions[p[len]];
            return len+1;
        }
        instr->prefix |= prefix;
        len++;
    }

    opcode = p[len];

    /* copy the op_info */
    if (instructions[opcode].name[0]) {
        instr->op = instructions[opcode];
    } else {
        byte subcode = (p[len+1] >> 3) & 7;

        /* do we have a member of an instruction group? */
        if (opcode == 0x0F) {
            unsigned i;
            
            len++;
            opcode = p[len];
            subcode = (p[len+1] >> 3) & 7;
            for (i=0; i<sizeof(instructions_0F)/sizeof(op_info); i++) {
                if (opcode == instructions_0F[i].opcode &&
                    (instructions_0F[i].subcode == 8 ||
                     instructions_0F[i].subcode == subcode)) {
                    instr->op = instructions_0F[i];
                    instr->op.opcode = 0x0F00 | instr->op.opcode;
                    break;
                }
            }
        } else if (opcode >= 0xD8 && opcode <= 0xDF) {
            len += get_fpu_instr(p+len, &instr->op);
        } else {
            unsigned i;
            for (i=0; i<sizeof(instructions_group)/sizeof(op_info); i++) {
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
            instr->op.opcode = opcode;
            instr->op.subcode = subcode;
            instr->op.size = 0;
            instr->op.arg0 = 0;
            instr->op.arg1 = 0;
            instr->op.flags = 0;
        }
    }

    len++;

    /* resolve the size */
    if (instr->prefix & PREFIX_OP32)
        instr->op.size = is32 ? 16 : 32;        /* yes, change it anyway */
    else if (instr->op.size == 16)
        instr->op.size = is32 ? 32 : 16;

    if (instr->prefix & PREFIX_ADDR32)
        instr->addrsize = is32 ? 16 : 32;
    else
        instr->addrsize = is32 ? 32 : 16;

    /* figure out what arguments we have */
    if (instr->op.arg0) {
        int base = len;

        len += get_arg(ip+len, &p[len], &instr->arg0, instr->op.arg0, instr, is32);

        /* registers that read from the modrm byte, which we might have just processed */
        if (instr->op.arg1 >= REG && instr->op.arg1 <= TR32)
            get_arg(ip+len, &p[base], &instr->arg1, instr->op.arg1, instr, is32);
        else
            len += get_arg(ip+len, &p[len], &instr->arg1, instr->op.arg1, instr, is32);

        /* arg2 */
        if (instr->op.flags & OP_ARG2_IMM)
            len += get_arg(ip+len, &p[len], &instr->arg2, IMM, instr, is32);
        else if (instr->op.flags & OP_ARG2_IMM8)
            len += get_arg(ip+len, &p[len], &instr->arg2, IMM8, instr, is32);
        else if (instr->op.flags & OP_ARG2_CL)
            len += get_arg(ip+len, &p[len], &instr->arg2, CL, instr, is32);
    }

    /* modify the instruction name if appropriate */
    if ((instr->op.flags & OP_STACK) && (instr->prefix & PREFIX_OP32)) {
        if (instr->op.size == 16)
            strcat(instr->op.name, "w");
        else
            strcat(instr->op.name, (asm_syntax == GAS) ? "l" : "d");
    } else if ((instr->op.flags & OP_STRING) && asm_syntax != GAS) {
        if (instr->op.size == 8)
            strcat(instr->op.name, "b");
        else if (instr->op.size == 16)
            strcat(instr->op.name, "w");
        else if (instr->op.size == 32)
            strcat(instr->op.name, "d");
    } else if (instr->op.opcode == 0x98 && (instr->prefix & PREFIX_OP32))
        strcpy(instr->op.name, "cwde");
    else if (instr->op.opcode == 0x99 && (instr->prefix & PREFIX_OP32))
        strcpy(instr->op.name, "cdq");
    else if (instr->op.opcode == 0xE3 && (instr->prefix & PREFIX_ADDR32))
        strcpy(instr->op.name, "jecxz");
    else if (instr->op.opcode == 0xD4 && instr->arg0 == 10) {
        strcpy(instr->op.name, "aam");
        instr->op.arg0 = 0;
    } else if (instr->op.opcode == 0xD5 && instr->arg0 == 10) {
        strcpy(instr->op.name, "aad");
        instr->op.arg0 = 0;
    } else if (asm_syntax == GAS) {
        if (instr->op.flags & OP_FAR) {
            memmove(instr->op.name+1, instr->op.name, strlen(instr->op.name));
            instr->op.name[0] = 'l';
        } else if (instr->op.opcode == 0x0FB6)   /* movzx */
            strcpy(instr->op.name, (instr->op.size == 32) ? "movzbl" : "movzbw");
        else if (instr->op.opcode == 0x0FB7)     /* movzx */
            strcpy(instr->op.name, (instr->op.size == 32) ? "movzwl" : "movzww");
        else if (instr->op.opcode == 0x0FBE)     /* movsx */
            strcpy(instr->op.name, (instr->op.size == 32) ? "movsbl" : "movsbw");
        else if (instr->op.opcode == 0x0FBF)     /* movsx */
            strcpy(instr->op.name, (instr->op.size == 32) ? "movswl" : "movsww");
        else if (instr->op.arg0 != REG &&
                 instr->op.arg1 != REG &&
                 instr->modrm_disp != DISP_REG) {
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
                strcat(instr->op.name, "l");
        }
    } else if (asm_syntax != GAS && (instr->op.opcode == 0xCA || instr->op.opcode == 0xCB))
        strcat(instr->op.name, "f");

    return len;
}
