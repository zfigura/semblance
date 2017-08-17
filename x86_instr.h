#ifndef __X86_INSTR_H
#define __X86_INSTR_H

#include <string.h>
#include "semblance.h"

enum arg {
    NONE = 0,

    /* the literal value 1, used for bit shift ops */
    ONE,
    
    /* specific registers */
    AL, CL, DL, BL, AH, CH, DH, BH,
    AX, CX, DX, BX, SP, BP, SI, DI,
    ES, CS, SS, DS, FS, GS,
    ALS, AXS,   /* the same as AL/AX except MASM doesn't print them */
    DXS,        /* the same as DX except GAS puts it in parentheses */

    /* absolute or relative numbers, given as 1/2/4 bytes */
    IMM8, IMM16, IMM,   /* immediate number */
    REL8, REL16,        /* relative to current instruction */
    PTR32,      /* absolute instruction, used for far calls/jumps */
    MOFFS16,    /* absolute location in memory, for A0-A3 MOV */

    /* specific memory addresses for string operations */
    DSBX, DSSI, ESDI,

    /* to be read from ModRM, appropriately */
    RM,         /* register/memory */
    MEM,        /* memory only (using 0x11xxxxxx is invalid) */
    REG,        /* register */
    SEG16,      /* segment register */
    REG32,      /* 32-bit only register, used for cr/dr/tr */
    CR32,       /* control register */
    DR32,       /* debug register */
    TR32,       /* test register */

    /* floating point regs */
    ST,         /* top of stack aka st(0) */
    STX,        /* element of stack given by lowest three bytes of "modrm" */
};

/* opcode flags */

#define OP_ARG2_IMM     0x0001  /* has IMM16/32 as third argument */
#define OP_ARG2_IMM8    0x0002  /* has IMM8 as third argument */
#define OP_ARG2_CL      0x0004  /* has CL as third argument */

#define OP_LOCK         0x0008  /* lock prefix valid */
#define OP_REPNE        0x0010  /* repne prefix valid */
#define OP_REPE         0x0020  /* repe prefix valid */
#define OP_REP          OP_REPE /* rep prefix valid */
#define OP_OP32_REGONLY 0x0040  /* operand-size prefix only valid if used with reg */

#define OP_STACK        0x0100  /* only marked for size if overridden */
#define OP_STRING       0x0200  /* string operations */
#define OP_FAR          0x0400  /* far operation */

#define OP_S            0x1000  /* (FPU) op takes -s if GCC */
#define OP_L            0x2000  /* (FPU) op takes -l if GCC */
#define OP_LL           0x3000  /* (FPU) op takes -ll if GCC */
/* -t doesn't need to be marked */

typedef struct {
    word opcode;
    byte subcode;
    byte size;  /* one of: 8, 16, 32, 64, 80, or 0 if not sized */
    char name[8];
    enum arg arg0; /* usually dest */
    enum arg arg1; /* usually src */
    /* arg2 only for imul, shrd, shld */
    dword flags;
} op_info;

#define PREFIX_ES       0x0001  /* 26 */
#define PREFIX_CS       0x0002  /* 2E */
#define PREFIX_SS       0x0003  /* 36 */
#define PREFIX_DS       0x0004  /* 3E */
#define PREFIX_FS       0x0005  /* 64 */
#define PREFIX_GS       0x0006  /* 65 */
#define PREFIX_SEG_MASK 0x0007

#define PREFIX_OP32     0x0008  /* 66 */
#define PREFIX_ADDR32   0x0010  /* 67 */
#define PREFIX_LOCK     0x0020  /* F0 */
#define PREFIX_REPNE    0x0040  /* F2 */
#define PREFIX_REPE     0x0080  /* F3 */

enum disptype {
    DISP_NONE = 0,      /* no disp, i.e. mod == 0 && m != 6 */
    DISP_8    = 1,      /* one byte */
    DISP_16   = 2,      /* two bytes */
    DISP_REG  = 3,      /* register, i.e. mod == 3 */
};

typedef struct {
    word prefix;
    op_info op;
    dword arg0;
    dword arg1;
    dword arg2;
    byte addrsize;
    enum disptype modrm_disp;
    byte modrm_reg;
    byte sib_scale;
    byte sib_index;
} instr_info;

extern int get_instr(word cs, word ip, const byte *p, instr_info *instr, int is32);
extern void print_arg(word cs, word ip, char *out, dword value, enum arg argtype, instr_info *instr, byte *usedmem);

#endif /* __X86_INSTR_H */
