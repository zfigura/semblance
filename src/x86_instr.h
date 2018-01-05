#ifndef __X86_INSTR_H
#define __X86_INSTR_H

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
    REGONLY,    /* register only (not using 0x11xxxxxx is invalid) */
    REG,        /* register */
    SEG16,      /* segment register */
    REG32,      /* 32-bit only register, used for cr/dr/tr */
    CR32,       /* control register */
    DR32,       /* debug register */
    TR32,       /* test register */
    MM,         /* MMX register/memory */
    MMX,        /* MMX register */
    MMXONLY,    /* MMX register only (not using 0x11xxxxxx is invalid) */
    XM,         /* SSE register/memory */
    XMM,        /* SSE register */
    XMMONLY,    /* SSE register only (not using 0x11xxxxxx is invalid) */

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

#define OP_STOP         0x4000  /* stop scanning (jmp, ret) */
#define OP_BRANCH       0x8000  /* branch to target (jmp, jXX) */

struct op {
    word opcode;
    byte subcode;
    byte size;  /* one of: 8, 16, 32, 64, 80, or 0 if not sized */
    char name[11];
    enum arg arg0; /* usually dest */
    enum arg arg1; /* usually src */
    /* arg2 only for imul, shrd, shld */
    dword flags;
};

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
#define PREFIX_WAIT     0x0100  /* 9B */

enum disptype {
    DISP_NONE = 0,      /* no disp, i.e. mod == 0 && m != 6 */
    DISP_8    = 1,      /* one byte */
    DISP_16   = 2,      /* two bytes */
    DISP_REG  = 3,      /* register, i.e. mod == 3 */
};

extern const char seg16[6][3];

struct instr {
    word prefix;
    struct op op;
    dword arg0;
    dword arg1;
    dword arg2;
    byte addrsize;
    enum disptype modrm_disp;
    byte modrm_reg;
    byte sib_scale;
    byte sib_index;
    int usedmem:1;  /* used for error checking */
};

extern int get_instr(dword ip, const byte *p, struct instr *instr, int is32);
extern void print_instr(char *out, char *ip, byte *p, int len, byte flags, struct instr *instr, char *arg0, char *arg1, char *comment);

/* 66 + 67 + seg + lock/rep + 2 bytes opcode + modrm + sib + 4 bytes displacement + 4 bytes immediate */
#define MAX_INSTR       16

/* flags relating to specific instructions */
#define INSTR_SCANNED   0x01    /* byte has been scanned */
#define INSTR_VALID     0x02    /* byte begins an instruction */
#define INSTR_JUMP      0x04    /* instruction is jumped to */
#define INSTR_FUNC      0x08    /* instruction begins a function */
#define INSTR_FAR       0x10    /* instruction is target of far call/jmp */
#define INSTR_RELOC     0x20    /* byte has relocation data */

#endif /* __X86_INSTR_H */
