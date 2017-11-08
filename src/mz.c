#include <stdlib.h>

#include "semblance.h"
#include "x86_instr.h"
#include "mz.h"

#pragma pack(1)

struct header_mz {
    word  e_magic;      /* 00: MZ Header signature */
    word  e_cblp;       /* 02: Bytes on last page of file */
    word  e_cp;         /* 04: Pages in file */
    word  e_crlc;       /* 06: Relocations */
    word  e_cparhdr;    /* 08: Size of header in paragraphs */
    word  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    word  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    word  e_ss;         /* 0e: Initial (relative) SS value */
    word  e_sp;         /* 10: Initial SP value */
    word  e_csum;       /* 12: Checksum */
    word  e_ip;         /* 14: Initial IP value */
    word  e_cs;         /* 16: Initial (relative) CS value */
    word  e_lfarlc;     /* 18: File address of relocation table */
    word  e_ovno;       /* 1a: Overlay number */
};

STATIC_ASSERT(sizeof(struct header_mz) == 0x1c);

static void print_header(struct header_mz *header) {
    printf("Minimum extra allocation: %d bytes\n", header->e_minalloc * 16); /* 0a */
    printf("Maximum extra allocation: %d bytes\n", header->e_maxalloc * 16); /* 0c */
    printf("Initial stack location: %#x\n", realaddr(header->e_ss, header->e_sp)); /* 0e */
    printf("Program entry point: %#x\n", realaddr(header->e_cs, header->e_ip)); /* 14 */
    printf("Overlay number: %d\n", header->e_ovno); /* 1a */
    printf("\n");
}

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %05x: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

static int print_instr(dword ip, byte *p, char *out) {
    instr_info instr = {0};
    char arg0[32] = {0}, arg1[32] = {0}, arg2[32] = {0};
    byte usedmem = 0;
    unsigned len;

    char *outp = out;
    unsigned i;
    char ip_string[7];

    out[0] = 0;

    len = get_instr(ip, p, &instr, 0);

    /* did we find too many prefixes? */
    if (get_prefix(instr.op.opcode)) {
        if (get_prefix(instr.op.opcode) & PREFIX_SEG_MASK)
            warn_at("Multiple segment prefixes found: %s, %s. Skipping to next instruction.\n",
                    seg16[(instr.prefix & PREFIX_SEG_MASK)-1], instr.op.name);
        else
            warn_at("Prefix specified twice: %s. Skipping to next instruction.\n", instr.op.name);
    }

    sprintf(ip_string, "%05x", ip);

    print_arg(ip_string, arg0, instr.arg0, instr.op.arg0, &instr, &usedmem);
    print_arg(ip_string, arg1, instr.arg1, instr.op.arg1, &instr, &usedmem);
    if (instr.op.flags & OP_ARG2_IMM)
        print_arg(ip_string, arg2, instr.arg2, IMM, &instr, &usedmem);
    else if (instr.op.flags & OP_ARG2_IMM8)
        print_arg(ip_string, arg2, instr.arg2, IMM8, &instr, &usedmem);
    else if (instr.op.flags & OP_ARG2_CL)
        print_arg(ip_string, arg2, instr.arg2, CL, &instr, &usedmem);

    /* check that we have a valid instruction */
    if (instr.op.name[0] == '?')
        warn_at("Unknown opcode %2X (extension %d)\n", instr.op.opcode, instr.op.subcode);

    /* okay, now we begin dumping */
    outp += sprintf(outp, "%05x:\t", ip);

    for (i=0; i<len && i<7; i++) {
        outp += sprintf(outp, "%02x ", p[i]);
    }
    for (; i<8; i++) {
        outp += sprintf(outp, "   ");
    }

    /* print prefixes, including (fake) prefixes if ours are invalid */
    if (instr.prefix & PREFIX_SEG_MASK) {
        /* note: is it valid to use overrides with lods and outs? */
        if (!usedmem || (instr.op.arg0 == ESDI || (instr.op.arg1 == ESDI && instr.op.arg0 != DSSI))) {  /* can't be overridden */
            warn_at("Segment prefix %s used with opcode 0x%02x %s\n", seg16[(instr.prefix & PREFIX_SEG_MASK)-1], instr.op.opcode, instr.op.name);
            outp += sprintf(outp, "%s ", seg16[(instr.prefix & PREFIX_SEG_MASK)-1]);
        }
    }
    if ((instr.prefix & PREFIX_OP32) && instr.op.size != 16 && instr.op.size != 32) {
        warn_at("Operand-size override used with opcode %2X %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, (asm_syntax == GAS) ? "data32 " : "o32 "); /* fixme: how should MASM print it? */
    }
    if ((instr.prefix & PREFIX_ADDR32) && (asm_syntax == NASM) && (instr.op.flags & OP_STRING)) {
        outp += sprintf(outp, "a32 ");
    } else if ((instr.prefix & PREFIX_ADDR32) && !usedmem && instr.op.opcode != 0xE3) { /* jecxz */
        warn_at("Address-size prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, (asm_syntax == GAS) ? "addr32 " : "a32 "); /* fixme: how should MASM print it? */
    }
    if (instr.prefix & PREFIX_LOCK) {
        if(!(instr.op.flags & OP_LOCK))
            warn_at("lock prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, "lock ");
    }
    if (instr.prefix & PREFIX_REPNE) {
        if(!(instr.op.flags & OP_REPNE))
            warn_at("repne prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, "repne ");
    }
    if (instr.prefix & PREFIX_REPE) {
        if(!(instr.op.flags & OP_REPE))
            warn_at("repe prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, (instr.op.flags & OP_REPNE) ? "repe ": "rep ");
    }

    outp += sprintf(outp, "%s", instr.op.name);

    if (arg0[0] || arg1[0])
        outp += sprintf(outp,"\t");

    if (asm_syntax == GAS) {
        /* fixme: are all of these orderings correct? */
        if (arg1[0])
            outp += sprintf(outp, "%s,", arg1);
        if (arg0[0])
            outp += sprintf(outp, "%s", arg0);
        if (arg2[0])
            outp += sprintf(outp, ",%s", arg2);
    } else {
        if (arg0[0])
            outp += sprintf(outp, "%s", arg0);
        if (arg0[0] && arg1[0])
            outp += sprintf(outp, ", ");
        if (arg1[0])
            outp += sprintf(outp, "%s", arg1);
        if (arg2[0])
            outp += sprintf(outp, ", %s", arg2);
    }

    /* if we have more than 7 bytes on this line, wrap around */
    if (len > 7) {
        if (asm_syntax == GAS)
            outp += sprintf(outp, "\n%05x:\t", ip+7);
        else
            outp += sprintf(outp, "\n\t\t");
        for (i=7; i<len; i++) {
            outp += sprintf(outp, "%02x ", p[i]);
        }
        outp--; /* trailing space */
    }

    return len;
}

static void print_mz_code(dword start, dword length) {
    dword ip = 0;
    byte buffer[MAX_INSTR];
    char out[256];

    while (ip < length) {
        fseek(f, start+ip, SEEK_SET);

        /* fixme: disassemble everything for now; we'll try to fix it later.
         * this is going to be a little more difficult since dos executables
         * unabashedly mix code and data, so we need to figure out a solution
         * for that. but we needed to do that anyway. */

        /* fixme: also we should have scanning regardless */

        if (length-ip < sizeof(buffer))
            fread(buffer, 1, length-ip, f);
        else
            fread(buffer, 1, sizeof(buffer), f);

        ip += print_instr(ip, buffer, out);
        printf("%s\n", out);
    }
}

void dumpmz(void) {
    struct header_mz header;

    fseek(f, 0, SEEK_SET);
    fread(&header, sizeof(header), 1, f);

    /* read the relocation table */
    reloc_table = malloc(header.e_crlc * sizeof(reloc));
    fseek(f, header.e_lfarlc, SEEK_SET);
    fread(reloc_table, sizeof(reloc), header.e_crlc, f);

    printf("Module type: MZ (DOS executable)\n");

    if (mode & DUMPHEADER)
        print_header(&header);

    if (mode & DISASSEMBLE) {
        dword length = ((header.e_cp - 1) * 512) + header.e_cblp;
        if (header.e_cblp == 0) length += 512;

        print_mz_code(header.e_cparhdr * 16, length);
    }

    free(reloc_table);
}
