#include <stdlib.h>
#include <string.h>

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

/* flags relating to specific instructions */
#define INSTR_SCANNED   0x01    /* byte has been scanned */
#define INSTR_VALID     0x02    /* byte begins an instruction */
#define INSTR_JUMP      0x04    /* instruction is jumped to */
#define INSTR_FUNC      0x08    /* instruction begins a function */

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %05x: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

static int print_instr(dword ip, byte *p, char *out, const byte *flags) {
    instr_info instr = {0};
    char arg0[32] = {0}, arg1[32] = {0}, arg2[32] = {0};
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

    print_arg(ip_string, arg0, instr.arg0, instr.op.arg0, &instr);
    print_arg(ip_string, arg1, instr.arg1, instr.op.arg1, &instr);
    if (instr.op.flags & OP_ARG2_IMM)
        print_arg(ip_string, arg2, instr.arg2, IMM, &instr);
    else if (instr.op.flags & OP_ARG2_IMM8)
        print_arg(ip_string, arg2, instr.arg2, IMM8, &instr);
    else if (instr.op.flags & OP_ARG2_CL)
        print_arg(ip_string, arg2, instr.arg2, CL, &instr);

    /* check that we have a valid instruction */
    if (instr.op.name[0] == '?')
        warn_at("Unknown opcode %2X (extension %d)\n", instr.op.opcode, instr.op.subcode);

    /* okay, now we begin dumping */
    if ((flags[ip] & INSTR_JUMP) && (opts & COMPILABLE)) {
        /* output a label, which is like an address but without the segment prefix */
        /* FIXME: check masm */
        if (asm_syntax == NASM)
            outp += sprintf(outp, ".");
        outp += sprintf(outp, "%05x:", ip);
    }

    if (!(opts & NO_SHOW_ADDRESSES))
        outp += sprintf(outp, "%05x:", ip);
    outp += sprintf(outp, "\t");

    if (!(opts & NO_SHOW_RAW_INSN))
        {
        for (i=0; i<len && i<7; i++) {
            outp += sprintf(outp, "%02x ", p[i]);
        }
        for (; i<8; i++) {
            outp += sprintf(outp, "   ");
        }
    }

    /* mark instructions that are jumped to */
    if (flags[ip] & INSTR_JUMP)
        outp[-1] = '>';

    /* print prefixes, including (fake) prefixes if ours are invalid */
    if (instr.prefix & PREFIX_SEG_MASK) {
        /* note: is it valid to use overrides with lods and outs? */
        if (!instr.usedmem || (instr.op.arg0 == ESDI || (instr.op.arg1 == ESDI && instr.op.arg0 != DSSI))) {  /* can't be overridden */
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
    } else if ((instr.prefix & PREFIX_ADDR32) && !instr.usedmem && instr.op.opcode != 0xE3) { /* jecxz */
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
    if (len > 7 && !(opts & NO_SHOW_RAW_INSN)) {
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

static void print_mz_code(dword start, dword length, byte *flags) {
    dword ip = 0;
    byte buffer[MAX_INSTR];
    char out[256];

    while (ip < length) {
        fseek(f, start+ip, SEEK_SET);

        /* find a valid instruction */
        if (!(flags[ip] & INSTR_VALID)) {
            if (opts & DISASSEMBLE_ALL) {
                /* still skip zeroes */
                if (read_byte() == 0) {
                    printf("      ...\n");
                    ip++;
                }
                while (read_byte() == 0) ip++;
            } else {
                printf("     ...\n");
                while ((ip < length) && !(flags[ip] & INSTR_VALID)) ip++;
            }
        }

        fseek(f, start+ip, SEEK_SET);
        if (ip >= length) return;

        /* fixme: disassemble everything for now; we'll try to fix it later.
         * this is going to be a little more difficult since dos executables
         * unabashedly mix code and data, so we need to figure out a solution
         * for that. but we needed to do that anyway. */

        if (length-ip < sizeof(buffer))
            fread(buffer, 1, length-ip, f);
        else
            fread(buffer, 1, sizeof(buffer), f);

        if (flags[ip] & INSTR_FUNC) {
            printf("\n");
            printf("%05x <no name>:\n", ip);
        }

        ip += print_instr(ip, buffer, out, flags);
        printf("%s\n", out);
    }
}

static void scan_segment(dword ip, dword start, dword length, byte *flags) {
    byte buffer[MAX_INSTR];
    instr_info instr;
    int instr_length;
    int i;

    if (ip > length) {
        warn_at("Attempt to scan past end of segment.\n");
        return;
    }

    if ((flags[ip] & (INSTR_VALID|INSTR_SCANNED)) == INSTR_SCANNED)
        warn_at("Attempt to scan byte that does not begin instruction.\n");

    while (ip < length) {
        /* check if we already read from here */
        if (flags[ip] & INSTR_SCANNED) return;

        /* read the instruction */
        fseek(f, start+ip, SEEK_SET);
        memset(buffer, 0, sizeof(buffer));  // fixme
        if (length-ip < sizeof(buffer))
            fread(buffer, 1, length-ip, f);
        else
            fread(buffer, 1, sizeof(buffer), f);
        instr_length = get_instr(ip, buffer, &instr, 0);

        /* mark the bytes */
        flags[ip] |= INSTR_VALID;
        for (i = ip; i < ip+instr_length && i < length; i++) flags[i] |= INSTR_SCANNED;

        if (i < ip+instr_length && i == length) break;

        /* handle conditional and unconditional jumps */
        if (instr.op.flags & OP_BRANCH) {
            /* near relative jump, loop, or call */
            if (!strcmp(instr.op.name, "call"))
                flags[instr.arg0] |= INSTR_FUNC;
            else
                flags[instr.arg0] |= INSTR_JUMP;

            /* scan it */
            scan_segment(instr.arg0, start, length, flags);
        }

        if (instr.op.flags & OP_STOP)
            return;

        ip += instr_length;
    }

    warn_at("Scan reached the end of segment.\n");
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
        dword entry_point = realaddr(header.e_cs, header.e_ip);
        byte *flags;
        dword length;

        length = ((header.e_cp - 1) * 512) + header.e_cblp;
        if (header.e_cblp == 0) length += 512;
        flags = calloc(length, sizeof(byte));

        /* Scan the segment */
        if (entry_point > length)
            warn("Entry point %05x exceeds segment length (%05x)\n", entry_point, length);
        flags[entry_point] |= INSTR_FUNC;
        scan_segment(entry_point, header.e_cparhdr * 16, length, flags);

        print_mz_code(header.e_cparhdr * 16, length, flags);

        free(flags);
    }

    free(reloc_table);
}
