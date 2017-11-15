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

static int print_mz_instr(dword ip, byte *p, char *out, const byte *flags) {
    instr_info instr = {0};
    char arg0[32] = {0}, arg1[32] = {0};
    unsigned len;

    char ip_string[7];

    out[0] = 0;

    len = get_instr(ip, p, &instr, 0);

    sprintf(ip_string, "%05x", ip);

    print_instr(out, ip_string, p, len, flags[ip], &instr, arg0, arg1, NULL);

    return len;
}

static void print_code(dword start, dword length, byte *flags) {
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

        ip += print_mz_instr(ip, buffer, out, flags);
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

        print_code(header.e_cparhdr * 16, length, flags);

        free(flags);
    }

    free(reloc_table);
}
