/*
 * MZ (DOS) files
 *
 * Copyright 2017-2018 Zebediah Figura
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
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdlib.h>
#include <string.h>

#include "semblance.h"
#include "x86_instr.h"
#include "mz.h"

#pragma pack(1)

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

static int print_mz_instr(dword ip, byte *p, char *out, const byte *flags) {
    struct instr instr = {0};
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
    struct instr instr;
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

void readmz(struct mz *mz) {
    fseek(f, 0, SEEK_SET);
    fread(&mz->header, sizeof(struct header_mz), 1, f);

    /* read the relocation table */
    mz->reltab = malloc(mz->header.e_crlc * sizeof(struct reloc));
    fseek(f, mz->header.e_lfarlc, SEEK_SET);
    fread(mz->reltab, sizeof(struct reloc), mz->header.e_crlc, f);
}

void freemz(struct mz *mz) {
    free(mz->reltab);
}

void dumpmz(void) {
    struct mz mz;

    readmz(&mz);

    printf("Module type: MZ (DOS executable)\n");

    if (mode & DUMPHEADER)
        print_header(&mz.header);

    if (mode & DISASSEMBLE) {
        dword entry_point = realaddr(mz.header.e_cs, mz.header.e_ip);
        byte *flags;
        dword length;

        length = ((mz.header.e_cp - 1) * 512) + mz.header.e_cblp;
        if (mz.header.e_cblp == 0) length += 512;
        flags = calloc(length, sizeof(byte));

        /* Scan the segment */
        if (entry_point > length)
            warn("Entry point %05x exceeds segment length (%05x)\n", entry_point, length);
        flags[entry_point] |= INSTR_FUNC;
        scan_segment(entry_point, mz.header.e_cparhdr * 16, length, flags);

        print_code(mz.header.e_cparhdr * 16, length, flags);

        free(flags);
    }

    freemz(&mz);
}
