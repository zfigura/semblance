/*
 * MZ (DOS) files
 *
 * Copyright 2017-2018,2020 Zebediah Figura
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

#include <stdlib.h>
#include <string.h>

#include "semblance.h"
#include "x86_instr.h"
#include "mz.h"

#pragma pack(1)

static void print_header(const struct header_mz *header) {
    putchar('\n');
    printf("Minimum extra allocation: %d bytes\n", header->e_minalloc * 16); /* 0a */
    printf("Maximum extra allocation: %d bytes\n", header->e_maxalloc * 16); /* 0c */
    printf("Initial stack location: %#x\n", realaddr(header->e_ss, header->e_sp)); /* 0e */
    printf("Program entry point: %#x\n", realaddr(header->e_cs, header->e_ip)); /* 14 */
    printf("Overlay number: %d\n", header->e_ovno); /* 1a */
}

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %05x: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

static int print_mz_instr(dword ip, const byte *p, const byte *flags) {
    struct instr instr = {0};
    unsigned len;

    char ip_string[7];

    len = get_instr(ip, p, &instr, 16);

    sprintf(ip_string, "%05x", ip);

    print_instr(ip_string, p, len, flags[ip], &instr, NULL, 16);

    return len;
}

static void print_code(struct mz *mz) {
    dword ip = 0;
    byte buffer[MAX_INSTR];

    putchar('\n');
    printf("Code (start = 0x%x, length = 0x%x):\n", mz->start, mz->length);

    while (ip < mz->length) {
        /* find a valid instruction */
        if (!(mz->flags[ip] & INSTR_VALID)) {
            if (opts & DISASSEMBLE_ALL) {
                /* still skip zeroes */
                if (read_byte(mz->start + ip) == 0) {
                    printf("      ...\n");
                    ip++;
                    while (read_byte(mz->start + ip) == 0) ip++;
                }
            } else {
                printf("     ...\n");
                while ((ip < mz->length) && !(mz->flags[ip] & INSTR_VALID)) ip++;
            }
        }

        if (ip >= mz->length) return;

        /* fixme: disassemble everything for now; we'll try to fix it later.
         * this is going to be a little more difficult since dos executables
         * unabashedly mix code and data, so we need to figure out a solution
         * for that. but we needed to do that anyway. */

        memcpy(buffer, read_data(mz->start + ip), min(sizeof(buffer), mz->length - ip));

        if (mz->flags[ip] & INSTR_FUNC) {
            printf("\n");
            printf("%05x <no name>:\n", ip);
        }

        ip += print_mz_instr(ip, buffer, mz->flags);
    }
}

static void scan_segment(dword ip, struct mz *mz) {
    byte buffer[MAX_INSTR];
    struct instr instr;
    int instr_length;
    int i;

    if (ip > mz->length) {
        warn_at("Attempt to scan past end of segment.\n");
        return;
    }

    if ((mz->flags[ip] & (INSTR_VALID|INSTR_SCANNED)) == INSTR_SCANNED)
        warn_at("Attempt to scan byte that does not begin instruction.\n");

    while (ip < mz->length) {
        /* check if we already read from here */
        if (mz->flags[ip] & INSTR_SCANNED) return;

        /* read the instruction */
        memset(buffer, 0, sizeof(buffer));  // fixme
        memcpy(buffer, read_data(mz->start + ip), min(sizeof(buffer), mz->length - ip));
        instr_length = get_instr(ip, buffer, &instr, 16);

        /* mark the bytes */
        mz->flags[ip] |= INSTR_VALID;
        for (i = ip; i < ip+instr_length && i < mz->length; i++) mz->flags[i] |= INSTR_SCANNED;

        /* instruction which hangs over the minimum allocation */
        if (i < ip+instr_length && i == mz->length) break;

        /* handle conditional and unconditional jumps */
        if (instr.op.flags & OP_BRANCH) {
            /* near relative jump, loop, or call */
            if (!strcmp(instr.op.name, "call"))
                mz->flags[instr.args[0].value] |= INSTR_FUNC;
            else
                mz->flags[instr.args[0].value] |= INSTR_JUMP;

            /* scan it */
            scan_segment(instr.args[0].value, mz);
        }

        if (instr.op.flags & OP_STOP)
            return;

        ip += instr_length;
    }

    warn_at("Scan reached the end of segment.\n");
}

static void read_code(struct mz *mz) {

    mz->entry_point = realaddr(mz->header->e_cs, mz->header->e_ip);
    mz->length = ((mz->header->e_cp - 1) * 512) + mz->header->e_cblp;
    if (mz->header->e_cblp == 0) mz->length += 512;
    mz->flags = calloc(mz->length, sizeof(byte));

    if (mz->entry_point > mz->length)
        warn("Entry point %05x exceeds segment length (%05x)\n", mz->entry_point, mz->length);
    mz->flags[mz->entry_point] |= INSTR_FUNC;
    scan_segment(mz->entry_point, mz);
}

void readmz(struct mz *mz) {
    mz->header = read_data(0);

    /* read the relocation table */
    mz->reltab = read_data(mz->header->e_lfarlc);

    /* read the code */
    mz->start = mz->header->e_cparhdr * 16;
    read_code(mz);
}

void freemz(struct mz *mz) {
    free(mz->flags);
}

void dumpmz(void) {
    struct mz mz;

    readmz(&mz);

    printf("Module type: MZ (DOS executable)\n");

    if (mode & DUMPHEADER)
        print_header(mz.header);

    if (mode & DISASSEMBLE)
        print_code(&mz);

    freemz(&mz);
}
