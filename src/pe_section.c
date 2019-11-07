/*
 * Functions for dumping PE code and data sections
 *
 * Copyright 2018 Zebediah Figura
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
#include "semblance.h"
#include "pe.h"
#include "x86_instr.h"

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %x: ", ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

int pe_rel_addr = -1;

struct section *addr2section(dword addr, const struct pe *pe) {
    /* Even worse than the below, some data is sensitive to which section it's in! */

    int i;
    for (i = 0; i < pe->header.NumberOfSections; i++) {
         if (addr >= pe->sections[i].address && addr < pe->sections[i].address + pe->sections[i].min_alloc)
            return &pe->sections[i];
    }

    return NULL;
}

long addr2offset(dword addr, const struct pe *pe) {
    /* Everything inside a PE file is built so that the file is read while it's
     * already loaded. Offsets aren't file offsets, they're *memory* offsets.
     * We don't want to load the whole file, so we have to search through each
     * section to figure out where in the *file* a virtual address points. */

    struct section *section = addr2section(addr, pe);
    if (!section) return 0;
    return addr - section->address + section->offset;
}

/* index function */
static char *get_export_name(dword ip, const struct pe *pe) {
    int i;
    for (i = 0; i < pe->export_count; i++) {
        if (pe->exports[i].address == ip)
            return pe->exports[i].name;
    }
    return NULL;
}

static char *get_imported_name(dword offset, const struct pe *pe) {
    unsigned i;

    offset -= pe->imagebase;

    for (i = 0; i < pe->import_count; i++) {
        unsigned index = (offset - pe->imports[i].nametab_addr) /
                         ((pe->magic == 0x10b) ? sizeof(dword) : sizeof(qword));
        if (index < pe->imports[i].count)
            return pe->imports[i].nametab[index];
    }
    return NULL;
}

/* index function */
static const struct reloc_pe *get_reloc(dword ip, const struct pe *pe) {
    unsigned i;
    for (i=0; i<pe->reloc_count; i++) {
        if (pe->reloc_base + pe->relocs[i].offset == ip)
            return &pe->relocs[i];
    }
    warn_at("Byte tagged INSTR_RELOC has no reloc; this is a bug.\n");
    return NULL;
}

static char *relocate_arg(struct instr *instr, struct arg *arg, const struct pe *pe) {
    const struct reloc_pe *r = get_reloc(arg->ip, pe);
    static char comment[10];

    if (r->type == 0)
        return NULL;    /* not even a real relocation, just padding */
    else if (r->type == 3) {
        if (arg->type == IMM || (arg->type == RM && instr->modrm_reg == -1) || arg->type == MOFFS16) {
            snprintf(comment, 10, "%lx", arg->value - pe->opt32.ImageBase);
            return comment;
        }
    }

    return NULL;
}

static int print_pe_instr(const struct section *sec, dword ip, byte *p, const struct pe *pe) {
    struct instr instr = {0};
    unsigned len;
    char *comment = NULL;
    char ip_string[17];
    qword absip = ip;
    int bits = (pe->magic == 0x10b) ? 32 : 64;
    char comment_str[10];

    if (!pe_rel_addr)
        absip += pe->imagebase;

    len = get_instr(ip, p, &instr, bits);

    sprintf(ip_string, "%8lx", absip);

    /* Check for relocations and imported names. PE separates the two concepts:
     * imported names are done by jumping into a block in .idata which is
     * relocated, and relocations proper are scattered throughout code sections
     * and relocated according to the contents of .reloc. */

    if (instr.op.opcode == 0xff && (instr.op.subcode == 2 || instr.op.subcode == 4)
        && instr.modrm_disp == DISP_16 && instr.modrm_reg == -1) {
        /* call/jmp to an absolute memory address */
        comment = get_imported_name(instr.args[0].value, pe);
    }

    /* check if we are referencing a named export */
    if (instr.op.arg0 == REL16 && !comment)
    {
        comment = get_export_name(instr.args[0].value, pe);
        if (!comment)
        {
            /* Sometimes we have TWO levels of indirection—call to jmp to
             * relocated address. mingw-w64 does this. */

            fseek(f, addr2offset(instr.args[0].value, pe), SEEK_SET);
            if (read_byte() == 0xff && read_byte() == 0x25) /* absolute jmp */
                comment = get_imported_name(read_dword(), pe);
        }
    }

    /* Not an import or an export. Is it a regular relocation? If so, adjust the
     * comment, since we prefer to print addresses relative to the image base. */
    if (!comment) {
        if (instr.args[0].type && sec->instr_flags[instr.args[0].ip - sec->address] & INSTR_RELOC)
            comment = relocate_arg(&instr, &instr.args[0], pe);
        if (instr.args[1].type && sec->instr_flags[instr.args[1].ip - sec->address] & INSTR_RELOC)
            comment = relocate_arg(&instr, &instr.args[1], pe);
    }

    /* 64-bit does it with IP-relative addressing. */
    if (!comment && instr.modrm_reg == 16) {
        dword tip;
        qword abstip;

        if (instr.args[0].type >= RM && instr.args[0].type <= MEM)
            tip = ip + len + instr.args[0].value;
        else
            tip = ip + len + instr.args[1].value;
        abstip = tip;
        if (!pe_rel_addr) abstip += pe->imagebase;

        comment = get_imported_name(tip + pe->imagebase, pe);

        if (!comment)
            comment = get_export_name(tip, pe);

        if (!comment) {
            snprintf(comment_str, 10, "%lx", abstip);
            comment = comment_str;
        }
    }

    /* We deal in relative addresses internally everywhere. That means we have
     * to fix up the values for relative jumps if we're not displaying relative
     * addresses. */
    if ((instr.op.arg0 == REL8 || instr.op.arg0 == REL16) && !pe_rel_addr) {
        instr.args[0].value += pe->imagebase;
    }

    print_instr(ip_string, p, len, sec->instr_flags[ip - sec->address], &instr, comment, bits);

    return len;
}

static void print_disassembly(const struct section *sec, const struct pe *pe) {
    dword relip = 0, ip;
    qword absip;

    byte buffer[MAX_INSTR];

    while (relip < sec->length && relip < sec->min_alloc) {
        fseek(f, sec->offset + relip, SEEK_SET);

        /* find a valid instruction */
        if (!(sec->instr_flags[relip] & INSTR_VALID)) {
            if (opts & DISASSEMBLE_ALL) {
                /* still skip zeroes */
                if (read_byte() == 0) {
                    printf("     ...\n");
                    relip++;
                    while (read_byte() == 0) relip++;
                }
            } else {
                printf("     ...\n");
                while ((relip < sec->length) && (relip < sec->min_alloc) && !(sec->instr_flags[relip] & INSTR_VALID)) relip++;
            }
        }

        ip = relip + sec->address;
        fseek(f, sec->offset + relip, SEEK_SET);
        if (relip >= sec->length || relip >= sec->min_alloc) return;

        /* Instructions can "hang over" the end of a segment.
         * Zero should be supplied. */
        memset(buffer, 0, sizeof(buffer));

        fread(buffer, 1, min(sizeof(buffer), sec->length - relip), f);

        absip = ip;
        if (!pe_rel_addr)
            absip += pe->imagebase;

        if (sec->instr_flags[relip] & INSTR_FUNC) {
            char *name = get_export_name(ip, pe);
            printf("\n");
            printf("%lx <%s>:\n", absip, name ? name : "no name");
        }

        relip += print_pe_instr(sec, ip, buffer, pe);
    }
    putchar('\n');
}

static void print_data(const struct section *sec, struct pe *pe) {
    dword relip = 0;
    qword absip;

    /* Page alignment means that (contrary to NE) sections are going to end with
     * a bunch of annoying zeroes. So don't read past the minimum allocation. */
    dword length = min(sec->length, sec->min_alloc);

    for (relip = 0; relip < length; relip += 16) {
        byte row[16];
        int len = min(length-relip, 16);
        int i;

        fseek(f, sec->offset + relip, SEEK_SET);
        fread(row, sizeof(byte), len, f);

        absip = relip + sec->address;
        if (!pe_rel_addr)
            absip += pe->imagebase;

        printf("%8lx", absip);
        for (i=0; i<16; i++) {
            if (i < len)
                printf(" %02x", row[i]);
            else
                printf("   ");
        }
        printf("  ");
        for (i=0; i<len; i++){
                if ((row[i] >= ' ') && (row[i] <= '~'))
                    putchar(row[i]);
                else
                    putchar('.');
        }
        putchar('\n');
    }
}

static void scan_segment(dword ip, struct pe *pe) {
    struct section *sec = addr2section(ip, pe);
    dword relip;

    byte buffer[MAX_INSTR];
    struct instr instr;
    int instr_length;
    int i;

//    fprintf(stderr, "scanning at %x, in section %s\n", ip, sec ? sec->name : "<none>");

    if (!sec) {
        warn_at("Attempt to scan byte not in image.\n");
        return;
    }

    relip = ip - sec->address;

    if ((sec->instr_flags[relip] & (INSTR_VALID|INSTR_SCANNED)) == INSTR_SCANNED)
        warn_at("Attempt to scan byte that does not begin instruction.\n");

    /* This code assumes that one stretch of code won't span multiple sections.
     * Is this a valid assumption? */

    while (relip < sec->length) {
        /* check if we've already read from here */
        if (sec->instr_flags[relip] & INSTR_SCANNED) return;

        /* read the instruction */
        fseek(f, sec->offset + relip, SEEK_SET);
        memset(buffer, 0, sizeof(buffer));
        fread(buffer, 1, min(sizeof(buffer), sec->length-relip), f);
        instr_length = get_instr(ip, buffer, &instr, (pe->magic == 0x10b) ? 32 : 64);

        /* mark the bytes */
        sec->instr_flags[relip] |= INSTR_VALID;
        for (i = relip; i < relip+instr_length && i < sec->min_alloc; i++) sec->instr_flags[i] |= INSTR_SCANNED;

        /* instruction which hangs over the minimum allocation */
        if (i < relip+instr_length && i == sec->min_alloc) break;

        /* handle conditional and unconditional jumps */
        if (instr.op.flags & OP_BRANCH) {
            /* relative jump, loop, or call */
            struct section *tsec = addr2section(instr.args[0].value, pe);

            if (tsec)
            {
                dword trelip = instr.args[0].value - tsec->address;

                if (!strcmp(instr.op.name, "call"))
                    tsec->instr_flags[trelip] |= INSTR_FUNC;
                else
                    tsec->instr_flags[trelip] |= INSTR_JUMP;
    
                /* scan it */
                scan_segment(instr.args[0].value, pe);
            } else
                warn_at("Branch '%s' to byte %lx not in image.\n", instr.op.name, instr.args[0].value);
        }

        for (i = relip; i < relip+instr_length; i++) {
            if (sec->instr_flags[i] & INSTR_RELOC) {
                const struct reloc_pe *r = get_reloc(i + sec->address, pe);
                struct section *tsec;
                dword taddr;

                fseek(f, sec->offset + i, SEEK_SET);
                switch (r->type)
                {
                case 3: /* HIGHLOW */
                    if (pe->magic != 0x10b)
                        warn_at("HIGHLOW relocation in 64-bit image?\n");
                    taddr = read_dword() - pe->opt32.ImageBase;
                    tsec = addr2section(taddr, pe);
                    /* Only try to scan it if it's an immediate address. If someone is
                     * dereferencing an address inside a code section, it's data. */
                    if (tsec->flags & 0x20 && (instr.op.arg0 == IMM || instr.op.arg1 == IMM)) {
                        tsec->instr_flags[taddr - tsec->address] |= INSTR_FUNC;
                        scan_segment(taddr, pe);
                    }
                    break;
                default:
                    warn_at("Don't know how to handle relocation type %d\n", r->type);
                    break;
                }
                break;
            }
        }

        if (instr.op.flags & OP_STOP)
            return;

        ip += instr_length;
        relip = ip - sec->address;
    }

    warn_at("Scan reached the end of section.\n");
}

static void print_section_flags(dword flags) {
    char buffer[1024] = "";
    int alignment = (flags & 0x00f00000) / 0x100000;

    /* Most of these shouldn't occur in an image file, either because they're
     * COFF flags that PE doesn't want or because they're object-only. Print
     * the COFF names. */
    if (flags & 0x00000001) strcat(buffer, ", STYP_DSECT");
    if (flags & 0x00000002) strcat(buffer, ", STYP_NOLOAD");
    if (flags & 0x00000004) strcat(buffer, ", STYP_GROUP");
    if (flags & 0x00000008) strcat(buffer, ", STYP_PAD");
    if (flags & 0x00000010) strcat(buffer, ", STYP_COPY");
    if (flags & 0x00000020) strcat(buffer, ", code");
    if (flags & 0x00000040) strcat(buffer, ", data");
    if (flags & 0x00000080) strcat(buffer, ", bss");
    if (flags & 0x00000100) strcat(buffer, ", S_NEWCFN");
    if (flags & 0x00000200) strcat(buffer, ", STYP_INFO");
    if (flags & 0x00000400) strcat(buffer, ", STYP_OVER");
    if (flags & 0x00000800) strcat(buffer, ", STYP_LIB");
    if (flags & 0x00001000) strcat(buffer, ", COMDAT");
    if (flags & 0x00002000) strcat(buffer, ", STYP_MERGE");
    if (flags & 0x00004000) strcat(buffer, ", STYP_REVERSE_PAD");
    if (flags & 0x00008000) strcat(buffer, ", FARDATA");
    if (flags & 0x00010000) strcat(buffer, ", (unknown flags 0x10000)");
    if (flags & 0x00020000) strcat(buffer, ", purgeable");  /* or 16BIT */
    if (flags & 0x00040000) strcat(buffer, ", locked");
    if (flags & 0x00080000) strcat(buffer, ", preload");
    if (flags & 0x01000000) strcat(buffer, ", extended relocations");
    if (flags & 0x02000000) strcat(buffer, ", discardable");
    if (flags & 0x04000000) strcat(buffer, ", not cached");
    if (flags & 0x08000000) strcat(buffer, ", not paged");
    if (flags & 0x10000000) strcat(buffer, ", shared");
    if (flags & 0x20000000) strcat(buffer, ", executable");
    if (flags & 0x40000000) strcat(buffer, ", readable");
    if (flags & 0x80000000) strcat(buffer, ", writable");

    printf("    Flags: 0x%08x (%s)\n", flags, buffer+2);
    printf("    Alignment: %d (2**%d)\n", 1 << alignment, alignment);
}

/* We don't actually know what sections contain code. In theory it could be any
 * of them. Fortunately we actually have everything we need already. */

void read_sections(struct pe *pe) {
    dword entry_point = (pe->magic == 0x10b) ? pe->opt32.AddressOfEntryPoint : pe->opt64.AddressOfEntryPoint;
    int i;

    /* We already read the section header (unlike NE, we had to in order to read
     * everything else), so our job now is just to scan the section contents. */

    /* Relocations first. */
    for (i = 0; i < pe->reloc_count; i++) {
        dword address = pe->reloc_base + pe->relocs[i].offset;
        struct section *sec = addr2section(address, pe);
        if (!sec)
        {
            warn("Relocation at %#x isn't in a section?\n", address);
            continue;
        }
        if (sec->flags & 0x20) {
            switch (pe->relocs[i].type) {
            case 0: /* padding */
                break;
            case 3: /* HIGHLOW */
                /* scanning is done in scan_segment() */
                sec->instr_flags[address - sec->address] |= INSTR_RELOC;
                break;
            default:
                warn("%#x: Don't know how to handle relocation type %d\n",
                    pe->relocs[i].offset, pe->relocs[i].type);
                break;
            }
        }
    }

    for (i = 0; i < pe->export_count; i++) {
        dword address = pe->exports[i].address;
        struct section *sec = addr2section(address, pe);
        if (!sec)
        {
            warn("Export %s at %#x isn't in a section?\n", pe->exports[i].name, pe->exports[i].address);
            continue;
        }
        if (sec->flags & 0x20 && !(address >= pe->dirs[0].address &&
            address < (pe->dirs[0].address + pe->dirs[0].size))) {
            sec->instr_flags[address - sec->address] |= INSTR_FUNC;
            scan_segment(pe->exports[i].address, pe);
        }
    }

    if (entry_point) {
        struct section *sec = addr2section(entry_point, pe);
        if (!sec)
            warn("Entry point %#x isn't in a section?\n", entry_point);
        else if (sec->flags & 0x20) {
            sec->instr_flags[entry_point - sec->address] |= INSTR_FUNC;
            scan_segment(entry_point, pe);
        }
    }
}

void print_sections(struct pe *pe) {
    int i;
    struct section *sec;

    for (i = 0; i < pe->header.NumberOfSections; i++) {
        sec = &pe->sections[i];

        putchar('\n');
        printf("Section %s (start = 0x%x, length = 0x%x, minimum allocation = 0x%x):\n",
            sec->name, sec->offset, sec->length, sec->min_alloc);
        printf("    Address: %x\n", sec->address);
        print_section_flags(sec->flags);

        /* These fields should only be populated for object files (I think). */
        if (sec->reloc_offset || sec->reloc_count)
            warn("Section %s has relocation data: offset = %x, count = %d\n",
                sec->name, sec->reloc_offset, sec->reloc_count);

        /* Sometimes the .text section is marked as both code and data. I've
         * seen mingw-w64 do this. (Because there's data stored in it?) */
        if (sec->flags & 0x20) {
            if (opts & FULL_CONTENTS)
                print_data(sec, pe);
            print_disassembly(sec, pe);
        } else if (sec->flags & 0x40) {
            /* see the appropriate FIXMEs on the NE side */
            /* Don't print .rsrc by default. Some others should probably be
             * excluded, too, but .rsrc is a particularly bad offender since
             * large binaries might be put into it. */
            if ((strcmp(sec->name, ".rsrc") && strcmp(sec->name, ".reloc"))
                || (opts & FULL_CONTENTS))
                print_data(sec, pe);
        }
    }
}
