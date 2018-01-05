/*
 * Functions for parsing the PE header
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "semblance.h"
#include "pe.h"

static void print_flags(word flags) {
    char buffer[1024] = "";

    if (flags & 0x0001) strcat(buffer, ", relocations stripped");
    if (flags & 0x0002) strcat(buffer, ", executable");
    if (flags & 0x0004) strcat(buffer, ", line numbers stripped");
    if (flags & 0x0008) strcat(buffer, ", local symbols stripped");
    if (flags & 0x0010) strcat(buffer, ", aggressively trimmed");
    if (flags & 0x0020) strcat(buffer, ", large address aware");
    if (flags & 0x0040) strcat(buffer, ", 16-bit");     /* deprecated and reserved */
    if (flags & 0x0080) strcat(buffer, ", little-endian");
    if (flags & 0x0100) strcat(buffer, ", 32-bit");
    if (flags & 0x0200) strcat(buffer, ", debug info stripped");
    if (flags & 0x0400) strcat(buffer, ", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
    if (flags & 0x0800) strcat(buffer, ", IMAGE_FILE_NET_RUN_FROM_SWAP");
    if (flags & 0x1000) strcat(buffer, ", system file");
    if (flags & 0x2000) strcat(buffer, ", DLL");
    if (flags & 0x4000) strcat(buffer, ", uniprocessor");
    if (flags & 0x8000) strcat(buffer, ", big-endian");
    
    printf("Flags: 0x%04x (%s)\n", flags, buffer+2);
}

static void print_dll_flags(word flags) {
    char buffer[1024] = "";

    if (flags & 0x0001) strcat(buffer, ", per-process initialization");
    if (flags & 0x0002) strcat(buffer, ", per-process termination");
    if (flags & 0x0004) strcat(buffer, ", per-thread initialization");
    if (flags & 0x0008) strcat(buffer, ", per-thread termination");
    if (flags & 0x0040) strcat(buffer, ", dynamic base");
    if (flags & 0x0080) strcat(buffer, ", force integrity");
    if (flags & 0x0100) strcat(buffer, ", DEP compatible");
    if (flags & 0x0200) strcat(buffer, ", no isolation");
    if (flags & 0x0400) strcat(buffer, ", no SEH");
    if (flags & 0x0800) strcat(buffer, ", no bind");
    if (flags & 0x2000) strcat(buffer, ", WDM driver");
    if (flags & 0x8000) strcat(buffer, ", terminal server aware");
    if (flags & 0x5030) sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0x5030);

    printf("DLL flags: 0x%04x (%s)\n", flags, buffer+2);
}

static const char *const subsystems[] = {
    "unknown",                      /* 0 */
    "native",                       /* 1 */
    "GUI",                          /* 2 */
    "CUI",                          /* 3 */
    "(unknown value 4)",
    "OS/2 CUI",                     /* 5 */
    "(unknown value 6)",
    "POSIX CUI",                    /* 7 */
    "(unknown value 8)",
    "CE",                           /* 9 */
    "EFI",                          /* 10 */
    "EFI with boot services",       /* 11 */
    "EFI with runtime services",    /* 12 */
    "EFI ROM image",                /* 13 */
    "Xbox",                         /* 14 */
    "(unknown value 15)",
    "boot",                         /* 16 */
    0
};

static void print_header(struct header_pe *header) {
    if (!header->file.SizeOfOptionalHeader) return;  /* 14 */
    else if (header->file.SizeOfOptionalHeader < sizeof(struct optional_header))
        warn("Size of optional header is %u (expected at least %lu).\n",
            header->file.SizeOfOptionalHeader, sizeof(struct optional_header));

    print_flags(header->file.Characteristics); /* 16 */

    if (header->opt.Magic == 0x10b) /* 18 */
        printf("Image type: 32-bit\n");
    else if (header->opt.Magic == 0x20b)
        printf("Image type: 64-bit\n");
    else if (header->opt.Magic == 0x107)
        printf("Image type: ROM\n");
    else
        printf("Image type: (unknown value 0x%x)\n", header->opt.Magic);

    printf("File version: %d.%d\n", header->opt.MajorImageVersion, header->opt.MinorImageVersion); /* 44 */

    printf("Linker version: %d.%d\n", header->opt.MajorLinkerVersion, header->opt.MinorLinkerVersion); /* 1a */

    if (header->opt.AddressOfEntryPoint)
        printf("Program entry point: 0x%x\n", header->opt.AddressOfEntryPoint); /* 28 */

    printf("Base of code section: 0x%x\n", header->opt.BaseOfCode);
    printf("Base of data section: 0x%x\n", header->opt.BaseOfData);

    printf("Preferred base address: 0x%x\n", header->opt.ImageBase); /* 34 */
    printf("Required OS version: %d.%d\n", header->opt.MajorOperatingSystemVersion, header->opt.MinorOperatingSystemVersion); /* 40 */

    if (header->opt.Win32VersionValue != 0)
        warn("Win32VersionValue is %d (expected 0)\n", header->opt.Win32VersionValue); /* 4c */

    if (header->opt.Subsystem <= 16) /* 5c */
        printf("Subsystem: %s\n", subsystems[header->opt.Subsystem]);
    else
        printf("Subsystem: (unknown value %d)\n", header->opt.Subsystem);
    printf("Subsystem version: %d.%d\n", header->opt.MajorSubsystemVersion, header->opt.MinorSubsystemVersion); /* 48 */

    print_dll_flags(header->opt.DllCharacteristics); /* 5e */

    printf("Stack size (reserve): %d bytes\n", header->opt.SizeOfStackReserve); /* 60 */
    printf("Stack size (commit): %d bytes\n", header->opt.SizeOfStackCommit); /* 64 */
    printf("Heap size (reserve): %d bytes\n", header->opt.SizeOfHeapReserve); /* 68 */
    printf("Heap size (commit): %d bytes\n", header->opt.SizeOfHeapCommit); /* 6c */

    if (header->opt.LoaderFlags != 0)
        warn("LoaderFlags is 0x%x (expected 0)\n", header->opt.LoaderFlags); /* 70 */
    putchar('\n');
}

static struct section *addr2section(dword addr, const struct pe *pe) {
    /* Even worse than the below, some data is sensitive to which section it's in! */

    int i;
    for (i = 0; i < pe->header.file.NumberOfSections; i++) {
         if (addr >= pe->sections[i].address && addr < pe->sections[i].address + pe->sections[i].size)
            return &pe->sections[i];
    }

    return NULL;
}

static long addr2offset(dword addr, const struct pe *pe) {
    /* Everything inside a PE file is built so that the file is read while it's
     * already loaded. Offsets aren't file offsets, they're *memory* offsets.
     * We don't want to load the whole file, so we have to search through each
     * section to figure out where in the *file* a virtual address points. */

    struct section *section = addr2section(addr, pe);
    if (!section) return 0;
    return addr - section->address + section->offset;
}

struct export_header {
    dword flags;            /* 00 */
    dword timestamp;        /* 04 */
    word  ver_major;        /* 08 */
    word  ver_minor;        /* 0a */
    dword module_name_addr; /* 0c */
    dword ordinal_base;     /* 10 */
    dword addr_table_count; /* 14 */
    dword export_count;     /* 18 */
    dword addr_table_addr;  /* 1c */
    dword name_table_addr;  /* 20 */
    dword ord_table_addr;   /* 24 */
};

STATIC_ASSERT(sizeof(struct export_header) == 0x28);

static char *fstrdup(long offset) {
    long cursor = ftell(f);
    int len;
    char *ret;

    fseek(f, offset, SEEK_SET);
    while (read_byte());
    len = ftell(f)-offset+1;
    fseek(f, offset, SEEK_SET);
    ret = malloc(len);
    fread(ret, sizeof(char), len, f);
    fseek(f, cursor, SEEK_SET);

    return ret;
}

static void get_export_table(struct pe *pe) {
    struct export_header header;
    long offset = addr2offset(pe->dirs[0].address, pe);
    int len, i;

    /* More headers. It's like a PE file is nothing but headers.
     * Do we really need to print any of this? No, not really. Just use the data. */
    fseek(f, offset, SEEK_SET);
    fread(&header, sizeof(struct export_header), 1, f);

    /* Grab the name. */
    pe->name = fstrdup(addr2offset(header.module_name_addr, pe));

    if (header.addr_table_count != header.export_count)
        warn("Export address table count %d does not mach export count %d\n",
            header.addr_table_count, header.export_count);

    /* Grab the exports. */
    pe->exports = malloc(header.export_count * sizeof(struct export));

    fseek(f, addr2offset(header.addr_table_addr, pe), SEEK_SET);
    for (i=0; i<header.addr_table_count; i++)
        pe->exports[i].address = addr2offset(read_dword(), pe);

    fseek(f, addr2offset(header.name_table_addr, pe), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        pe->exports[i].name = fstrdup(addr2offset(read_dword(), pe));

    fseek(f, addr2offset(header.ord_table_addr, pe), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        pe->exports[i].ordinal = read_word();

    pe->export_count = header.export_count;
}

void readpe(long offset_pe, struct pe *pe) {
    struct optional_header *opt = &pe->header.opt;

    fseek(f, offset_pe, SEEK_SET);
    fread(&pe->header, sizeof(struct header_pe), 1, f);

    pe->dirs = malloc(opt->NumberOfRvaAndSizes * sizeof(struct directory));
    fread(pe->dirs, sizeof(struct directory), opt->NumberOfRvaAndSizes, f);

    /* read the section table */
    pe->sections = malloc(pe->header.file.NumberOfSections * sizeof(struct section));
    fread(pe->sections, sizeof(struct section), pe->header.file.NumberOfSections, f);

    /* Read the Data Directories.
     * PE is bizarre. It tries to make all of these things generic by putting
     * them in separate "directories". But the order of these seems to be fixed
     * anyway, so why bother? */

    if (pe->header.opt.NumberOfRvaAndSizes >= 1 && pe->dirs[0].size)
        get_export_table(pe);
}

void freepe(struct pe *pe) {
    int i;

    free(pe->dirs);
    free(pe->sections);
    free(pe->name);
    for (i = 0; i < pe->export_count; i++)
        free(pe->exports[i].name);
    free(pe->exports);
}

void dumppe(long offset_pe) {
    struct pe pe;
    char *module_name;
    int i;

    readpe(offset_pe, &pe);

    printf("Module type: PE (Portable Executable)\n");
    if (module_name) printf("Module name: %s\n", module_name);

    if (mode & DUMPHEADER)
        print_header(&pe.header);

    if (mode & DUMPEXPORT) {
        if (pe.exports) {
            printf("Exports:\n");
            for (i = 0; i < pe.export_count; i++)
                printf("\t%5d\t%#8x\t%s\n", pe.exports[i].ordinal, pe.header.opt.ImageBase + pe.exports[i].address, pe.exports[i].name);
        } else
            printf("No export table\n");
        putchar('\n');
    }

    freepe(&pe);
}
