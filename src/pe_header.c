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
 * along with Semblance; if not, write to the Free Software
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
    putchar('\n');

    if (!header->file.SizeOfOptionalHeader) {
        printf("No optional header\n");
        return;
    } else if (header->file.SizeOfOptionalHeader < sizeof(struct optional_header))
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
    int i;

    /* More headers. It's like a PE file is nothing but headers.
     * Do we really need to print any of this? No, not really. Just use the data. */
    fseek(f, offset, SEEK_SET);
    fread(&header, sizeof(struct export_header), 1, f);

    /* Grab the name. */
    pe->name = fstrdup(addr2offset(header.module_name_addr, pe));

    if (header.addr_table_count != header.export_count)
        warn("Export address table count %d does not match export count %d\n",
            header.addr_table_count, header.export_count);

    /* Grab the exports. */
    pe->exports = malloc(header.export_count * sizeof(struct export));

    fseek(f, addr2offset(header.addr_table_addr, pe), SEEK_SET);
    for (i=0; i<header.addr_table_count; i++)
        pe->exports[i].address = read_dword();

    fseek(f, addr2offset(header.name_table_addr, pe), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        pe->exports[i].name = fstrdup(addr2offset(read_dword(), pe));

    fseek(f, addr2offset(header.ord_table_addr, pe), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        pe->exports[i].ordinal = read_word();

    pe->export_count = header.export_count;
}

static void get_import_name_table(struct import_module *module, struct pe *pe) {
    long offset = addr2offset(module->nametab_addr, pe);
    long cursor = ftell(f);
    unsigned i, count;

    fseek(f, offset, SEEK_SET);
    count = 0;
    while (read_dword()) count++;

    module->nametab = malloc(count * sizeof(char *));

    fseek(f, offset, SEEK_SET);
    for (i = 0; i < count; i++) {
        dword address = read_dword();
        if (address & 0x80000000) {
            address &= 0x7fffffff;
            module->nametab[i] = malloc(snprintf(NULL, 0, "%u", address));
            sprintf(module->nametab[i], "%u", address);
        } else
            module->nametab[i] = fstrdup(addr2offset(address, pe) + 2); /* skip hint */
    }
    module->count = count;

    fseek(f, cursor, SEEK_SET);
}

static void get_import_module_table(struct pe *pe) {
    long offset = addr2offset(pe->dirs[1].address, pe);
    int i;

    fseek(f, offset, SEEK_SET);
    pe->import_count = 0;
    while (read_dword()) {
        fseek(f, 4 * sizeof(dword), SEEK_CUR);
        pe->import_count++;
    }

    pe->imports = malloc(pe->import_count * sizeof(struct import_module));

    fseek(f, offset, SEEK_SET);

    for (i = 0; i < pe->import_count; i++) {

        fseek(f, 3 * sizeof(dword), SEEK_CUR);
        pe->imports[i].module = fstrdup(addr2offset(read_dword(), pe));
        pe->imports[i].nametab_addr = read_dword();

        /* grab the imports themselves */
        get_import_name_table(&pe->imports[i], pe);
    }
}

static void get_reloc_table(struct pe *pe) {
    long offset = addr2offset(pe->dirs[5].address, pe);

    fseek(f, offset, SEEK_SET);
    pe->reloc_base = read_dword();
    pe->reloc_count = (read_dword() - 8) / 2;
    pe->relocs = malloc(pe->reloc_count * sizeof(struct reloc_pe));
    fread(pe->relocs, sizeof(struct reloc_pe), pe->reloc_count, f);
}

void readpe(long offset_pe, struct pe *pe) {
    struct optional_header *opt = &pe->header.opt;
    int i;

    fseek(f, offset_pe, SEEK_SET);
    fread(&pe->header, sizeof(struct header_pe), 1, f);

    pe->dirs = malloc(opt->NumberOfRvaAndSizes * sizeof(struct directory));
    fread(pe->dirs, sizeof(struct directory), opt->NumberOfRvaAndSizes, f);

    /* read the section table */
    pe->sections = malloc(pe->header.file.NumberOfSections * sizeof(struct section));
    for (i = 0; i < pe->header.file.NumberOfSections; i++) {
        fread(&pe->sections[i], 0x28, 1, f);

        /* allocate zeroes, but only if it's a code section */
        /* in theory nobody will ever try to jump into a data section.
         * VirtualProtect() be damned */
        if (pe->sections[i].flags & 0x20)
            pe->sections[i].instr_flags = calloc(pe->sections[i].min_alloc, sizeof(byte));
        else
            pe->sections[i].instr_flags = NULL;
    }

    /* Read the Data Directories.
     * PE is bizarre. It tries to make all of these things generic by putting
     * them in separate "directories". But the order of these seems to be fixed
     * anyway, so why bother? */

    if (opt->NumberOfRvaAndSizes >= 1 && pe->dirs[0].size)
        get_export_table(pe);
    if (opt->NumberOfRvaAndSizes >= 2 && pe->dirs[1].size)
        get_import_module_table(pe);
    if (opt->NumberOfRvaAndSizes >= 6 && pe->dirs[5].size)
        get_reloc_table(pe);

    /* Read the code. */
    read_sections(pe);
}

void freepe(struct pe *pe) {
    int i;

    free(pe->dirs);
    for (i = 0; i < pe->header.file.NumberOfSections; i++)
        free(pe->sections[i].instr_flags);
    free(pe->sections);
    free(pe->name);
    for (i = 0; i < pe->export_count; i++)
        free(pe->exports[i].name);
    free(pe->exports);
}

void dumppe(long offset_pe) {
    struct pe pe = {0};
    int i;

    readpe(offset_pe, &pe);

    printf("Module type: PE (Portable Executable)\n");
    if (pe.name) printf("Module name: %s\n", pe.name);

    if (mode & DUMPHEADER)
        print_header(&pe.header);

    if (mode & DUMPEXPORT) {
        putchar('\n');
        if (pe.exports) {
            printf("Exports:\n");
            for (i = 0; i < pe.export_count; i++) {
                struct section *sec = addr2section(pe.exports[i].address, &pe);
                printf("\t%5d\t%#8x\t%s", pe.exports[i].ordinal, pe.exports[i].address, pe.exports[i].name);
                if (sec == addr2section(pe.dirs[0].address, &pe)) {
                    char c;
                    printf(" -> ");
                    fseek(f, addr2offset(pe.exports[i].address, &pe), SEEK_SET);
                    while ((c = read_byte())) putchar(c);
                }
                putchar('\n');
            }
        } else
            printf("No export table\n");
    }

    if (mode & DUMPIMPORTMOD) {
        putchar('\n');
        if (pe.imports) {
            printf("Imported modules:\n");
            for (i = 0; i < pe.import_count; i++)
                printf("\t%s\n", pe.imports[i].module);
        } else
            printf("No imported module table\n");
    }

    if (mode & DISASSEMBLE)
        print_sections(&pe);

    freepe(&pe);
}
