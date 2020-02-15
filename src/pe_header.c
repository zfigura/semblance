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

#include <assert.h>
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

static void print_opt32(struct optional_header *opt) {
    printf("File version: %d.%d\n", opt->MajorImageVersion, opt->MinorImageVersion); /* 44 */

    printf("Linker version: %d.%d\n", opt->MajorLinkerVersion, opt->MinorLinkerVersion); /* 1a */

    if (opt->AddressOfEntryPoint) {
        dword address = opt->AddressOfEntryPoint;
        if (!pe_rel_addr)
            address += opt->ImageBase;
        printf("Program entry point: 0x%x\n", address); /* 28 */
    }

    printf("Base of code section: 0x%x\n", opt->BaseOfCode); /* 2c */
    printf("Base of data section: 0x%x\n", opt->BaseOfData); /* 30 */

    printf("Preferred base address: 0x%x\n", opt->ImageBase); /* 34 */
    printf("Required OS version: %d.%d\n", opt->MajorOperatingSystemVersion, opt->MinorOperatingSystemVersion); /* 40 */

    if (opt->Win32VersionValue != 0)
        warn("Win32VersionValue is %d (expected 0)\n", opt->Win32VersionValue); /* 4c */

    if (opt->Subsystem <= 16) /* 5c */
        printf("Subsystem: %s\n", subsystems[opt->Subsystem]);
    else
        printf("Subsystem: (unknown value %d)\n", opt->Subsystem);
    printf("Subsystem version: %d.%d\n", opt->MajorSubsystemVersion, opt->MinorSubsystemVersion); /* 48 */

    print_dll_flags(opt->DllCharacteristics); /* 5e */

    printf("Stack size (reserve): %d bytes\n", opt->SizeOfStackReserve); /* 60 */
    printf("Stack size (commit): %d bytes\n", opt->SizeOfStackCommit); /* 64 */
    printf("Heap size (reserve): %d bytes\n", opt->SizeOfHeapReserve); /* 68 */
    printf("Heap size (commit): %d bytes\n", opt->SizeOfHeapCommit); /* 6c */

    if (opt->LoaderFlags != 0)
        warn("LoaderFlags is 0x%x (expected 0)\n", opt->LoaderFlags); /* 70 */
}

static void print_opt64(struct optional_header_pep *opt) {
    printf("File version: %d.%d\n", opt->MajorImageVersion, opt->MinorImageVersion); /* 44 */

    printf("Linker version: %d.%d\n", opt->MajorLinkerVersion, opt->MinorLinkerVersion); /* 1a */

    if (opt->AddressOfEntryPoint) {
        dword address = opt->AddressOfEntryPoint;
        if (!pe_rel_addr)
            address += opt->ImageBase;
        printf("Program entry point: 0x%x\n", address); /* 28 */
    }

    printf("Base of code section: 0x%x\n", opt->BaseOfCode); /* 2c */

    printf("Preferred base address: 0x%lx\n", opt->ImageBase); /* 30 */
    printf("Required OS version: %d.%d\n", opt->MajorOperatingSystemVersion, opt->MinorOperatingSystemVersion); /* 40 */

    if (opt->Win32VersionValue != 0)
        warn("Win32VersionValue is %d (expected 0)\n", opt->Win32VersionValue); /* 4c */

    if (opt->Subsystem <= 16) /* 5c */
        printf("Subsystem: %s\n", subsystems[opt->Subsystem]);
    else
        printf("Subsystem: (unknown value %d)\n", opt->Subsystem);
    printf("Subsystem version: %d.%d\n", opt->MajorSubsystemVersion, opt->MinorSubsystemVersion); /* 48 */

    print_dll_flags(opt->DllCharacteristics); /* 5e */

    printf("Stack size (reserve): %ld bytes\n", opt->SizeOfStackReserve); /* 60 */
    printf("Stack size (commit): %ld bytes\n", opt->SizeOfStackCommit); /* 68 */
    printf("Heap size (reserve): %ld bytes\n", opt->SizeOfHeapReserve); /* 70 */
    printf("Heap size (commit): %ld bytes\n", opt->SizeOfHeapCommit); /* 78 */

    if (opt->LoaderFlags != 0)
        warn("LoaderFlags is 0x%x (expected 0)\n", opt->LoaderFlags); /* 80 */
}

static void print_header(struct pe *pe) {
    putchar('\n');

    if (!pe->header.SizeOfOptionalHeader) {
        printf("No optional header\n");
        return;
    } else if (pe->header.SizeOfOptionalHeader < sizeof(struct optional_header))
        warn("Size of optional header is %u (expected at least %lu).\n",
            pe->header.SizeOfOptionalHeader, sizeof(struct optional_header));

    print_flags(pe->header.Characteristics); /* 16 */

    if (pe->magic == 0x10b) {
        printf("Image type: 32-bit\n");
        print_opt32(&pe->opt32);
    } else if (pe->magic == 0x20b) {
        printf("Image type: 64-bit\n");
        print_opt64(&pe->opt64);
    }
}

static void print_specfile(struct pe *pe) {
    int i;
    FILE *specfile;
    char *spec_name = malloc(strlen(pe->name) + 4);
    sprintf(spec_name, "%s.ord", pe->name);
    specfile = fopen(spec_name, "w");

    if (!specfile) {
        perror("Couldn't open %s");
        return;
    }

    fprintf(specfile, "#Generated by dump -o\n");
    for (i = 0; i < pe->export_count; i++)
        fprintf(specfile, "%d\t%s\n", pe->exports[i].ordinal, pe->exports[i].name);
    fclose(specfile);
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
    int i, j;
    dword address;

    /* More headers. It's like a PE file is nothing but headers.
     * Do we really need to print any of this? No, not really. Just use the data. */
    fseek(f, offset, SEEK_SET);
    fread(&header, sizeof(struct export_header), 1, f);

    /* Grab the name. */
    pe->name = fstrdup(addr2offset(header.module_name_addr, pe));

    /* If a DLL exports by ordinal and there are holes, they will have a 0
     * address. We don't really want to put them in our table in that case, so
     * run through it once to see how many exports there really are. */
    pe->export_count = 0;
    fseek(f, addr2offset(header.addr_table_addr, pe), SEEK_SET);
    for (i=0; i<header.addr_table_count; i++) {
        if (read_dword())
            pe->export_count++;
    }

    /* Grab the exports. */
    pe->exports = malloc(pe->export_count * sizeof(struct export));

    /* If addr_table_count exceeds export_count, this means that some exports
     * are nameless (and thus exported by ordinal). */

    fseek(f, addr2offset(header.addr_table_addr, pe), SEEK_SET);
    j = 0;
    for (i=0; i<header.addr_table_count; i++) {
        if ((address = read_dword()))
        {
            pe->exports[j].ordinal = i + header.ordinal_base;
            pe->exports[j].address = address;
            pe->exports[j].name = NULL;
            j++;
        }
    }
    assert(j == pe->export_count);

    /* Why? WHY? */
    for (i=0; i<header.export_count; i++) {
        word index;

        fseek(f, addr2offset(header.ord_table_addr, pe) + (i * sizeof(word)), SEEK_SET);
        index = read_word();
        fseek(f, addr2offset(header.name_table_addr, pe) + (i * sizeof(dword)), SEEK_SET);
        pe->exports[index].name = fstrdup(addr2offset(read_dword(), pe));
    }
}

static void get_import_name_table(struct import_module *module, struct pe *pe) {
    long offset = addr2offset(module->nametab_addr, pe);
    long cursor = ftell(f);
    unsigned i, count;

    fseek(f, offset, SEEK_SET);
    count = 0;
    if (pe->magic == 0x10b)
        while (read_dword()) count++;
    else
        while (read_qword()) count++;

    module->nametab = malloc(count * sizeof(char *));

    fseek(f, offset, SEEK_SET);
    for (i = 0; i < count; i++) {
        qword address = (pe->magic == 0x10b) ? read_dword() : read_qword();
        if (address & 0x80000000) {
            address &= 0x7fffffff;
            module->nametab[i] = malloc(snprintf(NULL, 0, "%s.%lu", module->module, address));
            sprintf(module->nametab[i], "%s.%lu", module->module, address);
        } else
            module->nametab[i] = fstrdup(addr2offset(address, pe) + 2); /* skip hint */
    }
    module->count = count;

    fseek(f, cursor, SEEK_SET);
}

static void get_import_module_table(struct pe *pe) {
    long offset = addr2offset(pe->dirs[1].address, pe);
    static const dword zeroes[5] = {0};
    dword entry[5];
    int i;

    fseek(f, offset, SEEK_SET);
    pe->import_count = 0;

    while (fread(entry, sizeof(dword), 5, f) == 5 && memcmp(entry, zeroes, sizeof(entry)))
        pe->import_count++;

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
    int i, cdirs;

    fseek(f, offset_pe + sizeof(dword), SEEK_SET);
    fread(&pe->header, sizeof(struct file_header), 1, f);
    pe->magic = read_word();
    fseek(f, -sizeof(word), SEEK_CUR);
    if (pe->magic == 0x10b) {
        fread(&pe->opt32, sizeof(struct optional_header), 1, f);
        pe->imagebase = pe->opt32.ImageBase;
        cdirs = pe->opt32.NumberOfRvaAndSizes;
    } else if (pe->magic == 0x20b) {
        fread(&pe->opt64, sizeof(struct optional_header_pep), 1, f);
        pe->imagebase = pe->opt64.ImageBase;
        cdirs = pe->opt64.NumberOfRvaAndSizes;
    } else {
        warn("Don't know how to read image type %#x\n", pe->magic);
        exit(1);
    }

    pe->dirs = malloc(cdirs * sizeof(struct directory));
    fread(pe->dirs, sizeof(struct directory), cdirs, f);

    /* read the section table */
    pe->sections = malloc(pe->header.NumberOfSections * sizeof(struct section));
    for (i = 0; i < pe->header.NumberOfSections; i++) {
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

    if (cdirs >= 1 && pe->dirs[0].size)
        get_export_table(pe);
    if (cdirs >= 2 && pe->dirs[1].size)
        get_import_module_table(pe);
    if (cdirs >= 6 && pe->dirs[5].size)
        get_reloc_table(pe);

    /* Read the code. */
    read_sections(pe);
}

void freepe(struct pe *pe) {
    int i, j;

    free(pe->dirs);
    for (i = 0; i < pe->header.NumberOfSections; i++)
        free(pe->sections[i].instr_flags);
    free(pe->sections);
    free(pe->name);
    for (i = 0; i < pe->export_count; i++)
        free(pe->exports[i].name);
    free(pe->exports);
    for (i = 0; i < pe->import_count; i++) {
        for (j = 0; j < pe->imports[i].count; j++)
            free(pe->imports[i].nametab[j]);
        free(pe->imports[i].nametab);
        free(pe->imports[i].module);
    }
    free(pe->imports);
    free(pe->relocs);
}

void dumppe(long offset_pe) {
    struct pe pe = {0};
    int i, j;

    readpe(offset_pe, &pe);

    if (mode == SPECFILE) {
        print_specfile(&pe);
        freepe(&pe);
        return;
    }

    /* objdump always applies the image base to addresses. This makes sense for
     * EXEs, which can always be loaded at their preferred address, but for DLLs
     * it just makes debugging more annoying, since you have to subtract the
     * image base and *then* add the address the DLL was actually loaded at.
     * In theory PE provides us with everything we need to fix up a DLL
     * (relocations etc.) so that we only ever print the *relative* addresses.
     * But we can't do the same for an EXE, and we probably don't want to either.
     * Is the discrepancy going to be confusing? Probably not that much.
     *
     * Anyway, offer the user the option. Default is to enable relative addressing
     * for DLLs but disable it for EXEs. Note that if they manually enable it,
     * we won't be able to fix up everything. Caveat emptor.
     *
     * Internally we want to use relative IPs everywhere possible. The only place
     * that we can't is in arg->value. */
    if (pe_rel_addr == -1)
        pe_rel_addr = pe.header.Characteristics & 0x2000;

    printf("Module type: PE (Portable Executable)\n");
    if (pe.name) printf("Module name: %s\n", pe.name);

    if (mode & DUMPHEADER)
        print_header(&pe);

    if (mode & DUMPEXPORT) {
        putchar('\n');
        if (pe.exports) {
            printf("Exports:\n");

            for (i = 0; i < pe.export_count; i++) {
                dword address = pe.exports[i].address;
                if (!pe_rel_addr)
                    address += pe.imagebase;
                printf("\t%5d\t%#8x\t%s", pe.exports[i].ordinal, address,
                    pe.exports[i].name ? pe.exports[i].name : "<no name>");
                if (pe.exports[i].address >= pe.dirs[0].address &&
                    pe.exports[i].address < (pe.dirs[0].address + pe.dirs[0].size)) {
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

    if (mode & DUMPIMPORT) {
        putchar('\n');
        if (pe.imports) {
            printf("Imported modules:\n");
            for (i = 0; i < pe.import_count; i++)
                printf("\t%s\n", pe.imports[i].module);

            printf("\nImported functions:\n");
            for (i = 0; i < pe.import_count; i++) {
                printf("\t%s:\n", pe.imports[i].module);
                for (j = 0; j < pe.imports[i].count; j++)
                    printf("\t\t%s\n", pe.imports[i].nametab[j]);
            }
        } else
            printf("No imported module table\n");
    }

    if (mode & DISASSEMBLE)
        print_sections(&pe);

    freepe(&pe);
}
