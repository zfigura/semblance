/* Functions for parsing the NE header */

#include <stddef.h>
#include <string.h>
#include "semblance.h"

struct file_header {
    word  Machine;                      /* 04 */
    word  NumberOfSections;             /* 06 */
    dword TimeDateStamp;                /* 08 */
    dword PointerToSymbolTable;         /* 0c */
    dword NumberOfSymbols;              /* 10 */
    word  SizeOfOptionalHeader;         /* 14 */
    word  Characteristics;              /* 16 */
};

struct directory {
    dword address;
    dword size;
};

struct optional_header {
    /* Standard COFF fields. */
    word  Magic;                        /* 18 */
    byte  MajorLinkerVersion;           /* 1a */
    byte  MinorLinkerVersion;           /* 1b */
    dword SizeOfCode;                   /* 1c */
    dword SizeOfInitializedData;        /* 20 */
    dword SizeOfUninitializedData;      /* 24 */
    dword AddressOfEntryPoint;          /* 28 */
    dword BaseOfCode;                   /* 2c */
    dword BaseOfData;                   /* 30 */

    /* PE fields. */
    dword ImageBase;                    /* 34 */
    dword SectionAlignment;             /* 38 */
    dword FileAlignment;                /* 3c */
    word  MajorOperatingSystemVersion;  /* 40 */
    word  MinorOperatingSystemVersion;  /* 42 */
    word  MajorImageVersion;            /* 44 */
    word  MinorImageVersion;            /* 46 */
    word  MajorSubsystemVersion;        /* 48 */
    word  MinorSubsystemVersion;        /* 4a */
    dword Win32VersionValue;            /* 4c */
    dword SizeOfImage;                  /* 50 */
    dword SizeOfHeaders;                /* 54 */
    dword CheckSum;                     /* 58 */
    word  Subsystem;                    /* 5c */
    word  DllCharacteristics;           /* 5e */
    dword SizeOfStackReserve;           /* 60 */
    dword SizeOfStackCommit;            /* 64 */
    dword SizeOfHeapReserve;            /* 68 */
    dword SizeOfHeapCommit;             /* 6c */
    dword LoaderFlags;                  /* 70 */
    dword NumberOfRvaAndSizes;          /* 74 */
};

struct header_pe {
    dword Signature;                    /* 00 */

    struct file_header file;
    struct optional_header opt;
};

STATIC_ASSERT(sizeof(struct header_pe) == 0x78);

struct section {
    char  name[8];          /* 00 */
    dword min_alloc;        /* 08 */
    dword address;          /* 0c */
    dword size;             /* 10 */
    dword offset;           /* 14 */
    dword reloc_offset;     /* 18 */
    dword lineno_offset;    /* 1c */
    word  reloc_count;      /* 20 */
    word  lineno_count;     /* 22 */
    dword flags;            /* 24 */
};

STATIC_ASSERT(sizeof(struct section) == 0x28);

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

static word section_count;
static struct section *sections;

static struct section *addr2section(dword addr) {
    /* Even worse than the below, some data is sensitive to which section it's in! */

    int i;
    for (i=0;i<section_count;i++) {
         if (addr >= sections[i].address && addr < sections[i].address + sections[i].size)
            return &sections[i];
    }

    return NULL;
}

static long addr2offset(dword addr) {
    /* Everything inside a PE file is built so that the file is read while it's
     * already loaded. Offsets aren't file offsets, they're *memory* offsets.
     * We don't want to load the whole file, so we have to search through each
     * section to figure out where in the *file* a virtual address points. */

    struct section *section = addr2section(addr);
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

struct export {
    dword address;
    word ordinal;
    char *name;
};

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

static unsigned get_export_table(struct directory dir, struct export **exports, char **module_name) {
    struct export_header header;
    long offset = addr2offset(dir.address);
    struct export *ret;
    int len, i;

    /* More headers. It's like a PE file is nothing but headers.
     * Do we really need to print any of this? No, not really. Just use the data. */
    fseek(f, offset, SEEK_SET);
    fread(&header, sizeof(struct export_header), 1, f);

    /* Grab the name. */
    *module_name = fstrdup(addr2offset(header.module_name_addr));

    if (header.addr_table_count != header.export_count)
        warn("Export address table count %d does not mach export count %d\n",
            header.addr_table_count, header.export_count);

    /* Grab the exports. */
    ret = malloc(header.export_count * sizeof(struct export));

    fseek(f, addr2offset(header.addr_table_addr), SEEK_SET);
    for (i=0; i<header.addr_table_count; i++)
        ret[i].address = addr2offset(read_dword());

    fseek(f, addr2offset(header.name_table_addr), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        ret[i].name = fstrdup(addr2offset(read_dword()));

    fseek(f, addr2offset(header.ord_table_addr), SEEK_SET);
    for (i=0; i<header.export_count; i++)
        ret[i].ordinal = read_word();

    *exports = ret;

    return header.export_count;
}

void dumppe(long offset_pe) {
    struct header_pe header;
    struct directory *dirs;
    struct export *export_table = NULL;
    unsigned export_count;
    char *module_name;
    int i;

    fseek(f, offset_pe, SEEK_SET);
    fread(&header, sizeof(struct header_pe), 1, f);

    dirs = malloc(header.opt.NumberOfRvaAndSizes * sizeof(*dirs));
    fread(dirs, sizeof(struct directory), header.opt.NumberOfRvaAndSizes, f);

    /* read the section table */
    section_count = header.file.NumberOfSections;
    sections = malloc(section_count * sizeof(struct section));
    fread(sections, sizeof(struct section), section_count, f);

    /* Read the Data Directories.
     * PE is bizarre. It tries to make all of these things generic by putting
     * them in separate "directories". But the order of these seems to be fixed
     * anyway, so why bother? */

    if (header.opt.NumberOfRvaAndSizes >= 1 && dirs[0].size)
        export_count = get_export_table(dirs[0], &export_table, &module_name);

    printf("Module type: PE (Portable Executable)\n");
    if (module_name) printf("Module name: %s\n", module_name);

    if (mode & DUMPHEADER)
        print_header(&header);

    if (mode & DUMPEXPORT) {
        if (export_table) {
            printf("Exports:\n");
            for (i = 0; i < export_count; i++)
                printf("\t%5d\t%#8x\t%s\n", export_table[i].ordinal, header.opt.ImageBase + export_table[i].address, export_table[i].name);
        } else
            printf("No export table\n");
        putchar('\n');
    }
}
