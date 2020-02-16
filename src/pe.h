#ifndef __PE_H
#define __PE_H

#include "semblance.h"

#pragma pack(1)

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

STATIC_ASSERT(sizeof(struct optional_header) == 0x60);

struct optional_header_pep {
    /* Standard COFF fields. */
    word  Magic;                        /* 18 */
    byte  MajorLinkerVersion;           /* 1a */
    byte  MinorLinkerVersion;           /* 1b */
    dword SizeOfCode;                   /* 1c */
    dword SizeOfInitializedData;        /* 20 */
    dword SizeOfUninitializedData;      /* 24 */
    dword AddressOfEntryPoint;          /* 28 */
    dword BaseOfCode;                   /* 2c */

    /* PE fields. */
    qword ImageBase;                    /* 30 */
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
    qword SizeOfStackReserve;           /* 60 */
    qword SizeOfStackCommit;            /* 68 */
    qword SizeOfHeapReserve;            /* 70 */
    qword SizeOfHeapCommit;             /* 78 */
    dword LoaderFlags;                  /* 80 */
    dword NumberOfRvaAndSizes;          /* 84 */
};

STATIC_ASSERT(sizeof(struct optional_header_pep) == 0x70);

struct section {
    char  name[8];          /* 00 */
    dword min_alloc;        /* 08 */
    dword address;          /* 0c */
    dword length;           /* 10 */
    dword offset;           /* 14 */
    dword reloc_offset;     /* 18 */
    dword lineno_offset;    /* 1c */
    word  reloc_count;      /* 20 */
    word  lineno_count;     /* 22 */
    dword flags;            /* 24 */

    /* and our data: */
    byte *instr_flags;
};

struct reloc_pe
{
    dword offset;
    dword type;
};

#pragma pack()

struct export {
    dword address;
    word ordinal;
    const char *name;
};

struct import_module {
    const char *module;
    dword iat_addr;
    struct
    {
        union
        {
            const char *name;
            word ordinal;
        };
        int is_ordinal;
    } *nametab;
    unsigned count;
};

struct pe {
    word magic; /* same as opt->Magic field, but avoids casting */
    qword imagebase; /* same as opt->ImageBase field, but simpler */

    const struct file_header *header;
    union {
        const struct optional_header *opt32;
        const struct optional_header_pep *opt64;
    };
    const struct directory *dirs;

    const char *name;

    struct section *sections;

    struct export *exports;
    unsigned export_count;

    struct import_module *imports;
    unsigned import_count;

    struct reloc_pe *relocs;
    unsigned reloc_count;
};

/* in pe_section.c */
extern struct section *addr2section(dword addr, const struct pe *pe);
extern off_t addr2offset(dword addr, const struct pe *pe);
extern void read_sections(struct pe *pe);
extern void print_sections(struct pe *pe);

#endif /* __PE_H */
