/* Functions for parsing the NE header */

#include <stddef.h>
#include <string.h>
#include "semblance.h"

struct header_pe {
    dword Signature;                    /* 00 */

    /* IMAGE_FILE_HEADER */
    word  Machine;                      /* 04 */
    word  NumberOfSections;             /* 06 */
    dword TimeDateStamp;                /* 08 */
    dword PointerToSymbolTable;         /* 0c */
    dword NumberOfSymbols;              /* 10 */
    word  SizeOfOptionalHeader;         /* 14 */
    word  Characteristics;              /* 16 */

    /* IMAGE_OPTIONAL_HEADER */
    word  Magic;                        /* 18 */
    byte  MajorLinkerVersion;           /* 1a */
    byte  MinorLinkerVersion;           /* 1b */
    dword SizeOfCode;                   /* 1c */
    dword SizeOfInitializedData;        /* 20 */
    dword SizeOfUninitializedData;      /* 24 */
    dword AddressOfEntryPoint;          /* 28 */
    dword BaseOfCode;                   /* 2c */
    dword BaseOfData;                   /* 30 */
    
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

STATIC_ASSERT(sizeof(struct header_pe) == 0x78);

static void print_flags(word flags) {
    char buffer[1024] = "";

    if (flags & 0x0001) strcat(buffer, ", relocations stripped");
    if (flags & 0x0002) strcat(buffer, ", executable");
    if (flags & 0x0004) strcat(buffer, ", line numbers stripped");
    if (flags & 0x0008) strcat(buffer, ", local symbols stripped");
    if (flags & 0x0010) strcat(buffer, ", aggressively trimmed");
    if (flags & 0x0020) strcat(buffer, ", large address aware");
    if (flags & 0x0040) strcat(buffer, ", (unknown flag 0x0040)");
    if (flags & 0x0080) strcat(buffer, ", IMAGE_FILE_BYTES_REVERSED_LO"); /* i.e. big-endian? */
    if (flags & 0x0100) strcat(buffer, ", 32-bit");
    if (flags & 0x0200) strcat(buffer, ", debug info stripped");
    if (flags & 0x0400) strcat(buffer, ", IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
    if (flags & 0x0800) strcat(buffer, ", IMAGE_FILE_NET_RUN_FROM_SWAP");
    if (flags & 0x1000) strcat(buffer, ", system file");
    if (flags & 0x2000) strcat(buffer, ", DLL");
    if (flags & 0x4000) strcat(buffer, ", uniprocessor");
    if (flags & 0x8000) strcat(buffer, ", IMAGE_FILE_BYTES_REVERSED_HI");
    
    printf("Flags: 0x%04x (%s)\n", flags, buffer+2);
}

static const char *const subsystems[] = {
    "unknown",      /* 0 */
    "native",       /* 1 */
    "GUI",          /* 2 */
    "CUI",          /* 3 */
    "(unknown value 4)",
    "OS/2 CUI",     /* 5 */
    "(unknown value 6)",
    "POSIX CUI",    /* 7 */
    "(unknown value 8)",
    "CE",           /* 9 */
    "EFI",          /* 10 */
    "EFI with boot services",       /* 11 */
    "EFI with runtime services",    /* 12 */
    "EFI ROM image",/* 13 */
    "Xbox",         /* 14 */
    "(unknown value 15)",
    "boot",         /* 16 */
    0
};

static void print_header(struct header_pe *header) {
    if (!header->SizeOfOptionalHeader) return;  /* 14 */
    else if (header->SizeOfOptionalHeader != sizeof(struct header_pe)-offsetof(struct header_pe, Magic))
        warn("Size of optional header is %u (expected %lu).\n", header->SizeOfOptionalHeader,
            sizeof(struct header_pe)-offsetof(struct header_pe, Magic));

    print_flags(header->Characteristics); /* 16 */

    if (header->Magic == 0x10b) /* 18 */
        printf("Image type: 32-bit\n");
    else if (header->Magic == 0x20b)
        printf("Image type: 64-bit\n");
    else if (header->Magic == 0x107)
        printf("Image type: ROM\n");

    printf("File version: %d.%d\n", header->MajorImageVersion, header->MinorImageVersion); /* 44 */

    printf("Linker version: %d.%d\n", header->MajorLinkerVersion, header->MinorLinkerVersion); /* 1a */

    printf("Size of initialized data: 0x%x bytes\n", header->SizeOfInitializedData); /* 20 */
    printf("Size of uninitialized data: 0x%x bytes\n", header->SizeOfUninitializedData); /* 24 */
    if (header->AddressOfEntryPoint)
        printf("Program entry point: 0x%x\n", header->AddressOfEntryPoint); /* 28 */

    printf("Preferred base address: 0x%x\n", header->ImageBase); /* 34 */
    printf("Required OS version: %d.%d\n", header->MajorOperatingSystemVersion, header->MinorOperatingSystemVersion); /* 40 */
    if (header->Subsystem <= 16) /* 5c */
        printf("Subsystem: %s\n", subsystems[header->Subsystem]);
    else
        printf("Subsystem: (unknown value %d)\n", header->Subsystem);
    printf("Subsystem version: %d.%d\n", header->MajorSubsystemVersion, header->MinorSubsystemVersion); /* 48 */
    if (header->Win32VersionValue != 0)
        warn("Win32VersionValue is %d (expected 0)\n", header->Win32VersionValue); /* 4c */
}

void dumppe(long offset_pe) {
    struct header_pe header;

    fseek(f, offset_pe, SEEK_SET);
    fread(&header, sizeof(header), 1, f);

    printf("Module type: PE (Portable Executable)\n");

    if (mode & DUMPHEADER)
        print_header(&header);
}
