#ifndef __MZ_H
#define __MZ_H

#include "semblance.h"

/* MZ (aka real-mode) addresses are "segmented", but not really. Just
 * use the actual value. */
static inline dword realaddr(word segment, word offset)
{
    if (segment < 0xfff0u)
        return (segment * 0x10) + offset;
    else                /* relative segments >= 0xfff0 really point into PSP */
        return (segment * 0x10) + offset - 0x100000;
}

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

#pragma pack()

struct reloc {
    word offset;
    word segment;
};

struct mz {
    /* fixme: file pointer here */

    const struct header_mz *header;
    const struct reloc *reltab;

    /* code */
    dword entry_point;
    byte *flags;
    dword start;
    dword length;
};

extern void readmz(struct mz *mz);
extern void freemz(struct mz *mz);

#endif /* __MZ_H */
