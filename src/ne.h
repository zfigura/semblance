#ifndef __NE_H
#define __NE_H

#include "semblance.h"

#pragma pack(1)

struct header_ne {
    word  ne_magic;             /* 00 NE signature 'NE' */
    byte  ne_ver;               /* 02 Linker version number */
    byte  ne_rev;               /* 03 Linker revision number */
    word  ne_enttab;            /* 04 Offset to entry table */
    word  ne_cbenttab;          /* 06 Length of entry table in bytes */
    dword ne_crc;               /* 08 Checksum */
    word  ne_flags;             /* 0c Flags about segments in this file */
    byte  ne_autodata;          /* 0e Automatic data segment number */
    byte  ne_unused;            /* 0f */
    word  ne_heap;              /* 10 Initial size of local heap */
    word  ne_stack;             /* 12 Initial size of stack */
    word  ne_ip;                /* 14 Initial IP */
    word  ne_cs;                /* 16 Initial CS */
    word  ne_sp;                /* 18 Initial SP */
    word  ne_ss;                /* 1a Initial SS */
    word  ne_cseg;              /* 1c # of entries in segment table */
    word  ne_cmod;              /* 1e # of entries in import module table */
    word  ne_cbnrestab;         /* 20 Length of nonresident-name table */
    word  ne_segtab;            /* 22 Offset to segment table */
    word  ne_rsrctab;           /* 24 Offset to resource table */
    word  ne_restab;            /* 26 Offset to resident-name table */
    word  ne_modtab;            /* 28 Offset to import module table */
    word  ne_imptab;            /* 2a Offset to name table */
    dword ne_nrestab;           /* 2c ABSOLUTE Offset to nonresident-name table */
    word  ne_cmovent;           /* 30 # of movable entry points */
    word  ne_align;             /* 32 Logical sector alignment shift count */
    word  ne_cres;              /* 34 # of resource segments */
    byte  ne_exetyp;            /* 36 Flags indicating target OS */
    byte  ne_flagsothers;       /* 37 Additional information flags */
    word  ne_pretthunks;        /* 38 Offset to return thunks */
    word  ne_psegrefbytes;      /* 3a Offset to segment ref. bytes */
    word  ne_swaparea;          /* 3c Reserved by Microsoft */
    byte  ne_expver_min;        /* 3e Expected Windows version number (minor) */
    byte  ne_expver_maj;        /* 3f Expected Windows version number (major) */
};

STATIC_ASSERT(sizeof(struct header_ne) == 0x40);

#pragma pack()

struct entry {
    byte flags;
    byte segment;
    word offset;
    char *name;     /* may be NULL */
};

struct export {
    word ordinal;
    char *name;
};

struct import_module {
    char *name;
    struct export *exports;
    unsigned export_count;
};

struct reloc {
    byte size;
    byte type;
    word offset_count;
    word *offsets;
    word tseg;
    word toffset;
    char *text;
};

struct segment {
    word cs;
    long start;
    word length;
    word flags;
    word min_alloc;
    byte *instr_flags;
    struct reloc *reloc_table;
    word reloc_count;
};

struct ne {
    /* fixme: file pointer here */

    struct header_ne header;

    char *name;
    char *description;

    const byte *nametab;    /* FIXME */

    struct entry *enttab;
    unsigned entcount;

    struct import_module *imptab;

    struct segment *segments;
};

extern void readne(long offset_ne, struct ne *ne);
extern void freene(struct ne *ne);

/* in ne_resource.c */
extern void print_rsrc(off_t start);
/* in ne_segment.c */
extern void read_segments(off_t start, struct ne *ne);
extern void free_segments(struct ne *ne);
extern void print_segments(struct ne *ne);

#endif /* __NE_H */
