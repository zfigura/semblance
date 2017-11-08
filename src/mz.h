#ifndef __MZ_H
#define __MZ_H

#include "semblance.h"

/* MZ, aka real-mode, addresses are "segmented", but not really. Just
 * use the actual value. */
static inline dword realaddr(word segment, word offset)
{
    return (segment * 0x10) + offset;
}

#pragma pack(1)

typedef struct _reloc {
    word offset;
    word segment;
} reloc;

/* per-file globals */
reloc *reloc_table;

extern void print_mz_segments(dword length);

#endif /* __MZ_H */
