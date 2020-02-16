/*
 * Functions for dumping NE code and data segments
 *
 * Copyright 2017-2018,2020 Zebediah Figura
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "semblance.h"
#include "ne.h"
#include "x86_instr.h"

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %d:%04x: ", cs, ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

/* index function */
static char *get_entry_name(word cs, word ip, const struct ne *ne) {
    unsigned i;
    for (i=0; i<ne->entcount; i++) {
        if (ne->enttab[i].segment == cs &&
            ne->enttab[i].offset == ip)
            return ne->enttab[i].name;
    }
    return NULL;
}

/* index function */
static const struct reloc *get_reloc(const struct segment *seg, word ip) {
    unsigned i, o;
    for (i = 0; i < seg->reloc_count; i++) {
        for (o = 0; o < seg->reloc_table[i].offset_count; o++)
            if (seg->reloc_table[i].offsets[o] == ip)
                return &seg->reloc_table[i];
    }
    return NULL;
}

/* load an imported name from a specfile */
static char *get_imported_name(word module, word ordinal, const struct ne *ne) {
    unsigned i;
    for (i=0; i<ne->imptab[module-1].export_count; i++) {
        if (ne->imptab[module-1].exports[i].ordinal == ordinal)
            return ne->imptab[module-1].exports[i].name;
    }
    return NULL;
}

/* Tweak the inline string and return the comment. */
static const char *relocate_arg(const struct segment *seg, struct arg *arg, const struct ne *ne)
{
    const struct reloc *r = get_reloc(seg, arg->ip);
    char *module = NULL;

    if (!r && arg->type == PTR32) r = get_reloc(seg, arg->ip+2);
    if (!r) {
        warn("%#x: Byte tagged INSTR_RELOC has no reloc attached; this is a bug.\n", arg->ip);
        return "?";
    }

    if (r->type == 1 || r->type == 2)
        module = ne->imptab[r->tseg-1].name;

    if (arg->type == PTR32 && r->size == 3) {
        /* 32-bit relocation on 32-bit pointer, so just copy the name */
        if (r->type == 0) {
            snprintf(arg->string, sizeof(arg->string), "%d:%04x", r->tseg, r->toffset);
            return r->text;
        } else if (r->type == 1) {
            snprintf(arg->string, sizeof(arg->string), "%s.%d", module, r->toffset);
            return get_imported_name(r->tseg, r->toffset, ne);
        } else if (r->type == 2) {
            snprintf(arg->string, sizeof(arg->string), "%s.%.*s", module,
                ne->nametab[r->toffset], &ne->nametab[r->toffset+1]);
            return NULL;
        }
    } else if (arg->type == PTR32 && r->size == 2 && r->type == 0) {
        /* segment relocation on 32-bit pointer; copy the segment but keep the
         * offset */
        snprintf(arg->string, sizeof(arg->string), "%d:%04lx", r->tseg, arg->value);
        return get_entry_name(r->tseg, arg->value, ne);
    } else if (arg->type == IMM && (r->size == 2 || r->size == 5)) {
        /* imm16 referencing a segment or offset directly */
        const char *pfx = (r->size == 2 ? "seg " : "");
        if (r->type == 0) {
            snprintf(arg->string, sizeof(arg->string), "%s%d", pfx, r->tseg);
            return NULL;
        } else if (r->type == 1) {
            snprintf(arg->string, sizeof(arg->string), "%s%s.%d", pfx, module, r->toffset);
            return get_imported_name(r->tseg, r->toffset, ne);
        } else if (r->type == 2) {
            snprintf(arg->string, sizeof(arg->string), "%s%s.%.*s", pfx, module,
                ne->nametab[r->toffset], &ne->nametab[r->toffset+1]);
            return NULL;
        }
    }

    warn("%#x: unhandled relocation: size %d, type %d, argtype %x\n",
        arg->ip, r->size, r->type, arg->type);

    return NULL;
}

/* Returns the number of bytes processed (same as get_instr). */
static int print_ne_instr(const struct segment *seg, word ip, byte *p, const struct ne *ne) {
    word cs = seg->cs;
    struct instr instr = {0};
    unsigned len;
    int bits = (seg->flags & 0x2000) ? 32 : 16;

    const char *comment = NULL;
    char ip_string[11];

    len = get_instr(ip, p, &instr, bits);

    sprintf(ip_string, "%3d:%04x", seg->cs, ip);

    /* check for relocations */
    if (seg->instr_flags[instr.args[0].ip] & INSTR_RELOC)
        comment = relocate_arg(seg, &instr.args[0], ne);
    if (seg->instr_flags[instr.args[1].ip] & INSTR_RELOC)
        comment = relocate_arg(seg, &instr.args[1], ne);
    /* make sure to check for PTR32 segment-only relocations */
    if (instr.op.arg0 == PTR32 && seg->instr_flags[instr.args[0].ip+2] & INSTR_RELOC)
        comment = relocate_arg(seg, &instr.args[0], ne);

    /* check if we are referencing a named export */
    if (!comment && instr.op.arg0 == REL16)
        comment = get_entry_name(cs, instr.args[0].value, ne);

    print_instr(ip_string, p, len, seg->instr_flags[ip], &instr, comment, bits);

    return len;
};

static void print_disassembly(const struct segment *seg, const struct ne *ne) {
    const word cs = seg->cs;
    word ip = 0;

    byte buffer[MAX_INSTR];

    while (ip < seg->length) {
        /* find a valid instruction */
        if (!(seg->instr_flags[ip] & INSTR_VALID)) {
            if (opts & DISASSEMBLE_ALL) {
                /* still skip zeroes */
                if (read_byte(seg->start + ip) == 0)
                {
                    printf("     ...\n");
                    ip++;
                    while (read_byte(seg->start + ip) == 0) ip++;
                }
            } else {
                printf("     ...\n");
                while ((ip < seg->length) && !(seg->instr_flags[ip] & INSTR_VALID)) ip++;
            }
        }

        if (ip >= seg->length) return;

        /* Instructions can "hang over" the end of a segment.
         * Zero should be supplied. */
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, read_data(seg->start + ip), min(sizeof(buffer), seg->length - ip));

        if (seg->instr_flags[ip] & INSTR_FUNC) {
            char *name = get_entry_name(cs, ip, ne);
            printf("\n");
            printf("%d:%04x <%s>:\n", cs, ip, name ? name : "no name");
            /* don't mark far functions—we can't reliably detect them
             * because of "push cs", and they should be evident anyway. */
        }

        ip += print_ne_instr(seg, ip, buffer, ne);
    }
    putchar('\n');
}

static void print_data(const struct segment *seg) {
    word ip;    /* well, not really ip */

    for (ip = 0; ip < seg->length; ip += 16) {
        int len = min(seg->length-ip, 16);
        int i;

        printf("%3d:%04x", seg->cs, ip);
        for (i=0; i<16; i++) {
            if (i < len)
                printf(" %02x", read_byte(seg->start + ip + i));
            else
                printf("   ");
        }
        printf("  ");
        for (i = 0; i < len; ++i)
        {
            char c = read_byte(seg->start + ip + i);
            putchar(isprint(c) ? c : '.');
        }
        putchar('\n');
    }
}

static void scan_segment(word cs, word ip, struct ne *ne) {
    struct segment *seg = &ne->segments[cs-1];

    byte buffer[MAX_INSTR];
    struct instr instr;
    int instr_length;
    int i;

    if (ip >= seg->length) {
        warn_at("Attempt to scan past end of segment.\n");
        return;
    }

    if ((seg->instr_flags[ip] & (INSTR_VALID|INSTR_SCANNED)) == INSTR_SCANNED)
        warn_at("Attempt to scan byte that does not begin instruction.\n");

    while (ip < seg->length) {
        /* check if we already read from here */
        if (seg->instr_flags[ip] & INSTR_SCANNED) return;

        /* read the instruction */
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, read_data(seg->start + ip), min(sizeof(buffer), seg->length - ip));
        instr_length = get_instr(ip, buffer, &instr, (seg->flags & 0x2000) ? 32 : 16);

        /* mark the bytes */
        seg->instr_flags[ip] |= INSTR_VALID;
        for (i = ip; i < ip+instr_length && i < seg->min_alloc; i++) seg->instr_flags[i] |= INSTR_SCANNED;

        /* instruction which hangs over the minimum allocation */
        if (i < ip+instr_length && i == seg->min_alloc) break;

        /* handle conditional and unconditional jumps */
        if (instr.op.arg0 == PTR32) {
            for (i = ip; i < ip+instr_length; i++) {
                if (seg->instr_flags[i] & INSTR_RELOC) {
                    const struct reloc *r = get_reloc(seg, i);
                    const struct segment *tseg;

                    if (!r) break;
                    tseg = &ne->segments[r->tseg-1];

                    if (r->type != 0) break;

                    if (r->size == 3) {
                        /* 32-bit relocation on 32-bit pointer */
                        tseg->instr_flags[r->toffset] |= INSTR_FAR;
                        if (!strcmp(instr.op.name, "call"))
                            tseg->instr_flags[r->toffset] |= INSTR_FUNC;
                        else
                            tseg->instr_flags[r->toffset] |= INSTR_JUMP;
                        scan_segment(r->tseg, r->toffset, ne);
                    } else if (r->size == 2) {
                        /* segment relocation on 32-bit pointer */
                        tseg->instr_flags[instr.args[0].value] |= INSTR_FAR;
                        if (!strcmp(instr.op.name, "call"))
                            tseg->instr_flags[instr.args[0].value] |= INSTR_FUNC;
                        else
                            tseg->instr_flags[instr.args[0].value] |= INSTR_JUMP;
                        scan_segment(r->tseg, instr.args[0].value, ne);
                    }

                    break;
                }
            }
        } else if (instr.op.flags & OP_BRANCH) {
            /* near relative jump, loop, or call */
            if (!strcmp(instr.op.name, "call"))
                seg->instr_flags[instr.args[0].value] |= INSTR_FUNC;
            else
                seg->instr_flags[instr.args[0].value] |= INSTR_JUMP;

            /* scan it */
            scan_segment(cs, instr.args[0].value, ne);
        }

        if (instr.op.flags & OP_STOP)
            return;

        ip += instr_length;
    }

    warn_at("Scan reached the end of segment.\n");
}

static void print_segment_flags(word flags) {
    char buffer[1024];

    if (flags & 0x0001)
        strcpy(buffer, "data");
    else
        strcpy(buffer, "code");

    /* I think these three should never occur in a file */
    if (flags & 0x0002) strcat(buffer, ", allocated");
    if (flags & 0x0004) strcat(buffer, ", loaded");
    if (flags & 0x0008) strcat(buffer, ", iterated");
        
    if (flags & 0x0010) strcat(buffer, ", moveable");
    if (flags & 0x0020) strcat(buffer, ", shareable");
    if (flags & 0x0040) strcat(buffer, ", preload");
    if (flags & 0x0080) strcat(buffer, (flags & 0x0001) ? ", read-only" : ", execute-only");
    if (flags & 0x0100) strcat(buffer, ", has relocation data");

    /* there's still an unidentified flag 0x0400 which appears in all of my testcases.
     * but WINE doesn't know what it is, so... */
    if (flags & 0x0800) strcat(buffer, ", self-loading");
    if (flags & 0x1000) strcat(buffer, ", discardable");
    if (flags & 0x2000) strcat(buffer, ", 32-bit");

    if (flags & 0xc608) sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0xc608);
    printf("    Flags: 0x%04x (%s)\n", flags, buffer);
}

static void read_reloc(const struct segment *seg, word index, struct ne *ne)
{
    off_t entry = seg->start + seg->length + 2 + (index * 8);
    struct reloc *r = &seg->reloc_table[index];
    byte size = read_byte(entry);
    byte type = read_byte(entry + 1);
    word offset = read_word(entry + 2);
    word module = read_word(entry + 4); /* or segment */
    word ordinal = read_word(entry + 6); /* or offset */

    word offset_cursor;
    word next;

    memset(r, 0, sizeof(*r));

    r->size = size;
    r->type = type & 3;

    if ((type & 3) == 0) {
        /* internal reference */
        char *name;

        if (module == 0xff) {
            r->tseg = ne->enttab[ordinal-1].segment;
            r->toffset = ne->enttab[ordinal-1].offset;
        } else {
            r->tseg = module;
            r->toffset = ordinal;
        }

        /* grab the name, if we can */
        if ((name = get_entry_name(r->tseg, r->toffset, ne)))
            r->text = name;
    } else if ((type & 3) == 1) {
        /* imported ordinal */

        r->tseg = module;
        r->toffset = ordinal;
    } else if ((type & 3) == 2) {
        /* imported name */
        r->tseg = module;
        r->toffset = ordinal;
    } else if ((type & 3) == 3) {
        /* OSFIXUP */
        /* FIXME: the meaning of this is not understood! */
        return;
    }

    /* get the offset list */
    offset_cursor = offset;
    r->offset_count = 0;
    do {
        /* One of my testcases has relocation offsets that exceed the length of
         * the segment. Until we figure out what that's about, ignore them. */
        if (offset_cursor >= seg->length) {
            warn("%d:%04x: Relocation offset exceeds segment length (%04x).\n", seg->cs, offset_cursor, seg->length);
            break;
        }

        if (seg->instr_flags[offset_cursor] & INSTR_RELOC) {
            warn("%d:%04x: Infinite loop reading relocation data.\n", seg->cs, offset_cursor);
            r->offset_count = 0;
            return;
        }

        r->offset_count++;
        seg->instr_flags[offset_cursor] |= INSTR_RELOC;

        next = read_word(seg->start + offset_cursor);
        if (type & 4)
            offset_cursor += next;
        else
            offset_cursor = next;
    } while (next < 0xFFFb);

    r->offsets = malloc(r->offset_count*sizeof(word *));

    offset_cursor = offset;
    r->offset_count = 0;
    do {
        if (offset_cursor >= seg->length) {
            break;
        }

        r->offsets[r->offset_count] = offset_cursor;
        r->offset_count++;

        next = read_word(seg->start + offset_cursor);
        if (type & 4)
            offset_cursor += next;
        else
            offset_cursor = next;
    } while (next < 0xFFFb);
}

static void free_reloc(struct reloc *reloc_data, word reloc_count) {
    int i;
    for (i = 0; i < reloc_count; i++) {
        free(reloc_data[i].offsets);
    }

    free(reloc_data);
}

void read_segments(off_t start, struct ne *ne)
{
    word entry_cs = ne->header.ne_cs;
    word entry_ip = ne->header.ne_ip;
    word count = ne->header.ne_cseg;
    struct segment *seg;
    word i, j;

    ne->segments = malloc(count * sizeof(struct segment));

    for (i = 0; i < count; ++i)
    {
        seg = &ne->segments[i];
        seg->cs = i + 1;
        seg->start = read_word(start + i*8) << ne->header.ne_align;
        seg->length = read_word(start + i*8 + 2);
        seg->flags = read_word(start + i*8 + 4);
        seg->min_alloc = read_word(start + i*8 + 6);

        /* Use min_alloc rather than length because data can "hang over". */
        seg->instr_flags = calloc(seg->min_alloc, sizeof(byte));
    }

    /* First pass: just read the relocation data */
    for (i = 0; i < count; ++i)
    {
        seg = &ne->segments[i];

        if (seg->flags & 0x0100) {
            seg->reloc_count = read_word(seg->start + seg->length);
            seg->reloc_table = malloc(seg->reloc_count * sizeof(struct reloc));

            for (j = 0; j < seg->reloc_count; j++)
                read_reloc(seg, j, ne);
        } else {
            seg->reloc_count = 0;
            seg->reloc_table = NULL;
        }
    }

    /* Second pass: scan entry points (we have to do this after we read
     * relocation data for all segments.) */
    for (i = 0; i < ne->entcount; i++) {

        /* don't scan exported values */
        if (ne->enttab[i].segment == 0 ||
            ne->enttab[i].segment == 0xfe) continue;

        /* or values that live in data segments */
        if (ne->segments[ne->enttab[i].segment-1].flags & 0x0001) continue;

        /* Annoyingly, data can be put in code segments, and without any
         * apparent indication that it is not code. As a dumb heuristic,
         * only scan exported entries—this won't work universally, and it
         * may potentially miss private entries, but it's better than nothing. */
        if (!(ne->enttab[i].flags & 1)) continue;

        scan_segment(ne->enttab[i].segment, ne->enttab[i].offset, ne);
        ne->segments[ne->enttab[i].segment-1].instr_flags[ne->enttab[i].offset] |= INSTR_FUNC;
    }

    /* and don't forget to scan the program entry point */
    if (entry_cs == 0 && entry_ip == 0) {
        /* do nothing */
    } else if (entry_ip >= ne->segments[entry_cs-1].length) {
        /* see note above under relocations */
        warn("Entry point %d:%04x exceeds segment length (%04x)\n", entry_cs, entry_ip, ne->segments[entry_cs-1].length);
    } else {
        ne->segments[entry_cs-1].instr_flags[entry_ip] |= INSTR_FUNC;
        scan_segment(entry_cs, entry_ip, ne);
    }
}

void free_segments(struct ne *ne) {
    unsigned cs;
    struct segment *seg;

    for (cs = 1; cs <= ne->header.ne_cseg; cs++) {
        seg = &ne->segments[cs-1];
        free_reloc(seg->reloc_table, seg->reloc_count);
        free(seg->instr_flags);
    }

    free(ne->segments);
}

void print_segments(struct ne *ne) {
    unsigned cs;
    struct segment *seg;

    /* Final pass: print data */
    for (cs = 1; cs <= ne->header.ne_cseg; cs++) {
        seg = &ne->segments[cs-1];

        putchar('\n');
        printf("Segment %d (start = 0x%lx, length = 0x%x, minimum allocation = 0x%x):\n",
            cs, seg->start, seg->length, seg->min_alloc ? seg->min_alloc : 65536);
        print_segment_flags(seg->flags);

        if (seg->flags & 0x0001) {
            /* FIXME: We should at least make a special note of entry points. */
            /* FIXME #2: Data segments can still have relocations... */
            print_data(seg);
        } else {
            /* like objdump, print the whole code segment like a data segment */
            if (opts & FULL_CONTENTS)
                print_data(seg);
            print_disassembly(seg, ne);
        }
    }
}
