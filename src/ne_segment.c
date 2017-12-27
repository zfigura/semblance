/* Functions for dumping NE code and data segments */

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

struct reloc {
    byte size;
    byte type;
    word offset_count;
    word *offsets;
    word target_segment;
    word target_offset;
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

/* global segment list */
static struct segment *segments;

/* index_function */
static char *get_entry_name(word cs, word ip) {
    unsigned i;
    for (i=0; i<entry_count; i++) {
        if (entry_table[i].segment == cs &&
            entry_table[i].offset == ip)
            return entry_table[i].name;
    }
    return NULL;
}

/* index function */
static const struct reloc *get_reloc(word cs, word ip, const struct reloc *reloc_data, word reloc_count) {
    unsigned i, o;
    for (i=0; i<reloc_count; i++) {
        for (o=0; o<reloc_data[i].offset_count; o++)
            if (reloc_data[i].offsets[o] == ip)
                return &reloc_data[i];
    }
    warn_at("Byte tagged INSTR_RELOC has no reloc; this is a bug.\n");
    return NULL;
}

/* load an imported name from a specfile */
static char *get_imported_name(word module, word ordinal) {
    unsigned i;
    for (i=0; i<import_module_table[module-1].export_count; i++) {
        if (import_module_table[module-1].exports[i].ordinal == ordinal)
            return import_module_table[module-1].exports[i].name;
    }
    return NULL;
}

/* Returns the number of bytes processed (same as get_instr). */
static int print_ne_instr(const struct segment *seg, word ip, byte *p, char *out) {
    word cs = seg->cs;
    struct instr instr = {0};
    char arg0[32] = "", arg1[32] = "";
    unsigned len;

    unsigned i;
    char *comment = NULL;
    char ip_string[10];

    out[0] = 0;

    len = get_instr(ip, p, &instr, seg->flags & 0x2000);

    sprintf(ip_string, "%3d:%04x", seg->cs, ip);

    /* check for relocations. ideally this should be done per argument, but
     * this would require annoying refactoring of the code. there should only
     * be one relocation per instruction anyway so don't bother. */
    for (i = ip; i < ip+len; i++) {
        if (seg->instr_flags[i] & INSTR_RELOC) {
            const struct reloc *r = get_reloc(seg->cs, i, seg->reloc_table, seg->reloc_count);
            if (!r) break;
            char *module;
            if (r->type == 1 || r->type == 2)
                module = import_module_table[r->target_segment-1].name;

            if (instr.op.arg0 == PTR32 && r->size == 3) {
                /* 32-bit relocation on 32-bit pointer, so just copy the name as appropriate */
                if (r->type == 0) {
                    sprintf(arg0, "%d:%04x", r->target_segment, r->target_offset);
                    comment = r->text;
                } else if (r->type == 1) {
                    snprintf(arg0, sizeof(arg0), "%s.%d", module, r->target_offset); // fixme please
                    comment = get_imported_name(r->target_segment, r->target_offset);
                } else if (r->type == 2)
                    snprintf(arg0, sizeof(arg0), "%s.%.*s", module, import_name_table[r->target_offset], &import_name_table[r->target_offset+1]);
            } else if (instr.op.arg0 == PTR32 && r->size == 2 && r->type == 0) {
                /* segment relocation on 32-bit pointer; copy the segment but keep the offset */
                sprintf(arg0, "%d:%04x", r->target_segment, instr.arg0);
                comment = get_entry_name(r->target_segment, instr.arg0);
            } else if (instr.op.arg0 == IMM && r->size == 2) {
                /* imm16 referencing a segment directly */
                if (r->type == 0)
                    sprintf(arg0, "seg %d", r->target_segment);
                else if (r->type == 1) {
                    snprintf(arg0, sizeof(arg0), "seg %s.%d", module, r->target_offset); // fixme please
                    comment = get_imported_name(r->target_segment, r->target_offset);
                } else if (r->type == 2)
                    snprintf(arg0, sizeof(arg0), "seg %s.%.*s", module, import_name_table[r->target_offset], &import_name_table[r->target_offset+1]);
            } else if (instr.op.arg1 == IMM && r->size == 2) {
                /* same as above wrt arg1 */
                if (r->type == 0)
                    sprintf(arg1, "seg %d", r->target_segment);
                else if (r->type == 1) {
                    snprintf(arg1, sizeof(arg1), "seg %s.%d", module, r->target_offset); // fixme please
                    comment = get_imported_name(r->target_segment, r->target_offset);
                } else if (r->type == 2)
                    snprintf(arg1, sizeof(arg1), "seg %s.%.*s", module, import_name_table[r->target_offset], &import_name_table[r->target_offset+1]);
            } else if (instr.op.arg0 == IMM && r->size == 5) {
                /* imm16 referencing an offset directly. MASM doesn't have a prefix for this
                 * and I don't personally think it should be necessary either. */
                if (r->type == 0)
                    sprintf(arg0, "%04x", r->target_offset);
                else if (r->type == 1) {
                    snprintf(arg0, sizeof(arg0), "%s.%d", module, r->target_offset); // fixme please
                    comment = get_imported_name(r->target_segment, r->target_offset);
                } else if (r->type == 2)
                    snprintf(arg0, sizeof(arg0), "%s.%.*s", module, import_name_table[r->target_offset], &import_name_table[r->target_offset+1]);
            } else if (instr.op.arg1 == IMM && r->size == 5) {
                /* same as above wrt arg1 */
                if (r->type == 0)
                    sprintf(arg1, "%04x", r->target_offset);
                else if (r->type == 1) {
                    snprintf(arg1, sizeof(arg1), "%s.%d", module, r->target_offset); // fixme please
                    comment = get_imported_name(r->target_segment, r->target_offset);
                } else if (r->type == 2)
                    snprintf(arg1, sizeof(arg1), "%s.%.*s", module, import_name_table[r->target_offset], &import_name_table[r->target_offset+1]);
            } else
                warn_at("unhandled relocation: size %d, type %d, instruction %02x %s\n", r->size, r->type, instr.op.opcode, instr.op.name);
        }
    }

    /* check if we are referencing a named export */
    if (instr.op.arg0 == REL16 && !comment)
        comment = get_entry_name(cs, instr.arg0);

    print_instr(out, ip_string, p, len, seg->instr_flags[ip], &instr, arg0, arg1, comment);

    return len;
};

static void print_disassembly(const struct segment *seg) {
    const word cs = seg->cs;
    word ip = 0;

    byte buffer[MAX_INSTR];
    char out[256];

    while (ip < seg->length) {
        fseek(f, seg->start+ip, SEEK_SET);

        /* find a valid instruction */
        if (!(seg->instr_flags[ip] & INSTR_VALID)) {
            if (opts & DISASSEMBLE_ALL) {
                /* still skip zeroes */
                if (read_byte() == 0) {
                    printf("     ...\n");
                    ip++;
                }
                while (read_byte() == 0) ip++;
            } else {
                printf("     ...\n");
                while ((ip < seg->length) && !(seg->instr_flags[ip] & INSTR_VALID)) ip++;
            }
        }

        fseek(f, seg->start+ip, SEEK_SET);
        if (ip >= seg->length) return;

        /* Instructions can "hang over" the end of a segment.
         * Zero should be supplied. */
        memset(buffer, 0, sizeof(buffer));
        if ((unsigned) seg->length-ip < sizeof(buffer))
            fread(buffer, 1, seg->length-ip, f);
        else
            fread(buffer, 1, sizeof(buffer), f);

        if (seg->instr_flags[ip] & INSTR_FUNC) {
            char *name = get_entry_name(cs, ip);
            printf("\n");
            printf("%d:%04x <%s>:\n", cs, ip, name ? name : "no name");
            /* don't mark far functions—we can't reliably detect them
             * because of "push cs", and they should be evident anyway. */
        }

        ip += print_ne_instr(seg, ip, buffer, out);
        printf("%s\n", out);
    }
    putchar('\n');
}

static void print_data(const struct segment *seg) {
    word ip;    /* well, not really ip */

    for (ip = 0; ip < seg->length; ip += 16) {
        byte row[16];
        int len = (seg->length-ip >= 16) ? 16 : (seg->length-ip);
        int i;

        fseek(f, seg->start+ip, SEEK_SET);
        fread(row, sizeof(byte), len, f);

        printf("%3d:%04x", seg->cs, ip);
        for (i=0; i<16; i++) {
            if (i < len)
                printf(" %02x", row[i]);
            else
                printf("   ");
        }
        printf("  ");
        for (i=0; i<len; i++){
                if ((row[i] >= ' ') && (row[i] <= '~'))
                    putchar(row[i]);
                else
                    putchar('.');
        }
        putchar('\n');
    }
    putchar('\n');
}

static void scan_segment(word cs, word ip) {
    struct segment *seg = &segments[cs-1];

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
        fseek(f, seg->start+ip, SEEK_SET);
        memset(buffer, 0, sizeof(buffer));
        if ((unsigned) seg->length-ip < sizeof(buffer))
            fread(buffer, 1, seg->length-ip, f);
        else
            fread(buffer, 1, sizeof(buffer), f);
        instr_length = get_instr(ip, buffer, &instr, seg->flags & 0x2000);

        /* mark the bytes */
        seg->instr_flags[ip] |= INSTR_VALID;
        for (i = ip; i < ip+instr_length && i < seg->min_alloc; i++) seg->instr_flags[i] |= INSTR_SCANNED;

        if (i < ip+instr_length && i == seg->min_alloc) break;

        /* handle conditional and unconditional jumps */
        if (instr.op.arg0 == PTR32) {
            for (i = ip; i < ip+instr_length; i++) {
                if (seg->instr_flags[i] & INSTR_RELOC) {
                    const struct reloc *r = get_reloc(cs, i, seg->reloc_table, seg->reloc_count);
                    const struct segment *tseg;

                    if (!r) break;
                    tseg = &segments[r->target_segment-1];

                    if (r->type != 0) break;

                    if (r->size == 3) {
                        /* 32-bit relocation on 32-bit pointer */
                        tseg->instr_flags[r->target_offset] |= INSTR_FAR;
                        if (!strcmp(instr.op.name, "call"))
                            tseg->instr_flags[r->target_offset] |= INSTR_FUNC;
                        else
                            tseg->instr_flags[r->target_offset] |= INSTR_JUMP;
                        scan_segment(r->target_segment, r->target_offset);
                    } else if (r->size == 2) {
                        /* segment relocation on 32-bit pointer */
                        tseg->instr_flags[instr.arg0] |= INSTR_FAR;
                        if (!strcmp(instr.op.name, "call"))
                            tseg->instr_flags[instr.arg0] |= INSTR_FUNC;
                        else
                            tseg->instr_flags[instr.arg0] |= INSTR_JUMP;
                        scan_segment(r->target_segment, instr.arg0);
                    }

                    break;
                }
            }
        } else if (instr.op.flags & OP_BRANCH) {
            /* near relative jump, loop, or call */
            if (!strcmp(instr.op.name, "call"))
                seg->instr_flags[instr.arg0] |= INSTR_FUNC;
            else
                seg->instr_flags[instr.arg0] |= INSTR_JUMP;

            /* scan it */
            scan_segment(cs, instr.arg0);
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
    if (flags & 0x0002)
        strcat(buffer, ", allocated");
    if (flags & 0x0004)
        strcat(buffer, ", loaded");
    if (flags & 0x0008)
        strcat(buffer, ", iterated");
        
    if (flags & 0x0010)
        strcat(buffer, ", moveable");
    if (flags & 0x0020)
        strcat(buffer, ", shareable");
    if (flags & 0x0040)
        strcat(buffer, ", preload");
    if (flags & 0x0080)
        strcat(buffer, (flags & 0x0001) ? ", read-only" : ", execute-only");
    if (flags & 0x0100)
        strcat(buffer, ", has relocation data");

    /* there's still an unidentified flag 0x0400 which appears in all of my testcases.
     * but WINE doesn't know what it is, so... */
    if (flags & 0x0800)
        strcat(buffer, ", self-loading");
    if (flags & 0x1000)
        strcat(buffer, ", discardable");
    if (flags & 0x2000)
        strcat(buffer, ", 32-bit");

    if (flags & 0xc608)
        sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0xc608);
    printf("    Flags: 0x%04x (%s)\n", flags, buffer);
}

static void read_reloc(const struct segment *seg, struct reloc *r) {
    byte size = read_byte();
    byte type = read_byte();
    word offset = read_word();
    word module = read_word(); /* or segment */
    word ordinal = read_word(); /* or offset */

    word offset_cursor;
    word next;

    memset(r, 0, sizeof(*r));

    r->size = size;
    r->type = type & 3;

    if ((type & 3) == 0) {
        /* internal reference */
        char *name;

        if (module == 0xff) {
            r->target_segment = entry_table[ordinal-1].segment;
            r->target_offset = entry_table[ordinal-1].offset;
        } else {
            r->target_segment = module;
            r->target_offset = ordinal;
        }

        /* grab the name, if we can */
        if ((name = get_entry_name(r->target_segment, r->target_offset)))
            r->text = name;
    } else if ((type & 3) == 1) {
        /* imported ordinal */

        r->target_segment = module;
        r->target_offset = ordinal;
    } else if ((type & 3) == 2) {
        /* imported name */
        r->target_segment = module;
        r->target_offset = ordinal;
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

        fseek(f, seg->start+offset_cursor, SEEK_SET);
        next = read_word();
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

        fseek(f, seg->start+offset_cursor, SEEK_SET);
        next = read_word();
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

void print_segments(word count, word align, word entry_cs, word entry_ip) {
    unsigned i, seg;

    segments = malloc(count * sizeof(struct segment));

    for (seg = 0; seg < count; seg++) {
        segments[seg].cs = seg+1;
        segments[seg].start = read_word() << align;
        segments[seg].length = read_word();
        segments[seg].flags = read_word();
        segments[seg].min_alloc = read_word();

        /* Use min_alloc rather than length because data can "hang over". */
        segments[seg].instr_flags = calloc(segments[seg].min_alloc, sizeof(byte));
    }

    /* First pass: just read the relocation data */
    for (seg = 0; seg < count; seg++) {
        if (segments[seg].flags & 0x0100) {
            fseek(f, segments[seg].start + segments[seg].length, SEEK_SET);
            segments[seg].reloc_count = read_word();
            segments[seg].reloc_table = malloc(segments[seg].reloc_count * sizeof(struct reloc));

            for (i = 0; i < segments[seg].reloc_count; i++) {
                fseek(f, segments[seg].start + segments[seg].length + 2 + (i*8), SEEK_SET);
                read_reloc(&segments[seg], &segments[seg].reloc_table[i]);
            }
        } else {
            segments[seg].reloc_count = 0;
            segments[seg].reloc_table = NULL;
        }
    }

    /* Second pass: scan entry points (we have to do this after we read
     * relocation data for all segments.) */
    for (i = 0; i < entry_count; i++) {

        /* don't scan exported values */
        if (entry_table[i].segment == 0 ||
            entry_table[i].segment == 0xfe) continue;

        /* or values that live in data segments */
        if (segments[entry_table[i].segment-1].flags & 0x0001) continue;

        /* Annoyingly, data can be put in code segments, and without any
         * apparent indication that it is not code. As a dumb heuristic,
         * only scan exported entries—this won't work universally, and it
         * may potentially miss private entries, but it's better than nothing. */
        if (!(entry_table[i].flags & 1)) continue;

        scan_segment(entry_table[i].segment, entry_table[i].offset);
        segments[entry_table[i].segment-1].instr_flags[entry_table[i].offset] |= INSTR_FUNC;
    }

    /* and don't forget to scan the program entry point */
    if (entry_cs == 0 && entry_ip == 0) {
        /* do nothing */
    } else if (entry_ip >= segments[entry_cs-1].length) {
        /* see note above under relocations */
        warn("Entry point %d:%04x exceeds segment length (%04x)\n", entry_cs, entry_ip, segments[seg].length);
    } else {
        segments[entry_cs-1].instr_flags[entry_ip] |= INSTR_FUNC;
        scan_segment(entry_cs, entry_ip);
    }

    /* Final pass: print data */
    for (seg = 0; seg < count; seg++) {
        printf("Segment %d (start = 0x%lx, length = 0x%x, minimum allocation = 0x%x):\n",
            seg+1, segments[seg].start, segments[seg].length,
            segments[seg].min_alloc ? segments[seg].min_alloc : 65536);
        print_segment_flags(segments[seg].flags);

        if (segments[seg].flags & 0x0001) {
            /* FIXME: We should at least make a special note of entry points. */
            /* FIXME #2: Data segments can still have relocations... */
            print_data(&segments[seg]);
        } else {
            /* like objdump, print the whole code segment like a data segment */
            if (opts & FULL_CONTENTS)
                print_data(&segments[seg]);
            print_disassembly(&segments[seg]);
        }

        /* and free our segment per-segment data */
        free_reloc(segments[seg].reloc_table, segments[seg].reloc_count);
        free(segments[seg].instr_flags);
    }

    free(segments);
}
