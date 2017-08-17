/* Functions for dumping NE code and data segments */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "semblance.h"
#include "ne.h"
#include "x86_instr.h"

/* flags relating to specific instructions */
#define INSTR_SCANNED   0x01    /* byte has been scanned */
#define INSTR_VALID     0x02    /* byte begins an instruction */
#define INSTR_JUMP      0x04    /* instruction is jumped to */
#define INSTR_FUNC      0x08    /* instruction begins a function */
#define INSTR_FAR       0x10    /* instruction is target of far call/jmp */
#define INSTR_RELOC     0x20    /* byte has relocation data */

#ifdef USE_WARN
#define warn_at(...) \
    do { fprintf(stderr, "Warning: %d:%04x: ", cs, ip); \
        fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define warn_at(...)
#endif

typedef struct {
    byte size;
    byte type;
    word offset_count;
    word *offsets;
    word target_segment;
    word target_offset;
    char *text;
} reloc;

typedef struct {
    word cs;
    long start;
    word length;
    word flags;
    word min_alloc;
    byte *instr_flags;
    reloc *reloc_table;
    word reloc_count;
} segment;

/* global segment list */
static segment *segments;

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
static const reloc *get_reloc(word cs, word ip, const reloc *reloc_data, word reloc_count) {
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
char *get_imported_name(word module, word ordinal) {
    unsigned i;
    for (i=0; i<import_module_table[module-1].export_count; i++) {
        if (import_module_table[module-1].exports[i].ordinal == ordinal)
            return import_module_table[module-1].exports[i].name;
    }
    return NULL;
}

static const char seg16[6][3] = {
    "es", "cs", "ss", "ds", "fs", "gs"
};

/* Returns the number of bytes processed (same as get_instr). */
int print_instr(word cs, word ip, const byte *flags, byte *p, char *out, const reloc *reloc_data, word reloc_count, int is32) {
    instr_info instr = {0};
    char arg0[32] = {0}, arg1[32] = {0}, arg2[32] = {0};
    byte usedmem = 0;
    unsigned len;

    char *outp = out;
    unsigned i;
    char *comment = NULL;

    out[0] = 0;

    len = get_instr(cs, ip, p, &instr, is32);

    print_arg(cs, ip, arg0, instr.arg0, instr.op.arg0, &instr, &usedmem);
    print_arg(cs, ip, arg1, instr.arg1, instr.op.arg1, &instr, &usedmem);
    if (instr.op.flags & OP_ARG2_IMM)
        print_arg(cs, ip, arg2, instr.arg2, IMM, &instr, &usedmem);
    else if (instr.op.flags & OP_ARG2_IMM8)
        print_arg(cs, ip, arg2, instr.arg2, IMM8, &instr, &usedmem);
    else if (instr.op.flags & OP_ARG2_CL)
        print_arg(cs, ip, arg2, instr.arg2, CL, &instr, &usedmem);

    /* if we have relocations, discard one of the above and replace it */
    for (i=ip; i<ip+len; i++) {
        if (flags[i] & INSTR_RELOC) {
            const reloc *r = get_reloc(cs, i, reloc_data, reloc_count);
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

    /* modify the instruction name if appropriate */
    if ((instr.op.flags & OP_STACK) && (instr.prefix & PREFIX_OP32)) {
        if (instr.op.size == 16)
            strcat(instr.op.name, "w");
        else
            strcat(instr.op.name, (asm_syntax == GAS) ? "l" : "d");
    } else if ((instr.op.flags & OP_STRING) && asm_syntax != GAS) {
        if (instr.op.size == 8)
            strcat(instr.op.name, "b");
        else if (instr.op.size == 16)
            strcat(instr.op.name, "w");
        else if (instr.op.size == 32)
            strcat(instr.op.name, "d");
    } else if (instr.op.opcode == 0x98 && (instr.prefix & PREFIX_OP32))
        strcpy(instr.op.name, "cwde");
    else if (instr.op.opcode == 0x99 && (instr.prefix & PREFIX_OP32))
        strcpy(instr.op.name, "cdq");
    else if (instr.op.opcode == 0xE3 && (instr.prefix & PREFIX_ADDR32))
        strcpy(instr.op.name, "jecxz");
    else if (instr.op.opcode == 0xD4 && instr.arg0 == 10) {
        strcpy(instr.op.name, "aam");
        arg0[0] = 0;
    } else if (instr.op.opcode == 0xD5 && instr.arg0 == 10) {
        strcpy(instr.op.name, "aad");
        arg0[0] = 0;
    } else if (asm_syntax == GAS) {
        if (instr.op.flags & OP_FAR) {
            memmove(instr.op.name+1, instr.op.name, strlen(instr.op.name));
            instr.op.name[0] = 'l';
        } else if (instr.op.opcode == 0x0FB6)   /* movzx */
            strcpy(instr.op.name, (instr.op.size == 32) ? "movzbl" : "movzbw");
        else if (instr.op.opcode == 0x0FB7)     /* movzx */
            strcpy(instr.op.name, (instr.op.size == 32) ? "movzwl" : "movzww");
        else if (instr.op.opcode == 0x0FBE)     /* movsx */
            strcpy(instr.op.name, (instr.op.size == 32) ? "movsbl" : "movsbw");
        else if (instr.op.opcode == 0x0FBF)     /* movsx */
            strcpy(instr.op.name, (instr.op.size == 32) ? "movswl" : "movsww");
        else if (instr.op.arg0 != REG &&
                 instr.op.arg1 != REG &&
                 instr.modrm_disp != DISP_REG) {
            if ((instr.op.flags & OP_LL) == OP_LL)
                strcat(instr.op.name, "ll");
            else if (instr.op.flags & OP_S)
                strcat(instr.op.name, "s");
            else if (instr.op.flags & OP_L)
                strcat(instr.op.name, "l");
            else if (instr.op.size == 80)
                strcat(instr.op.name, "t");
            else if (instr.op.size == 8)
                strcat(instr.op.name, "b");
            else if (instr.op.size == 16)
                strcat(instr.op.name, "w");
            else if (instr.op.size == 32)
                strcat(instr.op.name, "l");
        }
    }

    /* okay, now we begin dumping */
    outp += sprintf(outp, "%4d.%04x:\t", cs, ip);

    for (i=0; i<len && i<7; i++) {
        outp += sprintf(outp, "%02x ", p[i]);
    }
    for (; i<8; i++) {
        outp += sprintf(outp, "   ");
    }

    /* mark instructions that are jumped to */
    if (flags[ip] & INSTR_JUMP) {
        outp[-1] = '>';
        if (flags[ip] & INSTR_FAR) {
            outp[-2] = '>';
        }
    }

    /* print prefixes, including (fake) prefixes if ours are invalid */
    if (instr.prefix & PREFIX_SEG_MASK) {
        /* note: is it valid to use overrides with lods and outs? */
        if (!usedmem || (instr.op.arg0 == ESDI || (instr.op.arg1 == ESDI && instr.op.arg0 != DSSI))) {  /* can't be overridden */
            warn_at("Segment prefix %s used with opcode 0x%02x %s\n", seg16[(instr.prefix & PREFIX_SEG_MASK)-1], instr.op.opcode, instr.op.name);
            outp += sprintf(outp, "%s ", seg16[(instr.prefix & PREFIX_SEG_MASK)-1]);
        }
    }
    if ((instr.prefix & PREFIX_ADDR32) && (asm_syntax == NASM) && (instr.op.flags & OP_STRING)) {
        outp += sprintf(outp, "a32 ");
    } else if ((instr.prefix & PREFIX_ADDR32) && !usedmem && instr.op.opcode != 0xE3) { /* jecxz */
        warn_at("Address-size prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, (asm_syntax == GAS) ? "addr32 " : "a32 "); /* fixme: how should MASM print it? */
    }
    if (instr.prefix & PREFIX_LOCK) {
        if(!(instr.op.flags & OP_LOCK))
            warn_at("lock prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, "lock ");
    }
    if (instr.prefix & PREFIX_REPNE) {
        if(!(instr.op.flags & OP_REPNE))
            warn_at("repne prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, "repne ");
    }
    if (instr.prefix & PREFIX_REPE) {
        if(!(instr.op.flags & OP_REPE))
            warn_at("repe prefix used with opcode 0x%02x %s\n", instr.op.opcode, instr.op.name);
        outp += sprintf(outp, (instr.op.flags & OP_REPNE) ? "repe ": "rep ");
    }

    outp += sprintf(outp, "%s", instr.op.name);

    if (arg0[0] || arg1[0])
        outp += sprintf(outp,"\t");

    if (asm_syntax == GAS) {
        /* fixme: are all of these orderings correct? */
        if (arg1[0])
            outp += sprintf(outp, "%s,", arg1);
        if (arg0[0])
            outp += sprintf(outp, "%s", arg0);
        if (arg2[0])
            outp += sprintf(outp, ",%s", arg2);
    } else {
        if (arg0[0])
            outp += sprintf(outp, "%s", arg0);
        if (arg0[0] && arg1[0])
            outp += sprintf(outp, ", ");
        if (arg1[0])
            outp += sprintf(outp, "%s", arg1);
        if (arg2[0])
            outp += sprintf(outp, ", %s", arg2);
    }
    if (comment) {
        outp += sprintf(outp, "\t<%s>", comment);
    }

    /* if we have more than 7 bytes on this line, wrap around */
    if (len > 7) {
        if (asm_syntax == GAS)
            outp += sprintf(outp, "\n%4d.%04x:\t", cs, ip+7);
        else
            outp += sprintf(outp, "\n\t\t");
        for (i=7; i<len; i++) {
            outp += sprintf(outp, "%02x ", p[i]);
        }
        outp--; /* trailing space */
    }

    return len;
};

static void print_disassembly(const segment *seg) {
    const word cs = seg->cs;
    word ip = 0;

    byte buffer[MAX_INSTR];
    char out[256];
    int is32 = (seg->flags & 0x2000);

    while (ip < seg->length) {
        fseek(f, seg->start+ip, SEEK_SET);

        /* find a valid instruction */
        if (!(seg->instr_flags[ip] & INSTR_VALID)) {
            if (mode & DISASSEMBLE_ALL) {
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

        ip += print_instr(cs, ip, seg->instr_flags, buffer, out, seg->reloc_table, seg->reloc_count, is32);
        printf("%s\n", out);
    }
}

static void scan_segment(word cs, word ip) {
    segment *seg = &segments[cs-1];

    byte buffer[MAX_INSTR];
    instr_info instr;
    int instr_length;
    int i;

    if (ip >= seg->length) {
        warn_at("Attempt to scan past end of segment.\n");
        return;
    }

    if ((seg->instr_flags[ip] & (INSTR_VALID|INSTR_SCANNED)) == INSTR_SCANNED) {
        warn_at("Attempt to scan byte that does not begin instruction.\n");
    }

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
        instr_length = get_instr(cs, ip, buffer, &instr, seg->flags & 0x2000);

        /* mark the bytes */
        seg->instr_flags[ip] |= INSTR_VALID;
        for (i = 0; i < instr_length; i++) seg->instr_flags[ip+i] |= INSTR_SCANNED;

        /* note: it *is* valid for the last instruction to "hang over" the end
         * of the segment, so don't break here. */

        /* handle conditional and unconditional jumps */
        if (instr.op.arg0 == PTR32) {
            for (i = ip; i < ip+instr_length; i++) {
                if (seg->instr_flags[i] & INSTR_RELOC) {
                    const reloc *r = get_reloc(cs, i, seg->reloc_table, seg->reloc_count);
                    const segment *tseg = &segments[r->target_segment-1];

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

            if (!strcmp(instr.op.name, "jmp"))
                return;
        } else if (instr.op.arg0 == REL8 || instr.op.arg0 == REL16) {
            /* near relative jump, loop, or call */
            if (!strcmp(instr.op.name, "call"))
                seg->instr_flags[instr.arg0] |= INSTR_FUNC;
            else
                seg->instr_flags[instr.arg0] |= INSTR_JUMP;

            /* scan it */
            scan_segment(cs, instr.arg0);

            if (!strcmp(instr.op.name, "jmp"))
                return;
        } else if (!strcmp(instr.op.name, "jmp")) {
            /* i.e. 0xFF jump to memory */
            return;
        } else if (!strcmp(instr.op.name, "ret")) {
            return;
        }

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

static void read_reloc(reloc *r, const long start, const word length) {
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
        if (offset_cursor >= length) {
            warn("Offset %04x exceeds segment length (%04x).\n", offset_cursor, length);
            break;
        }

        r->offset_count++;

        fseek(f, start+offset_cursor, SEEK_SET);
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
        if (offset_cursor >= length) {
            break;
        }

        r->offsets[r->offset_count] = offset_cursor;
        r->offset_count++;

        fseek(f, start+offset_cursor, SEEK_SET);
        next = read_word();
        if (type & 4)
            offset_cursor += next;
        else
            offset_cursor = next;
    } while (next < 0xFFFb);
}

void free_reloc(reloc *reloc_data, word reloc_count) {
    int i;
    for (i = 0; i < reloc_count; i++) {
        free(reloc_data[i].offsets);
    }

    free(reloc_data);
}

void print_segments(word count, word align, word entry_cs, word entry_ip) {
    unsigned i, seg;

    segments = malloc(count * sizeof(segment));

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
        fseek(f, segments[seg].start + segments[seg].length, SEEK_SET);
        segments[seg].reloc_count = read_word();
        segments[seg].reloc_table = malloc(segments[seg].reloc_count * sizeof(reloc));

        for (i = 0; i < segments[seg].reloc_count; i++) {
            int o;
            fseek(f, segments[seg].start + segments[seg].length + 2 + (i*8), SEEK_SET);
            read_reloc(&segments[seg].reloc_table[i], segments[seg].start, segments[seg].length);
            for (o = 0; o < segments[seg].reloc_table[i].offset_count; o++) {
                segments[seg].instr_flags[segments[seg].reloc_table[i].offsets[o]] |= INSTR_RELOC;
            }
        }
    }

    /* Second pass: scan entry points (we have to do this after we read
     * relocation data for all segments.) */
    for (i = 0; i < entry_count; i++) {

        /* don't scan exported values */
        if (entry_table[i].segment == 0xfe) continue;

        /* Annoyingly, data can be put in code segments, and without any
         * apparent indication that it is not code. As a dumb heuristic,
         * only scan exported entries—this won't work universally, and it
         * may potentially miss private entries, but it's better than nothing. */
        if (!(entry_table[i].flags & 1)) continue;

        scan_segment(entry_table[i].segment, entry_table[i].offset);
        segments[entry_table[i].segment-1].instr_flags[entry_table[i].offset] |= INSTR_FUNC;
    }

    /* and don't forget to scan the program entry point */
    if (entry_ip >= segments[entry_cs-1].length) {
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
            /* todo */
        } else {
            print_disassembly(&segments[seg]);
        }

        /* and free our segment per-segment data */
        free_reloc(segments[seg].reloc_table, segments[seg].reloc_count);
        free(segments[seg].instr_flags);
    }

    free(segments);
}
