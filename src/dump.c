/*
 * Entry point of the "dump" program
 *
 * Copyright 2017-2020 Zebediah Figura
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

#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "semblance.h"

static void dump_file(char *file){
    struct stat st;
    word magic;
    long offset = 0;
    int fd;

    if ((fd = open(file, O_RDONLY)) < 0) {
        perror("Cannot open %s");
        return;
    }

    if (fstat(fd, &st) < 0)
    {
        perror("Cannot stat %s");
        return;
    }

    if ((map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("Cannot map %s");
        return;
    }

    magic = read_word(0);

    printf("File: %s\n", file);
    if (magic == 0x5a4d){ /* MZ */
        offset = read_dword(0x3c);
        magic = read_word(offset);

        if (magic == 0x4550)
            dumppe(offset);
        else if (magic == 0x454e)
            dumpne(offset);
        else
            dumpmz();
    } else
        fprintf(stderr, "File format not recognized\n");

    return;
}

static const char help_message[] =
"dump: tool to disassemble and print information from executable files.\n"
"Usage: dump [options] <file(s)>\n"
"Available options:\n"
"\t-a, --resource[=filter]              Print embedded resources.\n"
"\t-c, --compilable                     Produce output that can be compiled.\n"
"\t-C, --demangle                       Demangle C++ function names.\n"
"\t-d, --disassemble                    Print disassembled machine code.\n"
"\t-e, --exports                        Print exported functions.\n"
"\t-f, --file-headers                   Print contents of the file header.\n"
"\t-h, --help                           Display this help message.\n"
"\t-i, --imports                        Print imported modules.\n"
"\t-M, --disassembler-options=[...]     Extended options for disassembly.\n"
"\t\tatt        Alias for `gas'.\n"
"\t\tgas        Use GAS syntax for disassembly.\n"
"\t\tintel      Alias for `masm'.\n"
"\t\tmasm       Use MASM syntax for disassembly.\n"
"\t\tnasm       Use NASM syntax for disassembly.\n"
"\t-o, --specfile                       Create a specfile from exports.\n"
"\t-s, --full-contents                  Display full contents of all sections.\n"
"\t-v, --version                        Print the version number of semblance.\n"
"\t-x, --all-headers                    Print all headers.\n"
"\t--no-show-addresses                  Don't print instruction addresses.\n"
"\t--no-show-raw-insn                   Don't print raw instruction hex code.\n"
"\t--pe-rel-addr=[y/n]                  Use relative addresses for PE files.\n"
;

static const struct option long_options[] = {
    {"resource",                optional_argument,  NULL, 'a'},
    {"compilable",              no_argument,        NULL, 'c'},
    {"demangle",                no_argument,        NULL, 'C'},
    {"disassemble",             no_argument,        NULL, 'd'},
    {"disassemble-all",         no_argument,        NULL, 'D'},
    {"exports",                 no_argument,        NULL, 'e'},
    {"file-headers",            no_argument,        NULL, 'f'},
//  {"gas",                     no_argument,        NULL, 'G'},
    {"help",                    no_argument,        NULL, 'h'},
    {"imports",                 no_argument,        NULL, 'i'},
//  {"masm",                    no_argument,        NULL, 'I'}, /* for "Intel" */
    {"disassembler-options",    required_argument,  NULL, 'M'},
//  {"nasm",                    no_argument,        NULL, 'N'},
    {"specfile",                no_argument,        NULL, 'o'},
    {"full-contents",           no_argument,        NULL, 's'},
    {"version",                 no_argument,        NULL, 'v'},
    {"all-headers",             no_argument,        NULL, 'x'},
    {"no-show-raw-insn",        no_argument,        NULL, NO_SHOW_RAW_INSN},
    {"no-prefix-addresses",     no_argument,        NULL, NO_SHOW_ADDRESSES},
    {"pe-rel-addr",             required_argument,  NULL, 0x80},
    {0}
};

int main(int argc, char *argv[]){
    int opt;

    mode = 0;
    opts = 0;
    asm_syntax = NASM;

    while ((opt = getopt_long(argc, argv, "a::cCdDefhiM:osvx", long_options, NULL)) >= 0){
        switch (opt) {
        case NO_SHOW_RAW_INSN:
            opts |= NO_SHOW_RAW_INSN;
            break;
        case NO_SHOW_ADDRESSES:
            opts |= NO_SHOW_ADDRESSES;
            break;
        case 'a': /* dump resources only */
        {
            mode |= DUMPRSRC;
            if (optarg){
                const char *p = optarg;
                while (*p == ' ' || *p == '=') ++p;
                resource_filters = realloc(resource_filters, (resource_filters_count + 1) * sizeof(*resource_filters));
                resource_filters[resource_filters_count++] = strdup(p);
            }
            break;
        }
        case 'c': /* compilable */
            opts |= COMPILABLE|NO_SHOW_ADDRESSES|NO_SHOW_RAW_INSN;
            break;
        case 'C': /* demangle */
            opts |= DEMANGLE;
            break;
        case 'd': /* disassemble only */
            mode |= DISASSEMBLE;
            break;
        case 'D': /* disassemble all */
            opts |= DISASSEMBLE_ALL;
            break;
        case 'e': /* exports */
            mode |= DUMPEXPORT;
            break;
        case 'f': /* dump header only */
            mode |= DUMPHEADER;
            break;
        case 'h': /* help */
            printf(help_message);
            return 0;
        case 'i': /* imports */
            mode |= DUMPIMPORT;
            break;
        case 'M': /* additional options */
            if (!strcmp(optarg, "att") || !strcmp(optarg, "gas"))
                asm_syntax = GAS;
            else if (!strcmp(optarg, "intel") || !strcmp(optarg, "masm"))
                asm_syntax = MASM;
            else if (!strcmp(optarg, "nasm"))
                asm_syntax = NASM;
            else {
                fprintf(stderr, "Unrecognized disassembly option `%s'.\n", optarg);
                return 1;
            }
            break;
        case 'o': /* make a specfile */
            mode = SPECFILE;
            break;
        case 'v': /* version */
            printf("semblance version " VERSION "\n");
            return 0;
        case 's': /* full contents */
            opts |= FULL_CONTENTS;
            break;
        case 'x': /* all headers */
            mode |= DUMPHEADER | DUMPEXPORT | DUMPIMPORT;
            break;
        case 0x80:
            if (optarg[0] == '1' || optarg[0] == 'y' || optarg[0] == 'Y')
                pe_rel_addr = 1;
            else if (optarg[0] == '0' || optarg[0] == 'n' || optarg[0] == 'N')
                pe_rel_addr = 0;
            else {
                fprintf(stderr, "Unrecognized --pe-rel-addr option `%s'.\n", optarg);
                return 1;
            }
            break;
        default:
            fprintf(stderr, "Usage: dumpne [options] <file>\n");
            return 1;
        }
    }

    if (mode == 0)
        mode = ~0;

    if (optind == argc)
        printf(help_message);

    while (optind < argc){
        dump_file(argv[optind++]);
        if (optind < argc)
            printf("\n\n");
    }

    return 0;
}
