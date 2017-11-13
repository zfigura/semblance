#include <string.h>
#include <getopt.h>

#include "semblance.h"

static void dump_file(char *file){
    word magic;
    long offset_ne = 0;

    fprintf(stderr, "%s\n", file);

    f = fopen(file, "r");
    if (!f) {
        perror("Cannot open %s");
        return;
    }

    magic = read_word();

    if (magic == 0x5a4d){ /* MZ */
        fseek(f, 0x3c, SEEK_SET);
        offset_ne = read_dword();
        fseek(f, offset_ne, SEEK_SET);
        magic = read_word();

        if (magic == 0x4550)
            fprintf(stderr, "PE support not yet implemented\n");
        else if (magic == 0x454e)
            dumpne(offset_ne);
        else
            dumpmz();
    } else
        fprintf(stderr, "File format not recognized\n");

    fclose(f);
    fflush(stdout);
    return;
}

static const char help_message[] =
"dump: tool to disassemble and print information from executable files.\n"
"Usage: dump [options] <file(s)>\n"
"Available options:\n"
"\t-a, --resource                       Print embedded resources.\n"
"\t-c, --compilable                     Produce output that can be compiled.\n"
"\t                                     Equivalent to specifying all of the following:\n"
"\t--no-show-addresses                  Don't print instruction addresses.\n"
"\t--no-show-jump-target                Don't mark instructions that are jumped to.\n"
"\t--no-show-raw-insn                   Don't print raw instruction hex code.\n"
"\t-C, --demangle                       Demangle C++ function names.\n"
"\t-d, --disassemble                    Print disassembled machine code.\n"
"\t-f, --file-headers                   Print contents of the file header.\n"
"\t-h, --help                           Display this help message.\n"
"\t-M, --disassembler-options=[...]     Extended options for disassembly.\n"
"\t\tatt        Alias for `gas'.\n"
"\t\tgas        Use GAS syntax for disassembly.\n"
"\t\tintel      Alias for `masm'.\n"
"\t\tmasm       Use MASM syntax for disassembly.\n"
"\t\tnasm       Use NASM syntax for disassembly.\n"
"\t-o, --specfile                       Create a specfile from exports.\n"
"\t-s, --full-contents                  Display all information (default).\n"
"\t-v, --version                        Print the version number of dumpne.\n"
;

static const struct option long_options[] = {
    {"resource",                optional_argument,  NULL, 'a'},
    {"compilable",              no_argument,        NULL, 'c'},
    {"demangle",                no_argument,        NULL, 'C'},
    {"disassemble",             no_argument,        NULL, 'd'},
    {"disassemble-all",         no_argument,        NULL, 'D'},
    {"file-headers",            no_argument,        NULL, 'f'},
//  {"gas",                     no_argument,        NULL, 'G'},
    {"help",                    no_argument,        NULL, 'h'},
//  {"masm",                    no_argument,        NULL, 'I'}, /* for "Intel" */
    {"disassembler-options",    required_argument,  NULL, 'M'},
//  {"nasm",                    no_argument,        NULL, 'N'},
    {"specfile",                no_argument,        NULL, 'o'},
    {"full-contents",           no_argument,        NULL, 's'},
    {"version",                 no_argument,        NULL, 'v'},
    {"no-show-jump-target",     no_argument,        NULL, NO_SHOW_JUMP_TARGET},
    {"no-show-raw-insn",        no_argument,        NULL, NO_SHOW_RAW_INSN},
    {"no-prefix-addresses",     no_argument,        NULL, NO_SHOW_ADDRESSES},
    {0}
};

int main(int argc, char *argv[]){
    int opt;

    mode = 0;
    opts = 0;
    asm_syntax = NASM;

    while ((opt = getopt_long(argc, argv, "a::cCdDfhM:osv", long_options, NULL)) >= 0){
        switch (opt) {
        case NO_SHOW_RAW_INSN:
            opts |= NO_SHOW_RAW_INSN;
            break;
        case NO_SHOW_ADDRESSES:
            opts |= NO_SHOW_ADDRESSES;
            break;
        case NO_SHOW_JUMP_TARGET:
            opts |= NO_SHOW_JUMP_TARGET;
            break;
        case 'a': /* dump resources only */
        {
            int ret;
            char type[256];
            unsigned i;
            mode |= DUMPRSRC;
            if (optarg){
                if (resource_count == MAXARGS){
                    fprintf(stderr, "Too many resources specified\n");
                    return 1;
                }
                if (0 >= (ret = sscanf(optarg, "%s %hu", type, &resource_id[resource_count])))
                    /* empty argument, so do nothing */
                    break;
                if (ret == 1)
                    resource_id[resource_count] = 0;

                /* todo(?): let the user specify string [exe-defined] types, and also
                 * string id names */
                if (!sscanf(type, "%hu", &resource_type[resource_count])){
                    resource_type[resource_count] = 0;
                    for (i=1;i<rsrc_types_count;i++){
                        if(rsrc_types[i] && !strcasecmp(rsrc_types[i], type)){
                            resource_type[resource_count] = 0x8000|i;
                            break;
                        }
                    }
                    if(!resource_type[resource_count]){
                        fprintf(stderr, "Unrecognized resource type '%s'\n", type);
                        return 1;
                    }
                }
                resource_count++;
            }
            break;
        }
        case 'c': /* compilable */
            opts |= NO_SHOW_RAW_INSN|NO_SHOW_ADDRESSES|NO_SHOW_JUMP_TARGET;
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
        case 'f': /* dump header only */
            mode |= DUMPHEADER;
            break;
        case 'h': /* help */
            printf(help_message);
            return 0;
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
        case 's': /* dump everything */
            mode |= DUMPHEADER | DUMPRSRC | DISASSEMBLE;
            break;
        case 'v': /* version */
            printf("dump version 1.0\n");
        default: /* '?' */
            fprintf(stderr, "Usage: dumpne [options] <file>\n");
            return 1;
        }
    }

    if (mode == 0)
        mode = ~0;

    if (optind == argc)
        printf("No input given\n");

    while (optind < argc){
        dump_file(argv[optind++]);
        if (optind < argc)
            printf("\n\n");
    }
}
