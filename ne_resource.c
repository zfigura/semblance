/* Function(s) for dumping resources from NE files */

/* General TODO: add more sanity checks. In particular all of the times that
 * only one structure supposedly exists, we should check if the length/key/whatever
 * doesn't match anything and print an error if it doesn't. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "semblance.h"
#include "ne.h"

#pragma pack(1)

struct header_bitmap_info {
    dword biSize;           /* 00 */
    dword biWidth;          /* 04 */
    dword biHeight;         /* 08 */
    word  biPlanes;         /* 0c */
    word  biBitCount;       /* 0e */
    dword biCompression;    /* 10 */
    dword biSizeImage;      /* 14 */
    dword biXPelsPerMeter;  /* 18 */
    dword biYPelsPerMeter;  /* 1c */
    dword biClrUsed;        /* 20 */
    dword biClrImportant;   /* 24 */
};

STATIC_ASSERT(sizeof(struct header_bitmap_info) == 0x28);

static void print_string_resource(long ptr){
    char length;
    fseek(f, ptr, SEEK_SET);
    putchar('"');
    length = read_byte();
    while (length--)
        putchar(read_byte());
    putchar('"');
}

/* length-indexed */
static void print_escaped_string(long length){
    putchar('"');
    while (length--){
        char c = read_byte();
        if (c == '\t')
            printf("\\t");
        else if (c == '\n')
            printf("\\n");
        else if (c == '\r')
            printf("\\r");
        else if (c == '"')
            printf("\\\"");
        else if (c == '\\')
            printf("\\\\");
        else if (c >= ' ' && c <= '~')
            putchar(c);
        else
            printf("\\x%02hhx", c);
    }
    putchar('"');
}

/* null-terminated */
static void print_escaped_string0(void){
    char c;
    putchar('"');
    while ((c = read_byte())){
        if (c == '\t')
            printf("\\t");
        else if (c == '\n')
            printf("\\n");
        else if (c == '\r')
            printf("\\r");
        else if (c == '"')
            printf("\\\"");
        else if (c == '\\')
            printf("\\\\");
        else if (c >= ' ' && c <= '~')
            putchar(c);
        else
            printf("\\x%02hhx", c);
    }
    putchar('"');
}

static void print_timestamp(dword high, dword low){
    /* TODO */
};

const char *const rsrc_types[] = {
    0,
    "Cursor",            /* 1 */
    "Bitmap",            /* 2 */
    "Icon",              /* 3 */
    "Menu",              /* 4 */
    "Dialog box",        /* 5 */
    "String",            /* 6 */
    "Font directory",    /* 7 */
    "Font component",    /* 8 */
    "Accelerator table", /* 9 */
    "Resource data",     /* a */
    0,
    "Cursor directory",  /* c */
    0,
    "Icon directory",    /* e */
    0,
    "Version",           /* 10 */
    0
};
const size_t rsrc_types_count = sizeof(rsrc_types)/sizeof(rsrc_types[0]);

static const char *const rsrc_bmp_compression[] = {
    "none",                     /* 0 */
    "RLE (8 bpp)",              /* 1 */
    "RLE (4 bpp)",              /* 2 */
    "RGB bit field masks",      /* 3 */
    "JPEG", /* shouldn't occur?    4 */
    "PNG", /* shouldn't occur?     5 */
    "RGBA bit field masks",     /* 6 */
    0,
    0,
    0,
    0,
    "none (CMYK)",              /* 11 */
    "RLE (8 bpp, CMYK)",        /* 12 */
    "RLE (4 bpp, CMYK)",        /* 13 */
    0
};

/* todo: it is probably better just to fold this into the header, because
 * otherwise it loos like it is resource-specific. */
static void print_rsrc_flags(word flags){
    char buffer[1024];
    buffer[0] = 0;

    if (flags & 0x0010)
        strcat(buffer, ", moveable");
    if (flags & 0x0020)
        strcat(buffer, ", shareable");
    if (flags & 0x0040)
        strcat(buffer, ", preloaded");
    if (flags & 0xff8f)
        sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0xff8f);

    if(buffer[0])
        printf("    Flags: 0x%04x (%s)\n", flags, buffer+2);
    else
        printf("    Flags: 0x0000\n");
}

/* There are a lot of styles here and most of them would require longer
 * descriptions, so we're just going to use the C names.
 * Not all of these are dialog box-related, but I'm not going to try to
 * sort through them. */

static const char *const rsrc_dialog_style[] = {
    "DS_ABSALIGN",      /* 00000001 */
    "DS_SYSMODAL",      /* 00000002 */
    "DS_3DLOOK",        /* 00000004 */
    "DS_FIXEDSYS",      /* 00000008 */
    "DS_NOFAILCREATE",  /* 00000010 */
    "DS_LOCALEDIT",     /* 00000020 */
    "DS_SETFONT",       /* 00000040 */
    "DS_MODALFRAME",    /* 00000080 */
    "DS_NOIDLEMSG",     /* 00000100 */
    "DS_SETFOREGROUND", /* 00000200 */
    "DS_CONTROL",       /* 00000400 */
    "DS_CENTER",        /* 00000800 */
    "DS_CENTERMOUSE",   /* 00001000 */
    "DS_CONTEXTHELP",   /* 00002000 */
    "(unrecognized flag 0x00004000)",
    "DS_USEPIXELS",     /* 00008000 */
    "WS_TABSTOP",       /* 00010000 */
    "WS_GROUP",         /* 00020000 */
    "WS_THICKFRAME",    /* 00040000 */
    "WS_SYSMENU",       /* 00080000 */
    "WS_HSCROLL",       /* 00100000 */
    "WS_VSCROLL",       /* 00200000 */
    "WS_DLGFRAME",      /* 00400000 */
    "WS_BORDER",        /* 00800000 */
    "WS_MAXIMIZE",      /* 01000000 */
    "WS_CLIPCHILDREN",  /* 02000000 */
    "WS_CLIPSIBLINGS",  /* 04000000 */
    "WS_DISABLED",      /* 08000000 */
    "WS_VISIBLE",       /* 10000000 */
    "WS_MINIMIZE",      /* 20000000 */
    "WS_CHILD",         /* 40000000 */
    "WS_POPUP",         /* 80000000 */
    0
};

static void print_rsrc_dialog_style(dword flags){
    int i;
    char buffer[1024];
    buffer[0] = 0;

    for (i=0;i<32;i++){
        if (flags & (1<<i)){
            strcat(buffer, ", ");
            strcat(buffer, rsrc_dialog_style[i]);
        }
    }
    printf("    Style: %s\n", buffer+2);
}

static const char *const rsrc_button_type[] = {
    "BS_PUSHBUTTON",    /* 0 */
    "BS_DEFPUSHBUTTON", /* 1 */
    "BS_CHECKBOX",      /* 2 */
    "BS_AUTOCHECKBOX",  /* 3 */
    "BS_RADIOBUTTON",   /* 4 */
    "BS_3STATE",        /* 5 */
    "BS_AUTO3STATE",    /* 6 */
    "BS_GROUPBOX",      /* 7 */
    "BS_USERBUTTON",    /* 8 */
    "BS_AUTORADIOBUTTON", /* 9 */
    "BS_PUSHBOX",       /* 10 */
    "BS_OWNERDRAW",     /* 11 */
    "(unknown type 12)",
    "(unknown type 13)",
    "(unknown type 14)",
    "(unknown type 15)",
    0
};

static const char *const rsrc_edit_style[] = {
    0, 0,       /* type */
    "ES_MULTILINE",   /* 0004 */
    "ES_UPPERCASE",   /* 0008 */
    "ES_LOWERCASE",   /* 0010 */
    "ES_PASSWORD",    /* 0020 */
    "ES_AUTOVSCROLL", /* 0040 */
    "ES_AUTOHSCROLL", /* 0080 */
    "ES_NOHIDESEL",   /* 0100 */
    "ES_COMBO",       /* 0200 */
    "ES_OEMCONVERT",  /* 0400 */
    "ES_READONLY",    /* 0800 */
    "ES_WANTRETURN",  /* 1000 */
    "ES_NUMBER",      /* 2000 */
    "(unknown flag 0x4000)",
    "(unknown flag 0x8000)",
    0
};

static const char *const rsrc_static_type[] = {
    "SS_LEFT",          /* 0 */
    "SS_CENTER",        /* 1 */
    "SS_RIGHT",         /* 2 */
    "SS_ICON",          /* 3 */
    "SS_BLACKRECT",     /* 4 */
    "SS_GRAYRECT",      /* 5 */
    "SS_WHITERECT",     /* 6 */
    "SS_BLACKFRAME",    /* 7 */
    "SS_GRAYFRAME",     /* 8 */
    "SS_WHITEFRAME",    /* 9 */
    "SS_USERITEM",      /* 10 */
    "SS_SIMPLE",        /* 11 */
    "SS_LEFTNOWORDWRAP", /* 12 */
    "SS_OWNERDRAW",     /* 13 */
    "SS_BITMAP",        /* 14 */
    "SS_ENHMETAFILE",   /* 15 */
    "SS_ETCHEDHORZ",    /* 16 */
    "SS_ETCHEDVERT",    /* 17 */
    "SS_ETCHEDFRAME",   /* 18 */
    0
};

static const char *const rsrc_static_style[] = {
    0, 0, 0, 0, 0, /* type */
    "(unknown flag 0x0020)",
    "SS_REALSIZECONTROL", /* 0040 */
    "SS_NOPREFIX",        /* 0080 */
    "SS_NOTIFY",          /* 0100 */
    "SS_CENTERIMAGE",     /* 0200 */
    "SS_RIGHTJUST",       /* 0400 */
    "SS_REALSIZEIMAGE",   /* 0800 */
    "SS_SUNKEN",          /* 1000 */
    "SS_EDITCONTROL",     /* 2000 */
    0
};

static const char *const rsrc_listbox_style[] = {
    "LBS_NOTIFY",            /* 0001 */
    "LBS_SORT",              /* 0002 */
    "LBS_NOREDRAW",          /* 0004 */
    "LBS_MULTIPLESEL",       /* 0008 */
    "LBS_OWNERDRAWFIXED",    /* 0010 */
    "LBS_OWNERDRAWVARIABLE", /* 0020 */
    "LBS_HASSTRINGS",        /* 0040 */
    "LBS_USETABSTOPS",       /* 0080 */
    "LBS_NOINTEGRALHEIGHT",  /* 0100 */
    "LBS_MULTICOLUMN",       /* 0200 */
    "LBS_WANTKEYBOARDINPUT", /* 0400 */
    "LBS_EXTENDEDSEL",       /* 0800 */
    "LBS_DISABLENOSCROLL",   /* 1000 */
    "LBS_NODATA",            /* 2000 */
    "LBS_NOSEL",             /* 4000 */
    "LBS_COMBOBOX",          /* 8000 */
    0
};

static const char *const rsrc_combobox_style[] = {
    0, 0, /* type */
    0, 0, /* unknown */
    "CBS_OWNERDRAWFIXED",    /* 0010 */
    "CBS_OWNERDRAWVARIABLE", /* 0020 */
    "CBS_AUTOHSCROLL",       /* 0040 */
    "CBS_OEMCONVERT",        /* 0080 */
    "CBS_SORT",              /* 0100 */
    "CBS_HASSTRINGS",        /* 0200 */
    "CBS_NOINTEGRALHEIGHT",  /* 0400 */
    "CBS_DISABLENOSCROLL",   /* 0800 */
    0, /* unknown */
    "CBS_UPPERCASE",         /* 2000 */
    "CBS_LOWERCASE",         /* 4000 */
    0
};

static void print_rsrc_control_style(byte class, dword flags){
    int i;
    char buffer[1024];
    buffer[0] = 0;

    printf("        Style: ");
    
    switch (class){
    case 0x80: /* Button */
        strcpy(buffer, rsrc_button_type[flags & 0x000f]);
        
        if (flags & 0x0010)
            strcat(buffer, ", (unknown flag 0x0010)");
        if (flags & 0x0020)
            strcat(buffer, ", BS_LEFTTEXT");

        if ((flags & 0x0040) == 0)
            strcat(buffer, ", BS_TEXT");
        else {
            if (flags & 0x0040)
                strcat(buffer, "BS_ICON");
            if (flags & 0x0080)
                strcat(buffer, "BS_BITMAP");
        }

        if ((flags & 0x0300) == 0x0100)
            strcat(buffer, ", BS_LEFT");
        else if ((flags & 0x0300) == 0x0200)
            strcat(buffer, ", BS_RIGHT");
        else if ((flags & 0x0300) == 0x0300)
            strcat(buffer, ", BS_CENTER");

        if ((flags & 0x0C00) == 0x0400)
            strcat(buffer, ", BS_TOP");
        else if ((flags & 0x0C00) == 0x0800)
            strcat(buffer, ", BS_BOTTOM");
        else if ((flags & 0x0C00) == 0x0C00)
            strcat(buffer, ", BS_VCENTER");

        if (flags & 0x1000)
            strcat(buffer, ", BS_PUSHLIKE");
        if (flags & 0x2000)
            strcat(buffer, ", BS_MULTILINE");
        if (flags & 0x4000)
            strcat(buffer, ", BS_NOTIFY");
        if (flags & 0x8000)
            strcat(buffer, ", BS_FLAT");

        break;
        
    case 0x81: /* Edit */
        if ((flags & 3) == 0)
            strcpy(buffer, "ES_LEFT");
        else if ((flags & 3) == 1)
            strcpy(buffer, "ES_CENTER");
        else if ((flags & 3) == 2)
            strcpy(buffer, "ES_RIGHT");
        else if ((flags & 3) == 3)
            strcpy(buffer, "(unknown type 3)");

        for (i=2; i<16; i++){
            if (flags & (1<<i)){
                strcat(buffer, ", ");
                strcat(buffer, rsrc_edit_style[i]);
            }
        }
        break;
        
    case 0x82: /* Static */
        if ((flags & 0x001f) <= 0x12)
            strcpy(buffer, rsrc_static_type[flags & 0x001f]);
        else
            sprintf(buffer, "(unknown type %d)", flags & 0x001f);

        for (i=5; i<14; i++){
            if (flags & (1<<i)){
                strcat(buffer, ", ");
                strcat(buffer, rsrc_static_style[i]);
            }
        }
        break;

    case 0x83: /* ListBox */
        for (i=0; i<16; i++){
            if (flags & (1<<i)){
                strcat(buffer, ", ");
                strcat(buffer, rsrc_listbox_style[i]);
            }
        }
        break;

    case 0x84: /* ScrollBar */
        if (flags & 0x18){
            if (flags & 0x08)
                strcpy(buffer, "SBS_SIZEBOX");
            else if (flags & 0x10)
                strcpy(buffer, "SBS_SIZEGRIP");
            if (flags & 0x02)
                strcat(buffer, ", SBS_SIZEBOXTOPLEFTALIGN");
            if (flags & 0x04)
                strcat(buffer, ", SBS_SIZEBOXBOTTOMRIGHTALIGN");
        } else if (flags & 0x01){
            strcpy(buffer, "SBS_VERT");
            if (flags & 0x02)
                strcat(buffer, ", SBS_LEFTALIGN");
            if (flags & 0x04)
                strcat(buffer, ", SBS_RIGHTALIGN");
        } else {
            strcpy(buffer, "SBS_HORZ");
            if (flags & 0x02)
                strcat(buffer, ", SBS_TOPALIGN");
            if (flags & 0x04)
                strcat(buffer, ", SBS_BOTTOMALIGN");
        }
        if (flags & 0xffe0)
            sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0xffe0);
        break;

    case 0x85: /* ComboBox */
        if ((flags & 3) == 1)
            strcat(buffer, ", CBS_SIMPLE");
        else if ((flags & 3) == 2)
            strcat(buffer, ", CBS_DROPDOWN");
        else if ((flags & 3) == 3)
            strcat(buffer, ", CBS_DROPDOWNLIST");
        
        for (i=4; i<15; i++){
            if ((flags & (1<<i)) && rsrc_combobox_style[i]){
                strcat(buffer, ", ");
                strcat(buffer, rsrc_combobox_style[i]);
            }
        }
        if (flags & 0x900c)
            sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", flags & 0x900c);
        break;

    default:
        sprintf(buffer, "0x%04x", flags & 0xffff);
    }

    /* and finally, WS_ flags */
    for (i=16; i<32; i++){
        if (flags & (1<<i)){
            strcat(buffer, ", ");
            strcat(buffer, rsrc_dialog_style[i]);
        }
    }

    printf("%s\n", (buffer[0] == ',') ? (buffer+2) : buffer);
}

struct dialog_control {
    word x;
    word y;
    word width;
    word height;
    word id;
    dword style;
    byte class;
};

static const char *const rsrc_dialog_class[] = {
    "Button",    /* 80 */
    "Edit",      /* 81 */
    "Static",    /* 82 */
    "ListBox",   /* 83 */
    "ScrollBar", /* 84 */
    "ComboBox",  /* 85 */
    0
};

/* This is actually two headers, with the first (VS_VERSIONINFO)
 * describing the second. However it seems the second is always
 * a VS_FIXEDFILEINFO header, so we ignore most of those details. */
struct version_header {
    word length;
    word value_length; /* always 52 (0x34), the length of the second header */
    /* the "type" field given by Windows is missing */
    byte string[16]; /* the fixed string VS_VERSION_INFO\0 */
    dword magic; /* 0xfeef04bd */
    word struct_2; /* seems to always be 1.0 */
    word struct_1;
    word file_2; /* 1.2.3.4 &c. */
    word file_1;
    word file_4;
    word file_3;
    word prod_2; /* always the same as the above? */
    word prod_1;
    word prod_4;
    word prod_3;
    dword flags_file_mask; /* always 2 or 3f...? */
    dword flags_file;
    dword flags_os;
    dword flags_type;
    dword flags_subtype;
    dword date_1; /* always 0? */
    dword date_2;
};

static const char *const rsrc_version_file[] = {
    "VS_FF_DEBUG",        /* 0001 */
    "VS_FF_PRERELEASE",   /* 0002 */
    "VS_FF_PATCHED",      /* 0004 */
    "VS_FF_PRIVATEBUILD", /* 0008 */
    "VS_FF_INFOINFERRED", /* 0010 */
    "VS_FF_SPECIALBUILD", /* 0020 */
    0
};

static const char *const rsrc_version_type[] = {
    "unknown",             /* 0 VFT_UNKNOWN */
    "application",         /* 1 VFT_APP */
    "DLL",                 /* 2 VFT_DLL */
    "device driver",       /* 3 VFT_DRV */
    "font",                /* 4 VFT_FONT */
    "virtual device",      /* 5 VFT_VXD */
    "(unknown type 6)",
    "static-link library", /* 7 VFT_STATIC_LIB */
    0
};

static const char *const rsrc_version_subtype_drv[] = {
    "unknown",     /* 0 VFT2_UNKNOWN */
    "printer",     /* 1 VFT2_DRV_PRINTER etc. */
    "keyboard",    /* 2 */
    "language",    /* 3 */
    "display",     /* 4 */
    "mouse",       /* 5 */
    "network",     /* 6 */
    "system",      /* 7 */
    "installable", /* 8 */
    "sound",       /* 9 */
    "communications",    /* 10 */
    "input method",      /* 11, found in WINE */
    "versioned printer", /* 12 */
    0
};

static void print_rsrc_version_flags(struct version_header header){
    char buffer[1024];
    int i;
    
    buffer[0] = '\0';
    for (i=0;i<6;i++){
        if (header.flags_file & (1<<i)){
            strcat(buffer, ", ");
            strcat(buffer, rsrc_version_file[i]);
        }
    }
    if (header.flags_file & 0xffc0)
        sprintf(buffer+strlen(buffer), ", (unknown flags 0x%04x)", header.flags_file & 0xffc0);
    printf("    File flags: ");
    if (header.flags_file)
        printf("%s", buffer+2);

    buffer[0] = '\0';
    if (header.flags_os == 0)
        strcpy(buffer, ", VOS_UNKNOWN");
    else {
        switch (header.flags_os & 0xffff){
        case 1: strcpy(buffer, ", VOS__WINDOWS16"); break;
        case 2: strcpy(buffer, ", VOS__PM16"); break;
        case 3: strcpy(buffer, ", VOS__PM32"); break;
        case 4: strcpy(buffer, ", VOS__WINDOWS32"); break;
        default: sprintf(buffer, ", (unknown OS 0x%04x)", header.flags_os & 0xffff);
        }
        switch (header.flags_os >> 16){
        case 1: strcat(buffer, ", VOS_DOS"); break;
        case 2: strcat(buffer, ", VOS_OS216"); break;
        case 3: strcat(buffer, ", VOS_OS232"); break;
        case 4: strcat(buffer, ", VOS_NT"); break;
        case 5: strcat(buffer, ", VOS_WINCE"); break; /* found in WINE */
        default: sprintf(buffer+strlen(buffer), ", (unknown OS 0x%04x)", header.flags_os >> 16);
        }
    }
    printf("\n    OS flags: %s\n", buffer+2);

    if (header.flags_type <= 7)
        printf("    Type: %s\n", rsrc_version_type[header.flags_type]);
    else
        printf("    Type: (unknown type %d)\n", header.flags_type);

    if (header.flags_type == 3){ /* driver */
        if (header.flags_subtype <= 12)
            printf("    Subtype: %s driver\n", rsrc_version_subtype_drv[header.flags_subtype]);
        else
            printf("    Subtype: (unknown subtype %d)\n", header.flags_subtype);
    } else if (header.flags_type == 4){ /* font */
        if (header.flags_subtype == 0)
            printf("    Subtype: unknown font\n");
        else if (header.flags_subtype == 1)
            printf("    Subtype: raster font\n");
        else if (header.flags_subtype == 2)
            printf("    Subtype: vector font\n");
        else if (header.flags_subtype == 3)
            printf("    Subtype: TrueType font\n");
        else
            printf("    Subtype: (unknown subtype %d)\n", header.flags_subtype);
    } else if (header.flags_type == 5){ /* VXD */
        printf("    Virtual device ID: %d\n", header.flags_subtype);
    } else if (header.flags_subtype){
        /* according to MSDN nothing else is valid */
        printf("    Subtype: (unknown subtype %d)\n", header.flags_subtype);
    }
};

static void print_rsrc_strings(long end){
    word length;

    while (ftell(f) < end){
        /* first length is redundant */
        fseek(f, sizeof(word), SEEK_CUR);
        length = read_word();
        printf("        ");
        print_escaped_string0();
        skip_padding(4);
        printf(": ");
        /* According to MSDN this is zero-terminated, and in most cases it is.
         * However, at least one application (msbsolar) has NEs with what
         * appears to be a non-zero-terminated string. In Windows this is cut
         * off at one minus the given length, just like other strings, so
         * we'll do that here. */
        print_escaped_string(length-1);
        fseek(f, 1, SEEK_CUR); /* and skip the zero */
        skip_padding(4);
        putchar('\n');
    }
};

static void print_rsrc_stringfileinfo(long end){
    long cursor;
    word length;
    unsigned int lang = 0;
    unsigned int codepage = 0;

    /* we already processed the StringFileInfo header */
    while ((cursor = ftell(f)) < end){
        /* StringTable header */
        length = read_word();
        fseek(f, sizeof(word), SEEK_CUR); /* ValueLength, always 0 */

        /* codepage and language code */
        fscanf(f, "%4x%4x", &lang, &codepage);
        printf("    String table (lang=%04x, codepage=%04x):\n", lang, codepage);
        fseek(f, 4*sizeof(byte), SEEK_CUR); /* padding */

        print_rsrc_strings(cursor + length);
    }
};

static void print_rsrc_varfileinfo(long end){
    word length;
    
    while (ftell(f) < end){
        /* first length is redundant */
        length = read_word();
        fseek(f, 12*sizeof(byte), SEEK_CUR); /* Translation\0 */
        while (length -= 4)
            printf("    Var (lang=%04x, codepage=%04x)\n", read_word(), read_word());
    }
};

static void print_rsrc_resource(word type, long offset, long length, word rn_id){
    fseek(f, offset, SEEK_SET);
    
    switch (type){
    case 0x8001: /* Cursor */
    {
        printf("    Hotspot: (%d, %d)\n", read_word(), read_word());
    }
    /* fall through */
    case 0x8002: /* Bitmap */
    case 0x8003: /* Icon */
    {
        struct header_bitmap_info header = {0};
        /* header size should be 40 (INFOHEADER) or 12 (COREHEADER). */
        if ((header.biSize = read_dword()) == 12){
            header.biWidth = read_word();
            header.biHeight = read_word();
            header.biPlanes = read_word();
            header.biBitCount = read_word();
        } else if (header.biSize == 40){
            fseek(f, -sizeof(dword), SEEK_CUR);
            fread(&header, sizeof(header), 1, f);
        } else {
            printf("    Unknown header size %d\n", header.biSize);
            break;
        }

        printf("    Size: %dx%dx%d\n", header.biWidth,
               header.biHeight/2, header.biBitCount);
        /* skip color planes since it should always be 1 */
        if (header.biCompression <= 13 && rsrc_bmp_compression[header.biCompression])
            printf("    Compression: %s\n", rsrc_bmp_compression[header.biCompression]);
        else
            printf("    Compression: (unknown value %d)\n", header.biCompression);
        if (header.biXPelsPerMeter || header.biYPelsPerMeter)
            printf("    Resolution: %dx%d pixels/meter\n",
                   header.biXPelsPerMeter, header.biYPelsPerMeter);
        printf("    Colors used: %d", header.biClrUsed); /* todo: implied */
        if (header.biClrImportant)
            printf(" (%d marked important)", header.biClrImportant);
        putchar('\n');
    }
    break;
#if 0 /* until we find a testcase, hexdump */
    case 0x8004: /* Menu */
    {
        /* The following code has not been tested, since I couldn't find
         * any executables with menu resources. */
        word extended = read_word();
        word offset = read_word();
        long cursor;
        if (extended > 1){
            printf("    Unknown menu version %d\n",extended);
            break;
        }
        printf(extended ? "    Type: extended" : "    Type: standard");
        if (offset != extended*4)
            printf("    Unexpected offset value %d\n", offset);
        if (extended){
            printf("    Help ID: %d\n", read_dword());
            /* todo */
        } else {
            /* todo */
        }
    }
    break;
#endif
    case 0x8005: /* Dialog box */
    {
        byte count;
        word font_size;
        dword style = read_dword();
        print_rsrc_dialog_style(style);
        count = read_byte();
        printf("    Position: (%d, %d)\n", read_word(), read_word());
        printf("    Size: %dx%d\n", read_word(), read_word());
        if (read_byte() == 0xff){
            printf("    Menu resource: #%d", read_word());
        } else {
            printf("    Menu name: ");
            fseek(f, -sizeof(byte), SEEK_CUR);
            print_escaped_string0();
        }
        printf("\n    Class name: ");
        print_escaped_string0();
        printf("\n    Caption: ");
        print_escaped_string0();
        if (style & 0x00000040){ /* DS_SETFONT */
            font_size = read_word();
            printf("\n    Font: ");
            print_escaped_string0();
            printf(" (%d pt)", font_size);
        }
        putchar('\n');

        while (count--){
            struct dialog_control control;
            fread(&control, sizeof(control), 1, f);

            if (control.class & 0x80){
                if (control.class <= 0x85)
                    printf("    %s", rsrc_dialog_class[control.class & (~0x80)]);
                else
                    printf("    (unknown class %d)", control.class);
            } else {
                fseek(f, -sizeof(byte), SEEK_CUR);
                print_escaped_string0();
            }
            printf(" %d:\n", control.id);

            printf("        Position: (%d, %d)\n", control.x, control.y);
            printf("        Size: %dx%d\n", control.width, control.height);
            print_rsrc_control_style(control.class, control.style);

            if (read_byte() == 0xff){
                /* todo: we can check the style for SS_ICON/SS_BITMAP and *maybe* also
                 * refer back to a printed RT_GROUPICON/GROUPCUROR/BITMAP resource. */
                printf("        Resource: #%d", read_word());
            } else {
                fseek(f, -sizeof(byte), SEEK_CUR);
                printf("        Text: ");
                print_escaped_string0();
            }
            /* todo: WINE parses this as "data", but all of my testcases return 0. */
            read_byte();
            putchar('\n');
        }
    }
    break;
    case 0x8006: /* String */
    {
        int i = 0;
        long cursor;
        while ((cursor = ftell(f)) < offset+length){
            byte length = read_byte();
            if (length){
                printf("    %3d (0x%06lx): ", i + ((rn_id & (~0x8000))-1)*16, cursor);
                print_escaped_string(length);
                putchar('\n');
            }
            i++;
        }
    }
    break;
#if 0 /* No testcases for this either */
    case 0x8007: /* Font directory */
    case 0x8008: /* Font component */
    case 0x8009: /* Accelerator table */
        break;
#endif
    /* Resource data (0x800a) is parsed as default, i.e. hex-dumped. */
    case 0x800c: /* Cursor directory */
    case 0x800e: /* Icon directory */
    {
        /* All of the information supplied here is contained in the actual
         * resource. Therefore we only list the components this refers to.
         * Fortunately, the headers are different but the relevant information
         * is stored in the same bytes. */
        word count;
        char *buffer;
        char buffer_len = 0;
        long cursor;
        fseek(f, 2*sizeof(word), SEEK_CUR);
        count = read_word();
        buffer = malloc(count * sizeof(char) * 8); /* ", #12345" */
        while (count--){
            fseek(f, 6*sizeof(word), SEEK_CUR);
            buffer_len += sprintf(buffer+buffer_len, ", #%d", read_word());
        }
        printf("    Resources: %s\n", buffer+2);
        free(buffer);
    }
    break;
    case 0x8010: /* Version */
    {
        struct version_header header;
        word info_length; /* for the String/VarFileInfo */
        char info_type;
        long cursor;
        fread(&header, sizeof(header), 1, f);
        print_rsrc_version_flags(header);

        printf("    File version:    %d.%d.%d.%d\n",
               header.file_1, header.file_2, header.file_3, header.file_4);
        printf("    Product version: %d.%d.%d.%d\n",
               header.prod_1, header.prod_2, header.prod_3, header.prod_4);

        printf("    Created on: ");
        print_timestamp(header.date_1, header.date_2);
        putchar('\n');

        /* header's out of the way, now we have to possibly parse a StringFileInfo */
        if (header.length == 0x48)
            return; /* I don't have any testcases available so I think this is correct */

        cursor = ftell(f);
        info_length = read_word();
        fseek(f, sizeof(word), SEEK_CUR); /* ValueLength, which always == 0 */
        /* "type" is again omitted */
        if ((info_type = read_byte()) == 'S'){
            /* we have a StringFileInfo */
            fseek(f, 15*sizeof(byte), SEEK_CUR);
            print_rsrc_stringfileinfo(cursor+info_length);
            if (header.length == (0x48 + info_length))
                return;

            info_length = read_word();
            fseek(f, sizeof(word), SEEK_CUR);
            info_type = read_byte();
        }

        if (info_type == 'V'){
            /* we have a VarFileInfo */
            fseek(f, 11*sizeof(byte), SEEK_CUR);
            print_rsrc_varfileinfo(cursor+info_length);
        } else {
            printf("Unrecognized file info key: ");
            fseek(f, -sizeof(byte), SEEK_CUR);
            print_escaped_string0();
        }
    }
    break;
    default:
    {
        long cursor;
        byte row[16];
        char len;
        int i;
        /* hexl-style dump */
        while ((cursor = ftell(f)) < offset+length){
            len = (offset+length-cursor >= 16) ? 16 : (offset+length-cursor);
            fread(row, sizeof(byte), len, f);
            
            printf("    %lx:", cursor);
            for (i=0; i<16; i++){
                if (!(i & 1))
                    /* Since this is 16 bits, we put a space after (before) every other two bytes. */
                    putchar(' ');
                if (i<len)
                    printf("%02x", row[i]);
                else
                    printf("  ");
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
    }
    break;
    }
}

/* return true if this was one of the resources that was asked for */
static int filter_resource(word type_id, word rn_id){
    int i;
    rn_id = rn_id & (~0x8000);
    for (i=0; i<resource_count; i++){
        if ((resource_type[i] == type_id) &&
            (!resource_id[i] || resource_id[i] == rn_id))
            return 1;
    }
    return 0;
}

struct resource {
    word offset;
    word length;
    word flags;
    word id;
    word handle; /* fixme: what is this? */
    word usage; /* fixme: what is this? */
};

STATIC_ASSERT(sizeof(struct resource) == 0xc);

void print_rsrc(long start){
    word align = read_word();
    word type_id;
    word count;
    dword resloader; /* fixme: what is this? */
    struct resource rn;
    long cursor;

    while ((type_id = read_word())){
        count = read_word();
        resloader = read_dword();
        while (count--){
            fread(&rn, sizeof(rn), 1, f);
            cursor = ftell(f);

            /* if a specific type (and id) was requested, filter for it */
            if (resource_count && !filter_resource(type_id, rn.id))
                continue;
            
            /* print resource type */
            if (type_id & 0x8000){
                if ((type_id & (~0x8000)) < rsrc_types_count && rsrc_types[type_id & (~0x8000)])
                    printf("%s",rsrc_types[type_id & (~0x8000)]);
                else
                    printf("0x%04x", type_id);
            } else
                print_string_resource(start+type_id);

            putchar(' ');
            
            /* print resource id */
            if (rn.id & 0x8000)
                printf("%d", rn.id & (~0x8000));
            else
                print_string_resource(start+rn.id);

            printf(" (offset = 0x%x, length = %d [0x%x]):\n", rn.offset << align, rn.length << align, rn.length << align);
            if(0) print_rsrc_flags(rn.flags);

            print_rsrc_resource(type_id, rn.offset << align, rn.length << align, rn.id);
            fseek(f, cursor, SEEK_SET);
        }
    }
}
