/*
 * Function(s) for dumping resources from NE files
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

#include <ctype.h>
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

static char *dup_string_resource(off_t offset)
{
    byte length = read_byte(offset);
    char *ret = malloc(length + 1);
    memcpy(ret, read_data(offset + 1), length);
    ret[length] = 0;
    return ret;
}

/* length-indexed; returns  */
static void print_escaped_string(off_t offset, long length){
    putchar('"');
    while (length--){
        char c = read_byte(offset++);
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

/* null-terminated; returns the end of the string */
static off_t print_escaped_string0(off_t offset)
{
    char c;
    putchar('"');
    while ((c = read_byte(offset++))){
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
    return offset;
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
    "Message table",     /* b */    /* fixme: error table? */
    "Cursor directory",  /* c */
    0,
    "Icon directory",    /* e */
    "Name table",        /* f */
    "Version",           /* 10 */
    0,                              /* fixme: RT_DLGINCLUDE? */
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

static void print_rsrc_flags(word flags){
    if (flags & 0x0010)
        printf(", moveable");
    if (flags & 0x0020)
        printf(", shareable");
    if (flags & 0x0040)
        printf(", preloaded");
    if (flags & 0xff8f)
        printf(", (unknown flags 0x%04x)", flags & 0xff8f);
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
    "BS_PUSHBUTTON",        /* 0 */
    "BS_DEFPUSHBUTTON",     /* 1 */
    "BS_CHECKBOX",          /* 2 */
    "BS_AUTOCHECKBOX",      /* 3 */
    "BS_RADIOBUTTON",       /* 4 */
    "BS_3STATE",            /* 5 */
    "BS_AUTO3STATE",        /* 6 */
    "BS_GROUPBOX",          /* 7 */
    "BS_USERBUTTON",        /* 8 */
    "BS_AUTORADIOBUTTON",   /* 9 */
    "BS_PUSHBOX",           /* 10 */
    "BS_OWNERDRAW",         /* 11 */
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
    "SS_LEFTNOWORDWRAP",/* 12 */
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
        
        if (flags & 0x0010) strcat(buffer, ", (unknown flag 0x0010)");
        if (flags & 0x0020) strcat(buffer, ", BS_LEFTTEXT");

        if ((flags & 0x0040) == 0)
            strcat(buffer, ", BS_TEXT");
        else {
            if (flags & 0x0040) strcat(buffer, ", BS_ICON");
            if (flags & 0x0080) strcat(buffer, ", BS_BITMAP");
        }

        if      ((flags & 0x0300) == 0x0100) strcat(buffer, ", BS_LEFT");
        else if ((flags & 0x0300) == 0x0200) strcat(buffer, ", BS_RIGHT");
        else if ((flags & 0x0300) == 0x0300) strcat(buffer, ", BS_CENTER");

        if      ((flags & 0x0C00) == 0x0400) strcat(buffer, ", BS_TOP");
        else if ((flags & 0x0C00) == 0x0800) strcat(buffer, ", BS_BOTTOM");
        else if ((flags & 0x0C00) == 0x0C00) strcat(buffer, ", BS_VCENTER");

        if (flags & 0x1000) strcat(buffer, ", BS_PUSHLIKE");
        if (flags & 0x2000) strcat(buffer, ", BS_MULTILINE");
        if (flags & 0x4000) strcat(buffer, ", BS_NOTIFY");
        if (flags & 0x8000) strcat(buffer, ", BS_FLAT");

        break;

    case 0x81: /* Edit */
        if      ((flags & 3) == 0) strcpy(buffer, "ES_LEFT");
        else if ((flags & 3) == 1) strcpy(buffer, "ES_CENTER");
        else if ((flags & 3) == 2) strcpy(buffer, "ES_RIGHT");
        else if ((flags & 3) == 3) strcpy(buffer, "(unknown type 3)");

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

static off_t print_rsrc_menu_items(int depth, off_t offset)
{
    word flags, id;
    char buffer[1024];
    int i;

    while (1) {
        flags = read_word(offset);
        offset += 2;

        printf("        ");
        for (i = 0; i < depth; i++) printf("  ");
        if (!(flags & 0x0010)) {
            /* item ID */
            id = read_word(offset);
            offset += 2;
            printf("%d: ", id);
        }

        offset = print_escaped_string0(offset);

        /* and print flags */
        buffer[0] = '\0';
        if (flags & 0x0001) strcat(buffer, ", grayed");
        if (flags & 0x0002) strcat(buffer, ", inactive");
        if (flags & 0x0004) strcat(buffer, ", bitmap");
        if (flags & 0x0008) strcat(buffer, ", checked");
        if (flags & 0x0010) strcat(buffer, ", popup");
        if (flags & 0x0020) strcat(buffer, ", menu bar break");
        if (flags & 0x0040) strcat(buffer, ", menu break");
        /* don't print ENDMENU */
        if (flags & 0xff00)
            sprintf(buffer+strlen(buffer), ", unknown flags 0x%04x", flags & 0xff00);
    
        if (buffer[0])
            printf(" (%s)", buffer+2);
        putchar('\n');

        /* if we have a popup, recurse */
        if (flags & 0x0010)
            offset = print_rsrc_menu_items(depth + 1, offset);

        if (flags & 0x0080)
            break;
    }

    return offset;
}

/* This is actually two headers, with the first (VS_VERSIONINFO)
 * describing the second. However it seems the second is always
 * a VS_FIXEDFILEINFO header, so we ignore most of those details. */
struct version_header {
    word length;            /* 00 */
    word value_length;      /* 02 - always 52 (0x34), the length of the second header */
    /* the "type" field given by Windows is missing */
    byte string[16];        /* 04 - the fixed string VS_VERSION_INFO\0 */
    dword magic;            /* 14 - 0xfeef04bd */
    word struct_2;          /* 18 - seems to always be 1.0 */
    word struct_1;          /* 1a */
    /* 1.2.3.4 &c. */
    word file_2;            /* 1c */
    word file_1;            /* 1e */
    word file_4;            /* 20 */
    word file_3;            /* 22 */
    word prod_2;            /* 24 - always the same as the above? */
    word prod_1;            /* 26 */
    word prod_4;            /* 28 */
    word prod_3;            /* 2a */
    dword flags_file_mask;  /* 2c - always 2 or 3f...? */
    dword flags_file;       /* 30 */
    dword flags_os;         /* 34 */
    dword flags_type;       /* 38 */
    dword flags_subtype;    /* 3c */
    dword date_1;           /* 40 - always 0? */
    dword date_2;           /* 44 */
};

STATIC_ASSERT(sizeof(struct version_header) == 0x48);

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
    "unknown",              /* 0 VFT2_UNKNOWN */
    "printer",              /* 1 VFT2_DRV_PRINTER etc. */
    "keyboard",             /* 2 */
    "language",             /* 3 */
    "display",              /* 4 */
    "mouse",                /* 5 */
    "network",              /* 6 */
    "system",               /* 7 */
    "installable",          /* 8 */
    "sound",                /* 9 */
    "communications",       /* 10 */
    "input method",         /* 11, found in WINE */
    "versioned printer",    /* 12 */
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
        if (header.flags_subtype == 0)      printf("    Subtype: unknown font\n");
        else if (header.flags_subtype == 1) printf("    Subtype: raster font\n");
        else if (header.flags_subtype == 2) printf("    Subtype: vector font\n");
        else if (header.flags_subtype == 3) printf("    Subtype: TrueType font\n");
        else printf("    Subtype: (unknown subtype %d)\n", header.flags_subtype);
    } else if (header.flags_type == 5){ /* VXD */
        printf("    Virtual device ID: %d\n", header.flags_subtype);
    } else if (header.flags_subtype){
        /* according to MSDN nothing else is valid */
        printf("    Subtype: (unknown subtype %d)\n", header.flags_subtype);
    }
};

static void print_rsrc_strings(off_t offset, off_t end)
{
    word length;

    while (offset < end)
    {
        /* first length is redundant */
        length = read_word(offset + 2);
        printf("        ");
        offset = print_escaped_string0(offset + 4);
        offset = (offset + 3) & ~3;
        printf(": ");
        /* According to MSDN this is zero-terminated, and in most cases it is.
         * However, at least one application (msbsolar) has NEs with what
         * appears to be a non-zero-terminated string. In Windows this is cut
         * off at one minus the given length, just like other strings, so
         * we'll do that here. */
        print_escaped_string(offset, length - 1);
        offset += length;
        offset = (offset + 3) & ~3;
        putchar('\n');
    }
};

static void print_rsrc_stringfileinfo(off_t offset, off_t end)
{
    word length;
    unsigned int lang = 0;
    unsigned int codepage = 0;

    /* we already processed the StringFileInfo header */
    while (offset < end)
    {
        /* StringTable header */
        length = read_word(offset);

        /* codepage and language code */
        sscanf(read_data(offset + 4), "%4x%4x", &lang, &codepage);
        printf("    String table (lang=%04x, codepage=%04x):\n", lang, codepage);

        print_rsrc_strings(offset + 16, offset + length);
        offset += length;
    }
};

static void print_rsrc_varfileinfo(off_t offset, off_t end)
{
    while (offset < end)
    {
        /* first length is redundant */
        word length = read_word(offset + 2), i;
        offset += 16;
        for (i = 0; i < length; i += 4)
            printf("    Var (lang=%04x, codepage=%04x)\n", read_word(offset + i), read_word(offset + i + 2));
        offset += length;
    }
};

static void print_rsrc_resource(word type, off_t offset, size_t length, word rn_id)
{
    switch (type)
    {
    case 0x8001: /* Cursor */
        printf("    Hotspot: (%d, %d)\n", read_word(offset), read_word(offset + 2));
        offset += 4;
        /* fall through */

    case 0x8002: /* Bitmap */
    case 0x8003: /* Icon */
        if (read_dword(offset) == 12) /* BITMAPCOREHEADER */
        {
            printf("    Size: %dx%d\n", read_word(offset + 4), read_word(offset + 6));
            printf("    Planes: %d\n", read_word(offset + 8));
            printf("    Bit depth: %d\n", read_word(offset + 10));
        }
        else if (read_dword(offset) == 40) /* BITMAPINFOHEADER */
        {
            const struct header_bitmap_info *header = read_data(offset);
            printf("    Size: %dx%d\n", header->biWidth, header->biHeight / 2);
            printf("    Planes: %d\n", header->biPlanes);
            printf("    Bit depth: %d\n", header->biBitCount);
            if (header->biCompression <= 13 && rsrc_bmp_compression[header->biCompression])
                printf("    Compression: %s\n", rsrc_bmp_compression[header->biCompression]);
            else
                printf("    Compression: (unknown value %d)\n", header->biCompression);
            printf("    Resolution: %dx%d pixels/meter\n",
                    header->biXPelsPerMeter, header->biYPelsPerMeter);
            printf("    Colors used: %d", header->biClrUsed); /* todo: implied */
            if (header->biClrImportant)
                printf(" (%d marked important)", header->biClrImportant);
            putchar('\n');
        }
        else
            warn("Unknown bitmap header size %d.\n", read_dword(offset));
        break;

    case 0x8004: /* Menu */
    {
        word extended = read_word(offset);

        if (extended > 1) {
            warn("Unknown menu version %d\n",extended);
            break;
        }
        printf(extended ? "    Type: extended\n" : "    Type: standard\n");
        if (read_word(offset + 2) != extended*4)
            warn("Unexpected offset value %d (expected %d).\n", read_word(offset + 2), extended * 4);
        offset += 4;

        if (extended)
        {
            printf("    Help ID: %d\n", read_dword(offset));
            offset += 4;
        }

        printf("    Items:\n");
        print_rsrc_menu_items(0, offset);
        break;
    }
    case 0x8005: /* Dialog box */
    {
        byte count;
        word font_size;
        dword style = read_dword(offset);
        print_rsrc_dialog_style(style);
        count = read_byte(offset + 4);
        printf("    Position: (%d, %d)\n", read_word(offset + 5), read_word(offset + 7));
        printf("    Size: %dx%d\n", read_word(offset + 9), read_word(offset + 11));
        if (read_byte(offset + 13) == 0xff){
            printf("    Menu resource: #%d", read_word(offset + 14));
        } else {
            printf("    Menu name: ");
            offset = print_escaped_string0(offset + 13);
        }
        printf("\n    Class name: ");
        offset = print_escaped_string0(offset);
        printf("\n    Caption: ");
        offset = print_escaped_string0(offset);
        if (style & 0x00000040){ /* DS_SETFONT */
            font_size = read_word(offset);
            printf("\n    Font: ");
            offset = print_escaped_string0(offset + 2);
            printf(" (%d pt)", font_size);
        }
        putchar('\n');

        while (count--){
            const struct dialog_control *control = read_data(offset);
            offset += sizeof(*control);

            if (control->class & 0x80){
                if (control->class <= 0x85)
                    printf("    %s", rsrc_dialog_class[control->class & (~0x80)]);
                else
                    printf("    (unknown class %d)", control->class);
            }
            else
                offset = print_escaped_string0(offset);
            printf(" %d:\n", control->id);

            printf("        Position: (%d, %d)\n", control->x, control->y);
            printf("        Size: %dx%d\n", control->width, control->height);
            print_rsrc_control_style(control->class, control->style);

            if (read_byte(offset) == 0xff){
                /* todo: we can check the style for SS_ICON/SS_BITMAP and *maybe* also
                 * refer back to a printed RT_GROUPICON/GROUPCUROR/BITMAP resource. */
                printf("        Resource: #%d", read_word(offset));
                offset += 3;
            } else {
                printf("        Text: ");
                offset = print_escaped_string0(offset );
            }
            /* todo: WINE parses this as "data", but all of my testcases return 0. */
            /* read_byte(); */
            putchar('\n');
        }
    }
    break;
    case 0x8006: /* String */
    {
        off_t cursor = offset;
        int i = 0;

        while (cursor < offset + length)
        {
            byte str_length = read_byte(cursor++);
            if (str_length)
            {
                printf("    %3d (0x%06lx): ", i + ((rn_id & (~0x8000))-1)*16, cursor);
                print_escaped_string(cursor, str_length);
                putchar('\n');
                cursor += str_length;
            }
            i++;
        }
    }
    break;
#if 0 /* No testcases for this either */
    case 0x8007: /* Font directory */
    case 0x8008: /* Font component */
        break;
    case 0x8009: /* Accelerator table */
    {
        /* This format seems to be similar but older. Five bytes per
         * entry, in the format:
         * [byte] - flags
         * [word] - key
         * [word] - id
         *
         * Problem is, the key codes don't seem to make much sense. In
         * particular we have instances where the virtual flag isn't set
         * but we have C0 control codes. So the mapping must be different
         * than it is for current accelerator tables.
         */
        byte flags;

        do {
            flags = read_byte();
            key = read_word();
            id = read_word();

            printf("    ");

            if (flags & 0x02)
                printf("(FNOINVERT) ");

            if (flags & 0x04)
                printf("Shift+");
            if (flags & 0x08)
                printf("Ctrl+");
            if (flags & 0x10)
                printf("Alt+");
            if (flags & 0x60)
                warn("Unknown accelerator flags 0x%02x\n", flags & 0x60);

            /* fixme: print the key itself */

            printf(": %d\n", id);
        } while (!(flags & 0x80));
    }
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
        word count = read_word(offset + 4);
        offset += 6;
        printf("    Resources: ");
        if (count--) {
            printf("#%d", read_word(offset + 12));
            offset += 14;
        }
        while (count--) {
            printf(", #%d", read_word(offset + 12));
            offset += 14;
        }
        printf("\n");
    }
    break;
    case 0x8010: /* Version */
    {
        const struct version_header *header = read_data(offset);
        const off_t end = offset + header->length;

        if (header->value_length != 52)
            warn("Version header length is %d (expected 52).\n", header->value_length);
        if (strcmp((char *)header->string, "VS_VERSION_INFO"))
            warn("Version header is %.16s (expected VS_VERSION_INFO).\n", header->string);
        if (header->magic != 0xfeef04bd)
            warn("Version magic number is 0x%08x (expected 0xfeef04bd).\n", header->magic);
        if (header->struct_1 != 1 || header->struct_2 != 0)
            warn("Version header version is %d.%d (expected 1.0).\n", header->struct_1, header->struct_2);
        print_rsrc_version_flags(*header);

        printf("    File version:    %d.%d.%d.%d\n",
               header->file_1, header->file_2, header->file_3, header->file_4);
        printf("    Product version: %d.%d.%d.%d\n",
               header->prod_1, header->prod_2, header->prod_3, header->prod_4);

        if (0) {
        printf("    Created on: ");
        print_timestamp(header->date_1, header->date_2);
        putchar('\n');
        }

        offset += sizeof(struct version_header);

        while (offset < end)
        {
            word info_length = read_word(offset);
            word value_length = read_word(offset + 2);
            const char *key = read_data(offset + 4);

            if (value_length)
                warn("Value length is nonzero: %04x\n", value_length);

            /* "type" is again omitted */
            if (!strcmp(key, "StringFileInfo"))
                print_rsrc_stringfileinfo(offset + 20, offset + info_length);
            else if (!strcmp(key, "VarFileInfo"))
                print_rsrc_varfileinfo(offset + 16, offset + info_length);
            else
                warn("Unrecognized file info key: %s\n", key);

            offset += ((info_length + 3) & ~3);
        }
        break;
    }
    default:
    {
        off_t cursor = offset;
        char len;
        int i;
        /* hexl-style dump */
        while (cursor < offset + length)
        {
            len = min(offset + length - cursor, 16);
            
            printf("    %lx:", cursor);
            for (i=0; i<16; i++){
                if (!(i & 1))
                    /* Since this is 16 bits, we put a space after (before) every other two bytes. */
                    putchar(' ');
                if (i<len)
                    printf("%02x", read_byte(cursor + i));
                else
                    printf("  ");
            }
            printf("  ");
            for (i=0; i<len; i++){
                char c = read_byte(cursor + i);
                putchar(isprint(c) ? c : '.');
            }
            putchar('\n');

            cursor += len;
        }
    }
    break;
    }
}

/* return true if this was one of the resources that was asked for */
static int filter_resource(const char *type, const char *id){
    unsigned i;

    if (!resource_filters_count)
        return 1;

    for (i = 0; i < resource_filters_count; ++i){
        const char *filter_type = resource_filters[i], *p;
        size_t len = strlen(type);

        /* note that both resource types and IDs are case insensitive */

        /* if the filter is just a resource type or ID and we match that */
        if (!strcasecmp(type, filter_type) || !strcasecmp(id, filter_type))
            return 1;

        /* if the filter is a resource type followed by an ID and we match both */
        if (strncasecmp(type, filter_type, len) || filter_type[len] != ' ')
            continue;

        p = filter_type + len;
        while (*p == ' ') ++p;
        if (!strcasecmp(id, p))
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

struct type_header
{
    word type_id;
    word count;
    dword resloader; /* fixme: what is this? */
    struct resource resources[1];
};

void print_rsrc(off_t start){
    const struct type_header *header;
    word align = read_word(start);
    char *idstr;
    word i;

    header = read_data(start + sizeof(word));

    while (header->type_id)
    {
        if (header->resloader)
            warn("resloader is nonzero: %08x\n", header->resloader);

        for (i = 0; i < header->count; ++i)
        {
            const struct resource *rn = &header->resources[i];

            if (rn->id & 0x8000){
                idstr = malloc(6);
                sprintf(idstr, "%d", rn->id & ~0x8000);
            } else
                idstr = dup_string_resource(start + rn->id);

            if (header->type_id & 0x8000)
            {
                if ((header->type_id & (~0x8000)) < rsrc_types_count && rsrc_types[header->type_id & (~0x8000)]){
                    if (!filter_resource(rsrc_types[header->type_id & ~0x8000], idstr))
                        goto next;
                    printf("\n%s", rsrc_types[header->type_id & ~0x8000]);
                } else {
                    char typestr[7];
                    sprintf(typestr, "0x%04x", header->type_id);
                    if (!filter_resource(typestr, idstr))
                        goto next;
                    printf("\n%s", typestr);
                }
            }
            else
            {
                char *typestr = dup_string_resource(start + header->type_id);
                if (!filter_resource(typestr, idstr))
                {
                    free(typestr);
                    goto next;
                }
                printf("\n\"%s\"", typestr);
                free(typestr);
            }

            printf(" %s", idstr);
            printf(" (offset = 0x%x, length = %d [0x%x]", rn->offset << align, rn->length << align, rn->length << align);
            print_rsrc_flags(rn->flags);
            printf("):\n");

            print_rsrc_resource(header->type_id, rn->offset << align, rn->length << align, rn->id);

next:
            free(idstr);
        }

        header = (struct type_header *)(&header->resources[header->count]);
    }
}
