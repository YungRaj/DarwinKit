/*
 * Copyright (c) YungRaj
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#define BOOT_LINE_LENGTH 256

#define FRAMEBUFFER_WIDTH 640
#define FRAMEBUFFER_HEIGHT 960
#define FRAMEBUFFER_DEPTH_BITS 32
#define FRAMEBUFFER_STRIDE_BYTES (FRAMEBUFFER_WIDTH * FRAMEBUFFER_DEPTH_BITS / 8)
#define FRAMEBUFFER_SIZE_BYTES (FRAMEBUFFER_STRIDE_BYTES * FRAMEBUFFER_HEIGHT * 3)

/*
 * Video information..
 */

struct Boot_Video {
    unsigned long v_baseAddr; /* Base address of video memory */
    unsigned long v_display;  /* Display Code (if Applicable */
    unsigned long v_rowBytes; /* Number of bytes per pixel row */
    unsigned long v_width;    /* Width */
    unsigned long v_height;   /* Height */
    unsigned long v_depth;    /* Pixel Depth and other parameters */
};

#define kBootVideoDepthMask (0xFF)
#define kBootVideoDepthDepthShift (0)
#define kBootVideoDepthRotateShift (8)
#define kBootVideoDepthScaleShift (16)
#define kBootVideoDepthBootRotateShift (24)

#define kBootFlagsDarkBoot (1 << 0)

typedef struct Boot_Video Boot_Video;

/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kBootArgsRevision 1
#define kBootArgsRevision2 2 /* added boot_args->bootFlags */
#define kBootArgsVersion1 1
#define kBootArgsVersion2 2

typedef struct boot_args {
    UInt16 Revision;                    /* Revision of boot_args structure */
    UInt16 Version;                     /* Version of boot_args structure */
    UInt64 virtBase;                    /* Virtual base of memory */
    UInt64 physBase;                    /* Physical base of memory */
    UInt64 memSize;                     /* Size of memory */
    UInt64 topOfKernelData;             /* Highest physical address used in kernel data area */
    Boot_Video Video;                   /* Video Information */
    UInt32 machineType;                 /* Machine Type */
    void* deviceTreeP;                  /* Base of flattened device tree */
    UInt32 deviceTreeLength;            /* Length of flattened tree */
    char CommandLine[BOOT_LINE_LENGTH]; /* Passed in command line */
    UInt64 bootFlags;                   /* Additional flags specified by the bootloader */
    UInt64 memSizeActual;               /* Actual size of memory */
} boot_args;