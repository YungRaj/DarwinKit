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

#include <types.h>

#include <capstone/capstone.h>

#include "macho.h"

class MachO;

namespace arch {
namespace x86_64 {
namespace PatchFinder {
enum text : int {
    __UNKNOWN_TEXT = -1,
    __NO_TEXT = 0,
    __TEXT_XNU_BASE,
    __TEXT_PRELINK_BASE,
    __TEXT_PPL_BASE,
    __TEXT_KLD_BASE,
};

enum data : int {
    __UNKNOWN_DATA = -1,
    __DATA_CONST = 0,
    __PPLDATA_CONST,
    __PPLDATA,
    __DATA,
    __BOOTDATA,
    __PRELINK_DATA,
    __PLK_DATA_CONST,
};

enum string : int {
    __unknown_ = -1,
    __no_string_ = 0,
    __cstring_,
    __pstring_,
    __oslstring_,
    __data_,
    __const_,
};

unsigned char* boyermoore_horspool_memmem(const unsigned char* haystack, Size hlen,
                                          const unsigned char* needle, Size nlen);

xnu::Mach::VmAddress xref64(MachO* macho, xnu::Mach::VmAddress start, xnu::Mach::VmAddress end,
                            xnu::Mach::VmAddress what);

xnu::Mach::VmAddress findInstruction64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                       UInt8* insn);
xnu::Mach::VmAddress findInstructionBack64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                           UInt8* insn);
xnu::Mach::VmAddress findInstructionNTimes64(MachO* macho, int n, xnu::Mach::VmAddress start,
                                             Size length, UInt8* insn, bool forward);

xnu::Mach::VmAddress step64(MachO* macho, xnu::Mach::VmAddress start, Size length, char* mnemonic,
                            char* op_string);
xnu::Mach::VmAddress stepBack64(MachO* macho, xnu::Mach::VmAddress start, Size length,
                                char* mnemonic, char* op_string);

xnu::Mach::VmAddress findFunctionBegin(MachO* macho, xnu::Mach::VmAddress start,
                                       xnu::Mach::VmAddress where);

xnu::Mach::VmAddress findReference(MachO* macho, xnu::Mach::VmAddress to, int n,
                                   enum text which_text);
xnu::Mach::VmAddress findDataReference(MachO* macho, xnu::Mach::VmAddress to, enum data which_data,
                                       int n);

uint8_t* findString(MachO* macho, char* string, xnu::Mach::VmAddress base, Size size,
                    Bool full_match);
xnu::Mach::VmAddress findStringReference(MachO* macho, char* string, int n,
                                         enum string which_string, enum text which_text,
                                         Bool full_match);

void printInstruction64(MachO* macho, xnu::Mach::VmAddress start, UInt32 length, char* mnemonic,
                        char* op_string);
} // namespace PatchFinder
} // namespace x86_64
}; // namespace arch
