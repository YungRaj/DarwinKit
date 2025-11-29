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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>

#include <mach/kmod.h>

#include <mach-o.h>

using Bool = bool;

using Int8 = int8_t;
using Int16 = int16_t;
using Int32 = int32_t;
using Int64 = int64_t;

using UInt8 = uint8_t;
using UInt16 = uint16_t;
using UInt32 = uint32_t;
using UInt64 = uint64_t;
using UIntPtr = uintptr_t;

using Offset = off_t;

#ifdef __KERNEL__
using Size = size_t;
#include "vector.h"
#elif __USER__
#include <IOKit/IOKitLib.h>
#include <vector>
#endif

namespace xnu {
using KmodInfo = kmod_info_t;

using KmodStartFunc = kmod_start_func_t;
using KmodStopFunc = kmod_stop_func_t;
using VmAddress = vm_address_t;

namespace mach {
using VmMap = vm_map_t;
using VmAddress = mach_vm_address_t;
using VmProtection = vm_prot_t;
using Port = mach_port_t;
}; // namespace mach

namespace macho {
using Header64 = struct mach_header_64;
using FatHeader = struct fat_header;
using FatArch = struct fat_arch;
using Nlist64 = struct nlist_64;
using SymbolName = char*;

using SectionName = char*;
using SegmentName = char*;
using Segment64 = struct segment_command_64;
using Section64 = struct section_64;

namespace LoadCommand {
using Cmd = struct load_command;
using FilesetEntry = struct fileset_entry_command;
using Symtab = struct symtab_command;
using Dysymtab = struct dysymtab_command;
using LinkeditData = linkedit_data_command;
using EncryptionInfo = struct encryption_info_command;
using EntryPoint = struct entry_point_command;
using UnixThread = struct unixthread_command;
using Uuid = struct uuid_command;
using Dylib = struct dylib_command;
using DyldInfo = struct dyld_info_command;
}; // namespace LoadCommand
}; // namespace macho
}; // namespace xnu