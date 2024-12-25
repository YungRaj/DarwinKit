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

#include <mach/kmod.h>
#include <mach/mach_types.h>

#include <types.h>

#include "macho.h"

#include "symbol_table.h"
#include "vector.h"

namespace xnu {
class Kernel;
class Kext;
class KextMachO;
} // namespace xnu

namespace xnu {
class KextMachO : public MachO {
public:
    explicit KextMachO(xnu::Kernel* kernel, char* name, xnu::mach::VmAddress base);
    explicit KextMachO(xnu::Kernel* kernel, char* name, xnu::KmodInfo* kmod_info);

    ~KextMachO() = default;

    xnu::Kernel* GetKernel() {
        return kernel;
    }

    char* GetKextName() {
        return name;
    }

    xnu::mach::VmAddress GetAddress() {
        return address;
    }

    virtual Size GetSize() {
        return kmod_info->size > 0 ? kmod_info->size : MachO::GetSize();
    }

    xnu::KmodStartFunc* GetKmodStart() {
        return kmod_info->start;
    }
    xnu::KmodStopFunc* GetKmodStop() {
        return kmod_info->stop;
    }

    void SetKernelCollection(xnu::mach::VmAddress kc) {
        kernel_collection = kc;
    }

    virtual void ParseSymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                  Size strsize);

    virtual void ParseLinkedit();

    virtual bool ParseLoadCommands();

    virtual void ParseHeader();

    virtual void ParseMachO();

private:
    xnu::Kernel* kernel;

    xnu::mach::VmAddress address;

    char* name;

    Offset base_offset;

    xnu::mach::VmAddress kernel_cache;
    xnu::mach::VmAddress kernel_collection;

    xnu::KmodInfo* kmod_info;

    UInt8* linkedit;

    Offset linkedit_off;

    Size linkedit_size;
};
} // namespace xnu
