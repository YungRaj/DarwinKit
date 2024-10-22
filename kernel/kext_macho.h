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

#include <Types.h>

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
    explicit KextMachO(xnu::Kernel* kernel, char* name, xnu::Mach::VmAddress base);
    explicit KextMachO(xnu::Kernel* kernel, char* name, xnu::KmodInfo* kmod_info);

    ~KextMachO() = default;

    xnu::Kernel* getKernel() {
        return kernel;
    }

    char* getKextName() {
        return name;
    }

    xnu::Mach::VmAddress getAddress() {
        return address;
    }

    virtual Size getSize() {
        return kmod_info->size > 0 ? kmod_info->size : MachO::getSize();
    }

    xnu::KmodStartFunc* getKmodStart() {
        return kmod_info->start;
    }
    xnu::KmodStopFunc* getKmodStop() {
        return kmod_info->stop;
    }

    void setKernelCollection(xnu::Mach::VmAddress kc) {
        kernel_collection = kc;
    }

    virtual void parseSymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                  Size strsize);

    virtual void parseLinkedit();

    virtual bool parseLoadCommands();

    virtual void parseHeader();

    virtual void parseMachO();

private:
    xnu::Kernel* kernel;

    xnu::Mach::VmAddress address;

    char* name;

    Offset base_offset;

    xnu::Mach::VmAddress kernel_cache;
    xnu::Mach::VmAddress kernel_collection;

    xnu::KmodInfo* kmod_info;

    UInt8* linkedit;

    Offset linkedit_off;

    Size linkedit_size;
};
} // namespace xnu
