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

#include "macho.h"

class MachO;

namespace xnu {
class Kernel;
class Kext;

class KernelMachO : public MachO {
public:
    explicit KernelMachO() {}

    explicit KernelMachO(xnu::Kernel* kernel);

    ~KernelMachO() = default;

    xnu::Mach::VmAddress getKernelCache() {
        return kernel_cache;
    }

    xnu::Mach::VmAddress getKernelCollection() {
        return kernel_collection;
    }

    void setKernelCache(xnu::Mach::VmAddress kc) {
        kernel_cache = kc;
    }

    void setKernelCollection(xnu::Mach::VmAddress kc) {
        kernel_collection = kc;
    }

    static xnu::Kext* kextLoadedAt(xnu::Kernel* kernel, xnu::Mach::VmAddress address);
    static xnu::Kext* kextWithIdentifier(xnu::Kernel* kernel, char* kext);

    virtual void parseLinkedit();

    virtual bool parseLoadCommands();

    virtual void parseMachO();

protected:
    xnu::Kernel* kernel;

    xnu::Mach::VmAddress kernel_cache;

    xnu::Mach::VmAddress kernel_collection;

    UInt8* linkedit;

    xnu::Mach::VmAddress linkedit_off;

    Size linkedit_size;
};

} // namespace xnu
