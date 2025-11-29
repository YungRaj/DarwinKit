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

    xnu::mach::VmAddress GetKernelCache() {
        return kernel_cache;
    }

    xnu::mach::VmAddress GetKernelCollection() {
        return kernel_collection;
    }

    void SetKernelCache(xnu::mach::VmAddress kc) {
        kernel_cache = kc;
    }

    void SetKernelCollection(xnu::mach::VmAddress kc) {
        kernel_collection = kc;
    }

    static xnu::Kext* KextLoadedAt(xnu::Kernel* kernel, xnu::mach::VmAddress address);
    static xnu::Kext* KextWithIdentifier(xnu::Kernel* kernel, char* kext);

    virtual void ParseLinkedit();

    virtual bool ParseLoadCommands();

    virtual void ParseMachO();

protected:
    xnu::Kernel* kernel;
    xnu::mach::VmAddress kernel_cache;
    xnu::mach::VmAddress kernel_collection;

    UInt8* linkedit;
    xnu::mach::VmAddress linkedit_off;
    Size linkedit_size;
};

} // namespace xnu
