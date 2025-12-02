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
#include <stddef.h>
#include <stdint.h>
#include <types.h>

#include "kext_macho.h"

namespace xnu {}

namespace xnu {
class Kernel;

class Kext {
public:
    explicit Kext(xnu::Kernel* kernel, xnu::mach::VmAddress base, char* identifier);

    explicit Kext(xnu::Kernel* kernel, void* kext, xnu::KmodInfo* kmod_info);

    ~Kext() = default;

    static xnu::Kext* FindKextWithIdentifier(xnu::Kernel* kernel, char* name);
    static xnu::Kext* FindKextWithIdentifier_deprecated(xnu::Kernel* kernel, char* name);

    static xnu::Kext* FindKextWithId(xnu::Kernel* kernel, UInt32 kext_id);

    static void OnKextLoad(void* kext, xnu::KmodInfo* kmod_info);

    char* GetName() {
        return identifier;
    }

    xnu::KextMachO* GetMachO() {
        return macho;
    }

    xnu::mach::VmAddress GetBase() {
        return address;
    }

    xnu::mach::VmAddress GetAddress() {
        return address;
    }

    Size GetSize() {
        return size;
    }

    void* GetOSKext() {
        return kext;
    }

    xnu::KmodInfo* GetKmodInfo() {
        return kmod_info;
    }

    xnu::KmodStartFunc* GetKmodStart() {
        return kmod_info->start;
    }
    xnu::KmodStopFunc* GetKmodStop() {
        return kmod_info->stop;
    }

    std::vector<Symbol*>& GetAllSymbols() {
        return macho->GetAllSymbols();
    }

    Symbol* GetSymbolByName(char* symname) {
        return macho->GetSymbolByName(symname);
    }
    Symbol* GetSymbolByAddress(xnu::mach::VmAddress address) {
        return macho->GetSymbolByAddress(address);
    }

    xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname) {
        return macho->GetSymbolAddressByName(symbolname);
    }

private:
    xnu::Kernel* kernel;
    xnu::KextMachO* macho;
    xnu::KmodInfo* kmod_info;

    void* kext;
    xnu::mach::VmAddress address;
    Size size;
    char* identifier;
};

}; // namespace xnu
