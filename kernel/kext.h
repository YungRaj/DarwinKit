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

#include <stddef.h>
#include <stdint.h>

#include <mach/kmod.h>
#include <mach/mach_types.h>

#include <types.h>

#include "kext_macho.h"

namespace xnu {}

namespace xnu {
class Kernel;

class Kext {
public:
    explicit Kext(xnu::Kernel* kernel, xnu::Mach::VmAddress base, char* identifier);

    explicit Kext(xnu::Kernel* kernel, void* kext, xnu::KmodInfo* kmod_info);

    ~Kext() = default;

    static xnu::Kext* findKextWithIdentifier(xnu::Kernel* kernel, char* name);
    static xnu::Kext* findKextWithIdentifier_deprecated(xnu::Kernel* kernel, char* name);

    static xnu::Kext* findKextWithId(xnu::Kernel* kernel, UInt32 kext_id);

    static void onKextLoad(void* kext, xnu::KmodInfo* kmod_info);

    char* getName() {
        return identifier;
    }

    xnu::KextMachO* getMachO() {
        return macho;
    }

    xnu::Mach::VmAddress getBase() {
        return address;
    }

    xnu::Mach::VmAddress getAddress() {
        return address;
    }

    Size getSize() {
        return size;
    }

    void* getOSKext() {
        return kext;
    }

    xnu::KmodInfo* getKmodInfo() {
        return kmod_info;
    }

    xnu::KmodStartFunc* getKmodStart() {
        return kmod_info->start;
    }
    xnu::KmodStopFunc* getKmodStop() {
        return kmod_info->stop;
    }

    std::vector<Symbol*>& getAllSymbols() {
        return macho->getAllSymbols();
    }

    Symbol* getSymbolByName(char* symname) {
        return macho->getSymbolByName(symname);
    }
    Symbol* getSymbolByAddress(xnu::Mach::VmAddress address) {
        return macho->getSymbolByAddress(address);
    }

    xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname) {
        return macho->getSymbolAddressByName(symbolname);
    }

private:
    xnu::Kernel* kernel;

    xnu::KextMachO* macho;

    xnu::KmodInfo* kmod_info;

    void* kext;

    xnu::Mach::VmAddress address;

    Size size;

    char* identifier;
};

}; // namespace xnu
