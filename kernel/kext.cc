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

#include "darwin_kit.h"

#include "kext.h"
#include "kext_macho.h"

#include "kernel.h"
#include "kernel_macho.h"

#include "macho.h"

namespace xnu {

Kext::Kext(Kernel* kernel, xnu::mach::VmAddress base, char* identifier)
    : kernel(kernel), address(base), identifier(identifier) {
    macho = new KextMachO(kernel, identifier, address);
    kmod_info = reinterpret_cast<xnu::KmodInfo*>(macho->GetSymbolAddressByName("_kmod_info"));
}

Kext::Kext(Kernel* kernel, void* kext, xnu::KmodInfo* kmod_info)
    : kernel(kernel), kext(kext), kmod_info(kmod_info), address(kmod_info->address),
      size(kmod_info->size), identifier(&kmod_info->name[0]) {
    macho = kmod_info->address ? new KextMachO(kernel, identifier, kmod_info) : nullptr;
}

Kext* Kext::FindKextWithIdentifier(Kernel* kernel, char* name) {
    darwin::DarwinKit* darwinkit = kernel->GetDarwinKit();
    return darwinkit->GetKextByIdentifier(name);
}

Kext* Kext::FindKextWithIdentifier_deprecated(Kernel* kernel, char* name) {
    xnu::KmodInfo** kextKmods;
    xnu::mach::VmAddress _kmod = kernel->GetSymbolAddressByName("_kmod");
    kextKmods = reinterpret_cast<xnu::KmodInfo**>(_kmod);
    for (xnu::KmodInfo* kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (strcmp(kmod->name, name) == 0) {
            Kext* kext;
            void* OSKext;
            typedef void* (*lookupKextWithIdentifier)(const char*);
            void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);
            xnu::mach::VmAddress OSKext_lookupWithIdentifier =
                kernel->GetSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");
            __ZN6OSKext24lookupKextWithIdentifierEPKc =
                reinterpret_cast<lookupKextWithIdentifier>(OSKext_lookupWithIdentifier);

            OSKext = __ZN6OSKext24lookupKextWithIdentifierEPKc(name);
            kext = new Kext(kernel, OSKext, kmod);
        }
    }

    return nullptr;
}

Kext* Kext::FindKextWithId(Kernel* kernel, UInt32 kext_id) {
    return nullptr;
}

void Kext::OnKextLoad(void* kext, xnu::KmodInfo* kmod_info) {
    return;
}

} // namespace xnu
