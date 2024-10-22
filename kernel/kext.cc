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

using namespace xnu;

Kext::Kext(Kernel* kernel, xnu::Mach::VmAddress base, char* identifier)
    : kernel(kernel), address(base), identifier(identifier) {
    macho = new KextMachO(kernel, identifier, address);

    kmod_info = reinterpret_cast<xnu::KmodInfo*>(macho->getSymbolAddressByName("_kmod_info"));
}

Kext::Kext(Kernel* kernel, void* kext, xnu::KmodInfo* kmod_info)
    : kernel(kernel), kext(kext), kmod_info(kmod_info), address(kmod_info->address),
      size(kmod_info->size), identifier(&kmod_info->name[0]) {
    macho = kmod_info->address ? new KextMachO(kernel, identifier, kmod_info) : nullptr;
}

Kext* Kext::findKextWithIdentifier(Kernel* kernel, char* name) {
    darwin::DarwinKit* rootkit = kernel->getRootKit();

    return rootkit->getKextByIdentifier(name);
}

Kext* Kext::findKextWithIdentifier_deprecated(Kernel* kernel, char* name) {
    xnu::KmodInfo** kextKmods;

    xnu::Mach::VmAddress _kmod = kernel->getSymbolAddressByName("_kmod");

    kextKmods = reinterpret_cast<xnu::KmodInfo**>(_kmod);

    for (xnu::KmodInfo* kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (strcmp(kmod->name, name) == 0) {
            Kext* kext;

            void* OSKext;

            typedef void* (*lookupKextWithIdentifier)(const char*);

            void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);

            xnu::Mach::VmAddress OSKext_lookupWithIdentifier =
                kernel->getSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");

            __ZN6OSKext24lookupKextWithIdentifierEPKc =
                reinterpret_cast<lookupKextWithIdentifier>(OSKext_lookupWithIdentifier);

            OSKext = __ZN6OSKext24lookupKextWithIdentifierEPKc(name);

            kext = new Kext(kernel, OSKext, kmod);
        }
    }

    return nullptr;
}

Kext* Kext::findKextWithId(Kernel* kernel, UInt32 kext_id) {
    return nullptr;
}

void Kext::onKextLoad(void* kext, xnu::KmodInfo* kmod_info) {
    return;
}
