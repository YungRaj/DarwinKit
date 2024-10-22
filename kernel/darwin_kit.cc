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

using namespace arch;
using namespace xnu;

namespace darwin {

DarwinKit::DarwinKit(xnu::Kernel* kernel)
    : kernel(kernel),
      kextKmods(reinterpret_cast<xnu::KmodInfo**>(kernel->getSymbolAddressByName("_kmod"))),
      platformArchitecture(arch::getCurrentArchitecture()) {
    kernel->setRootKit(this);

    registerCallbacks();

    kernelPatcher = new KernelPatcher(kernel);

    architecture = arch::initArchitecture();
}

void DarwinKit::registerCallbacks() {
    registerEntitlementCallback(
        (void*)this, [](void* user, task_t task, const char* entitlement, void* original) {
            static_cast<DarwinKit*>(user)->onEntitlementRequest(task, entitlement, original);
        });

    registerBinaryLoadCallback(
        (void*)this, [](void* user, task_t task, const char* path, Size len) {
            static_cast<DarwinKit*>(user)->onProcLoad(task, path, len);
        });

    registerKextLoadCallback((void*)this, [](void* user, void* kext, xnu::KmodInfo* kmod) {
        static_cast<DarwinKit*>(user)->onKextLoad(kext, kmod);
    });
}

void DarwinKit::registerEntitlementCallback(void* user, EntitlementCallback callback) {
    StoredPair<EntitlementCallback>* pair =
        StoredPair<EntitlementCallback>::create(callback, user);

    entitlementCallbacks.push_back(pair);
}

void DarwinKit::registerBinaryLoadCallback(void* user, BinaryLoadCallback callback) {
    StoredPair<BinaryLoadCallback>* pair =
        StoredPair<BinaryLoadCallback>::create(callback, user);

    binaryLoadCallbacks.push_back(pair);
}

void DarwinKit::registerKextLoadCallback(void* user, KextLoadCallback callback) {
    StoredPair<KextLoadCallback>* pair = StoredPair<KextLoadCallback>::create(callback, user);

    kextLoadCallbacks.push_back(pair);
}

Kext* DarwinKit::getKextByIdentifier(char* name) {
    std::vector<Kext*>& kexts = getKexts();

    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);

        if (strcmp(kext->getName(), name) == 0) {
            return kext;
        }
    }

    return nullptr;
}

Kext* DarwinKit::getKextByAddress(xnu::Mach::VmAddress address) {
    std::vector<Kext*>& kexts = getKexts();

    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);

        if (kext->getAddress() == address) {
            return kext;
        }
    }

    return nullptr;
}

void DarwinKit::onEntitlementRequest(task_t task, const char* entitlement, void* original) {}

void DarwinKit::onProcLoad(task_t task, const char* path, Size len) {}

void DarwinKit::onKextLoad(void* loaded_kext, xnu::KmodInfo* kmod_info) {
    Kext* kext;

    if (loaded_kext && kmod_info->size) {
        kext = new xnu::Kext(getKernel(), loaded_kext, kmod_info);
    } else {
        kext = new xnu::Kext(getKernel(), kmod_info->address,
                             reinterpret_cast<char*>(&kmod_info->name));
    }

    kexts.push_back(kext);
}

xnu::KmodInfo* DarwinKit::findKmodInfo(const char* kextname) {
    xnu::KmodInfo* kmod;

    if (!kextKmods)
        return nullptr;

    for (kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (strcmp(kmod->name, kextname) == 0) {
            return kmod;
        }
    }

    return nullptr;
}

void* DarwinKit::findOSKextByIdentifier(const char* kextidentifier) {
    void* (*lookupKextWithIdentifier)(const char*);

    typedef void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);

    lookupKextWithIdentifier = reinterpret_cast<__ZN6OSKext24lookupKextWithIdentifierEPKc>(
        kernel->getSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc"));

    void* OSKext = lookupKextWithIdentifier(kextidentifier);

    return OSKext;
}

} // namespace darwin