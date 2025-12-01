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
      kextKmods(reinterpret_cast<xnu::KmodInfo**>(kernel->GetSymbolAddressByName("_kmod"))),
      platformArchitecture(arch::GetCurrentArchitecture()) {
    kernel->SetDarwinKit(this);
    RegisterCallbacks();
    kernelPatcher = new KernelPatcher(kernel);
    architecture = arch::InitArchitecture();
}

void DarwinKit::RegisterCallbacks() {
    RegisterEntitlementCallback(
        (void*)this, [](void* user, task_t task, const char* entitlement, void* original) {
            static_cast<DarwinKit*>(user)->OnEntitlementRequest(task, entitlement, original);
        });
    RegisterBinaryLoadCallback(
        (void*)this, [](void* user, task_t task, const char* path, Size len) {
            static_cast<DarwinKit*>(user)->OnProcLoad(task, path, len);
        });
    RegisterKextLoadCallback((void*)this, [](void* user, void* kext, xnu::KmodInfo* kmod) {
        static_cast<DarwinKit*>(user)->OnKextLoad(kext, kmod);
    });
}

void DarwinKit::RegisterEntitlementCallback(void* user, EntitlementCallback callback) {
    StoredPair<EntitlementCallback>* pair =
        StoredPair<EntitlementCallback>::create(callback, user);
    entitlementCallbacks.push_back(pair);
}

void DarwinKit::RegisterBinaryLoadCallback(void* user, BinaryLoadCallback callback) {
    StoredPair<BinaryLoadCallback>* pair =
        StoredPair<BinaryLoadCallback>::create(callback, user);
    binaryLoadCallbacks.push_back(pair);
}

void DarwinKit::RegisterKextLoadCallback(void* user, KextLoadCallback callback) {
    StoredPair<KextLoadCallback>* pair = StoredPair<KextLoadCallback>::create(callback, user);
    kextLoadCallbacks.push_back(pair);
}

Kext* DarwinKit::GetKextByIdentifier(char* name) {
    std::vector<Kext*>& kexts = GetKexts();
    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);
        if (strcmp(kext->GetName(), name) == 0) {
            return kext;
        }
    }
    return nullptr;
}

Kext* DarwinKit::GetKextByAddress(xnu::mach::VmAddress address) {
    std::vector<Kext*>& kexts = GetKexts();
    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);
        if (kext->GetAddress() == address) {
            return kext;
        }
    }
    return nullptr;
}

void DarwinKit::OnEntitlementRequest(task_t task, const char* entitlement, void* original) {}

void DarwinKit::OnProcLoad(task_t task, const char* path, Size len) {}

void DarwinKit::OnKextLoad(void* loaded_kext, xnu::KmodInfo* kmod_info) {
    Kext* kext;
    if (loaded_kext && kmod_info->size) {
        kext = new xnu::Kext(GetKernel(), loaded_kext, kmod_info);
    } else {
        kext = new xnu::Kext(GetKernel(), kmod_info->address,
                             reinterpret_cast<char*>(kmod_info->name));
    }
    kexts.push_back(kext);
}

xnu::KmodInfo* DarwinKit::FindKmodInfo(const char* kextname) {
    xnu::KmodInfo* kmod;
    if (!kextKmods) {
        return nullptr;
    }
    for (kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (strcmp(kmod->name, kextname) == 0) {
            return kmod;
        }
    }
    return nullptr;
}

void* DarwinKit::FindOSKextByIdentifier(const char* kextidentifier) {
    void* (*lookupKextWithIdentifier)(const char*);
    typedef void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);
    lookupKextWithIdentifier = reinterpret_cast<__ZN6OSKext24lookupKextWithIdentifierEPKc>(
        kernel->GetSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc"));
    void* OSKext = lookupKextWithIdentifier(kextidentifier);
    return OSKext;
}

} // namespace darwin