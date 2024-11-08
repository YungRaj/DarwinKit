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

using namespace Arch;
using namespace xnu;

namespace mrk {

DarwinKit::DarwinKit(xnu::Kernel* kernel)
    : kernel(kernel),
      kextKmods(reinterpret_cast<xnu::KmodInfo**>(kernel->getSymbolAddressByName("_kmod"))),
      platformArchitecture(Arch::getCurrentArchitecture()) {
    kernel->setRootKit(this);

    this->registerCallbacks();

    kernelPatcher = new KernelPatcher(this->kernel);

    architecture = Arch::initArchitecture();
}

DarwinKit::~DarwinKit() {}

void DarwinKit::registerCallbacks() {
    this->registerEntitlementCallback(
        (void*)this, [](void* user, task_t task, const char* entitlement, void* original) {
            static_cast<DarwinKit*>(user)->onEntitlementRequest(task, entitlement, original);
        });

    this->registerBinaryLoadCallback(
        (void*)this, [](void* user, task_t task, const char* path, Size len) {
            static_cast<DarwinKit*>(user)->onProcLoad(task, path, len);
        });

    this->registerKextLoadCallback((void*)this, [](void* user, void* kext, xnu::KmodInfo* kmod) {
        static_cast<DarwinKit*>(user)->onKextLoad(kext, kmod);
    });
}

void DarwinKit::registerEntitlementCallback(void* user, entitlement_callback_t callback) {
    StoredPair<entitlement_callback_t>* pair =
        StoredPair<entitlement_callback_t>::create(callback, user);

    this->entitlementCallbacks.push_back(pair);
}

void DarwinKit::registerBinaryLoadCallback(void* user, binaryload_callback_t callback) {
    StoredPair<binaryload_callback_t>* pair =
        StoredPair<binaryload_callback_t>::create(callback, user);

    this->binaryLoadCallbacks.push_back(pair);
}

void DarwinKit::registerKextLoadCallback(void* user, kextload_callback_t callback) {
    StoredPair<kextload_callback_t>* pair = StoredPair<kextload_callback_t>::create(callback, user);

    this->kextLoadCallbacks.push_back(pair);
}

Kext* DarwinKit::getKextByIdentifier(char* name) {
    std::vector<Kext*>& kexts = this->getKexts();

    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);

        if (strcmp(kext->getName(), name) == 0) {
            return kext;
        }
    }

    return NULL;
}

Kext* DarwinKit::getKextByAddress(xnu::Mach::VmAddress address) {
    std::vector<Kext*>& kexts = this->getKexts();

    for (int i = 0; i < kexts.size(); i++) {
        Kext* kext = kexts.at(i);

        if (kext->getAddress() == address) {
            return kext;
        }
    }

    return NULL;
}

void DarwinKit::onEntitlementRequest(task_t task, const char* entitlement, void* original) {}

void DarwinKit::onProcLoad(task_t task, const char* path, Size len) {}

void DarwinKit::onKextLoad(void* loaded_kext, xnu::KmodInfo* kmod_info) {
    Kext* kext;

    if (loaded_kext && kmod_info->size) {
        kext = new xnu::Kext(this->getKernel(), loaded_kext, kmod_info);
    } else {
        kext = new xnu::Kext(this->getKernel(), kmod_info->address,
                             reinterpret_cast<char*>(&kmod_info->name));
    }

    kexts.push_back(kext);
}

xnu::KmodInfo* DarwinKit::findKmodInfo(const char* kextname) {
    xnu::KmodInfo* kmod;

    if (!kextKmods)
        return NULL;

    for (kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (strcmp(kmod->name, kextname) == 0) {
            return kmod;
        }
    }

    return NULL;
}

void* DarwinKit::findOSKextByIdentifier(const char* kextidentifier) {
    void* (*lookupKextWithIdentifier)(const char*);

    typedef void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);

    lookupKextWithIdentifier = reinterpret_cast<__ZN6OSKext24lookupKextWithIdentifierEPKc>(
        this->kernel->getSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc"));

    void* OSKext = lookupKextWithIdentifier(kextidentifier);

    return OSKext;
}

} // namespace mrk