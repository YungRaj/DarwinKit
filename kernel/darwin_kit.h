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

#include "arch.h"

#include "kernel.h"
#include "kernel_patcher.h"

#include "plugin.h"

#include "kext.h"

#include <string.h>

namespace xnu {
class Kext;
class Kernel;
} // namespace xnu

using namespace xnu;

class IOKernelDarwinKitService;

namespace darwin {
class Hook;

template <typename T, typename Y = void*>
using StoredPair = Pair<T, Y>;

template <typename T, typename Y = void*>
using StoredArray = std::vector<StoredPair<T, Y>*>;

class DarwinKit {
public:
    using EntitlementCallback = void (*)(void* user, task_t task, const char* entitlement,
                                            void* original);
    using BinaryLoadCallback = void (*)(void* user, task_t task, const char* path, Size len);
    using KextLoadCallback = void (*)(void* user, void* kext, xnu::KmodInfo* kmod_info);

public:
    explicit DarwinKit(xnu::Kernel* kernel);

    ~DarwinKit() = default;

    xnu::Kernel* getKernel() {
        return kernel;
    }

    arch::Architecture* getArchitecture() {
        return architecture;
    }

    enum arch::Architectures getPlatformArchitecture() {
        return platformArchitecture;
    }

    std::vector<xnu::Kext*>& getKexts() {
        return kexts;
    }

    xnu::Kext* getKextByIdentifier(char* name);

    xnu::Kext* getKextByAddress(xnu::Mach::VmAddress address);

    darwin::KernelPatcher* getKernelPatcher() {
        return kernelPatcher;
    }

    darwin::Plugin* getPlugin(const char* pluginName) {
        for (int i = 0; i < plugins.size(); i++) {
            darwin::Plugin* plugin = plugins.at(i);

            if (strcmp(plugin->getProduct(), pluginName) == 0)
                return plugin;
        }

        return nullptr;
    }

    void installPlugin(darwin::Plugin* plugin) {
        plugins.push_back(plugin);
    }

    StoredArray<EntitlementCallback>& getEntitlementCallbacks() {
        return entitlementCallbacks;
    }

    StoredArray<BinaryLoadCallback>& getBinaryLoadCallbacks() {
        return binaryLoadCallbacks;
    }

    StoredArray<KextLoadCallback>& getKextLoadCallbacks() {
        return kextLoadCallbacks;
    }

    void registerCallbacks();

    void registerEntitlementCallback(void* user, EntitlementCallback callback);

    void registerBinaryLoadCallback(void* user, BinaryLoadCallback callback);

    void registerKextLoadCallback(void* user, KextLoadCallback callback);

    void onEntitlementRequest(task_t task, const char* entitlement, void* original);

    void onProcLoad(task_t task, const char* path, Size len);

    void onKextLoad(void* kext, xnu::KmodInfo* kmod);

    xnu::KmodInfo* findKmodInfo(const char* kextname);

    void* findOSKextByIdentifier(const char* kextidentifier);

private:
    arch::Architecture* architecture;

    xnu::Kernel* kernel;

    darwin::KernelPatcher* kernelPatcher;

    enum arch::Architectures platformArchitecture;

    bool waitingForAlreadyLoadedKexts;

    std::vector<xnu::Kext*> kexts;

    xnu::KmodInfo** kextKmods;

    std::vector<darwin::Plugin*> plugins;

    StoredArray<EntitlementCallback> entitlementCallbacks;

    StoredArray<BinaryLoadCallback> binaryLoadCallbacks;

    StoredArray<KextLoadCallback> kextLoadCallbacks;
};
} // namespace darwin
