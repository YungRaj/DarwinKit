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

    xnu::Kernel* GetKernel() {
        return kernel;
    }

    arch::Architecture* GetArchitecture() {
        return architecture;
    }

    enum arch::Architectures GetPlatformArchitecture() {
        return platformArchitecture;
    }

    std::vector<xnu::Kext*>& GetKexts() {
        return kexts;
    }

    xnu::Kext* GetKextByIdentifier(char* name);

    xnu::Kext* GetKextByAddress(xnu::mach::VmAddress address);

    darwin::KernelPatcher* GetKernelPatcher() {
        return kernelPatcher;
    }

    darwin::Plugin* GetPlugin(const char* pluginName) {
        for (int i = 0; i < plugins.size(); i++) {
            darwin::Plugin* plugin = plugins.at(i);

            if (strcmp(plugin->GetProduct(), pluginName) == 0)
                return plugin;
        }

        return nullptr;
    }

    void InstallPlugin(darwin::Plugin* plugin) {
        plugins.push_back(plugin);
    }

    StoredArray<EntitlementCallback>& GetEntitlementCallbacks() {
        return entitlementCallbacks;
    }

    StoredArray<BinaryLoadCallback>& GetBinaryLoadCallbacks() {
        return binaryLoadCallbacks;
    }

    StoredArray<KextLoadCallback>& GetKextLoadCallbacks() {
        return kextLoadCallbacks;
    }

    void RegisterCallbacks();

    void RegisterEntitlementCallback(void* user, EntitlementCallback callback);

    void RegisterBinaryLoadCallback(void* user, BinaryLoadCallback callback);

    void RegisterKextLoadCallback(void* user, KextLoadCallback callback);

    void OnEntitlementRequest(task_t task, const char* entitlement, void* original);

    void OnProcLoad(task_t task, const char* path, Size len);

    void OnKextLoad(void* kext, xnu::KmodInfo* kmod);

    xnu::KmodInfo* FindKmodInfo(const char* kextname);

    void* FindOSKextByIdentifier(const char* kextidentifier);

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
