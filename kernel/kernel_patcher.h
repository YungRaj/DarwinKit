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

#include <IOKit/IOLib.h>
#include <mach/kmod.h>
#include <mach/mach_types.h>

#include <types.h>

#include "arch.h"
#include "patcher.h"

namespace xnu {
class Kernel;
class Kext;
} // namespace xnu

class MachO;
class Symbol;

struct KextPatch {
public:
    xnu::Kext* kext;

    MachO* macho;
    Symbol* symbol;

    const UInt8* find;
    const UInt8* replace;

    Size size;
    Size count;

    Offset offset;
};

struct KernelPatch {
public:
    xnu::Kernel* kernel;

    MachO* macho;
    Symbol* symbol;

    const UInt8* find;
    const UInt8* replace;

    Size size;
    Size count;

    Offset offset;
};

extern KernelPatch kernelPatches[];
extern KextPatch kextPatches[];

namespace darwin {
class Hook;
class Payload;

class KernelPatcher : public darwin::Patcher {
public:
    explicit KernelPatcher() = default;
    explicit KernelPatcher(xnu::Kernel* kernel);

    ~KernelPatcher() = default;

    xnu::Kernel* GetKernel() {
        return kernel;
    }

    xnu::KmodInfo** GetKextKmods() {
        return kextKmods;
    }

    darwin::Hook* GetCopyClientEntitlementHook() {
        return copyClientEntitlementHook;
    }
    darwin::Hook* GetHasEntitlementHook() {
        return hasEntitlementHook;
    }
    darwin::Hook* GetBinaryLoadHook() {
        return binaryLoadHook;
    }
    darwin::Hook* GetKextLoadHook() {
        return kextLoadHook;
    }

    void Initialize();

    static bool DummyBreakpoint(union arch::RegisterState* state);

    static void OnOSKextSaveLoadedKextPanicList();

    static void* OSKextLookupKextWithIdentifier(const char* identifier);

    static OSObject* CopyClientEntitlement(task_t task, const char* entitlement);

    static bool IOCurrentTaskHasEntitlement(const char* entitlement);

    static void TaskSetMainThreadQos(task_t task, thread_t thread);

    virtual void FindAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                const void* replace, Size replace_size);

    virtual void RouteFunction(darwin::Hook* hook);

    virtual void OnKextLoad(void* kext, xnu::KmodInfo* kmod);

    virtual void OnExec(task_t task, const char* path, Size len);

    virtual void OnEntitlementRequest(task_t task, const char* entitlement, void* original);

    darwin::Hook* InstallDummyBreakpoint();

    darwin::Hook* InstallCopyClientEntitlementHook();
    darwin::Hook* InstallHasEntitlementHook();
    darwin::Hook* InstallBinaryLoadHook();
    darwin::Hook* InstallKextLoadHook();

    void RegisterCallbacks();

    void ProcessAlreadyLoadedKexts();

    void ProcessKext(xnu::KmodInfo* kmod, bool loaded);

    xnu::mach::VmAddress InjectPayload(xnu::mach::VmAddress address, darwin::Payload* payload);

    xnu::mach::VmAddress InjectSegment(xnu::mach::VmAddress address, darwin::Payload* payload);

    void ApplyKernelPatch(struct KernelPatch* patch);
    void ApplyKextPatch(struct KextPatch* patch);

    void PatchPmapEnterOptions();

    void RemoveKernelPatch(struct KernelPatch* patch);
    void RemoveKextPatch(struct KextPatch* patch);

private:
    xnu::Kernel* kernel;
    xnu::KmodInfo** kextKmods;

    darwin::Hook* copyClientEntitlementHook;
    darwin::Hook* hasEntitlementHook;
    darwin::Hook* binaryLoadHook;
    darwin::Hook* kextLoadHook;

    bool waitingForAlreadyLoadedKexts = false;

    std::vector<struct KernelPatch*> kernelPatches;
    std::vector<struct KextPatch*> kextPatches;
};

}; // namespace darwin
