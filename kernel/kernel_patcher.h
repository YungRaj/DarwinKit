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
    explicit KernelPatcher();
    explicit KernelPatcher(xnu::Kernel* kernel);

    ~KernelPatcher();

    xnu::Kernel* getKernel() {
        return kernel;
    }

    xnu::KmodInfo** getKextKmods() {
        return kextKmods;
    }

    darwin::Hook* getCopyClientEntitlementHook() {
        return copyClientEntitlementHook;
    }
    darwin::Hook* getHasEntitlementHook() {
        return hasEntitlementHook;
    }
    darwin::Hook* getBinaryLoadHook() {
        return binaryLoadHook;
    }
    darwin::Hook* getKextLoadHook() {
        return kextLoadHook;
    }

    void initialize();

    static bool dummyBreakpoint(union arch::RegisterState* state);

    static void onOSKextSaveLoadedKextPanicList();

    static void* OSKextLookupKextWithIdentifier(const char* identifier);

    static OSObject* copyClientEntitlement(task_t task, const char* entitlement);

    static bool IOCurrentTaskHasEntitlement(const char *entitlement);

    static void taskSetMainThreadQos(task_t task, thread_t thread);

    virtual void findAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                const void* replace, Size replace_size);

    virtual void routeFunction(darwin::Hook* hook);

    virtual void onKextLoad(void* kext, xnu::KmodInfo* kmod);

    virtual void onExec(task_t task, const char* path, Size len);

    virtual void onEntitlementRequest(task_t task, const char* entitlement, void* original);

    darwin::Hook* installDummyBreakpoint();

    darwin::Hook* installCopyClientEntitlementHook();
    darwin::Hook* installHasEntitlementHook();
    darwin::Hook* installBinaryLoadHook();
    darwin::Hook* installKextLoadHook();

    void registerCallbacks();

    void processAlreadyLoadedKexts();

    void processKext(xnu::KmodInfo* kmod, bool loaded);

    xnu::Mach::VmAddress injectPayload(xnu::Mach::VmAddress address, darwin::Payload* payload);

    xnu::Mach::VmAddress injectSegment(xnu::Mach::VmAddress address, darwin::Payload* payload);

    void applyKernelPatch(struct KernelPatch* patch);
    void applyKextPatch(struct KextPatch* patch);

    void patchPmapEnterOptions();

    void removeKernelPatch(struct KernelPatch* patch);
    void removeKextPatch(struct KextPatch* patch);

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
