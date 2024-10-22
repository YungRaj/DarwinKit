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

#include "kernel.h"
#include "patcher.h"

#include "arch.h"

#include "vector.h"

#include <types.h>

#include <arm64/isa_arm64.h>
#include <x86_64/isa_x86_64.h>

namespace darwin {
class MacRootKit;

class Patcher;

class Payload;
}; // namespace darwin

namespace xnu {
class Kernel;
class Kext;

class Task;
} // namespace xnu

using namespace arch;

enum HookType {
    kHookTypeNone,
    kHookTypeBreakpoint,
    kHookTypeCallback,
    kHookTypeInstrumentFunction,
    kHookTypeReplaceFunction,
};

struct HookPatch {
    xnu::Mach::VmAddress to;
    xnu::Mach::VmAddress from;

    xnu::Mach::VmAddress trampoline;

    enum HookType type;

    union Branch patch;

    darwin::Payload* payload;

    UInt8* original;
    UInt8* replace;

    Size patch_size;
};

template <typename T, typename Y = enum HookType>
using HookCallbackPair = Pair<T, Y>;

template <typename T, typename Y = enum HookType>
using HookCallbackArray = std::vector<HookCallbackPair<T, Y>*>;

template <typename T = struct HookPatch*>
using HookArray = std::vector<T>;

namespace darwin {
class Hook {
public:
    explicit Hook(darwin::Patcher* patcher, enum HookType hooktype);
    explicit Hook(darwin::Patcher* patcher, enum HookType hooktype, xnu::Task* task,
                  xnu::Mach::VmAddress from);

    static Hook* hookForFunction(xnu::Task* task, darwin::Patcher* patcher,
                                 xnu::Mach::VmAddress address);
    static Hook* hookForFunction(void* target, xnu::Task* task, darwin::Patcher* patcher,
                                 xnu::Mach::VmAddress address);

    static Hook* breakpointForAddress(xnu::Task* task, darwin::Patcher* patcher,
                                      xnu::Mach::VmAddress address);
    static Hook* breakpointForAddress(void* target, xnu::Task* task, darwin::Patcher* patcher,
                                      xnu::Mach::VmAddress address);

    void* getTarget() {
        return target;
    }

    darwin::Patcher* getPatcher() {
        return patcher;
    }

    xnu::Task* getTask() {
        return task;
    }

    Architecture* getArchitecture() {
        return architecture;
    }

    Disassembler* getDisassembler() {
        return disassembler;
    }

    xnu::Mach::VmAddress getFrom() {
        return from;
    }

    struct HookPatch* getLatestRegisteredHook();

    xnu::Mach::VmAddress getTrampoline() {
        return trampoline;
    }

    xnu::Mach::VmAddress getTrampolineFromChain(xnu::Mach::VmAddress address);

    HookArray<struct HookPatch*>& getHooks() {
        return hooks;
    }

    HookCallbackArray<xnu::Mach::VmAddress>& getCallbacks() {
        return callbacks;
    }

    enum HookType getHookType() {
        return hooktype;
    }

    enum HookType getHookTypeForCallback(xnu::Mach::VmAddress callback);

    void setTarget(void* target) {
        target = target;
    }

    void setPatcher(Patcher* patcher) {
        patcher = patcher;
    }

    void setDisassembler(Disassembler* disassembler) {
        disassembler = disassembler;
    }

    void setTask(Task* task) {
        task = task;
    }

    void setFrom(xnu::Mach::VmAddress from) {
        from = from;
    }

    void setTrampoline(xnu::Mach::VmAddress trampoline) {
        trampoline = trampoline;
    }

    void setHookType(enum HookType hooktype) {
        hooktype = hooktype;
    }

    void prepareHook(xnu::Task* task, xnu::Mach::VmAddress from);
    void prepareBreakpoint(xnu::Task* task, xnu::Mach::VmAddress breakpoint);

    darwin::Payload* prepareTrampoline();

    void registerHook(struct HookPatch* patch);

    void registerCallback(xnu::Mach::VmAddress callback,
                          enum HookType hooktype = kHookTypeCallback);

    void hookFunction(xnu::Mach::VmAddress to,
                      enum HookType hooktype = kHookTypeInstrumentFunction);

    void uninstallHook();

    void addBreakpoint(xnu::Mach::VmAddress breakpoint_hook,
                       enum HookType hooktype = kHookTypeBreakpoint);

    void removeBreakpoint();

private:
    void* target;

    darwin::Patcher* patcher;

    xnu::Task* task;

    arch::Architecture* architecture;

    Disassembler* disassembler;

    darwin::Payload* payload;

    bool kernelHook = false;

    xnu::Mach::VmAddress from;
    xnu::Mach::VmAddress trampoline;

    enum HookType hooktype;

    HookCallbackArray<xnu::Mach::VmAddress> callbacks;

    HookArray<struct HookPatch*> hooks;
};

} // namespace darwin
