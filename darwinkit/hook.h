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
    xnu::mach::VmAddress to;
    xnu::mach::VmAddress from;

    xnu::mach::VmAddress trampoline;

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
                  xnu::mach::VmAddress from);

    ~Hook() = default;

    static Hook* CreateHookForFunction(xnu::Task* task, darwin::Patcher* patcher,
                                      xnu::mach::VmAddress address);
    static Hook* CreateHookForFunction(void* target, xnu::Task* task, darwin::Patcher* patcher,
                                      xnu::mach::VmAddress address);

    static Hook* CreateBreakpointForAddress(xnu::Task* task, darwin::Patcher* patcher,
                                            xnu::mach::VmAddress address);
    static Hook* CreateBreakpointForAddress(void* target, xnu::Task* task, darwin::Patcher* patcher,
                                           xnu::mach::VmAddress address);

    void* GetTarget() {
        return target;
    }

    darwin::Patcher* GetPatcher() {
        return patcher;
    }

    xnu::Task* GetTask() {
        return task;
    }

    Architecture* GetArchitecture() {
        return architecture;
    }

    Disassembler* GetDisassembler() {
        return disassembler;
    }

    xnu::mach::VmAddress GetFrom() {
        return from;
    }

    struct HookPatch* GetLatestRegisteredHook();

    xnu::mach::VmAddress GetTrampoline() {
        return trampoline;
    }

    xnu::mach::VmAddress GetTrampolineFromChain(xnu::mach::VmAddress address);

    HookArray<struct HookPatch*>& GetHooks() {
        return hooks;
    }

    HookCallbackArray<xnu::mach::VmAddress>& GetCallbacks() {
        return callbacks;
    }

    enum HookType GetHookType() {
        return hooktype;
    }

    enum HookType GetHookTypeForCallback(xnu::mach::VmAddress callback);

    void SetTarget(void* targ) {
        target = targ;
    }

    void SetPatcher(Patcher* p) {
        patcher = p;
    }

    void SetDisassembler(Disassembler* disasm) {
        disassembler = disasm;
    }

    void SetTask(Task* t) {
        task = t;
    }

    void SetFrom(xnu::mach::VmAddress f) {
        from = f;
    }

    void SetTrampoline(xnu::mach::VmAddress tramp) {
        trampoline = tramp;
    }

    void SetHookType(enum HookType type) {
        hooktype = type;
    }

    void PrepareHook(xnu::Task* task, xnu::mach::VmAddress from);
    void PrepareBreakpoint(xnu::Task* task, xnu::mach::VmAddress breakpoint);

    darwin::Payload* PrepareTrampoline();

    void RegisterHook(struct HookPatch* patch);

    void RegisterCallback(xnu::mach::VmAddress callback,
                          enum HookType hooktype = kHookTypeCallback);

    void HookFunction(xnu::mach::VmAddress to,
                      enum HookType hooktype = kHookTypeInstrumentFunction);

    void UninstallHook();

    void AddBreakpoint(xnu::mach::VmAddress breakpoint_hook,
                       enum HookType hooktype = kHookTypeBreakpoint);

    void RemoveBreakpoint();

private:
    void* target;
    darwin::Patcher* patcher;
    xnu::Task* task;
    arch::Architecture* architecture;
    Disassembler* disassembler;
    darwin::Payload* payload;

    bool kernel_hook = false;
    xnu::mach::VmAddress from;
    xnu::mach::VmAddress trampoline;
    enum HookType hooktype;

    HookCallbackArray<xnu::mach::VmAddress> callbacks;
    HookArray<struct HookPatch*> hooks;
};

} // namespace darwin
