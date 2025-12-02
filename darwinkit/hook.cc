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

#include "hook.h"

#include "arch.h"
#include "disassembler.h"
#include "kernel.h"
#include "patcher.h"
#include "payload.h"
#include "task.h"

using namespace xnu;

namespace darwin {

static constexpr UInt64 kBaseKernelAddress = 0xfffffe0000000000;

Hook::Hook(Patcher* patcher, enum HookType hooktype)
    : patcher(patcher), hooktype(hooktype), payload(nullptr),
      architecture(arch::InitArchitecture()) {}

Hook::Hook(Patcher* patcher, enum HookType hooktype, Task* task, xnu::mach::VmAddress from)
    : patcher(patcher), hooktype(hooktype), payload(nullptr), task(task), from(from),
      disassembler(task->GetDisassembler()), architecture(arch::InitArchitecture()) {
    if (hooktype == kHookTypeInstrumentFunction) {
        PrepareHook(task, from);
    }
    if (hooktype == kHookTypeBreakpoint) {
        PrepareBreakpoint(task, from);
    }
}

Hook* Hook::CreateHookForFunction(Task* task, Patcher* patcher, xnu::mach::VmAddress address) {
    Hook* hook;
    std::vector<Hook*>& hooks = patcher->GetHooks();
#ifdef __KERNEL__
    address |= kBaseKernelAddress;
#endif
    for (int i = 0; i < hooks.size(); i++) {
        hook = hooks.at(i);
        if (hook->GetFrom() == address && hook->GetHookType() == kHookTypeInstrumentFunction) {
            return hook;
        }
    }
    hook = new Hook(patcher, kHookTypeInstrumentFunction);
    hook->PrepareHook(task, address);
    return hook;
}

Hook* Hook::CreateHookForFunction(void* target, xnu::Task* task, darwin::Patcher* patcher,
                                  xnu::mach::VmAddress address) {
    Hook* hook = Hook::CreateHookForFunction(task, patcher, address);
#ifdef __KERNEL__
    address |= kBaseKernelAddress;
#endif
    hook->SetTarget(target);
    return hook;
}

Hook* Hook::CreateBreakpointForAddress(Task* task, Patcher* patcher, xnu::mach::VmAddress address) {
    Hook* hook;
    std::vector<Hook*>& hooks = patcher->GetHooks();
#ifdef __KERNEL__
    address |= kBaseKernelAddress;
#endif
    for (int i = 0; i < hooks.size(); i++) {
        hook = hooks.at(i);
        if (hook->GetFrom() == address && hook->GetHookType() == kHookTypeBreakpoint) {
            return hook;
        }
    }
    hook = new Hook(patcher, kHookTypeBreakpoint);
    hook->PrepareBreakpoint(task, address);
    return hook;
}

Hook* Hook::CreateBreakpointForAddress(void* target, Task* task, Patcher* patcher,
                                       xnu::mach::VmAddress address) {
    Hook* hook = Hook::CreateBreakpointForAddress(task, patcher, address);
    hook->SetTarget(target);
    return hook;
}

void Hook::PrepareHook(Task* task, xnu::mach::VmAddress from) {
#ifdef __KERNEL__
    from |= kBaseKernelAddress;
#endif
    SetTask(task);
    SetFrom(from);
    SetDisassembler(task->GetDisassembler());
}

void Hook::PrepareBreakpoint(Task* task, xnu::mach::VmAddress breakpoint) {
#ifdef __KERNEL__
    breakpoint |= kBaseKernelAddress;
#endif
    SetHookType(kHookTypeBreakpoint);
    SetTask(task);
    SetFrom(breakpoint);
    SetDisassembler(task->GetDisassembler());
}

struct HookPatch* Hook::GetLatestRegisteredHook() {
    std::vector<struct HookPatch*>& hooks = GetHooks();
    if (hooks.size() == 0) {
        return nullptr;
    }
    return hooks.at((int)(hooks.size() - 1));
}

xnu::mach::VmAddress Hook::GetTrampolineFromChain(xnu::mach::VmAddress addr) {
    std::vector<struct HookPatch*>& hooks = GetHooks();
#ifdef __KERNEL__
    addr |= kBaseKernelAddress;
#endif
    for (int i = 0; i < hooks.size(); i++) {
        struct HookPatch* patch = hooks.at(i);
        xnu::mach::VmAddress tramp = patch->trampoline;
#ifdef __arm64__
        __asm__ volatile("PACIZA %[pac]" : [pac] "+rm"(tramp));
#endif
        if (patch->to == addr) {
            return tramp;
        }
    }
    return 0;
}

enum HookType Hook::GetHookTypeForCallback(xnu::mach::VmAddress callback) {
    for (int i = 0; i < GetCallbacks().size(); i++) {
        auto pair = GetCallbacks().at(i);
        xnu::mach::VmAddress cb = pair->first;
        if (callback == cb) {
            return pair->second;
        }
    }
    return kHookTypeNone;
}

Payload* Hook::PrepareTrampoline() {
    if (payload) {
        return payload;
    }
    payload = new Payload(GetTask(), this, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    payload->Prepare();
    return payload;
}

void Hook::RegisterHook(struct HookPatch* patch) {
    hooks.push_back(patch);
}

void Hook::RegisterCallback(xnu::mach::VmAddress callback, enum HookType hooktype) {
    HookCallbackPair<xnu::mach::VmAddress, enum HookType>* pair =
        HookCallbackPair<xnu::mach::VmAddress, enum HookType>::create(callback, hooktype);
    callbacks.push_back(pair);
}

void Hook::HookFunction(xnu::mach::VmAddress to, enum HookType hooktype) {
    struct HookPatch* hook = new HookPatch;
    Architecture* architecture = GetArchitecture();
    Disassembler* disassembler = GetDisassembler();
    Patcher* patcher = GetPatcher();
    PrepareTrampoline();
    struct HookPatch* chain = GetLatestRegisteredHook();
    xnu::mach::VmAddress tramp;
#if __KERNEL__
    to |= kBaseKernelAddress;
#endif
    // If we don't have any entries in the chain
    // Then we start at the payload's starting point
    // If we have entries in the chain, then start at the correct offset
    if (!chain) {
        tramp = trampoline = payload->GetAddress();
    } else {
        tramp = payload->GetAddress() + payload->GetCurrentOffset();
    }
    Size min;
    Size branch_size;
    xnu::mach::VmAddress chain_addr = chain ? chain->to : from;
    branch_size = architecture->GetBranchSize();
    min = disassembler->InstructionSize(chain_addr, branch_size);
    if (!min) {
        DARWIN_KIT_LOG("Cannot hook! Capstone failed!\n");
        return;
    }
    UInt8* original_opcodes;
    UInt8* replace_opcodes;
    original_opcodes = new UInt8[min];
    task->Read(chain_addr, (void*)original_opcodes, min);
    payload->WriteBytes(original_opcodes, min);
    union Branch to_hook_function;
    // Builds the FunctionPatch branch/jmp instruction from original function to hooked function
    // If the function is hooked more than once, then original = previous hook
    architecture->MakeBranch(&to_hook_function, to, chain_addr);
    replace_opcodes = new UInt8[branch_size];
    memcpy(replace_opcodes, (void*)&to_hook_function, branch_size);
    union Branch to_original_function;
    // Builds the FunctionPatch branch/jmp instruction from trampoline to original function
    architecture->MakeBranch(&to_original_function, chain_addr + min,
                             payload->GetAddress() + payload->GetCurrentOffset());

    payload->WriteBytes((UInt8*)&to_original_function, branch_size);
    task->Write(chain_addr, (void*)&to_hook_function, branch_size);
    payload->Commit();

    hook->from = chain_addr;
    hook->to = to;
    hook->trampoline = tramp;
    hook->patch = to_hook_function;
    hook->payload = payload;
    hook->type = hooktype;
    hook->original = original_opcodes;
    hook->replace = replace_opcodes;
    hook->patch_size = branch_size;
    RegisterHook(hook);
}

void Hook::UninstallHook() {}

void Hook::AddBreakpoint(xnu::mach::VmAddress breakpoint_hook, enum HookType hooktype) {
    struct HookPatch* hook = new HookPatch;
    Architecture* architecture = GetArchitecture();
    Disassembler* disassembler = GetDisassembler();
    Patcher* patcher = GetPatcher();
    PrepareTrampoline();
    xnu::mach::VmAddress tramp;
    tramp = payload->GetAddress() + payload->GetCurrentOffset();
    Size min;
    Size branch_size;
    xnu::mach::VmAddress chain_addr = from;
    branch_size = architecture->GetBranchSize();
    min = disassembler->InstructionSize(chain_addr, branch_size);
    UInt8* original_opcodes;
    UInt8* replace_opcodes;
    original_opcodes = new UInt8[min];
    task->Read(chain_addr, (void*)original_opcodes, min);
    union Branch to_trampoline;
    // Builds the FunctionPatch branch/jmp instruction from original function to hooked function
    // If the function is hooked more than once, then original = previous hook
    architecture->MakeBranch(&to_trampoline, tramp, chain_addr);
    replace_opcodes = new UInt8[branch_size];
    memcpy(replace_opcodes, (void*)&to_trampoline, branch_size);
    Size breakpoint_size = architecture->GetBreakpointSize();
    if (breakpoint_hook) {
        // Sets a conditional breakpoint
        union FunctionCall call_breakpoint_hook;
        union Breakpoint breakpoint;
        Size call_size = architecture->GetCallSize();
        payload->WriteBytes((UInt8*)push_registers,
                            (Size)((UInt8*)push_registers_end - (UInt8*)push_registers));
        payload->WriteBytes((UInt8*)set_argument,
                            (Size)((UInt8*)set_argument_end - (UInt8*)set_argument));
        architecture->MakeCall(&call_breakpoint_hook, breakpoint_hook,
                               payload->GetAddress() + payload->GetCurrentOffset());
        payload->WriteBytes((UInt8*)&call_breakpoint_hook, call_size);
        payload->WriteBytes((UInt8*)check_breakpoint,
                            (Size)((UInt8*)check_breakpoint_end - (UInt8*)check_breakpoint));
        architecture->MakeBreakpoint(&breakpoint);
        payload->WriteBytes((UInt8*)&breakpoint, breakpoint_size);
        payload->WriteBytes((UInt8*)pop_registers,
                            (Size)((UInt8*)pop_registers_end - (UInt8*)pop_registers));
    } else {
        // Breaks regardless
        union Breakpoint breakpoint;
        payload->WriteBytes((UInt8*)push_registers,
                            (Size)((UInt8*)push_registers_end - (UInt8*)push_registers));
        architecture->MakeBreakpoint(&breakpoint);
        payload->WriteBytes((UInt8*)&breakpoint, breakpoint_size);
        payload->WriteBytes((UInt8*)pop_registers,
                            (Size)((UInt8*)pop_registers_end - (UInt8*)pop_registers));
    }
    union Branch to_original_function;
    // Builds the FunctionPatch branch/jmp instruction from trampoline to original function
    payload->WriteBytes(original_opcodes, min);
    architecture->MakeBranch(&to_original_function, chain_addr + min,
                             payload->GetAddress() + payload->GetCurrentOffset());
    payload->WriteBytes((UInt8*)&to_original_function, branch_size);
    task->Write(chain_addr, (void*)replace_opcodes, branch_size);
    payload->Commit();

    hook->from = chain_addr;
    hook->to = tramp;
    hook->trampoline = tramp;
    hook->patch = to_trampoline;
    hook->payload = payload;
    hook->type = hooktype;
    hook->original = original_opcodes;
    hook->replace = replace_opcodes;
    hook->patch_size = branch_size;
    RegisterHook(hook);
}

void Hook::RemoveBreakpoint() {}

} // namespace darwin