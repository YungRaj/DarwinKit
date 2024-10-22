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

#include "patcher.h"
#include "payload.h"

#include "disassembler.h"

#include "kernel.h"
#include "task.h"

#include "arch.h"

using namespace darwin;
using namespace xnu;

Hook::Hook(Patcher* patcher, enum HookType hooktype)
    : patcher(patcher), hooktype(hooktype), payload(nullptr),
      architecture(arch::initArchitecture()) {}

Hook::Hook(Patcher* patcher, enum HookType hooktype, Task* task, xnu::Mach::VmAddress from)
    : patcher(patcher), hooktype(hooktype), payload(nullptr), task(task), from(from),
      disassembler(task->getDisassembler()), architecture(arch::initArchitecture()) {
    if (hooktype == kHookTypeInstrumentFunction)
        prepareHook(task, from);
    if (hooktype == kHookTypeBreakpoint)
        prepareBreakpoint(task, from);
}

Hook* Hook::hookForFunction(Task* task, Patcher* patcher, xnu::Mach::VmAddress address) {
    Hook* hook;

    std::vector<Hook*>& hooks = patcher->getHooks();

    for (int i = 0; i < hooks.size(); i++) {
        hook = hooks.at(i);

        if (hook->getFrom() == address && hook->getHookType() == kHookTypeInstrumentFunction) {
            return hook;
        }
    }

    hook = new Hook(patcher, kHookTypeInstrumentFunction);

    hook->prepareHook(task, address);

    return hook;
}

Hook* Hook::hookForFunction(void* target, xnu::Task* task, darwin::Patcher* patcher,
                            xnu::Mach::VmAddress address) {
    Hook* hook = Hook::hookForFunction(task, patcher, address);

    hook->setTarget(target);

    return hook;
}

Hook* Hook::breakpointForAddress(Task* task, Patcher* patcher, xnu::Mach::VmAddress address) {
    Hook* hook;

    std::vector<Hook*>& hooks = patcher->getHooks();

    for (int i = 0; i < hooks.size(); i++) {
        hook = hooks.at(i);

        if (hook->getFrom() == address && hook->getHookType() == kHookTypeBreakpoint) {
            return hook;
        }
    }

    hook = new Hook(patcher, kHookTypeBreakpoint);

    hook->prepareBreakpoint(task, address);

    return hook;
}

Hook* Hook::breakpointForAddress(void* target, Task* task, Patcher* patcher,
                                 xnu::Mach::VmAddress address) {
    Hook* hook = Hook::breakpointForAddress(target, task, patcher, address);

    hook->setTarget(target);

    return hook;
}

void Hook::prepareHook(Task* task, xnu::Mach::VmAddress from) {
    setTask(task);
    setFrom(from);
    setDisassembler(task->getDisassembler());
}

void Hook::prepareBreakpoint(Task* task, xnu::Mach::VmAddress breakpoint) {
    setHookType(kHookTypeBreakpoint);
    setTask(task);
    setFrom(breakpoint);
    setDisassembler(task->getDisassembler());
}

struct HookPatch* Hook::getLatestRegisteredHook() {
    std::vector<struct HookPatch*>& hooks = getHooks();

    if (hooks.size() == 0)
        return nullptr;

    return hooks.at((int)(hooks.size() - 1));
}

xnu::Mach::VmAddress Hook::getTrampolineFromChain(xnu::Mach::VmAddress address) {
    std::vector<struct HookPatch*>& hooks = getHooks();

    for (int i = 0; i < hooks.size(); i++) {
        struct HookPatch* patch = hooks.at(i);

        xnu::Mach::VmAddress to = patch->to;
        xnu::Mach::VmAddress trampoline = patch->trampoline;

        if (to == address) {
#ifdef __arm64__

            __asm__ volatile("PACIZA %[pac]" : [pac] "+rm"(trampoline));

#endif

            return trampoline;
        }
    }

    return 0;
}

enum HookType Hook::getHookTypeForCallback(xnu::Mach::VmAddress callback) {
    for (int i = 0; i < getCallbacks().size(); i++) {
        auto pair = getCallbacks().at(i);

        xnu::Mach::VmAddress cb = pair->first;

        if (callback == cb) {
            return pair->second;
        }
    }

    return kHookTypeNone;
}

Payload* Hook::prepareTrampoline() {
    Payload* payload;

    if (payload) {
        return payload;
    }

    payload = payload =
        new Payload(getTask(), this, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    payload->prepare();

    return payload;
}

void Hook::registerHook(struct HookPatch* patch) {
    hooks.push_back(patch);
}

void Hook::registerCallback(xnu::Mach::VmAddress callback, enum HookType hooktype) {
    HookCallbackPair<xnu::Mach::VmAddress, enum HookType>* pair =
        HookCallbackPair<xnu::Mach::VmAddress, enum HookType>::create(callback, hooktype);

    callbacks.push_back(pair);
}

void Hook::hookFunction(xnu::Mach::VmAddress to, enum HookType hooktype) {
    struct HookPatch* hook = new HookPatch;

    Architecture* architecture = getArchitecture();

    Disassembler* disassembler = getDisassembler();

    Patcher* patcher = getPatcher();

    Payload* payload = prepareTrampoline();

    struct HookPatch* chain = getLatestRegisteredHook();

    xnu::Mach::VmAddress trampoline;

    // if we don't have any entries in the chain
    // then we start at the payload's starting point

    // if we have entries in the chain, then start at the correct offset

    if (!chain) {
        trampoline = trampoline = payload->getAddress();
    } else {
        trampoline = payload->getAddress() + payload->getCurrentOffset();
    }

    Size min;

    Size branch_size;

    xnu::Mach::VmAddress from = chain ? chain->to : from;

    branch_size = architecture->getBranchSize();

    min = disassembler->instructionSize(from, branch_size);

    if (!min) {
        DARWIN_RK_LOG("Cannot hook! Capstone failed!\n");

        return;
    }

    UInt8* original_opcodes;
    UInt8* replace_opcodes;

    original_opcodes = new UInt8[min];

    task->read(from, (void*)original_opcodes, min);

    payload->writeBytes(original_opcodes, min);

    union Branch to_hook_function;

    // build the FunctionPatch branch/jmp instruction from original function to hooked function
    // NOTE: if function is hooked more than once, then original = previous hook

    architecture->makeBranch(&to_hook_function, to, from);

    replace_opcodes = new UInt8[branch_size];

    memcpy(replace_opcodes, (void*)&to_hook_function, branch_size);

    union Branch to_original_function;

    // build the FunctionPatch branch/jmp instruction from trampoline to original function

    architecture->makeBranch(&to_original_function, from + min,
                             payload->getAddress() + payload->getCurrentOffset());

    payload->writeBytes((UInt8*)&to_original_function, branch_size);

    task->write(from, (void*)&to_hook_function, branch_size);

    payload->commit();

    hook->from = from;
    hook->to = to;

    hook->trampoline = trampoline;
    hook->patch = to_hook_function;
    hook->payload = payload;
    hook->type = hooktype;

    hook->original = original_opcodes;
    hook->replace = replace_opcodes;
    hook->patch_size = branch_size;

    registerHook(hook);
}

void Hook::uninstallHook() {}

void Hook::addBreakpoint(xnu::Mach::VmAddress breakpoint_hook, enum HookType hooktype) {
    struct HookPatch* hook = new HookPatch;

    Architecture* architecture = getArchitecture();

    Disassembler* disassembler = getDisassembler();

    Patcher* patcher = getPatcher();

    Payload* payload = prepareTrampoline();

    xnu::Mach::VmAddress trampoline;

    trampoline = payload->getAddress() + payload->getCurrentOffset();

    Size min;
    Size branch_size;

    xnu::Mach::VmAddress from = from;

    branch_size = architecture->getBranchSize();

    min = disassembler->instructionSize(from, branch_size);

    UInt8* original_opcodes;
    UInt8* replace_opcodes;

    original_opcodes = new UInt8[min];

    task->read(from, (void*)original_opcodes, min);

    union Branch to_trampoline;

    // build the FunctionPatch branch/jmp instruction from original function to hooked function
    // NOTE: if function is hooked more than once, then original = previous hook

    architecture->makeBranch(&to_trampoline, trampoline, from);

    replace_opcodes = new UInt8[branch_size];

    memcpy(replace_opcodes, (void*)&to_trampoline, branch_size);

    Size breakpoint_size = architecture->getBreakpointSize();

    if (breakpoint_hook) {
        // set a conditional breakpoint
        union FunctionCall call_breakpoint_hook;

        union Breakpoint breakpoint;

        Size call_size = architecture->getCallSize();

        payload->writeBytes((UInt8*)push_registers,
                            (Size)((UInt8*)push_registers_end - (UInt8*)push_registers));
        payload->writeBytes((UInt8*)set_argument,
                            (Size)((UInt8*)set_argument_end - (UInt8*)set_argument));

        architecture->makeCall(&call_breakpoint_hook, breakpoint_hook,
                               payload->getAddress() + payload->getCurrentOffset());

        payload->writeBytes((UInt8*)&call_breakpoint_hook, call_size);

        payload->writeBytes((UInt8*)check_breakpoint,
                            (Size)((UInt8*)check_breakpoint_end - (UInt8*)check_breakpoint));

        architecture->makeBreakpoint(&breakpoint);

        payload->writeBytes((UInt8*)&breakpoint, breakpoint_size);

        payload->writeBytes((UInt8*)pop_registers,
                            (Size)((UInt8*)pop_registers_end - (UInt8*)pop_registers));
    } else {
        // break regardless
        union Breakpoint breakpoint;

        payload->writeBytes((UInt8*)push_registers,
                            (Size)((UInt8*)push_registers_end - (UInt8*)push_registers));

        architecture->makeBreakpoint(&breakpoint);

        payload->writeBytes((UInt8*)&breakpoint, breakpoint_size);

        payload->writeBytes((UInt8*)pop_registers,
                            (Size)((UInt8*)pop_registers_end - (UInt8*)pop_registers));
    }

    union Branch to_original_function;

    // build the FunctionPatch branch/jmp instruction from trampoline to original function

    payload->writeBytes(original_opcodes, min);

    architecture->makeBranch(&to_original_function, from + min,
                             payload->getAddress() + payload->getCurrentOffset());

    payload->writeBytes((UInt8*)&to_original_function, branch_size);

    task->write(from, (void*)replace_opcodes, branch_size);

    payload->commit();

    hook->from = from;
    hook->to = trampoline;

    hook->trampoline = trampoline;
    hook->patch = to_trampoline;
    hook->payload = payload;
    hook->type = hooktype;

    hook->original = original_opcodes;
    hook->replace = replace_opcodes;
    hook->patch_size = branch_size;

    registerHook(hook);
}

void Hook::removeBreakpoint() {}
