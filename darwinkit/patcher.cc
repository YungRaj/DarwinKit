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

#include "patcher.h"

#include "hook.h"

namespace darwin {

void Patcher::FindAndReplace(void* data, Size data_size, const void* find, Size find_size,
                             const void* replace, Size replace_size) {}

void Patcher::OnKextLoad(void* kext, kmod_info_t* kmod) {}

void Patcher::RouteFunction(Hook* hook) {
    hooks.push_back(hook);
}

bool Patcher::IsFunctionHooked(xnu::mach::VmAddress address) {
    for (int i = 0; i < GetHooks().size(); i++) {
        Hook* hook = GetHooks().at(i);
        if (hook->GetHookType() == kHookTypeInstrumentFunction ||
            hook->GetHookType() == kHookTypeReplaceFunction) {
            if (hook->GetFrom() == address) {
                return true;
            }
        }
    }
    return false;
}

bool Patcher::IsBreakpointAtInstruction(xnu::mach::VmAddress address) {
    for (int i = 0; i < GetHooks().size(); i++) {
        Hook* hook = GetHooks().at(i);
        if (hook->GetHookType() == kHookTypeBreakpoint) {
            if (hook->GetFrom() == address) {
                return true;
            }
        }
    }
    return false;
}

Hook* Patcher::HookForFunction(xnu::mach::VmAddress address) {
    Hook* hook = nullptr;
    if (!IsFunctionHooked(address)) {
        return nullptr;
    }
    for (int i = 0; i < GetHooks().size(); i++) {
        Hook* h = GetHooks().at(i);
        if (h->GetHookType() == kHookTypeInstrumentFunction ||
            h->GetHookType() == kHookTypeReplaceFunction) {
            if (hook->GetFrom() == address) {
                hook = h;
            }
        }
    }
    return hook;
}

Hook* Patcher::BreakpointForAddress(xnu::mach::VmAddress address) {
    Hook* hook = nullptr;
    if (!IsBreakpointAtInstruction(address)) {
        return nullptr;
    }
    for (int i = 0; i < GetHooks().size(); i++) {
        Hook* h = GetHooks().at(i);
        if (h->GetHookType() == kHookTypeBreakpoint) {
            if (hook->GetFrom() == address) {
                hook = h;
            }
        }
    }
    return hook;
}

void Patcher::InstallHook(Hook* hook, xnu::mach::VmAddress hooked) {
    hook->HookFunction(hooked);
    if (std::find(hooks.begin(), hooks.end(), hook) != hooks.end()) {
        hooks.push_back(hook);
    }
}

void Patcher::RemoveHook(Hook* hook) {
    hook->UninstallHook();
    hooks.erase(std::remove(hooks.begin(), hooks.end(), hook), hooks.end());
    delete hook;
}

} // namespace darwin