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

using namespace darwin;

Patcher::Patcher() {}

Patcher::~Patcher() {}

void Patcher::findAndReplace(void* data, Size data_size, const void* find, Size find_size,
                             const void* replace, Size replace_size) {}

void Patcher::onKextLoad(void* kext, kmod_info_t* kmod) {}

void Patcher::routeFunction(Hook* hook) {
    hooks.push_back(hook);
}

bool Patcher::isFunctionHooked(xnu::Mach::VmAddress address) {
    for (int i = 0; i < getHooks().size(); i++) {
        Hook* hook = getHooks().at(i);

        if (hook->getHookType() == kHookTypeInstrumentFunction ||
            hook->getHookType() == kHookTypeReplaceFunction) {
            if (hook->getFrom() == address) {
                return true;
            }
        }
    }

    return false;
}

bool Patcher::isBreakpointAtInstruction(xnu::Mach::VmAddress address) {
    for (int i = 0; i < getHooks().size(); i++) {
        Hook* hook = getHooks().at(i);

        if (hook->getHookType() == kHookTypeBreakpoint) {
            if (hook->getFrom() == address) {
                return true;
            }
        }
    }

    return false;
}

Hook* Patcher::hookForFunction(xnu::Mach::VmAddress address) {
    Hook* hook = nullptr;

    if (!isFunctionHooked(address))
        return nullptr;

    for (int i = 0; i < getHooks().size(); i++) {
        Hook* h = getHooks().at(i);

        if (h->getHookType() == kHookTypeInstrumentFunction ||
            h->getHookType() == kHookTypeReplaceFunction) {
            if (hook->getFrom() == address) {
                hook = h;
            }
        }
    }

    return hook;
}

Hook* Patcher::breakpointForAddress(xnu::Mach::VmAddress address) {
    Hook* hook = nullptr;

    if (!isBreakpointAtInstruction(address))
        return nullptr;

    for (int i = 0; i < getHooks().size(); i++) {
        Hook* h = getHooks().at(i);

        if (h->getHookType() == kHookTypeBreakpoint) {
            if (hook->getFrom() == address) {
                hook = h;
            }
        }
    }

    return hook;
}

void Patcher::installHook(Hook* hook, xnu::Mach::VmAddress hooked) {
    hook->hookFunction(hooked);

    if (std::find(hooks.begin(), hooks.end(), hook) != hooks.end()) {
        hooks.push_back(hook);
    }
}

void Patcher::removeHook(Hook* hook) {
    hook->uninstallHook();

    hooks.erase(std::remove(hooks.begin(), hooks.end(), hook), hooks.end());

    delete hook;
}