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

#include <mach/kmod.h>

#include "pair.h"
#include "vector.h"

namespace darwin {
class Hook;

class Patcher {
public:
    explicit Patcher();

    ~Patcher();

    virtual void findAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                const void* replace, Size replace_size);

    virtual void onKextLoad(void* kext, kmod_info_t* kmod);

    virtual void routeFunction(darwin::Hook* hook);

    std::vector<Hook*>& getHooks() {
        return hooks;
    }

    darwin::Hook* hookForFunction(xnu::Mach::VmAddress address);

    darwin::Hook* breakpointForAddress(xnu::Mach::VmAddress address);

    bool isFunctionHooked(xnu::Mach::VmAddress address);

    bool isBreakpointAtInstruction(xnu::Mach::VmAddress address);

    void installHook(darwin::Hook* hook, xnu::Mach::VmAddress hooked);

    void removeHook(darwin::Hook* hook);

private:
    std::vector<darwin::Hook*> hooks;
};

} // namespace darwin
