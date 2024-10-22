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

#include "patcher.h"

namespace darwin {
class Hook;
class Payload;

class UserPatcher : Patcher {
public:
    explicit UserPatcher() = default;

    ~UserPatcher() = default;

    virtual void findAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                const void* replace, Size replace_size);

    virtual void routeFunction(Hook* hook);

    virtual void onExec(char* name, int pid, xnu::Mach::Port port, xnu::Mach::VmAddress task,
                        xnu::Mach::VmAddress proc);

    virtual void onKextLoad(void* kext, kmod_info_t* kmod);

    xnu::Mach::VmAddress injectPayload(xnu::Mach::VmAddress address, Payload* payload);

    xnu::Mach::VmAddress injectSegment(xnu::Mach::VmAddress address, Payload* payload);

    Size mapAddresses(const char* mapBuf);

private:
};
} // namespace darwin
