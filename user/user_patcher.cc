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

#include "user_patcher.h"

#include "hook.h"
#include "payload.h"

void UserPatcher::findAndReplace(void* data, Size dataSize, const void* find, Size findSize,
                                 const void* replace, Size replaceSize) {}

void UserPatcher::routeFunction(Hook* hook) {}

void UserPatcher::onKextLoad(void* kext, kmod_info_t* kmod) {}

void UserPatcher::onExec(char* name, int pid, xnu::Mach::Port port, xnu::Mach::VmAddress task,
                         xnu::Mach::VmAddress proc) {}

xnu::Mach::VmAddress injectPayload(xnu::Mach::VmAddress address, Payload* payload) {
    return 0;
}

xnu::Mach::VmAddress injectSegment(xnu::Mach::VmAddress address, Payload* payload) {
    return 0;
}