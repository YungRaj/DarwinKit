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

#include <stddef.h>
#include <stdint.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>

#include "arch.h"
#include "hook.h"

namespace xnu {
class Kernel;
class Task;
}; // namespace xnu

using namespace xnu;

namespace darwin {
class Payload {
    static constexpr UInt32 expectedSize = arch::GetPageSize<arch::GetCurrentArchitecture()>();

public:
    explicit Payload(Task* task, Hook* hook, xnu::mach::VmProtection protection)
        : task(task), hook(hook), prot(protection), current_offset(0) {}

    ~Payload() = default;

    Hook* GetHook() {
        return hook;
    }

    xnu::mach::VmAddress GetAddress() {
        return address;
    }

    void SetCurrentOffset(Offset offset);

    Offset GetCurrentOffset() {
        return current_offset;
    }

    Size GetSize() {
        return size;
    }

    xnu::mach::VmProtection GetProt() {
        return prot;
    }

    Task* GetTask() {
        return task;
    }

    bool ReadBytes(UInt8* bytes, Size size);
    bool ReadBytes(Offset offset, UInt8* bytes, Size size);

    bool WriteBytes(UInt8* bytes, Size size);
    bool WriteBytes(Offset offset, UInt8* bytes, Size size);

    void SetWritable();
    void SetExecutable();

    bool Prepare();

    bool Commit();

private:
    Hook* hook;
    xnu::Task* task;
    xnu::mach::VmAddress address;

    Offset current_offset;
    bool kernel_payload = false;
    Size size;
    xnu::mach::VmProtection prot;
};
}; // namespace darwin
