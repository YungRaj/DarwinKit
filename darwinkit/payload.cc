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

#include "payload.h"

#include "hook.h"

using namespace xnu;

namespace darwin {

bool Payload::ReadBytes(UInt8* bytes, Size sz) {
    bool success;
    success = ReadBytes(current_offset, bytes, sz);
    return success;
}

bool Payload::ReadBytes(Offset offset, UInt8* bytes, Size sz) {
    bool success;
    xnu::mach::VmAddress addr = address + offset;
    success = GetTask()->Read(addr, (void*)bytes, sz);
    return success;
}

bool Payload::WriteBytes(UInt8* bytes, Size sz) {
    bool success;
    success = WriteBytes(current_offset, bytes, sz);
    if (success) {
        current_offset += sz;
    }
    return success;
}

bool Payload::WriteBytes(Offset offset, UInt8* bytes, Size sz) {
    bool success;
    xnu::mach::VmAddress addr = address + offset;
    success = GetTask()->Write(addr, (void*)bytes, sz);
#ifdef __KERNEL__
    if (addr >= (xnu::mach::VmAddress)Kernel::GetExecutableMemory() &&
        addr < (xnu::mach::VmAddress)Kernel::GetExecutableMemory() +
                      Kernel::GetExecutableMemorySize()) {
        Kernel::SetExecutableMemoryOffset(Kernel::GetExecutableMemoryOffset() + sz);
    }
#endif
    return success;
}

bool Payload::Prepare() {
    bool success;
    xnu::mach::VmAddress tramp;
    Task* task = GetTask();
#if defined(__x86_64__) || (defined(__arm64__) && defined(__USER__))
    tramp =
        task->VmAllocate(Payload::expectedSize, VM_FLAGS_ANYWHERE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (!tramp) {
        return false;
    }
/*#elif defined(__arm64__) && defined(__KERNEL__)*/
#else

    tramp = Kernel::GetExecutableMemory() + Kernel::GetExecutableMemoryOffset();

#endif
    address = tramp;
    return true;
}

void Payload::SetWritable() {
    task->VmProtect(address, Payload::expectedSize, VM_PROT_READ | VM_PROT_WRITE);
}

void Payload::SetExecutable() {
    task->VmProtect(address, Payload::expectedSize, VM_PROT_READ | VM_PROT_EXECUTE);
}

bool Payload::Commit() {
#if defined(__x86_64__) || (defined(__arm64__) && defined(__USER__))
    SetExecutable();
#endif
    return true;
}

}