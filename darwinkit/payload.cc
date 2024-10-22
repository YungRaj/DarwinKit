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

using namespace darwin;
using namespace xnu;

bool Payload::readBytes(UInt8* bytes, Size size) {
    bool success;

    success = readBytes(current_offset, bytes, size);

    return success;
}

bool Payload::readBytes(Offset offset, UInt8* bytes, Size size) {
    bool success;

    xnu::Mach::VmAddress address = address + offset;

    success = getTask()->read(address + offset, (void*)bytes, size);

    return success;
}

bool Payload::writeBytes(UInt8* bytes, Size size) {
    bool success;

    success = writeBytes(current_offset, bytes, size);

    if (success)
        current_offset += size;

    return success;
}

bool Payload::writeBytes(Offset offset, UInt8* bytes, Size size) {
    bool success;

    xnu::Mach::VmAddress address = address + offset;

    success = getTask()->write(address, (void*)bytes, size);

#ifdef __KERNEL__

    if (address >= (xnu::Mach::VmAddress)Kernel::getExecutableMemory() &&
        address < (xnu::Mach::VmAddress)Kernel::getExecutableMemory() +
                      Kernel::getExecutableMemorySize()) {
        Kernel::setExecutableMemoryOffset(Kernel::getExecutableMemoryOffset() + size);
    }

#endif

    return success;
}

bool Payload::prepare() {
    bool success;

    xnu::Mach::VmAddress trampoline;

    Task* task = getTask();

#if defined(__x86_64__) || (defined(__arm64__) && defined(__USER__))

    trampoline =
        task->vmAllocate(Payload::expectedSize, VM_FLAGS_ANYWHERE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (!trampoline)
        return false;

/*#elif defined(__arm64__) && defined(__KERNEL__)*/
#else

    trampoline = Kernel::getExecutableMemory() + Kernel::getExecutableMemoryOffset();

#endif

    address = trampoline;

    return true;
}

void Payload::setWritable() {
    task->vmProtect(address, Payload::expectedSize, VM_PROT_READ | VM_PROT_WRITE);
}

void Payload::setExecutable() {
    task->vmProtect(address, Payload::expectedSize, VM_PROT_READ | VM_PROT_EXECUTE);
}

bool Payload::commit() {

#if defined(__x86_64__) || (defined(__arm64__) && defined(__USER__))

    setExecutable();

#endif

    return true;
}
