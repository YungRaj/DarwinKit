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

#include "kernel.h"

using namespace xnu;

const char* xnu::getKernelVersion() {
    char* kernelBuildVersion = new char[256];

    struct utsname kernelInfo;

    uname(&kernelInfo);

    strlcpy(kernelBuildVersion, kernelInfo.version, 256);

    DARWIN_RK_LOG("MacRK::macOS kernel version = %s\n", kernelInfo.version);

    return kernelBuildVersion;
}

const char* xnu::getOSBuildVersion() {
    int mib[2];

    size_t len = 256;
    char* buildVersion = new char[len];

    mib[0] = CTL_KERN;
    mib[1] = KERN_OSVERSION;

    if (sysctl(mib, 2, buildVersion, &len, nullptr, 0) == 0) {
        DARWIN_RK_LOG("MacRK::macOS OS build version = %s\n", buildVersion);
    } else {
        return nullptr;
    }

    return buildVersion;
}

Kernel::Kernel() : connection(open_kernel_tfp0_connection()), slide(getSlide()) {
    kernel = this;

    Task();

    // UserMachO *userMachO = new UserMachO();
#ifdef __x86_64__
    // userMachO->initWithFilePath("/System/Library/Kernels/kernel");
#elif __arm64__
    // userMachO->initWithFilePath("/System/Library/Kernels/kernel.release.t8110");
#endif

    // macho = userMachO;
}

Kernel::~Kernel() {
    close_kernel_tfp0_connection();

    delete macho;
}

xnu::Mach::VmAddress Kernel::getBase() {
    return get_kernel_base();
}

Offset Kernel::getSlide() {
    return get_kernel_slide();
}

UInt64 Kernel::call(char* symbolname, UInt64* arguments, Size argCount) {
    return kernel_call_function(symbolname, arguments, argCount);
}

UInt64 Kernel::call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount) {
    return kernel_call(func, arguments, argCount);
}

xnu::Mach::VmAddress Kernel::vmAllocate(Size size) {
    return kernel_vm_allocate(size);
}

xnu::Mach::VmAddress Kernel::vmAllocate(Size size, UInt32 flags, xnu::Mach::VmProtection prot) {
    return 0;
}

void Kernel::vmDeallocate(xnu::Mach::VmAddress address, Size size) {
    kernel_vm_deallocate(address, size);
}

bool Kernel::vmProtect(xnu::Mach::VmAddress address, Size size, xnu::Mach::VmProtection prot) {
    return kernel_vm_protect(address, size, prot);
}

void* Kernel::vmRemap(xnu::Mach::VmAddress address, Size size) {
    return kernel_vm_remap(address, size);
}

UInt64 Kernel::virtualToPhysical(xnu::Mach::VmAddress address) {
    return kernel_virtual_to_physical(address);
}

bool Kernel::physicalRead(UInt64 paddr, void* data, Size size) {
    return false;
}

UInt64 Kernel::physicalRead64(UInt64 paddr) {
    return phys_read64(paddr);
}

UInt32 Kernel::physicalRead32(UInt64 paddr) {
    return phys_read32(paddr);
}

UInt16 Kernel::physicalRead16(UInt64 paddr) {
    return phys_read16(paddr);
}

UInt8 Kernel::physicalRead8(UInt64 paddr) {
    return phys_read64(paddr);
}

bool Kernel::physicalWrite(UInt64 paddr, void* data, Size size) {
    return false;
}

void Kernel::physicalWrite64(UInt64 paddr, UInt64 value) {
    phys_write64(paddr, value);
}

void Kernel::physicalWrite32(UInt64 paddr, UInt32 value) {
    phys_write32(paddr, value);
}

void Kernel::physicalWrite16(UInt64 paddr, UInt16 value) {
    phys_write16(paddr, value);
}

void Kernel::physicalWrite8(UInt64 paddr, UInt8 value) {
    phys_write8(paddr, value);
}

bool Kernel::read(xnu::Mach::VmAddress address, void* data, Size size) {
    return kernel_read(address, data, size);
}

bool Kernel::readUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return false;
}

UInt8 Kernel::read8(xnu::Mach::VmAddress address) {
    return kernel_read8(address);
}

UInt16 Kernel::read16(xnu::Mach::VmAddress address) {
    return kernel_read16(address);
}

UInt32 Kernel::read32(xnu::Mach::VmAddress address) {
    return kernel_read32(address);
}

UInt64 Kernel::read64(xnu::Mach::VmAddress address) {
    return kernel_read64(address);
}

bool Kernel::write(xnu::Mach::VmAddress address, void* data, Size size) {
    return kernel_write(address, data, size);
}

bool Kernel::writeUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return false;
}

void Kernel::write8(xnu::Mach::VmAddress address, UInt8 value) {
    kernel_write8(address, value);
}

void Kernel::write16(xnu::Mach::VmAddress address, UInt16 value) {
    kernel_write16(address, value);
}

void Kernel::write32(xnu::Mach::VmAddress address, UInt32 value) {
    kernel_write32(address, value);
}

void Kernel::write64(xnu::Mach::VmAddress address, UInt64 value) {
    kernel_write64(address, value);
}

bool Kernel::hookFunction(char* symname, xnu::Mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::hookFunction(xnu::Mach::VmAddress address, xnu::Mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::setBreakpoint(char* symname) {
    return false;
}

bool Kernel::setBreakpoint(char* symname, xnu::Mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::setBreakpoint(xnu::Mach::VmAddress address) {
    return false;
}

bool Kernel::setBreakpoint(xnu::Mach::VmAddress address, xnu::Mach::VmAddress breakpoint_hook,
                           Size breakpoint_hook_size) {
    return false;
}

#define MAX_LENGTH 0x100

char* Kernel::readString(xnu::Mach::VmAddress address) {
    char* s;

    int index = 0;

    char c;

    do {
        c = static_cast<char>(read8(address + index));

        index++;

    } while (c);

    s = new char[index + 1];

    read(address, reinterpret_cast<void*>(s), index);

    s[index] = '\0';

    return s;
}

Symbol* Kernel::getSymbolByName(char* symname) {
    return nullptr;
}

Symbol* Kernel::getSymbolByAddress(xnu::Mach::VmAddress address) {
    return nullptr;
}

xnu::Mach::VmAddress Kernel::getSymbolAddressByName(char* symbolname) {
    return get_kernel_symbol(symbolname);
}