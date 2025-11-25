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

namespace xnu {

const char* GetKernelVersion() {
    char* kernelBuildVersion = new char[256];

    struct utsname kernelInfo;

    uname(&kernelInfo);

    strlcpy(kernelBuildVersion, kernelInfo.version, 256);

    DARWIN_KIT_LOG("DarwinKit::macOS kernel version = %s\n", kernelInfo.version);

    return kernelBuildVersion;
}

const char* GetOSBuildVersion() {
    int mib[2];

    size_t len = 256;
    char* buildVersion = new char[len];

    mib[0] = CTL_KERN;
    mib[1] = KERN_OSVERSION;

    if (sysctl(mib, 2, buildVersion, &len, nullptr, 0) == 0) {
        DARWIN_KIT_LOG("DarwinKit::macOS OS build version = %s\n", buildVersion);
    } else {
        return nullptr;
    }

    return buildVersion;
}

Kernel::Kernel() : connection(open_kernel_tfp0_connection()), slide(GetSlide()) {
    kernel = this;

    Task();

    // MachOUserspace *MachOUserspace = new MachOUserspace();
#ifdef __x86_64__
    // MachOUserspace->initWithFilePath("/System/Library/Kernels/kernel");
#elif __arm64__
    // MachOUserspace->initWithFilePath("/System/Library/Kernels/kernel.release.t8110");
#endif

    // macho = MachOUserspace;
}

Kernel::~Kernel() {
    close_kernel_tfp0_connection();

    delete macho;
}

xnu::mach::VmAddress Kernel::GetBase() {
    return get_kernel_base();
}

Offset Kernel::GetSlide() {
    return get_kernel_slide();
}

UInt64 Kernel::Call(char* symbolname, UInt64* arguments, Size argCount) {
    return kernel_call_function(symbolname, arguments, argCount);
}

UInt64 Kernel::Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount) {
    return kernel_call(func, arguments, argCount);
}

xnu::mach::VmAddress Kernel::VmAllocate(Size size) {
    return kernel_vm_allocate(size);
}

xnu::mach::VmAddress Kernel::VmAllocate(Size size, UInt32 flags, xnu::mach::VmProtection prot) {
    return 0;
}

void Kernel::VmDeallocate(xnu::mach::VmAddress address, Size size) {
    kernel_vm_deallocate(address, size);
}

bool Kernel::VmProtect(xnu::mach::VmAddress address, Size size, xnu::mach::VmProtection prot) {
    return kernel_vm_protect(address, size, prot);
}

void* Kernel::VmRemap(xnu::mach::VmAddress address, Size size) {
    return kernel_vm_remap(address, size);
}

UInt64 Kernel::VirtualToPhysical(xnu::mach::VmAddress address) {
    return kernel_virtual_to_physical(address);
}

bool Kernel::PhysicalRead(UInt64 paddr, void* data, Size size) {
    return false;
}

UInt64 Kernel::PhysicalRead64(UInt64 paddr) {
    return phys_read64(paddr);
}

UInt32 Kernel::PhysicalRead32(UInt64 paddr) {
    return phys_read32(paddr);
}

UInt16 Kernel::PhysicalRead16(UInt64 paddr) {
    return phys_read16(paddr);
}

UInt8 Kernel::PhysicalRead8(UInt64 paddr) {
    return phys_read64(paddr);
}

bool Kernel::PhysicalWrite(UInt64 paddr, void* data, Size size) {
    return false;
}

void Kernel::PhysicalWrite64(UInt64 paddr, UInt64 value) {
    phys_write64(paddr, value);
}

void Kernel::PhysicalWrite32(UInt64 paddr, UInt32 value) {
    phys_write32(paddr, value);
}

void Kernel::PhysicalWrite16(UInt64 paddr, UInt16 value) {
    phys_write16(paddr, value);
}

void Kernel::PhysicalWrite8(UInt64 paddr, UInt8 value) {
    phys_write8(paddr, value);
}

bool Kernel::Read(xnu::mach::VmAddress address, void* data, Size size) {
    return kernel_read(address, data, size);
}

bool Kernel::ReadUnsafe(xnu::mach::VmAddress address, void* data, Size size) {
    return false;
}

UInt8 Kernel::Read8(xnu::mach::VmAddress address) {
    return kernel_read8(address);
}

UInt16 Kernel::Read16(xnu::mach::VmAddress address) {
    return kernel_read16(address);
}

UInt32 Kernel::Read32(xnu::mach::VmAddress address) {
    return kernel_read32(address);
}

UInt64 Kernel::Read64(xnu::mach::VmAddress address) {
    return kernel_read64(address);
}

bool Kernel::Write(xnu::mach::VmAddress address, void* data, Size size) {
    return kernel_write(address, data, size);
}

bool Kernel::WriteUnsafe(xnu::mach::VmAddress address, void* data, Size size) {
    return false;
}

void Kernel::Write8(xnu::mach::VmAddress address, UInt8 value) {
    kernel_write8(address, value);
}

void Kernel::Write16(xnu::mach::VmAddress address, UInt16 value) {
    kernel_write16(address, value);
}

void Kernel::Write32(xnu::mach::VmAddress address, UInt32 value) {
    kernel_write32(address, value);
}

void Kernel::Write64(xnu::mach::VmAddress address, UInt64 value) {
    kernel_write64(address, value);
}

bool Kernel::HookFunction(char* symname, xnu::mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::HookFunction(xnu::mach::VmAddress address, xnu::mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::SetBreakpoint(char* symname) {
    return false;
}

bool Kernel::SetBreakpoint(char* symname, xnu::mach::VmAddress hook, Size hook_size) {
    return false;
}

bool Kernel::SetBreakpoint(xnu::mach::VmAddress address) {
    return false;
}

bool Kernel::SetBreakpoint(xnu::mach::VmAddress address, xnu::mach::VmAddress breakpoint_hook,
                           Size breakpoint_hook_size) {
    return false;
}

#define MAX_LENGTH 0x100

char* Kernel::ReadString(xnu::mach::VmAddress address) {
    char* s;

    int index = 0;

    char c;

    do {
        c = static_cast<char>(Read8(address + index));

        index++;

    } while (c);

    s = new char[index + 1];

    Read(address, reinterpret_cast<void*>(s), index);

    s[index] = '\0';

    return s;
}

Symbol* Kernel::GetSymbolByName(char* symname) {
    return nullptr;
}

Symbol* Kernel::GetSymbolByAddress(xnu::mach::VmAddress address) {
    return nullptr;
}

xnu::mach::VmAddress Kernel::GetSymbolAddressByName(char* symbolname) {
    return get_kernel_symbol(symbolname);
}

UInt8* Kernel::GetCoverageMap() {
    return kcov_get_coverage_map();
}

void Kernel::Fuzz() {
    kcov_begin_fuzzing();
}

}