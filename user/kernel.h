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

#include <mach/mach_types.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

extern "C" {
#include "api.h"
#include "kern_user.h"
}

#include "dwarf.h"
#include "kernel_macho.h"
#include "macho.h"
#include "macho_userspace.h"
#include "task.h"

class Disassembler;

namespace xnu {
class Task;

const char* GetKernelVersion();
const char* GetOSBuildVersion();

class Kernel : public xnu::Task {
    static constexpr UInt8* kXnuKcovCoverageMap = kernel_coverage_map;
    static constexpr Size kXnuKcovCoverageMapSize = KCOV_COVERAGE_BITMAP_SIZE;

public:
    explicit Kernel();

    ~Kernel();

    static xnu::Kernel* Xnu();

    virtual xnu::mach::VmAddress GetBase();

    virtual Offset GetSlide();

    virtual UInt64 Call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::mach::VmAddress VmAllocate(Size size);
    virtual xnu::mach::VmAddress VmAllocate(Size size, UInt32 flags, xnu::mach::VmProtection prot);

    virtual void VmDeallocate(xnu::mach::VmAddress address, Size size);

    virtual bool VmProtect(xnu::mach::VmAddress address, Size size, xnu::mach::VmProtection prot);

    virtual void* VmRemap(xnu::mach::VmAddress address, Size size);

    virtual UInt64 VirtualToPhysical(xnu::mach::VmAddress address);

    virtual bool PhysicalRead(UInt64 paddr, void* data, Size size);

    virtual UInt64 PhysicalRead64(UInt64 paddr);
    virtual UInt32 PhysicalRead32(UInt64 paddr);
    virtual UInt16 PhysicalRead16(UInt64 paddr);
    virtual UInt8 PhysicalRead8(UInt64 paddr);

    virtual bool PhysicalWrite(UInt64 paddr, void* data, Size size);

    virtual void PhysicalWrite64(UInt64 paddr, UInt64 value);
    virtual void PhysicalWrite32(UInt64 paddr, UInt32 value);
    virtual void PhysicalWrite16(UInt64 paddr, UInt16 value);
    virtual void PhysicalWrite8(UInt64 paddr, UInt8 value);

    virtual bool Read(xnu::mach::VmAddress address, void* data, Size size);
    virtual bool ReadUnsafe(xnu::mach::VmAddress address, void* data, Size size);

    virtual UInt8 Read8(xnu::mach::VmAddress address);
    virtual UInt16 Read16(xnu::mach::VmAddress address);
    virtual UInt32 Read32(xnu::mach::VmAddress address);
    virtual UInt64 Read64(xnu::mach::VmAddress address);

    virtual bool Write(xnu::mach::VmAddress address, void* data, Size size);
    virtual bool WriteUnsafe(xnu::mach::VmAddress address, void* data, Size size);

    virtual void Write8(xnu::mach::VmAddress address, UInt8 value);
    virtual void Write16(xnu::mach::VmAddress address, UInt16 value);
    virtual void Write32(xnu::mach::VmAddress address, UInt32 value);
    virtual void Write64(xnu::mach::VmAddress address, UInt64 value);

    virtual bool HookFunction(char* symname, xnu::mach::VmAddress hook, Size hook_size);
    virtual bool HookFunction(xnu::mach::VmAddress address, xnu::mach::VmAddress hook,
                              Size hook_size);

    virtual bool SetBreakpoint(char* symname);
    virtual bool SetBreakpoint(char* symname, xnu::mach::VmAddress hook, Size hook_size);

    virtual bool SetBreakpoint(xnu::mach::VmAddress address);
    virtual bool SetBreakpoint(xnu::mach::VmAddress address, xnu::mach::VmAddress breakpoint_hook,
                               Size breakpoint_hook_size);

    virtual char* ReadString(xnu::mach::VmAddress address);

    virtual Symbol* GetSymbolByName(char* symname);
    virtual Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    virtual xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname);

    void CollectCoverage();

    void EnableCoverage();
    void DisableCoverage();

    void FuzzOne(enum FuzzContext context, UInt8* data, Size size);

private:
    darwin::MachOUserspace* macho;
    xnu::mach::Port connection;
    Disassembler* disassembler;
    xnu::mach::VmAddress base;
    Offset slide;
};

enum KDKKernelType {
    KdkKernelTypeNone = -1,
    KdkKernelTypeRelease = 0,
    KdkKernelTypeReleaseT6000,
    KdkKernelTypeReleaseT6020,
    KdkKernelTypeReleaseT8103,
    KdkKernelTypeReleaseT8112,
    KdkKernelTypeReleaseVmApple,

    KdkKernelTypeDevelopment = 0x10,
    KdkKernelTypeDevelopmentT6000,
    KdkKernelTypeDevelopmentT6020,
    KdkKernelTypeDevelopmentT8103,
    KdkKernelTypeDevelopmentT8112,
    KdkKernelTypeDevelopmentVmApple,

    KdkKernelTypeKasan = 0x20,
    KdkKernelTypeKasanT6000,
    KdkKernelTypeKasanT6020,
    KdkKernelTypeKasanT8103,
    KdkKernelTypeKasanT8112,
    KdkKernelTypeKasanVmApple,
};

#define KDK_PATH_SIZE 1024

struct KDKInfo {
    KDKKernelType type;
    char* kernelName;
    char path[KDK_PATH_SIZE];
    char kernelPath[KDK_PATH_SIZE];
    char kernelDebugSymbolsPath[KDK_PATH_SIZE];
};

template <typename T>
struct Xref {
    xnu::mach::VmAddress what;
    xnu::mach::VmAddress where;
    T data;
};

class KDK {
public:
    explicit KDK(xnu::Kernel* kernel, struct KDKInfo* kdkInfo);

    static KDK* KDKFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                                 const char* kernelVersion);

    static KDKInfo* KDKInfoFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                                         const char* kernelVersion);
    static KDKInfo* KDKInfoFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                                         const char* kernelVersion, bool Vm);

    static void GetKDKPathFromBuildInfo(const char* buildVersion, char* outPath);

    static void GetKDKKernelFromPath(const char* path, const char* kernelVersion,
                                     KDKKernelType* outType, char* outKernelPath);
    static void GetKDKKernelFromPath(const char* path, const char* kernelVersion,
                                     KDKKernelType* outType, char* outKernelPath, bool Vm);

    char* GetPath() const {
        return path;
    }

    xnu::Kernel* GetKernel() const {
        return kernel;
    }

    debug::Dwarf<KernelMachO*>* GetDwarf() const {
        return dwarf;
    }

    MachO* GetMachO() const {
        return dynamic_cast<MachO*>(kernelWithDebugSymbols);
    }

    xnu::mach::VmAddress GetBase() const {
        return base;
    }

    xnu::mach::VmAddress GetKDKSymbolAddressByName(char* sym);

    Symbol* GetKDKSymbolByName(char* symname);
    Symbol* GetKDKSymbolByAddress(xnu::mach::VmAddress address);

    char* FindString(char* s);

    template <typename T>
    std::vector<Xref<T>*> GetExternalReferences(xnu::mach::VmAddress addr);

    template <typename T>
    std::vector<Xref<T>*> GetStringReferences(xnu::mach::VmAddress addr);

    template <typename T>
    std::vector<Xref<T>*> GetStringReferences(const char* s);

    void ParseDebugInformation();

private:
    bool valid;
    char* path;

    KDKKernelType type;
    xnu::KDKInfo* kdkInfo;
    xnu::Kernel* kernel;
    xnu::KernelMachO* kernelWithDebugSymbols;
    debug::Dwarf<KernelMachO*>* dwarf;
    xnu::mach::VmAddress base;
};
}; // namespace xnu
