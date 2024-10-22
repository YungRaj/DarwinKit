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

#include <Types.h>

#include "task.h"

#include "dwarf.h"

#include "kernel_macho.h"
#include "macho.h"
#include "user_machO.h"

#include "disassembler.h"

extern "C" {
#include "kern_user.h"
}

#include <mach/mach_types.h>

#include <sys/sysctl.h>
#include <sys/utsname.h>

namespace xnu {
class Task;

const char* getKernelVersion();
const char* getOSBuildVersion();

class Kernel : public xnu::Task {
public:
    explicit Kernel();

    ~Kernel();

    virtual xnu::Mach::VmAddress getBase();

    virtual Offset getSlide();

    virtual UInt64 call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::Mach::VmAddress vmAllocate(Size size);
    virtual xnu::Mach::VmAddress vmAllocate(Size size, UInt32 flags, xnu::Mach::VmProtection prot);

    virtual void vmDeallocate(xnu::Mach::VmAddress address, Size size);

    virtual bool vmProtect(xnu::Mach::VmAddress address, Size size, xnu::Mach::VmProtection prot);

    virtual void* vmRemap(xnu::Mach::VmAddress address, Size size);

    virtual UInt64 virtualToPhysical(xnu::Mach::VmAddress address);

    virtual bool physicalRead(UInt64 paddr, void* data, Size size);

    virtual UInt64 physicalRead64(UInt64 paddr);
    virtual UInt32 physicalRead32(UInt64 paddr);
    virtual UInt16 physicalRead16(UInt64 paddr);
    virtual UInt8 physicalRead8(UInt64 paddr);

    virtual bool physicalWrite(UInt64 paddr, void* data, Size size);

    virtual void physicalWrite64(UInt64 paddr, UInt64 value);
    virtual void physicalWrite32(UInt64 paddr, UInt32 value);
    virtual void physicalWrite16(UInt64 paddr, UInt16 value);
    virtual void physicalWrite8(UInt64 paddr, UInt8 value);

    virtual bool read(xnu::Mach::VmAddress address, void* data, Size size);
    virtual bool readUnsafe(xnu::Mach::VmAddress address, void* data, Size size);

    virtual UInt8 read8(xnu::Mach::VmAddress address);
    virtual UInt16 read16(xnu::Mach::VmAddress address);
    virtual UInt32 read32(xnu::Mach::VmAddress address);
    virtual UInt64 read64(xnu::Mach::VmAddress address);

    virtual bool write(xnu::Mach::VmAddress address, void* data, Size size);
    virtual bool writeUnsafe(xnu::Mach::VmAddress address, void* data, Size size);

    virtual void write8(xnu::Mach::VmAddress address, UInt8 value);
    virtual void write16(xnu::Mach::VmAddress address, UInt16 value);
    virtual void write32(xnu::Mach::VmAddress address, UInt32 value);
    virtual void write64(xnu::Mach::VmAddress address, UInt64 value);

    virtual bool hookFunction(char* symname, xnu::Mach::VmAddress hook, Size hook_size);
    virtual bool hookFunction(xnu::Mach::VmAddress address, xnu::Mach::VmAddress hook,
                              Size hook_size);

    virtual bool setBreakpoint(char* symname);
    virtual bool setBreakpoint(char* symname, xnu::Mach::VmAddress hook, Size hook_size);

    virtual bool setBreakpoint(xnu::Mach::VmAddress address);
    virtual bool setBreakpoint(xnu::Mach::VmAddress address, xnu::Mach::VmAddress breakpoint_hook,
                               Size breakpoint_hook_size);

    virtual char* readString(xnu::Mach::VmAddress address);

    virtual Symbol* getSymbolByName(char* symname);
    virtual Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    virtual xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname);

private:
    darwin::UserMachO* macho;

    xnu::Mach::Port connection;

    Disassembler* disassembler;

    xnu::Mach::VmAddress base;

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
    xnu::Mach::VmAddress what;

    xnu::Mach::VmAddress where;

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
                                         const char* kernelVersion, bool vm);

    static void getKDKPathFromBuildInfo(const char* buildVersion, char* outPath);

    static void getKDKKernelFromPath(const char* path, const char* kernelVersion,
                                     KDKKernelType* outType, char* outKernelPath);
    static void getKDKKernelFromPath(const char* path, const char* kernelVersion,
                                     KDKKernelType* outType, char* outKernelPath, bool vm);

    char* getPath() const {
        return path;
    }

    xnu::Kernel* getKernel() const {
        return kernel;
    }

    debug::Dwarf<KernelMachO*>* getDwarf() const {
        return dwarf;
    }

    MachO* getMachO() const {
        return dynamic_cast<MachO*>(kernelWithDebugSymbols);
    }

    xnu::Mach::VmAddress getBase() const {
        return base;
    }

    xnu::Mach::VmAddress getKDKSymbolAddressByName(char* sym);

    Symbol* getKDKSymbolByName(char* symname);
    Symbol* getKDKSymbolByAddress(xnu::Mach::VmAddress address);

    char* findString(char* s);

    template <typename T>
    std::vector<Xref<T>*> getExternalReferences(xnu::Mach::VmAddress addr);

    template <typename T>
    std::vector<Xref<T>*> getStringReferences(xnu::Mach::VmAddress addr);

    template <typename T>
    std::vector<Xref<T>*> getStringReferences(const char* s);

    void parseDebugInformation();

private:
    bool valid;

    char* path;

    KDKKernelType type;

    xnu::KDKInfo* kdkInfo;

    xnu::Kernel* kernel;

    xnu::KernelMachO* kernelWithDebugSymbols;

    debug::Dwarf<KernelMachO*>* dwarf;

    xnu::Mach::VmAddress base;
};
}; // namespace xnu
