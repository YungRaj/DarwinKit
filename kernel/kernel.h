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

extern "C" {
#include <kern/host.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/sysctl.h>
}
#include <IOKit/IOLib.h>
#include <types.h>

#include "coverage.h"
#include "disassembler.h"
#include "dwarf.h"
#include "kernel_macho.h"
#include "task.h"

class IOKernelDarwinKitService;

class MachO;
class Symbol;

class Disassembler;

namespace darwin {
class DarwinKit;
};

namespace debug {
class Dwarf;
};

namespace xnu {
class KDK;

static char* GetKernelVersion();

static char* GetOSBuildVersion();

class Kernel : public xnu::Task {
    static constexpr Size tempExecutableMemorySize{4096 * 4 * 32};
    static constexpr Size coverageMapSize = KCOV_COVERAGE_BITMAP_SIZE;

    static Offset tempExecutableMemoryOffset;

    static UInt8 tempExecutableMemory[tempExecutableMemorySize]
        __attribute__((section("__TEXT,__text")));

    static xnu::Kernel* kernel;

public:
    explicit Kernel(xnu::mach::Port kernel_task_port);

    explicit Kernel(xnu::mach::VmAddress cache, xnu::mach::VmAddress base, Offset slide);

    explicit Kernel(xnu::mach::VmAddress base, Offset slide);

    ~Kernel() = default;

    static xnu::Kernel* Xnu() {
        return kernel;
    }

    static xnu::Kernel* Create(xnu::mach::Port kernel_task_port);

    static xnu::Kernel* Create(xnu::mach::VmAddress cache, xnu::mach::VmAddress base, Offset slide);

    static xnu::Kernel* Create(xnu::mach::VmAddress base, Offset slide);

    static xnu::mach::VmAddress FindKernelCache();

    static xnu::mach::VmAddress FindKernelCollection();

    static xnu::mach::VmAddress FindKernelBase();

    static Offset FindKernelSlide();

    static xnu::mach::VmAddress GetExecutableMemory() {
        return reinterpret_cast<xnu::mach::VmAddress>(&tempExecutableMemory[0]);
    }

    static xnu::mach::VmAddress GetExecutableMemoryAtOffset(Offset offset) {
        return reinterpret_cast<xnu::mach::VmAddress>(
            &tempExecutableMemory[tempExecutableMemoryOffset]);
    }

    static Size GetExecutableMemorySize() {
        return tempExecutableMemorySize;
    }

    static Offset GetExecutableMemoryOffset() {
        return tempExecutableMemoryOffset;
    }

    static void SetExecutableMemoryOffset(Offset offset) {
        tempExecutableMemoryOffset = offset;
    }

    const char* GetVersion() const {
        return version;
    }

    const char* GetOSBuildVersion() const {
        return osBuildVersion;
    }

    MachO* GetMachO() const {
        return macho;
    }

    virtual xnu::mach::VmAddress GetBase();

    virtual Offset GetSlide();

    void SetDarwinKit(darwin::DarwinKit* kit) {
        darwinkit = kit;
    }

    darwin::DarwinKit* GetDarwinKit() {
        return darwinkit;
    }

    void SetDarwinKitService(IOKernelDarwinKitService* service) {
        darwinkitService = service;
    }

    IOKernelDarwinKitService* GetDarwinKitService() {
        return darwinkitService;
    }

    xnu::mach::Port GetKernelTaskPort() {
        return kernel_task_port;
    }

    bool SetKernelWriting(bool enable);

    bool SetNXBit(bool enable);

    bool SetInterrupts(bool enable);

    void GetKernelObjects();

    virtual task_t GetKernelTask() {
        return GetTask();
    }

    virtual vm_map_t GetKernelMap() {
        return GetMap();
    }

    virtual pmap_t GetKernelPmap() {
        return GetPmap();
    }

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

    virtual char* ReadString(xnu::mach::VmAddress address);

    virtual std::vector<Symbol*>& GetAllSymbols() {
        return macho->GetAllSymbols();
    }

    virtual Symbol* GetSymbolByName(char* symbolname);
    virtual Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    virtual xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname, bool sign = false);

    void EnableCoverage();
    void DisableCoverage();

    void Fuzz(enum FuzzContext context);

protected:
    KDK* kernelDebugKit;
    MachO* macho;
    IOKernelDarwinKitService* darwinkitService;
    darwin::DarwinKit* darwinkit;
    xnu::mach::Port kernel_task_port;

private:
    char* version;
    char* osBuildVersion;
    IOSimpleLock* kernelWriteLock;

    void CreateKernelTaskPort();
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

    static KDK* KDKFromBuildInfo(xnu::Kernel* kernel, char* buildVersion, char* kernelVersion);
    static KDKInfo* KDKInfoFromBuildInfo(xnu::Kernel* kernel, char* buildVersion,
                                         char* kernelVersion);

    static void GetKDKPathFromBuildInfo(char* buildVersion, char* outPath);

    static void GetKDKKernelFromPath(char* path, char* kernelVersion, KDKKernelType* outType,
                                     char* outKernelPath);

    xnu::Kernel* GetKernel() const {
        return kernel;
    }

    debug::Dwarf* GetDwarf() const {
        return dwarf;
    }

    MachO* GetMachO() const {
        return dynamic_cast<MachO*>(kernelWithDebugSymbols);
    }

    xnu::mach::VmAddress GetBase() const {
        return base;
    }

    char* GetPath() const {
        return path;
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
    std::vector<Xref<T>*> GetStringReferences(char* s);

    void ParseDebugInformation();

private:
    bool valid;
    char* path;

    KDKInfo* kdkInfo;
    KDKKernelType type;

    xnu::Kernel* kernel;
    xnu::KernelMachO* kernelWithDebugSymbols;
    debug::Dwarf* dwarf;
    xnu::mach::VmAddress base;
};

class KDKKernelMachO : public KernelMachO {
public:
    explicit KDKKernelMachO(xnu::Kernel* kernel, const char* path);

    xnu::mach::VmAddress GetBase() override;

    void ParseSymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                          Size strsize) override;

private:
    const char* path;
};
}; // namespace xnu
