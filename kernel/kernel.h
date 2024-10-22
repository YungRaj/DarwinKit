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
#include <libkern/libkern.h>

#include <kern/host.h>

#include <mach/mach_types.h>

#include <sys/sysctl.h>
}

#include <IOKit/IOLib.h>

#include <types.h>

#include "task.h"

#include "disassembler.h"
#include "dwarf.h"

#include "kernel_macho.h"

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

static char* getKernelVersion();

static char* getOSBuildVersion();

class Kernel : public xnu::Task {
    static constexpr Size tempExecutableMemorySize{4096 * 4 * 32};

    static Offset tempExecutableMemoryOffset;

    static UInt8 tempExecutableMemory[tempExecutableMemorySize];

    static xnu::Kernel* kernel;

public:
    explicit Kernel(xnu::Mach::Port kernel_task_port);

    explicit Kernel(xnu::Mach::VmAddress cache, xnu::Mach::VmAddress base, Offset slide);

    explicit Kernel(xnu::Mach::VmAddress base, Offset slide);

    ~Kernel() = default;

    static xnu::Kernel* xnu() {
        return kernel;
    }

    static xnu::Kernel* create(xnu::Mach::Port kernel_task_port);

    static xnu::Kernel* create(xnu::Mach::VmAddress cache, xnu::Mach::VmAddress base, Offset slide);

    static xnu::Kernel* create(xnu::Mach::VmAddress base, Offset slide);

    static xnu::Mach::VmAddress findKernelCache();

    static xnu::Mach::VmAddress findKernelCollection();

    static xnu::Mach::VmAddress findKernelBase();

    static Offset findKernelSlide();

    static xnu::Mach::VmAddress getExecutableMemory() {
        return reinterpret_cast<xnu::Mach::VmAddress>(&tempExecutableMemory[0]);
    }

    static xnu::Mach::VmAddress getExecutableMemoryAtOffset(Offset offset) {
        return reinterpret_cast<xnu::Mach::VmAddress>(
            &tempExecutableMemory[tempExecutableMemoryOffset]);
    }

    static Size getExecutableMemorySize() {
        return tempExecutableMemorySize;
    }

    static Offset getExecutableMemoryOffset() {
        return tempExecutableMemoryOffset;
    }

    static void setExecutableMemoryOffset(Offset offset) {
        tempExecutableMemoryOffset = offset;
    }

    const char* getVersion() const {
        return version;
    }

    const char* getOSBuildVersion() const {
        return osBuildVersion;
    }

    MachO* getMachO() const {
        return macho;
    }

    virtual xnu::Mach::VmAddress getBase();

    virtual Offset getSlide();

    void setRootKit(darwin::DarwinKit* rootkit) {
        rootkit = rootkit;
    }

    darwin::DarwinKit* getRootKit() {
        return rootkit;
    }

    void setRootKitService(IOKernelDarwinKitService* service) {
        rootkitService = service;
    }

    IOKernelDarwinKitService* getRootKitService() {
        return rootkitService;
    }

    xnu::Mach::Port getKernelTaskPort() {
        return kernel_task_port;
    }

    bool setKernelWriting(bool enable);

    bool setNXBit(bool enable);

    bool setInterrupts(bool enable);

    void getKernelObjects();

    virtual task_t getKernelTask() {
        return getTask();
    }

    virtual vm_map_t getKernelMap() {
        return getMap();
    }

    virtual pmap_t getKernelPmap() {
        return getPmap();
    }

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

    virtual char* readString(xnu::Mach::VmAddress address);

    virtual std::vector<Symbol*>& getAllSymbols() {
        return macho->getAllSymbols();
    }

    virtual Symbol* getSymbolByName(char* symbolname);
    virtual Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    virtual xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname);

protected:
    KDK* kernelDebugKit;

    MachO* macho;

    IOKernelDarwinKitService* rootkitService;

    darwin::DarwinKit* rootkit;

    xnu::Mach::Port kernel_task_port;

private:
    char* version;
    char* osBuildVersion;

    IOSimpleLock* kernelWriteLock;

    void createKernelTaskPort();
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

    static KDK* KDKFromBuildInfo(xnu::Kernel* kernel, char* buildVersion, char* kernelVersion);
    static KDKInfo* KDKInfoFromBuildInfo(xnu::Kernel* kernel, char* buildVersion,
                                         char* kernelVersion);

    static void getKDKPathFromBuildInfo(char* buildVersion, char* outPath);

    static void getKDKKernelFromPath(char* path, char* kernelVersion, KDKKernelType* outType,
                                     char* outKernelPath);

    xnu::Kernel* getKernel() const {
        return kernel;
    }

    debug::Dwarf* getDwarf() const {
        return dwarf;
    }

    MachO* getMachO() const {
        return dynamic_cast<MachO*>(kernelWithDebugSymbols);
    }

    xnu::Mach::VmAddress getBase() const {
        return base;
    }

    char* getPath() const {
        return path;
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
    std::vector<Xref<T>*> getStringReferences(char* s);

    void parseDebugInformation();

private:
    bool valid;

    char* path;

    KDKInfo* kdkInfo;

    KDKKernelType type;

    xnu::Kernel* kernel;

    xnu::KernelMachO* kernelWithDebugSymbols;

    debug::Dwarf* dwarf;

    xnu::Mach::VmAddress base;
};

class KDKKernelMachO : public KernelMachO {
public:
    explicit KDKKernelMachO(xnu::Kernel* kernel, const char* path);

    xnu::Mach::VmAddress getBase() override;

    void parseSymbolTable(xnu::Macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                          Size strsize) override;

private:
    const char* path;
};
}; // namespace xnu
