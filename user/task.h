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
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

class Disassembler;

namespace xnu {
class Kernel;
};

namespace darwin {
namespace dyld {
class Dyld;
};
}; // namespace darwin

namespace bsd {
class Process;
};

class Symbol;
class Segment;
class Section;

class MachO;

namespace darwin {
class MachOUserspace;
};

using namespace darwin;

namespace xnu {
class Task {
public:
    explicit Task();

    explicit Task(xnu::Kernel* kernel, int pid);

    explicit Task(xnu::Kernel* kernel, char* name);

    explicit Task(Kernel* kernel, xnu::mach::Port task_port)
        : kernel(kernel), task_port(task_port) {}

    ~Task() = default;

    xnu::Kernel* GetKernel();

    int GetPid() {
        return pid;
    }

    int FindPid();

    xnu::mach::Port GetTaskPort() {
        return task_port;
    }

    xnu::mach::VmAddress GetTask() {
        return task;
    }

    xnu::mach::VmAddress GetProc() {
        return proc;
    }

    char* GetName() {
        return name;
    }

    darwin::dyld::Dyld* GetDyld() {
        return dyld;
    }

    bsd::Process* GetProcess() {
        return process;
    }

    Disassembler* GetDisassembler() {
        return disassembler;
    }

    static xnu::mach::Port GetTaskForPid(int pid);

    static Task* GetTaskInfo(Kernel* kernel, char* task_name);

    static xnu::mach::VmAddress FindProcByPid(xnu::Kernel* kernel, int pid);
    static xnu::mach::VmAddress FindProcByName(xnu::Kernel* kernel, char* name);

    static xnu::mach::VmAddress FindTaskByPid(xnu::Kernel* kernel, int pid);
    static xnu::mach::VmAddress FindTaskByName(xnu::Kernel* kernel, char* name);

    static xnu::mach::VmAddress GetTaskFromProc(xnu::Kernel* kernel, xnu::mach::VmAddress proc);

    static xnu::mach::VmAddress FindPort(xnu::Kernel* kernel, xnu::mach::VmAddress task,
                                         xnu::mach::Port port);

    virtual xnu::mach::VmAddress GetBase();

    virtual Offset GetSlide();

    virtual char* GetTaskName();

    virtual UInt64 Call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::mach::VmAddress VmAllocate(Size size);
    virtual xnu::mach::VmAddress VmAllocate(Size size, UInt32 flags, xnu::mach::VmProtection prot);

    virtual void VmDeallocate(xnu::mach::VmAddress address, Size size);

    virtual bool VmProtect(xnu::mach::VmAddress address, Size size, xnu::mach::VmProtection prot);

    virtual void* VmRemap(xnu::mach::VmAddress address, Size size);

    virtual UInt64 VirtualToPhysical(xnu::mach::VmAddress address);

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

    virtual Symbol* GetSymbolByName(char* symname);
    virtual Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    virtual xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname);

    xnu::mach::VmAddress GetImageLoadedAt(char* image_name, char** image_path);

    virtual void PrintLoadedImages();

protected:
    xnu::Kernel* kernel;

    darwin::MachOUserspace* macho;

    Disassembler* disassembler;

    xnu::mach::Port task_port;

    Offset slide;

    xnu::mach::VmAddress task;
    xnu::mach::VmAddress proc;

    xnu::mach::VmAddress map;
    xnu::mach::VmAddress pmap;

    char* name;
    char* path;

    bsd::Process* process;

    int pid;

    xnu::mach::VmAddress base;

    xnu::mach::VmAddress dyld_base;
    xnu::mach::VmAddress dyld_shared_cache;

    darwin::dyld::Dyld* dyld;
};
}; // namespace xnu
