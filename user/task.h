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

#include <stdint.h>
#include <string.h>

#include <mach/mach_types.h>
#include <sys/types.h>

#include "disassembler.h"

namespace xnu {
class Kernel;
};

namespace darwin {
namespace dyld {
class Dyld;
};
};

namespace bsd {
class Process;
};

class Symbol;
class Segment;
class Section;

class MachO;

namespace darwin {
class UserMachO;
};

using namespace darwin;

namespace xnu {
class Task {
public:
    explicit Task() : disassembler(new Disassembler(this)) {}

    explicit Task(xnu::Kernel* kernel, int pid);

    explicit Task(xnu::Kernel* kernel, char* name);

    explicit Task(Kernel* kernel, xnu::Mach::Port task_port)
                : kernel(kernel), task_port(task_port) {}

    ~Task() = default;

    xnu::Kernel* getKernel();

    int getPid() {
        return pid;
    }

    int findPid();

    xnu::Mach::Port getTaskPort() {
        return task_port;
    }

    xnu::Mach::VmAddress getTask() {
        return task;
    }

    xnu::Mach::VmAddress getProc() {
        return proc;
    }

    char* getName() {
        return name;
    }

    darwin::dyld::Dyld* getDyld() {
        return dyld;
    }

    bsd::Process* getProcess() {
        return process;
    }

    Disassembler* getDisassembler() {
        return disassembler;
    }

    static xnu::Mach::Port getTaskForPid(int pid);

    static Task* getTaskInfo(Kernel* kernel, char* task_name);

    static xnu::Mach::VmAddress findProcByPid(xnu::Kernel* kernel, int pid);
    static xnu::Mach::VmAddress findProcByName(xnu::Kernel* kernel, char* name);

    static xnu::Mach::VmAddress findTaskByPid(xnu::Kernel* kernel, int pid);
    static xnu::Mach::VmAddress findTaskByName(xnu::Kernel* kernel, char* name);

    static xnu::Mach::VmAddress getTaskFromProc(xnu::Kernel* kernel, xnu::Mach::VmAddress proc);

    static xnu::Mach::VmAddress findPort(xnu::Kernel* kernel, xnu::Mach::VmAddress task,
                                         xnu::Mach::Port port);

    virtual xnu::Mach::VmAddress getBase();

    virtual Offset getSlide();

    virtual char* getTaskName();

    virtual UInt64 call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::Mach::VmAddress vmAllocate(Size size);
    virtual xnu::Mach::VmAddress vmAllocate(Size size, UInt32 flags, xnu::Mach::VmProtection prot);

    virtual void vmDeallocate(xnu::Mach::VmAddress address, Size size);

    virtual bool vmProtect(xnu::Mach::VmAddress address, Size size, xnu::Mach::VmProtection prot);

    virtual void* vmRemap(xnu::Mach::VmAddress address, Size size);

    virtual UInt64 virtualToPhysical(xnu::Mach::VmAddress address);

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

    virtual Symbol* getSymbolByName(char* symname);
    virtual Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    virtual xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname);

    xnu::Mach::VmAddress getImageLoadedAt(char* image_name, char** image_path);

    virtual void printLoadedImages();

protected:
    xnu::Kernel* kernel;

    darwin::UserMachO* macho;

    Disassembler* disassembler;

    xnu::Mach::Port task_port;

    Offset slide;

    xnu::Mach::VmAddress task;
    xnu::Mach::VmAddress proc;

    xnu::Mach::VmAddress map;
    xnu::Mach::VmAddress pmap;

    char* name;
    char* path;

    bsd::Process* process;

    int pid;

    xnu::Mach::VmAddress base;

    xnu::Mach::VmAddress dyld_base;
    xnu::Mach::VmAddress dyld_shared_cache;

    darwin::dyld::Dyld* dyld;
};
}; // namespace xnu
