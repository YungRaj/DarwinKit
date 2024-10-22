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

#include "disassembler.h"

#include "macho.h"
#include "section.h"
#include "segment.h"

#include "process.h"

extern "C" {
#include <libkern/libkern.h>

#include <kern/host.h>
#include <mach/mach_types.h>
#include <sys/sysctl.h>
}

typedef void* pmap_t;

class Disassembler;

namespace xnu {
class Kernel;

class Task {
public:
    explicit Task() = default;

    explicit Task(xnu::Kernel* kernel, xnu::Mach::Port task_port);
    explicit Task(xnu::Kernel* kernel, task_t task);

    void initialize();

    static xnu::Mach::Port getTaskPort(Kernel* kernel, int pid);

    static Task* getTaskByName(Kernel* kernel, char* name);

    static proc_t findProcByPid(Kernel* kernel, int pid);
    static proc_t findProcByName(Kernel* kernel, char* name);

    static task_t findTaskByPid(Kernel* kernel, int pid);
    static task_t findTaskByName(Kernel* kernel, char* name);

    char* getName() {
        return name;
    }

    task_t getTask() {
        return task;
    }

    vm_map_t getMap() {
        return map;
    }

    pmap_t getPmap() {
        return pmap;
    }

    proc_t getProc() {
        return proc;
    }

    Disassembler* getDisassembler() {
        return disassembler;
    }

    bsd::Process* getProcess() {
        return process;
    }

    int getPid() {
        return pid;
    }

    void setTask(task_t task) {
        task = task;
    }

    void setMap(vm_map_t map) {
        map = map;
    }

    void setPmap(pmap_t pmap) {
        pmap = pmap;
    }

    void setProc(proc_t proc) {
        proc = proc;
    }

    virtual xnu::Mach::VmAddress getBase() {
        return base;
    }

    virtual Offset getSlide() {
        return slide;
    }

    void setBase(xnu::Mach::VmAddress base) {
        base = base;
    }

    void setSlide(Offset slide) {
        slide = slide;
    }

    virtual UInt64 call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::Mach::VmAddress vmAllocate(Size size);
    virtual xnu::Mach::VmAddress vmAllocate(Size size, UInt32 flags, vm_prot_t prot);

    virtual void vmDeallocate(xnu::Mach::VmAddress address, Size size);

    virtual bool vmProtect(xnu::Mach::VmAddress address, Size size, vm_prot_t prot);

    virtual void* vmRemap(xnu::Mach::VmAddress address, Size size);

    virtual UInt64 virtualToPhysical(xnu::Mach::VmAddress address);

    virtual bool read(xnu::Mach::VmAddress address, void* data, Size size);

    virtual UInt8 read8(xnu::Mach::VmAddress address);
    virtual UInt16 read16(xnu::Mach::VmAddress address);
    virtual UInt32 read32(xnu::Mach::VmAddress address);
    virtual UInt64 read64(xnu::Mach::VmAddress address);

    virtual bool write(xnu::Mach::VmAddress address, void* data, Size size);

    virtual void write8(xnu::Mach::VmAddress address, UInt8 value);
    virtual void write16(xnu::Mach::VmAddress address, UInt16 value);
    virtual void write32(xnu::Mach::VmAddress address, UInt32 value);
    virtual void write64(xnu::Mach::VmAddress address, UInt64 value);

    virtual char* readString(xnu::Mach::VmAddress address);

    virtual Symbol* getSymbolByName(char* symname);
    virtual Symbol* getSymbolByAddress(xnu::Mach::VmAddress address);

    virtual xnu::Mach::VmAddress getSymbolAddressByName(char* symbolname);

protected:
    xnu::Kernel* kernel;

    char* name;

    Disassembler* disassembler;

    xnu::Mach::Port task_port;

    bsd::Process* process;

    task_t task;
    proc_t proc;

    vm_map_t map;
    pmap_t pmap;

    xnu::Mach::VmAddress base;

    Offset slide;

    xnu::Mach::VmAddress dyld = 0;
    xnu::Mach::VmAddress dyld_shared_cache = 0;

    int pid;
};

} // namespace xnu
