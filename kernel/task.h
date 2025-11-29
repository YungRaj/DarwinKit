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

#include <types.h>

#include "disassembler.h"

#include "macho.h"
#include "section.h"
#include "segment.h"

#include "process.h"

typedef void* pmap_t;

class Disassembler;

namespace xnu {
class Kernel;

class Task {
public:
    explicit Task() = default;

    explicit Task(xnu::Kernel* kernel, xnu::mach::Port task_port);
    explicit Task(xnu::Kernel* kernel, task_t task);

    void Initialize();

    static xnu::mach::Port GetTaskPort(Kernel* kernel, int pid);

    static pid_t GetPid(task_t task);

    static Task* GetTaskByName(Kernel* kernel, char* name);

    static proc_t FindProcByPid(Kernel* kernel, int pid);
    static proc_t FindProcByName(Kernel* kernel, char* name);

    static task_t FindTaskByPid(Kernel* kernel, int pid);
    static task_t FindTaskByName(Kernel* kernel, char* name);

    char* GetName() {
        return name;
    }

    task_t GetTask() {
        return task;
    }

    vm_map_t GetMap() {
        return map;
    }

    pmap_t GetPmap() {
        return pmap;
    }

    proc_t GetProc() {
        return proc;
    }

    Disassembler* GetDisassembler() {
        return disassembler;
    }

    bsd::Process* GetProcess() {
        return process;
    }

    int GetPid() {
        return pid;
    }

    void SetTask(task_t tsk) {
        task = tsk;
    }

    void SetMap(vm_map_t vm_map) {
        map = vm_map;
    }

    void SetPmap(pmap_t p_map) {
        pmap = p_map;
    }

    void SetProc(proc_t p) {
        proc = p;
    }

    virtual xnu::mach::VmAddress GetBase() {
        return base;
    }

    virtual Offset GetSlide() {
        return slide;
    }

    void SetBase(xnu::mach::VmAddress bse) {
        base = bse;
    }

    void SetSlide(Offset s) {
        slide = s;
    }

    virtual UInt64 Call(char* symbolname, UInt64* arguments, Size argCount);
    virtual UInt64 Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount);

    virtual xnu::mach::VmAddress VmAllocate(Size size);
    virtual xnu::mach::VmAddress VmAllocate(Size size, UInt32 flags, vm_prot_t prot);

    virtual void VmDeallocate(xnu::mach::VmAddress address, Size size);

    virtual bool VmProtect(xnu::mach::VmAddress address, Size size, vm_prot_t prot);

    virtual void* VmRemap(xnu::mach::VmAddress address, Size size);

    virtual UInt64 VirtualToPhysical(xnu::mach::VmAddress address);

    virtual bool Read(xnu::mach::VmAddress address, void* data, Size size);

    virtual UInt8 Read8(xnu::mach::VmAddress address);
    virtual UInt16 Read16(xnu::mach::VmAddress address);
    virtual UInt32 Read32(xnu::mach::VmAddress address);
    virtual UInt64 Read64(xnu::mach::VmAddress address);

    virtual bool Write(xnu::mach::VmAddress address, void* data, Size size);

    virtual void Write8(xnu::mach::VmAddress address, UInt8 value);
    virtual void Write16(xnu::mach::VmAddress address, UInt16 value);
    virtual void Write32(xnu::mach::VmAddress address, UInt32 value);
    virtual void Write64(xnu::mach::VmAddress address, UInt64 value);

    virtual char* ReadString(xnu::mach::VmAddress address);

    virtual Symbol* GetSymbolByName(char* symname);
    virtual Symbol* GetSymbolByAddress(xnu::mach::VmAddress address);

    virtual xnu::mach::VmAddress GetSymbolAddressByName(char* symbolname, bool sign = false);

protected:
    char* name;
    xnu::Kernel* kernel;

    Disassembler* disassembler;
    xnu::mach::Port task_port;
    bsd::Process* process;

    task_t task;
    proc_t proc;
    vm_map_t map;
    pmap_t pmap;

    xnu::mach::VmAddress base;
    Offset slide;
    xnu::mach::VmAddress dyld = 0;
    xnu::mach::VmAddress dyld_shared_cache = 0;

    int pid;
};

} // namespace xnu
