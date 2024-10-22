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
#include "pac.h"
#include "task.h"

#include "log.h"

#include <IOKit/IOLib.h>
#include <mach/mach_types.h>

extern "C" {
#include "kern.h"
}

static int EndsWith(const char* str, const char* suffix) {
    if (!str || !suffix)
        return 0;

    Size lenstr = strlen(str);
    Size lensuffix = strlen(suffix);

    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

Task::Task(Kernel* kernel, xnu::Mach::Port task_port) : kernel(kernel), task_port(task_port) {
    typedef vm_offset_t ipc_kobject_t;

    ipc_port_t port = reinterpret_cast<ipc_port_t>(task_port);

    UInt8* port_buf = reinterpret_cast<UInt8*>(port);

    task = (task_t) * (UInt64*)(port_buf + 0x68);

    initialize();
}

Task::Task(Kernel* kernel, task_t task)
    : kernel(kernel), task(task), disassembler(new Disassembler(this)) {
    initialize();
}

void Task::initialize() {
    typedef proc_t (*get_bsdtask_info)(task_t task);
    proc_t (*_get_bsdtask_info)(task_t task);

    _get_bsdtask_info =
        reinterpret_cast<get_bsdtask_info>(kernel->getSymbolAddressByName("_get_bsdtask_info"));

    proc = _get_bsdtask_info(task);

    typedef vm_map_t (*get_task_map)(task_t task);
    vm_map_t (*_get_task_map)(task_t);

    _get_task_map = reinterpret_cast<get_task_map>(kernel->getSymbolAddressByName("_get_task_map"));

    map = _get_task_map(task);

    typedef pmap_t (*get_task_pmap)(task_t task);
    pmap_t (*_get_task_pmap)(task_t);

    _get_task_pmap =
        reinterpret_cast<get_task_pmap>(kernel->getSymbolAddressByName("_get_task_pmap"));

    pmap = _get_task_pmap(task);
}

xnu::Mach::Port Task::getTaskPort(Kernel* kernel, int pid) {
    char buffer[128];

    proc_t proc = Task::findProcByPid(kernel, pid);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)proc);

    DARWIN_RK_LOG("MacPE::Task::getTaskPort() proc = %s\n", buffer);

    typedef task_t (*proc_task)(proc_t proc);
    task_t (*_proc_task)(proc_t proc);

    _proc_task = reinterpret_cast<proc_task>(kernel->getSymbolAddressByName("_proc_task"));

    task_t task = _proc_task(proc);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)task);

    DARWIN_RK_LOG("MacPE::Task::getTaskPort() task = %s\n", buffer);

    typedef ipc_port_t (*convert_task_to_port)(task_t task);
    ipc_port_t (*_convert_task_to_port)(task_t task);

    _convert_task_to_port = reinterpret_cast<convert_task_to_port>(
        kernel->getSymbolAddressByName("_convert_task_to_port"));

    ipc_port_t port = _convert_task_to_port(task);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)port);

    DARWIN_RK_LOG("MacPE::Task::getTaskPort() port = %s\n", buffer);

    if (!port)
        return NULL;

    return (xnu::Mach::Port)port;
}

Task* Task::getTaskByName(Kernel* kernel, char* name) {
    Task* task_;

    char buffer[128];

    proc_t proc = Task::findProcByName(kernel, name);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)proc);

    DARWIN_RK_LOG("MacPE::Task::getTaskByName() proc = %s\n", buffer);

    typedef task_t (*proc_task)(proc_t proc);
    task_t (*_proc_task)(proc_t proc);

    _proc_task = reinterpret_cast<proc_task>(kernel->getSymbolAddressByName("_proc_task"));

    task_t task = _proc_task(proc);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)task);

    DARWIN_RK_LOG("MacPE::Task::getTaskByName() task = %s\n", buffer);

    typedef ipc_port_t (*convert_task_to_port)(task_t task);
    ipc_port_t (*_convert_task_to_port)(task_t task);

    _convert_task_to_port = reinterpret_cast<convert_task_to_port>(
        kernel->getSymbolAddressByName("_convert_task_to_port"));

    ipc_port_t port = _convert_task_to_port(task);

    snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)port);

    DARWIN_RK_LOG("MacPE::Task::getTaskByName() port = %s\n", buffer);

    if (!port)
        return NULL;

    task_ = new Task(kernel, port);

    return task_;
}

proc_t Task::findProcByPid(Kernel* kernel, int pid) {
    proc_t current_proc;

    int current_pid;

    char buffer[128];

    current_proc = *reinterpret_cast<proc_t*>(kernel->getSymbolAddressByName("_kernproc"));

    current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);

    while (current_proc) {
        typedef int (*proc_pid)(proc_t proc);
        int (*_proc_pid)(proc_t proc);

        _proc_pid = reinterpret_cast<proc_pid>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_proc_pid")));

        current_pid = _proc_pid(current_proc);

        snprintf(buffer, 128, "0x%llx", (xnu::Mach::VmAddress)current_proc);

        DARWIN_RK_LOG("MacPE::proc = %s pid = %d\n", buffer, current_pid);

        if (current_pid == pid) {
            return current_proc;
        }

        if (current_pid == 0)
            break;

        current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);
    }

    return nullptr;
}

proc_t Task::findProcByName(Kernel* kernel, char* name) {
    proc_t current_proc;

    current_proc = *(proc_t*)reinterpret_cast<proc_t*>(kernel->getSymbolAddressByName("_kernproc"));

    current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);

    while (current_proc) {
        char* current_name;

        int current_pid;

        UInt64 buffer;

        typedef int (*proc_pid)(proc_t proc);
        int (*_proc_pid)(proc_t proc);

        typedef void* (*kalloc)(Size size);
        void* (*_kalloc)(Size size);

        typedef void (*kfree)(void* p, Size s);
        void (*_kfree)(void* p, Size);

        typedef void (*proc_name)(int pid, char* name, Size size);
        void (*_proc_name)(int pid, char* name, Size size);

        _proc_pid = reinterpret_cast<proc_pid>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_proc_pid")));

        current_pid = _proc_pid(current_proc);

        _kalloc = reinterpret_cast<kalloc>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_kalloc")));

        buffer = (UInt64)_kalloc(256);

        _proc_name = reinterpret_cast<proc_name>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_proc_name")));

        _proc_name(current_pid, (char*)buffer, 256);

        current_name = reinterpret_cast<char*>(buffer);

        char pointer[128];

        snprintf(pointer, 128, "0x%llx", (xnu::Mach::VmAddress)current_proc);

        DARWIN_RK_LOG("MacRK::proc = %s name = %s\n", pointer, current_name);

        if (EndsWith(current_name, name)) {
            return current_proc;
        }

        _kfree = reinterpret_cast<kfree>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_kfree")));

        _kfree(reinterpret_cast<void*>(buffer), 256);

        current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);
    }

    return nullptr;
}

task_t Task::findTaskByPid(Kernel* kernel, int pid) {
    task_t task;
    proc_t proc;

    proc = Task::findProcByPid(kernel, pid);

    if (proc != nullptr) {
        typedef task_t (*proc_task)(proc_t proc);

        task_t (*_proc_task)(proc_t proc);

        _proc_task = reinterpret_cast<proc_task>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_proc_task")));

        task = _proc_task(proc);

        return task;
    }

    return nullptr;
}

task_t Task::findTaskByName(Kernel* kernel, char* name) {
    task_t task;
    proc_t proc;

    proc = Task::findProcByName(kernel, name);

    if (proc != nullptr) {
        typedef task_t (*proc_task)(proc_t proc);

        task_t (*_proc_task)(proc_t proc);

        _proc_task = reinterpret_cast<proc_task>(
            PACSignPointerWithAKey(kernel->getSymbolAddressByName("_proc_task")));

        task = _proc_task(proc);

        return task;
    }

    return nullptr;
}

UInt64 Task::call(char* symbolname, UInt64* arguments, Size argCount) {
    return 0;
}

UInt64 Task::call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount) {
    return 0;
}

xnu::Mach::VmAddress Task::vmAllocate(Size size) {
    return task_vm_allocate(getMap(), size);
}

#define VM_KERN_MEMORY_KEXT 6

#define VM_INHERIT_SHARE ((vm_inherit_t)0)       /* shared with child */
#define VM_INHERIT_COPY ((vm_inherit_t)1)        /* copy into child */
#define VM_INHERIT_NONE ((vm_inherit_t)2)        /* absent from child */
#define VM_INHERIT_DONATE_COPY ((vm_inherit_t)3) /* copy and delete */

#define VM_INHERIT_DEFAULT VM_INHERIT_COPY

xnu::Mach::VmAddress Task::vmAllocate(Size size, UInt32 flags, vm_prot_t prot) {
    kern_return_t ret;

    xnu::Mach::VmAddress address = 0;

    vm_map_t map = getMap();

    UInt64 vmEnterArgs[13] = {reinterpret_cast<UInt64>(map),
                              (UInt64)&address,
                              size,
                              0,
                              flags,
                              VM_KERN_MEMORY_KEXT,
                              0,
                              0,
                              FALSE,
                              (UInt64)prot,
                              (UInt64)VM_INHERIT_DEFAULT};

    ret = static_cast<kern_return_t>(call("_vm_map_enter", vmEnterArgs, 13));

    if (ret != KERN_SUCCESS) {
        address = 0;
    }

    return address;
}

void Task::vmDeallocate(xnu::Mach::VmAddress address, Size size) {
    task_vm_deallocate(getMap(), address, size);
}

bool Task::vmProtect(xnu::Mach::VmAddress address, Size size, vm_prot_t prot) {
    return task_vm_protect(getMap(), address, size, prot);
}

void* Task::vmRemap(xnu::Mach::VmAddress address, Size size) {
    return task_vm_remap(getMap(), address, size);
}

UInt64 Task::virtualToPhysical(xnu::Mach::VmAddress address) {
    return 0;
}

bool Task::read(xnu::Mach::VmAddress address, void* data, Size size) {
    return task_vm_read(getMap(), address, data, size);
}

UInt8 Task::read8(xnu::Mach::VmAddress address) {
    UInt8 value;

    bool success =
        task_vm_read(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));

    if (!success)
        return 0;

    return value;
}

UInt16 Task::read16(xnu::Mach::VmAddress address) {
    UInt16 value;

    bool success =
        task_vm_read(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));

    if (!success)
        return 0;

    return value;
}

UInt32 Task::read32(xnu::Mach::VmAddress address) {
    UInt32 value;

    bool success =
        task_vm_read(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));

    if (!success)
        return 0;

    return value;
}

UInt64 Task::read64(xnu::Mach::VmAddress address) {
    UInt64 value;

    bool success =
        task_vm_read(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));

    if (!success)
        return 0;

    return value;
}

bool Task::write(xnu::Mach::VmAddress address, void* data, Size size) {
    return task_vm_write(getMap(), address, data, size);
}

void Task::write8(xnu::Mach::VmAddress address, UInt8 value) {
    task_vm_write(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::write16(xnu::Mach::VmAddress address, UInt16 value) {
    task_vm_write(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::write32(xnu::Mach::VmAddress address, UInt32 value) {
    task_vm_write(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::write64(xnu::Mach::VmAddress address, UInt64 value) {
    task_vm_write(getMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

char* Task::readString(xnu::Mach::VmAddress address) {
    return nullptr;
}

Symbol* Task::getSymbolByName(char* symname) {
    return nullptr;
}

Symbol* Task::getSymbolByAddress(xnu::Mach::VmAddress address) {
    return nullptr;
}

xnu::Mach::VmAddress Task::getSymbolAddressByName(char* symbolname) {
    return (xnu::Mach::VmAddress)0;
}