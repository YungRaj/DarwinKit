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
#include "task.h"

#include "log.h"

#include <IOKit/IOLib.h>
#include <mach/mach_types.h>

extern "C" {
#include "kern.h"
}

static int EndsWith(const char* str, const char* suffix) {
    if (!str || !suffix) {
        return 0;
    }
    Size lenstr = strlen(str);
    Size lensuffix = strlen(suffix);
    if (lensuffix > lenstr) {
        return 0;
    }
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

Task::Task(Kernel* kernel, xnu::mach::Port task_port) : kernel(kernel), task_port(task_port) {
    typedef vm_offset_t ipc_kobject_t;
    ipc_port_t port = reinterpret_cast<ipc_port_t>(task_port);
    UInt8* port_buf = reinterpret_cast<UInt8*>(port);
    task = (task_t) * (UInt64*)(port_buf + 0x68);

    Initialize();
}

Task::Task(Kernel* kernel, task_t task)
    : kernel(kernel), task(task), disassembler(new Disassembler(this)) {
    Initialize();
}

void Task::Initialize() {
    typedef proc_t (*get_bsdtask_info)(task_t task);
    auto _get_bsdtask_info =
        reinterpret_cast<get_bsdtask_info>(kernel->GetSymbolAddressByName("_get_bsdtask_info"));
    proc = _get_bsdtask_info(task);

    typedef vm_map_t (*get_task_map)(task_t task);
    auto _get_task_map = reinterpret_cast<get_task_map>(kernel->GetSymbolAddressByName("_get_task_map"));
    map = _get_task_map(task);

    typedef pmap_t (*get_task_pmap)(task_t task);
    auto _get_task_pmap =
        reinterpret_cast<get_task_pmap>(kernel->GetSymbolAddressByName("_get_task_pmap"));
    pmap = _get_task_pmap(task);
}

xnu::mach::Port Task::GetTaskPort(Kernel* kernel, int pid) {
    char buffer[128];

    proc_t proc = Task::FindProcByPid(kernel, pid);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)proc);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskPort() proc = %s\n", buffer);

    typedef task_t (*proc_task)(proc_t proc);
    auto _proc_task = reinterpret_cast<proc_task>(kernel->GetSymbolAddressByName("_proc_task"));

    task_t task = _proc_task(proc);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)task);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskPort() task = %s\n", buffer);

    typedef ipc_port_t (*convert_task_to_port)(task_t task);
    auto _convert_task_to_port = reinterpret_cast<convert_task_to_port>(
        kernel->GetSymbolAddressByName("_convert_task_to_port"));

    ipc_port_t port = _convert_task_to_port(task);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)port);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskPort() port = %s\n", buffer);

    if (!port) {
        return nullptr;
    }

    return (xnu::mach::Port)port;
}

pid_t Task::GetPid(task_t task) {
    Kernel *kernel = xnu::Kernel::Xnu();
    auto _get_bsd_task_info = reinterpret_cast<proc_t (*)(task_t task)>(
        kernel->GetSymbolAddressByName("_get_bsdtask_info", /*sign=*/true));
    proc_t proc = _get_bsd_task_info(task);

    auto _proc_pid = reinterpret_cast<int (*)(proc_t proc)>(
        kernel->GetSymbolAddressByName("_proc_pid", /*sign=*/true));
   return _proc_pid(proc);
}

Task* Task::GetTaskByName(Kernel* kernel, char* name) {
    char buffer[128];

    proc_t proc = Task::FindProcByName(kernel, name);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)proc);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskByName() proc = %s\n", buffer);

    typedef task_t (*proc_task)(proc_t proc);
    auto _proc_task = reinterpret_cast<proc_task>(kernel->GetSymbolAddressByName("_proc_task"));

    task_t task = _proc_task(proc);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)task);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskByName() task = %s\n", buffer);

    typedef ipc_port_t (*convert_task_to_port)(task_t task);
    auto _convert_task_to_port = reinterpret_cast<convert_task_to_port>(
        kernel->GetSymbolAddressByName("_convert_task_to_port"));

    ipc_port_t port = _convert_task_to_port(task);

    snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)port);
    DARWIN_KIT_LOG("DarwinKit::Task::GetTaskByName() port = %s\n", buffer);

    if (!port) {
        return nullptr;
    }
    return new Task(kernel, port);
}

proc_t Task::FindProcByPid(Kernel* kernel, int pid) {
    proc_t current_proc;
    int current_pid;
    char buffer[128];

    current_proc = *reinterpret_cast<proc_t*>(kernel->GetSymbolAddressByName("_kernproc"));
    current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);

    typedef int (*proc_pid)(proc_t proc);
    auto _proc_pid = reinterpret_cast<proc_pid>(
        kernel->GetSymbolAddressByName("_proc_pid", true));

    while (current_proc) {
        current_pid = _proc_pid(current_proc);

        snprintf(buffer, 128, "0x%llx", (xnu::mach::VmAddress)current_proc);
        DARWIN_KIT_LOG("DarwinKit::proc = %s pid = %d\n", buffer, current_pid);

        if (current_pid == pid) {
            return current_proc;
        }
        if (current_pid == 0) {
            break;
        }
        current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);
    }

    return nullptr;
}

proc_t Task::FindProcByName(Kernel* kernel, char* name) {
    proc_t current_proc;

    current_proc = *(proc_t*)reinterpret_cast<proc_t*>(kernel->GetSymbolAddressByName("_kernproc"));
    current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);

    typedef int (*proc_pid)(proc_t proc);
    typedef void (*proc_name)(int pid, char* name, Size size);

    auto _proc_pid = reinterpret_cast<proc_pid>(
        kernel->GetSymbolAddressByName("_proc_pid", /*sign=*/true));
    auto _proc_name = reinterpret_cast<proc_name>(
        kernel->GetSymbolAddressByName("_proc_name",/*sign=*/true));

    while (current_proc) {
        char* current_name;
        int current_pid;

        current_pid = _proc_pid(current_proc);

        char proc_name[256];
        _proc_name(current_pid, proc_name, 256);

        char pointer[128];
        snprintf(pointer, 128, "0x%llx", (xnu::mach::VmAddress)current_proc);
        DARWIN_KIT_LOG("DarwinKit::proc = %s name = %s\n", pointer, proc_name);

        if (EndsWith(proc_name, name)) {
            return current_proc;
        }
        current_proc = (proc_t) * (UInt64*)((UInt8*)current_proc + 0x8);
    }
    return nullptr;
}

task_t Task::FindTaskByPid(Kernel* kernel, int pid) {
    proc_t proc = Task::FindProcByPid(kernel, pid);
    typedef task_t (*proc_task)(proc_t proc);
    auto _proc_task = reinterpret_cast<proc_task>(
        kernel->GetSymbolAddressByName("_proc_task", /*sign=*/true));
    if (proc != nullptr) {
        task_t task = _proc_task(proc);
        return task;
    }
    return nullptr;
}

task_t Task::FindTaskByName(Kernel* kernel, char* name) {
    proc_t proc = Task::FindProcByName(kernel, name);
    if (proc != nullptr) {
        typedef task_t (*proc_task)(proc_t proc);
        auto _proc_task = reinterpret_cast<proc_task>(
            kernel->GetSymbolAddressByName("_proc_task", /*sign=*/true));
        task_t task = _proc_task(proc);
        return task;
    }
    return nullptr;
}

UInt64 Task::Call(char* symbolname, UInt64* arguments, Size argCount) {
    return 0;
}

UInt64 Task::Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount) {
    return 0;
}

xnu::mach::VmAddress Task::VmAllocate(Size size) {
    return task_vm_allocate(GetMap(), size);
}

#define VM_KERN_MEMORY_KEXT 6

#define VM_INHERIT_SHARE ((vm_inherit_t)0)       /* shared with child */
#define VM_INHERIT_COPY ((vm_inherit_t)1)        /* copy into child */
#define VM_INHERIT_NONE ((vm_inherit_t)2)        /* absent from child */
#define VM_INHERIT_DONATE_COPY ((vm_inherit_t)3) /* copy and delete */

#define VM_INHERIT_DEFAULT VM_INHERIT_COPY

xnu::mach::VmAddress Task::VmAllocate(Size size, UInt32 flags, vm_prot_t prot) {
    kern_return_t ret;
    xnu::mach::VmAddress address = 0;
    vm_map_t map = GetMap();
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

    ret = static_cast<kern_return_t>(Call("_vm_map_enter", vmEnterArgs, 13));
    if (ret != KERN_SUCCESS) {
        address = 0;
    }
    return address;
}

void Task::VmDeallocate(xnu::mach::VmAddress address, Size size) {
    task_vm_deallocate(GetMap(), address, size);
}

bool Task::VmProtect(xnu::mach::VmAddress address, Size size, vm_prot_t prot) {
    return task_vm_protect(GetMap(), address, size, prot);
}

void* Task::VmRemap(xnu::mach::VmAddress address, Size size) {
    return task_vm_remap(GetMap(), address, size);
}

UInt64 Task::VirtualToPhysical(xnu::mach::VmAddress address) {
    return 0;
}

bool Task::Read(xnu::mach::VmAddress address, void* data, Size size) {
    return task_vm_read(GetMap(), address, data, size);
}

UInt8 Task::Read8(xnu::mach::VmAddress address) {
    UInt8 value;
    bool success =
        task_vm_read(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
    if (!success) {
        return 0;
    }
    return value;
}

UInt16 Task::Read16(xnu::mach::VmAddress address) {
    UInt16 value;
    bool success =
        task_vm_read(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
    if (!success) {
        return 0;
    }
    return value;
}

UInt32 Task::Read32(xnu::mach::VmAddress address) {
    UInt32 value;
    bool success =
        task_vm_read(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
    if (!success) {
        return 0;
    }
    return value;
}

UInt64 Task::Read64(xnu::mach::VmAddress address) {
    UInt64 value;
    bool success =
        task_vm_read(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
    if (!success) {
        return 0;
    }
    return value;
}

bool Task::Write(xnu::mach::VmAddress address, void* data, Size size) {
    return task_vm_write(GetMap(), address, data, size);
}

void Task::Write8(xnu::mach::VmAddress address, UInt8 value) {
    task_vm_write(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::Write16(xnu::mach::VmAddress address, UInt16 value) {
    task_vm_write(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::Write32(xnu::mach::VmAddress address, UInt32 value) {
    task_vm_write(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

void Task::Write64(xnu::mach::VmAddress address, UInt64 value) {
    task_vm_write(GetMap(), address, reinterpret_cast<void*>(&value), sizeof(value));
}

char* Task::ReadString(xnu::mach::VmAddress address) {
    return nullptr;
}

Symbol* Task::GetSymbolByName(char* symname) {
    return nullptr;
}

Symbol* Task::GetSymbolByAddress(xnu::mach::VmAddress address) {
    return nullptr;
}

xnu::mach::VmAddress Task::GetSymbolAddressByName(char* symbolname, bool sign) {
    return (xnu::mach::VmAddress)0;
}
