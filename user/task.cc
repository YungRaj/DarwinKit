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

#include <assert.h>
#include <mach/mach.h>

#include "task.h"

#include "disassembler.h"
#include "dyld.h"
#include "kernel.h"
#include "log.h"

namespace xnu {

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

Task::Task() : disassembler(new Disassembler(this)) {}

Task::Task(Kernel* kernel, int pid)
    : kernel(kernel), pid(pid), task_port(Task::GetTaskForPid(pid)),
      proc(Task::FindProcByPid(kernel, pid)) {
    task = Task::GetTaskFromProc(kernel, proc);
    name = GetTaskName();
    dyld = new darwin::dyld::Dyld(kernel, this);
    macho = new darwin::MachOUserspace();
}

Task::Task(Kernel* kernel, char* name)
    : kernel(kernel), name(name), proc(Task::FindProcByName(kernel, name)) {
    task = Task::GetTaskFromProc(kernel, proc);
    pid = FindPid();
    task_port = Task::GetTaskForPid(pid);
    dyld = new darwin::dyld::Dyld(kernel, this);
    macho = new darwin::MachOUserspace();
}

xnu::mach::Port Task::GetTaskForPid(int pid) {
    kern_return_t ret;
    xnu::mach::Port task;
    ret = task_for_pid(mach_task_self(), pid, &task);
    if (ret != KERN_SUCCESS) {
        DARWIN_KIT_LOG("task_for_pid() failed! ret = %d\n", ret);
    }
    assert(task != MACH_PORT_NULL);
    assert(ret == KERN_SUCCESS);
    return task;
}

int Task::FindPid() {
    UInt64 arguments[] = {proc};
    int pid = kernel->Call("_proc_pid", arguments, 1);
    return pid;
}

Task* Task::GetTaskInfo(Kernel* kernel, char* task_name) {
    return nullptr;
}

xnu::mach::VmAddress Task::FindProcByPid(Kernel* kernel, int pid) {
    xnu::mach::VmAddress current_proc;
    int current_pid;
    current_proc =
        (xnu::mach::VmAddress)kernel->Read64(kernel->GetSymbolAddressByName("_kernproc"));
    current_proc = (xnu::mach::VmAddress)kernel->Read64(current_proc + 0x8);
    while (current_proc) {
        UInt64 arguments[] = {current_proc};
        current_pid = kernel->Call("_proc_pid", arguments, 1);
        if (current_pid == pid) {
            return current_proc;
        }
        if (current_pid == 0) {
            break;
        }
        current_proc = (xnu::mach::VmAddress)kernel->Read64(current_proc + 0x8);
    }
    current_proc = get_proc_for_pid(pid);
    if (current_proc) {
        return current_proc;
    }
    DARWIN_KIT_LOG("DarwinKit::could not find proc for pid = %d\n", pid);
    assert(false);
    return 0;
}

xnu::mach::VmAddress Task::FindProcByName(Kernel* kernel, char* name) {
    xnu::mach::VmAddress current_proc = kernel->Read64(kernel->GetSymbolAddressByName("_kernproc"));
    current_proc = kernel->Read64(current_proc + 0x8);
    while (current_proc) {
        UInt64 arguments[] = {current_proc};
        xnu::mach::VmAddress proc_name;
        proc_name = kernel->Call("_proc_name", arguments, 1);
        if (EndsWith(name, kernel->ReadString(proc_name)) == 0) {
            return current_proc;
        }
        current_proc = kernel->Read64(current_proc + 0x8);
    }
    current_proc = get_proc_by_name(name);
    if (current_proc) {
        return current_proc;
    }
    DARWIN_KIT_LOG("DarwinKit::could not find proc for name = %s\n", name);
    assert(false);
    return 0;
}

xnu::mach::VmAddress Task::FindTaskByPid(Kernel* kernel, int pid) {
    xnu::mach::VmAddress task;
    xnu::mach::VmAddress proc;
    proc = Task::FindProcByPid(kernel, pid);
    if (proc) {
        UInt64 arguments[] = {proc};
        task = kernel->Call("_proc_task", arguments, 1);
        return task;
    }
    task = get_task_for_pid(pid);
    if (task) {
        return task;
    }
    DARWIN_KIT_LOG("MacPE::could not find task by pid = %d\n", pid);
    assert(false);
    return 0;
}

xnu::mach::VmAddress Task::FindTaskByName(Kernel* kernel, char* name) {
    xnu::mach::VmAddress task;
    xnu::mach::VmAddress proc;
    proc = Task::FindProcByName(kernel, name);
    if (proc) {
        UInt64 arguments[] = {proc};
        task = kernel->Call("_proc_task", arguments, 1);
        return task;
    }
    task = get_task_by_name(name);
    if (task) {
        return task;
    }
    DARWIN_KIT_LOG("MacPE::could not find task by name = %s\n", name);
    assert(false);
    return 0;
}

xnu::mach::VmAddress Task::GetTaskFromProc(Kernel* kernel, xnu::mach::VmAddress proc) {
    xnu::mach::VmAddress task;
    if (proc) {
        UInt64 arguments[] = {proc};
        task = kernel->Call("_proc_task", arguments, 1);
        return task;
    }
    return 0;
}

char* Task::GetTaskName() {
    char* task_name;
    xnu::mach::VmAddress name;

    UInt64 kalloc_args[] = {256};
    UInt64 buffer = kernel->Call("_kalloc", kalloc_args, 1);
    UInt64 proc_name_args[] = {static_cast<UInt64>(pid), buffer, 256};
    name = kernel->Call("_proc_name", proc_name_args, 3);
    task_name = kernel->ReadString(buffer);

    UInt64 kfree_args[] = {buffer, 256};
    kernel->Call("_kfree", kfree_args, 2);

    return task_name;
}

xnu::mach::VmAddress Task::FindPort(Kernel* kernel, xnu::mach::VmAddress task,
                                    xnu::mach::Port port) {
    return 0;
}

xnu::mach::VmAddress Task::GetBase() {
    return 0;
}

Offset Task::GetSlide() {
    return 0;
}

UInt64 Task::Call(char* symbolname, UInt64* arguments, Size argCount) {
    // return task_call(task_port, symaddr, arguments, argcount);
    return 0;
}

UInt64 Task::Call(xnu::mach::VmAddress func, UInt64* arguments, Size argCount) {
    return task_call(task_port, func, arguments, argCount);
}

xnu::mach::VmAddress Task::VmAllocate(Size size) {
    kern_return_t ret;
    xnu::mach::VmAddress address;
    ret = vm_allocate(task_port, (vm_address_t*)&address, size, VM_PROT_DEFAULT);
    if (ret == KERN_SUCCESS) {
        return address;
    }
    DARWIN_KIT_LOG("mach_vm_allocate() failed!\n");
    assert(ret == KERN_SUCCESS);
    return task_vm_allocate(task_port, size);
}

xnu::mach::VmAddress Task::VmAllocate(Size size, UInt32 flags, xnu::mach::VmProtection prot) {
    kern_return_t ret;
    xnu::mach::VmAddress address;
    ret = vm_allocate(task_port, (vm_address_t*)&address, size, prot);
    if (ret == KERN_SUCCESS) {
        return address;
    }
    DARWIN_KIT_LOG("mach_vm_allocate() failed!\n");
    assert(ret == KERN_SUCCESS);
    return task_vm_allocate(task_port, size);
}

void Task::VmDeallocate(xnu::mach::VmAddress address, Size size) {
    kern_return_t ret;
    ret = vm_deallocate(task_port, address, size);
    if (ret != KERN_SUCCESS) {
        DARWIN_KIT_LOG("mach_vm_deallocate() failed!\n");
    }
    assert(ret == KERN_SUCCESS);
    if (ret != KERN_SUCCESS) {
        task_vm_deallocate(task_port, address, size);
    }
}

bool Task::VmProtect(xnu::mach::VmAddress address, Size size, xnu::mach::VmProtection prot) {
    kern_return_t ret;
    ret = vm_protect(task_port, address, size, FALSE, prot);
    if (ret == KERN_SUCCESS) {
        return true;
    }
    DARWIN_KIT_LOG("mach_vm_protect() failed!\n");
    assert(ret == KERN_SUCCESS);
    return task_vm_protect(task_port, address, size, prot);
}

void* Task::VmRemap(xnu::mach::VmAddress address, Size size) {
    kern_return_t ret;
    xnu::mach::VmAddress remap = 0;
    // ret = vm_remap(task_port, address, size, &remap);
    if (ret == KERN_SUCCESS) {
        return reinterpret_cast<void*>(remap);
    }
    DARWIN_KIT_LOG("mach_vm_remap() failed!\n");
    assert(ret == KERN_SUCCESS);
    return nullptr;
}

UInt64 Task::VirtualToPhysical(xnu::mach::VmAddress address) {
    return 0;
}

bool Task::Read(xnu::mach::VmAddress address, void* data, Size size) {
    kern_return_t ret;
    mach_msg_type_number_t dataCount = size;
    ret = vm_read_overwrite(task_port, address, size, (mach_vm_address_t)data,
                            (vm_size_t*)&dataCount);
    if (ret == KERN_SUCCESS) {
        return true;
    }
    DARWIN_KIT_LOG("mach_vm_read() failed! %d\n", ret);
    assert(ret == KERN_SUCCESS);
    return task_vm_read(task_port, address, data, size);
}

bool Task::ReadUnsafe(xnu::mach::VmAddress address, void* data, Size size) {
    return false;
}

UInt8 Task::Read8(xnu::mach::VmAddress address) {
    UInt8 read;
    bool success = this->Read(address, reinterpret_cast<void*>(&read), sizeof(UInt8));
    if (!success) {
        DARWIN_KIT_LOG("Task::Read8() failed!\n");
    }
    assert(success);
    return read;
}

UInt16 Task::Read16(xnu::mach::VmAddress address) {
    UInt16 read;
    bool success = this->Read(address, reinterpret_cast<void*>(&read), sizeof(UInt16));
    if (!success) {
        DARWIN_KIT_LOG("Task::Read16() failed!\n");
    }
    assert(success);
    return read;
}

UInt32 Task::Read32(xnu::mach::VmAddress address) {
    UInt32 read;
    bool success = this->Read(address, reinterpret_cast<void*>(&read), sizeof(UInt32));
    if (!success) {
        DARWIN_KIT_LOG("Task::Read32() failed!\n");
    }
    assert(success);
    return read;
}

UInt64 Task::Read64(xnu::mach::VmAddress address) {
    UInt64 read;
    bool success = this->Read(address, reinterpret_cast<void*>(&read), sizeof(UInt64));
    if (!success) {
        DARWIN_KIT_LOG("Task::Read64() failed!\n");
    }
    assert(success);
    return read;
}

bool Task::Write(xnu::mach::VmAddress address, void* data, Size size) {
    return task_vm_write(task_port, address, data, size);
}

bool Task::WriteUnsafe(xnu::mach::VmAddress address, void* data, Size size) {
    return false;
}

void Task::Write8(xnu::mach::VmAddress address, UInt8 value) {
    bool success = Write(address, reinterpret_cast<void*>(&value), sizeof(UInt8));
    if (!success) {
        DARWIN_KIT_LOG("Task::Write8() failed!\n");
    }
    assert(success);
}

void Task::Write16(xnu::mach::VmAddress address, UInt16 value) {
    bool success = Write(address, reinterpret_cast<void*>(&value), sizeof(UInt16));
    if (!success) {
        DARWIN_KIT_LOG("Task::Write16() failed!\n");
    }
    assert(success);
}

void Task::Write32(xnu::mach::VmAddress address, UInt32 value) {
    bool success = Write(address, reinterpret_cast<void*>(&value), sizeof(UInt32));
    if (!success) {
        DARWIN_KIT_LOG("Task::Write32() failed!\n");
    }
    assert(success);
}

void Task::Write64(xnu::mach::VmAddress address, UInt64 value) {
    bool success = Write(address, reinterpret_cast<void*>(&value), sizeof(UInt64));
    if (!success) {
        DARWIN_KIT_LOG("Task::Write64() failed!\n");
    }
    assert(success);
}

char* Task::ReadString(xnu::mach::VmAddress address) {
    char* string;
    UInt8 value;
    Size size = 0;
    do {
        Read(address + size++, &value, sizeof(value));
    } while (value);

    assert(size > 0);
    string = (char*)malloc(size + 1);
    Read(address, string, size + 1);
    return string;
}

Symbol* Task::GetSymbolByName(char* symname) {
    return macho->GetSymbolByName(symname);
}

Symbol* Task::GetSymbolByAddress(xnu::mach::VmAddress address) {
    return macho->GetSymbolByAddress(address);
}

xnu::mach::VmAddress Task::GetSymbolAddressByName(char* symbolname) {
    Symbol* symbol = macho->GetSymbolByName(symbolname);
    if (!symbol) {
        return 0;
    }
    return symbol->GetAddress();
}

xnu::mach::VmAddress Task::GetImageLoadedAt(char* image_name, char** image_path) {
    xnu::mach::VmAddress image = dyld->GetImageLoadedAt(image_name, image_path);
    if (!image) {
        DARWIN_KIT_LOG("Locating image %s failed!\n", image_name);
    }
    assert(image != 0);
    return image;
}

void Task::PrintLoadedImages() {}

} // namespace xnu
