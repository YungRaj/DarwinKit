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

#include "disassembler.h"
#include "kernel.h"
#include "log.h"

#include "dyld.h"
#include "task.h"

using namespace xnu;

static int EndsWith(const char* str, const char* suffix) {
    if (!str || !suffix)
        return 0;

    Size lenstr = strlen(str);
    Size lensuffix = strlen(suffix);

    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

Task::Task(Kernel* kernel, int pid)
    : kernel(kernel), pid(pid), task_port(Task::getTaskForPid(pid)),
      proc(Task::findProcByPid(kernel, pid)) {
    task = Task::getTaskFromProc(kernel, proc);
    name = getTaskName();

    dyld = new darwin::dyld::Dyld(kernel, this);
    macho = new darwin::UserMachO();
}

Task::Task(Kernel* kernel, char* name)
    : kernel(kernel), name(name), proc(Task::findProcByName(kernel, name)) {
    task = Task::getTaskFromProc(kernel, proc);

    pid = findPid();
    task_port = Task::getTaskForPid(pid);

    dyld = new darwin::dyld::Dyld(kernel, this);
    macho = new darwin::UserMachO();
}

xnu::Mach::Port Task::getTaskForPid(int pid) {
    kern_return_t ret;

    xnu::Mach::Port task;

    ret = task_for_pid(mach_task_self(), pid, &task);

    if (ret != KERN_SUCCESS) {
        DARWIN_RK_LOG("task_for_pid() failed! ret = %d\n", ret);
    }

    assert(task != MACH_PORT_NULL);
    assert(ret == KERN_SUCCESS);

    return task;
}

int Task::findPid() {
    UInt64 arguments[] = {proc};

    int pid = kernel->call("_proc_pid", arguments, 1);

    return pid;
}

Task* Task::getTaskInfo(Kernel* kernel, char* task_name) {
    return nullptr;
}

xnu::Mach::VmAddress Task::findProcByPid(Kernel* kernel, int pid) {
    xnu::Mach::VmAddress current_proc;

    int current_pid;

    current_proc =
        (xnu::Mach::VmAddress)kernel->read64(kernel->getSymbolAddressByName("_kernproc"));

    current_proc = (xnu::Mach::VmAddress)kernel->read64(current_proc + 0x8);

    while (current_proc) {
        UInt64 arguments[] = {current_proc};

        current_pid = kernel->call("_proc_pid", arguments, 1);

        if (current_pid == pid) {
            return current_proc;
        }

        if (current_pid == 0)
            break;

        current_proc = (xnu::Mach::VmAddress)kernel->read64(current_proc + 0x8);
    }

    current_proc = get_proc_for_pid(pid);

    if (current_proc) {
        return current_proc;
    }

    DARWIN_RK_LOG("MacRK::could not find proc for pid = %d\n", pid);

    assert(false);

    return 0;
}

xnu::Mach::VmAddress Task::findProcByName(Kernel* kernel, char* name) {
    xnu::Mach::VmAddress current_proc;

    current_proc = kernel->read64(kernel->getSymbolAddressByName("_kernproc"));

    current_proc = kernel->read64(current_proc + 0x8);

    while (current_proc) {
        UInt64 arguments[] = {current_proc};

        xnu::Mach::VmAddress proc_name;

        proc_name = kernel->call("_proc_name", arguments, 1);

        if (EndsWith(name, kernel->readString(proc_name)) == 0) {
            return current_proc;
        }

        current_proc = kernel->read64(current_proc + 0x8);
    }

    current_proc = get_proc_by_name(name);

    if (current_proc) {
        return current_proc;
    }

    DARWIN_RK_LOG("MacRK::could not find proc for name = %s\n", name);

    assert(false);

    return 0;
}

xnu::Mach::VmAddress Task::findTaskByPid(Kernel* kernel, int pid) {
    xnu::Mach::VmAddress task;
    xnu::Mach::VmAddress proc;

    proc = Task::findProcByPid(kernel, pid);

    if (proc) {
        UInt64 arguments[] = {proc};

        task = kernel->call("_proc_task", arguments, 1);

        return task;
    }

    task = get_task_for_pid(pid);

    if (task) {
        return task;
    }

    DARWIN_RK_LOG("MacPE::could not find task by pid = %d\n", pid);

    assert(false);

    return 0;
}

xnu::Mach::VmAddress Task::findTaskByName(Kernel* kernel, char* name) {
    xnu::Mach::VmAddress task;
    xnu::Mach::VmAddress proc;

    proc = Task::findProcByName(kernel, name);

    if (proc) {
        UInt64 arguments[] = {proc};

        task = kernel->call("_proc_task", arguments, 1);

        return task;
    }

    task = get_task_by_name(name);

    if (task) {
        return task;
    }

    DARWIN_RK_LOG("MacPE::could not find task by name = %s\n", name);

    assert(false);

    return 0;
}

xnu::Mach::VmAddress Task::getTaskFromProc(Kernel* kernel, xnu::Mach::VmAddress proc) {
    xnu::Mach::VmAddress task;

    if (proc) {
        UInt64 arguments[] = {proc};

        task = kernel->call("_proc_task", arguments, 1);

        return task;
    }

    return 0;
}

char* Task::getTaskName() {
    char* task_name;

    xnu::Mach::VmAddress name;

    UInt64 kalloc_args[] = {256};

    UInt64 buffer = kernel->call("_kalloc", kalloc_args, 1);

    UInt64 proc_name_args[] = {static_cast<UInt64>(pid), buffer, 256};

    name = kernel->call("_proc_name", proc_name_args, 3);

    task_name = kernel->readString(buffer);

    UInt64 kfree_args[] = {buffer, 256};

    kernel->call("_kfree", kfree_args, 2);

    return task_name;
}

xnu::Mach::VmAddress Task::findPort(Kernel* kernel, xnu::Mach::VmAddress task,
                                    xnu::Mach::Port port) {
    return 0;
}

xnu::Mach::VmAddress Task::getBase() {
    return 0;
}

Offset Task::getSlide() {
    return 0;
}

UInt64 Task::call(char* symbolname, UInt64* arguments, Size argCount) {
    // return task_call(task_port, symaddr, arguments, argcount);
    return 0;
}

UInt64 Task::call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount) {
    return task_call(task_port, func, arguments, argCount);
}

xnu::Mach::VmAddress Task::vmAllocate(Size size) {
    kern_return_t ret;

    xnu::Mach::VmAddress address;

    ret = vm_allocate(task_port, (vm_address_t*)&address, size, VM_PROT_DEFAULT);

    if (ret == KERN_SUCCESS) {
        return address;
    }

    DARWIN_RK_LOG("mach_vm_allocate() failed!\n");

    assert(ret == KERN_SUCCESS);

    return task_vm_allocate(task_port, size);
}

xnu::Mach::VmAddress Task::vmAllocate(Size size, UInt32 flags, xnu::Mach::VmProtection prot) {
    kern_return_t ret;

    xnu::Mach::VmAddress address;

    ret = vm_allocate(task_port, (vm_address_t*)&address, size, prot);

    if (ret == KERN_SUCCESS) {
        return address;
    }

    DARWIN_RK_LOG("mach_vm_allocate() failed!\n");

    assert(ret == KERN_SUCCESS);

    return task_vm_allocate(task_port, size);
}

void Task::vmDeallocate(xnu::Mach::VmAddress address, Size size) {
    kern_return_t ret;

    ret = vm_deallocate(task_port, address, size);

    if (ret != KERN_SUCCESS) {
        DARWIN_RK_LOG("mach_vm_deallocate() failed!\n");
    }

    assert(ret == KERN_SUCCESS);

    if (ret != KERN_SUCCESS) {
        task_vm_deallocate(task_port, address, size);
    }
}

bool Task::vmProtect(xnu::Mach::VmAddress address, Size size, xnu::Mach::VmProtection prot) {
    kern_return_t ret;

    ret = vm_protect(task_port, address, size, FALSE, prot);

    if (ret == KERN_SUCCESS) {
        return true;
    }

    DARWIN_RK_LOG("mach_vm_protect() failed!\n");

    assert(ret == KERN_SUCCESS);

    return task_vm_protect(task_port, address, size, prot);
}

void* Task::vmRemap(xnu::Mach::VmAddress address, Size size) {
    kern_return_t ret;

    xnu::Mach::VmAddress remap = 0;

    // ret = vm_remap(task_port, address, size, &remap);

    if (ret == KERN_SUCCESS) {
        return reinterpret_cast<void*>(remap);
    }

    DARWIN_RK_LOG("mach_vm_remap() failed!\n");

    assert(ret == KERN_SUCCESS);

    return nullptr;
}

UInt64 Task::virtualToPhysical(xnu::Mach::VmAddress address) {
    return 0;
}

bool Task::read(xnu::Mach::VmAddress address, void* data, Size size) {
    kern_return_t ret;

    mach_msg_type_number_t dataCount = size;

    ret = vm_read_overwrite(task_port, address, size, (mach_vm_address_t)data,
                            (vm_size_t*)&dataCount);

    if (ret == KERN_SUCCESS) {
        return true;
    }

    DARWIN_RK_LOG("mach_vm_read() failed! %d\n", ret);

    assert(ret == KERN_SUCCESS);

    return task_vm_read(task_port, address, data, size);
}

bool Task::readUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return false;
}

UInt8 Task::read8(xnu::Mach::VmAddress address) {
    bool success;

    UInt8 read;

    success = this->read(address, reinterpret_cast<void*>(&read), sizeof(UInt8));

    if (!success) {
        DARWIN_RK_LOG("Task::read8() failed!\n");
    }

    assert(success);

    return read;
}

UInt16 Task::read16(xnu::Mach::VmAddress address) {
    bool success;

    UInt16 read;

    success = this->read(address, reinterpret_cast<void*>(&read), sizeof(UInt16));

    if (!success) {
        DARWIN_RK_LOG("Task::read16() failed!\n");
    }

    assert(success);

    return read;
}

UInt32 Task::read32(xnu::Mach::VmAddress address) {
    bool success;

    UInt32 read;

    success = this->read(address, reinterpret_cast<void*>(&read), sizeof(UInt32));

    if (!success) {
        DARWIN_RK_LOG("Task::read32() failed!\n");
    }

    assert(success);

    return read;
}

UInt64 Task::read64(xnu::Mach::VmAddress address) {
    bool success;

    UInt64 read;

    success = this->read(address, reinterpret_cast<void*>(&read), sizeof(UInt64));

    if (!success) {
        DARWIN_RK_LOG("Task::read64() failed!\n");
    }

    assert(success);

    return read;
}

bool Task::write(xnu::Mach::VmAddress address, void* data, Size size) {
    return task_vm_write(task_port, address, data, size);
}

bool Task::writeUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return false;
}

void Task::write8(xnu::Mach::VmAddress address, UInt8 value) {
    bool success;

    success = write(address, reinterpret_cast<void*>(&value), sizeof(UInt8));

    if (!success) {
        DARWIN_RK_LOG("Task::write8() failed!\n");
    }

    assert(success);
}

void Task::write16(xnu::Mach::VmAddress address, UInt16 value) {
    bool success;

    success = write(address, reinterpret_cast<void*>(&value), sizeof(UInt16));

    if (!success) {
        DARWIN_RK_LOG("Task::write16() failed!\n");
    }

    assert(success);
}

void Task::write32(xnu::Mach::VmAddress address, UInt32 value) {
    bool success;

    success = write(address, reinterpret_cast<void*>(&value), sizeof(UInt32));

    if (!success) {
        DARWIN_RK_LOG("Task::write32() failed!\n");
    }

    assert(success);
}

void Task::write64(xnu::Mach::VmAddress address, UInt64 value) {
    bool success;

    success = write(address, reinterpret_cast<void*>(&value), sizeof(UInt64));

    if (!success) {
        DARWIN_RK_LOG("Task::write64() failed!\n");
    }

    assert(success);
}

char* Task::readString(xnu::Mach::VmAddress address) {
    char* string;

    UInt8 value;

    Size size = 0;

    do {
        read(address + size++, &value, sizeof(value));
    } while (value);

    assert(size > 0);

    string = (char*)malloc(size + 1);

    read(address, string, size + 1);

    return string;
}

Symbol* Task::getSymbolByName(char* symname) {
    return macho->getSymbolByName(symname);
}

Symbol* Task::getSymbolByAddress(xnu::Mach::VmAddress address) {
    return macho->getSymbolByAddress(address);
}

xnu::Mach::VmAddress Task::getSymbolAddressByName(char* symbolname) {
    Symbol* symbol = macho->getSymbolByName(symbolname);

    if (!symbol)
        return 0;

    return symbol->getAddress();
}

xnu::Mach::VmAddress Task::getImageLoadedAt(char* image_name, char** image_path) {
    xnu::Mach::VmAddress image = dyld->getImageLoadedAt(image_name, image_path);

    if (!image) {
        DARWIN_RK_LOG("Locating image %s failed!\n", image_name);
    }

    assert(image != 0);

    return image;
}

void Task::printLoadedImages() {}
