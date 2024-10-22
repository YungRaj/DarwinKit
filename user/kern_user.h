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

#include <IOKit/IOKitLib.h>

#include <CoreFoundation/CoreFoundation.h>

#include <mach/mach_types.h>

#include <sys/types.h>

#include "api.h"

extern mach_port_t connection;

mach_port_t open_kernel_tfp0_connection();
void close_kernel_tfp0_connection();

mach_port_t _task_for_pid(int pid);

mach_vm_address_t get_kernel_base();
mach_vm_address_t get_kernel_symbol(char* symname);

off_t get_kernel_slide();

bool kernel_hook_function(char* symname, mach_vm_address_t hook, size_t hook_size);
bool kernel_hook(mach_vm_address_t address, mach_vm_address_t hook, size_t hook_size);

bool kernel_set_breakpoint_function(char* symname, mach_vm_address_t hook, size_t hook_size);
bool kernel_set_breakpoint(mach_vm_address_t address, mach_vm_address_t breakpoint_hook,
                           size_t breakpoint_hook_size);

uint64_t kernel_call_function(char* symname, uint64_t* arguments, size_t argcount);
uint64_t kernel_call(mach_vm_address_t symaddr, uint64_t* arguments, size_t argcount);

bool kernel_read(mach_vm_address_t address, void* data, size_t size);

uint8_t kernel_read8(mach_vm_address_t address);
uint16_t kernel_read16(mach_vm_address_t address);
uint32_t kernel_read32(mach_vm_address_t address);
uint64_t kernel_read64(mach_vm_address_t address);

bool kernel_write(mach_vm_address_t address, const void* data, size_t size);

bool kernel_write8(mach_vm_address_t address, uint8_t value);
bool kernel_write16(mach_vm_address_t address, uint16_t value);
bool kernel_write32(mach_vm_address_t address, uint32_t value);
bool kernel_write64(mach_vm_address_t address, uint64_t value);

mach_vm_address_t kernel_vm_allocate(size_t size);
void kernel_vm_deallocate(mach_vm_address_t address, size_t size);

bool kernel_vm_protect(mach_vm_address_t address, size_t size, vm_prot_t prot);
void* kernel_vm_remap(mach_vm_address_t address, size_t size);

uint64_t kernel_virtual_to_physical(mach_vm_address_t vaddr);

uint64_t phys_read64(uint64_t paddr);
uint32_t phys_read32(uint64_t paddr);
uint16_t phys_read16(uint64_t paddr);
uint8_t phys_read8(uint64_t paddr);

void phys_write64(uint64_t paddr, uint64_t value);
void phys_write32(uint64_t paddr, uint32_t value);
void phys_write16(uint64_t paddr, uint16_t value);
void phys_write8(uint64_t paddr, uint8_t value);

void dump_kernel(char** kernel, size_t* size, off_t* slide);

// uint64_t task_call_function(mach_port_t task_port, char *symname, uint64_t *arguments, size_t
// argcount);
uint64_t task_call(mach_port_t task_port, mach_vm_address_t symaddr, uint64_t* arguments,
                   size_t argcount);

mach_vm_address_t get_task_for_pid(int pid);
mach_vm_address_t get_proc_for_pid(int pid);

mach_vm_address_t get_task_by_name(char* name);
mach_vm_address_t get_proc_by_name(char* name);

bool task_vm_read(mach_port_t task, mach_vm_address_t address, void* data, size_t size);
bool task_vm_write(mach_port_t task, mach_vm_address_t address, const void* data, size_t size);

mach_vm_address_t task_vm_allocate(mach_port_t task, size_t size);

void task_vm_deallocate(mach_port_t task, mach_vm_address_t address, size_t size);

bool task_vm_protect(mach_port_t task, mach_vm_address_t address, size_t size, vm_prot_t prot);

uint64_t virtual_to_physical(mach_port_t task, mach_vm_address_t vaddr);
