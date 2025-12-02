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

#include <IOKit/IOLib.h>
#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <os/log.h>

typedef void* pmap_t;

extern vm_map_t kernel_map_;

extern pmap_t kernel_pmap_;

extern mach_vm_address_t vm_read_;
extern mach_vm_address_t vm_write_;

extern mach_vm_address_t vm_protect_;
extern mach_vm_address_t vm_remap_;

extern mach_vm_address_t vm_allocate_;
extern mach_vm_address_t vm_deallocate_;

extern mach_vm_address_t vm_map_copyin_;
extern mach_vm_address_t vm_map_copyout_;
extern mach_vm_address_t vm_map_copy_overwrite_;

extern mach_vm_address_t pmap_find_phys_;

extern mach_vm_address_t phys_read64_;
extern mach_vm_address_t phys_read32_;
extern mach_vm_address_t phys_read16_;
extern mach_vm_address_t phys_read8_;

extern mach_vm_address_t phys_write64_;
extern mach_vm_address_t phys_write32_;
extern mach_vm_address_t phys_write16_;
extern mach_vm_address_t phys_write8_;

struct vm_map_copy {
    int type;
    vm_object_offset_t offset;
    vm_map_size_t size;
    void* kdata;
};

typedef struct vm_map_copy* vm_map_copy_t;

void set_kernel_map(vm_map_t kernel_map);

void set_vm_functions(mach_vm_address_t vm_read, mach_vm_address_t vm_write,
                      mach_vm_address_t vm_protect, mach_vm_address_t vm_remap,
                      mach_vm_address_t vm_allocate, mach_vm_address_t vm_deallocate,
                      mach_vm_address_t vm_map_copyin, mach_vm_address_t vm_map_copy_overwrite);

void set_phys_functions(mach_vm_address_t pmap_find_phys, mach_vm_address_t phys_read64,
                        mach_vm_address_t phys_read32, mach_vm_address_t phys_read16,
                        mach_vm_address_t phys_read8, mach_vm_address_t phys_write64,
                        mach_vm_address_t phys_write32, mach_vm_address_t phys_write16,
                        mach_vm_address_t phys_write8);

bool kernel_read(mach_vm_address_t address, void* data, size_t size);
bool kernel_write(mach_vm_address_t address, const void* data, size_t size);

bool kernel_read_unsafe(mach_vm_address_t address, void* data, size_t size);
bool kernel_write_unsafe(mach_vm_address_t address, const void* data, size_t size);

bool kernel_vm_read(mach_vm_address_t address, void* data, size_t size);
bool kernel_vm_write(mach_vm_address_t address, const void* data, size_t size);

mach_vm_address_t kernel_vm_allocate(size_t size);

void kernel_vm_deallocate(mach_vm_address_t address, size_t size);

bool kernel_vm_protect(mach_vm_address_t address, size_t size, vm_prot_t prot);
void* kernel_vm_remap(mach_vm_address_t address, size_t size);

uint64_t kernel_virtual_to_physical(mach_vm_address_t vaddr);

bool task_vm_read(vm_map_t task_map, mach_vm_address_t address, void* data, size_t size);
bool task_vm_write(vm_map_t task_map, mach_vm_address_t address, const void* data, size_t size);

mach_vm_address_t task_vm_allocate(vm_map_t task_map, size_t size);

void task_vm_deallocate(vm_map_t task_map, mach_vm_address_t address, size_t size);

bool task_vm_protect(vm_map_t task_map, mach_vm_address_t address, size_t size, vm_prot_t prot);
void* task_vm_remap(vm_map_t task_map, mach_vm_address_t address, size_t size);

uint64_t physical_read64(uint64_t paddr);
uint32_t physical_read32(uint64_t paddr);
uint16_t physical_read16(uint64_t paddr);
uint8_t physical_read8(uint64_t paddr);

void physical_write64(uint64_t paddr, uint64_t value);
void physical_write32(uint64_t paddr, uint32_t value);
void physical_write16(uint64_t paddr, uint16_t value);
void physical_write8(uint64_t paddr, uint8_t value);
