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

#include "kern.h"

vm_map_t kernel_map_ = 0;

pmap_t kernel_pmap_ = 0;

mach_vm_address_t vm_read_ = 0;
mach_vm_address_t vm_write_ = 0;

mach_vm_address_t vm_protect_ = 0;
mach_vm_address_t vm_remap_ = 0;

mach_vm_address_t vm_allocate_ = 0;
mach_vm_address_t vm_deallocate_ = 0;

mach_vm_address_t vm_map_copyin_ = 0;
mach_vm_address_t vm_map_copyout_ = 0;
mach_vm_address_t vm_map_copy_overwrite_ = 0;

mach_vm_address_t pmap_find_phys_ = 0;

mach_vm_address_t phys_read64_ = 0;
mach_vm_address_t phys_read32_ = 0;
mach_vm_address_t phys_read16_ = 0;
mach_vm_address_t phys_read8_ = 0;

mach_vm_address_t phys_write64_ = 0;
mach_vm_address_t phys_write32_ = 0;
mach_vm_address_t phys_write16_ = 0;
mach_vm_address_t phys_write8_ = 0;

void set_kernel_map(vm_map_t kernel_map) {
	kernel_map_ = kernel_map;
}

void set_kernel_pmap(pmap_t kernel_pmap) {
	kernel_pmap_ = kernel_pmap;
}

void set_vm_functions(mach_vm_address_t vm_read,
					  mach_vm_address_t vm_write,
					  mach_vm_address_t vm_protect,
					  mach_vm_address_t vm_remap,
					  mach_vm_address_t vm_allocate,
					  mach_vm_address_t vm_deallocate,
					  mach_vm_address_t vm_map_copyin,
					  mach_vm_address_t vm_map_copy_overwrite) {
	vm_read_ = vm_read;
	vm_write_ = vm_write;
	vm_protect_ = vm_protect;
	vm_remap_ = vm_remap;
	vm_allocate_ = vm_allocate;
	vm_deallocate_ = vm_deallocate;
	vm_map_copyin_ = vm_map_copyin;
	vm_map_copy_overwrite_ = vm_map_copy_overwrite;
}

void set_phys_functions(mach_vm_address_t pmap_find_phys,
						mach_vm_address_t phys_read64,
						mach_vm_address_t phys_read32,
						mach_vm_address_t phys_read16,
						mach_vm_address_t phys_read8,
						mach_vm_address_t phys_write64,
						mach_vm_address_t phys_write32,
						mach_vm_address_t phys_write16,
						mach_vm_address_t phys_write8) {
	pmap_find_phys_ = pmap_find_phys;

	phys_read64_ = phys_read64;
	phys_read32_ = phys_read32;
	phys_read16_ = phys_read16;
	phys_read8_ = phys_read8;

	phys_write64_ = phys_write64;
	phys_write32_ = phys_write32;
	phys_write16_ = phys_write16;
	phys_write8_ = phys_write8;
}

bool kernel_read(mach_vm_address_t address, void *data, size_t size) {
	bool success;
	success = kernel_vm_read(address, data, size);
	if(!success) {
		success = kernel_read_unsafe(address, data, size);
	}
	return success;
}

bool kernel_write(mach_vm_address_t address, const void *data, size_t size) {
	bool success;
	success = kernel_vm_write(address, data, size);
	if(!success) {
		success = kernel_write_unsafe(address, data, size);
	}
	return success;
}

bool kernel_read_unsafe(mach_vm_address_t address, void *data, size_t size) {
	uint8_t dereference = *(uint8_t*) address;
	memcpy(data, (void*) address, size);
	return true;
}

bool kernel_write_unsafe(mach_vm_address_t address, const void *data, size_t size) {
	uint8_t dereference = *(uint8_t*) address;
	memcpy((void*) address, data, size);
	return true;
}

bool kernel_vm_read(mach_vm_address_t address, void *data, size_t size) {
	kern_return_t ret;
	vm_map_copy_t copy;
	if(!vm_map_copyin_ || !vm_map_copy_overwrite_) {
		return false;
	}
	kern_return_t (*_vm_map_copyin)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*);
	ret = _vm_map_copyin(kernel_map_, (vm_address_t) address, (vm_map_size_t) size, FALSE, &copy);
	kern_return_t (*_vm_map_copy_overwrite)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);
	_vm_map_copy_overwrite = (kern_return_t (*)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t)) vm_map_copy_overwrite_;
	ret = _vm_map_copy_overwrite(kernel_map_, (vm_offset_t) data, copy, size, FALSE);
	if(ret != KERN_SUCCESS) {
		return false;
	}
	return true;
}

bool kernel_vm_write(mach_vm_address_t address, const void *data, size_t size) {
	const uint8_t *write_data = (uint8_t*) data;
	if(!vm_map_copyin_ || !vm_map_copy_overwrite_) {
		return false;
	}
	while(size > 0) {
		size_t write_size = size;
		if(write_size > 0x1000) {
			write_size = 0x1000;
		}
		vm_map_copy_t copy;
		kern_return_t ret;
		kern_return_t (*_vm_map_copyin)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*);
		_vm_map_copyin = (kern_return_t (*)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*)) vm_map_copyin_;
		ret = _vm_map_copyin(kernel_map_, (vm_address_t) write_data, (vm_map_size_t) write_size, FALSE, &copy);
		kern_return_t (*_vm_map_copy_overwrite)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);
		_vm_map_copy_overwrite = (kern_return_t (*)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t)) vm_map_copy_overwrite_;
		ret = _vm_map_copy_overwrite(kernel_map_, address, copy, write_size, FALSE);
		if(ret != KERN_SUCCESS) {
			return true;
		}
		address += write_size;
		write_data += write_size;
		size -= write_size;
	}
	return true;
}

mach_vm_address_t kernel_vm_allocate(size_t size) {
	mach_vm_address_t address;
	kern_return_t ret = vm_allocate(kernel_map_, (vm_address_t*) &address, size, VM_FLAGS_ANYWHERE);
	if(ret != KERN_SUCCESS) {
		address = 0;
	} else {
		for(uint32_t offset = 0; offset < size; offset += 0x1000) {
			uint64_t value;
			kernel_vm_read(address + offset, &value, sizeof(value));
		}
	}
	return address;
}

void kernel_vm_deallocate(mach_vm_address_t address, size_t size) {
	kern_return_t ret = vm_deallocate(kernel_map_, (vm_address_t) address, size);
	if(ret != KERN_SUCCESS) {
		return;
	}
}

bool kernel_vm_protect(mach_vm_address_t address, size_t size, vm_prot_t prot) {
	kern_return_t ret;
	kern_return_t (*_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
	_vm_protect = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t)) vm_protect_;
	ret = _vm_protect(kernel_map_, address, size, FALSE, prot);
	if(ret != KERN_SUCCESS) {
		return false;
	}
	return true;
}

void* kernel_vm_remap(mach_vm_address_t address, size_t size) {
	kern_return_t ret;
	mach_vm_address_t target_address = 0;
	vm_prot_t cur_prot, max_prot;
	kern_return_t (*_vm_remap)(vm_map_t, vm_address_t*, vm_size_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t*, vm_prot_t*, vm_inherit_t);
	_vm_remap = (kern_return_t (*)(vm_map_t, vm_address_t*, vm_size_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t*, vm_prot_t*, vm_inherit_t)) vm_remap_;
	ret = _vm_remap(kernel_map_,
					(vm_address_t*) &target_address,
					size,
					0,
					kernel_map_,
					address,
					FALSE,
					&cur_prot,
					&max_prot,
					VM_INHERIT_NONE
	);
	if(ret != KERN_SUCCESS) {
		return NULL;
	}
	return (void*) target_address;
}

uint64_t kernel_virtual_to_physical(mach_vm_address_t vaddr) {
	return 0;
}

bool task_vm_read(vm_map_t task_map, mach_vm_address_t address, void *data, size_t size) {
	kern_return_t ret;
	vm_map_copy_t copy;
	kern_return_t (*_vm_map_copyin)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*);

	_vm_map_copyin = (kern_return_t (*)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*)) vm_map_copyin_;
	ret = _vm_map_copyin(task_map, (vm_address_t) address, (vm_map_size_t) size, FALSE, &copy);

	kern_return_t (*_vm_map_copy_overwrite)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);
	_vm_map_copy_overwrite = (kern_return_t (*)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t)) vm_map_copy_overwrite_;
	ret = _vm_map_copy_overwrite(task_map, (vm_offset_t) data, copy, size, FALSE);
	if(ret != KERN_SUCCESS) {
		return false;
	}
	return true;
}

bool task_vm_write(vm_map_t task_map, mach_vm_address_t address, const void *data, size_t size) {
	const uint8_t *write_data = (uint8_t*) data;
	while(size > 0) {
		size_t write_size = size;
		if(write_size > 0x1000) {
			write_size = 0x1000;
		}
		vm_map_copy_t copy;
		kern_return_t ret;
		kern_return_t (*_vm_map_copyin)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*);

		_vm_map_copyin = (kern_return_t (*)(vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*)) vm_map_copyin_;
		ret = _vm_map_copyin(task_map, (vm_address_t) write_data, (vm_map_size_t) write_size, FALSE, &copy);

		kern_return_t (*_vm_map_copy_overwrite)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);
		_vm_map_copy_overwrite = (kern_return_t (*)(vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t)) vm_map_copy_overwrite_;
		ret = _vm_map_copy_overwrite(task_map, address, copy, write_size, FALSE);
		if(ret != KERN_SUCCESS) {
			return false;
		}
		address += write_size;
		write_data += write_size;
		size -= write_size;
	}
	return true;
}

mach_vm_address_t task_vm_allocate(vm_map_t task_map, size_t size) {
	mach_vm_address_t address;
	kern_return_t ret = vm_allocate(task_map, (vm_address_t*) &address, size, VM_FLAGS_ANYWHERE);
	if(ret != KERN_SUCCESS) {
		address = 0;
	} else {
		for(uint32_t offset = 0; offset < size; offset += 0x1000) {
			uint64_t value;
			kernel_vm_read(address + offset, &value, sizeof(value));
		}
	}
	return address;
}

void task_vm_deallocate(vm_map_t task_map, mach_vm_address_t address, size_t size) {
	kern_return_t ret = vm_deallocate(task_map, (vm_address_t) address, size);
	if(ret != KERN_SUCCESS) {
		return;
	}
}

bool task_vm_protect(vm_map_t task_map, mach_vm_address_t address, size_t size, vm_prot_t prot) {
	kern_return_t ret;
	kern_return_t (*_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
	_vm_protect = (kern_return_t (*)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t)) vm_protect_;
	ret = _vm_protect(task_map, address, size, FALSE, prot);
	if(ret != KERN_SUCCESS) {
		return false;
	}
	return true;
}

void* task_vm_remap(vm_map_t task_map, mach_vm_address_t address, size_t size) {
	kern_return_t ret;
	mach_vm_address_t target_address = 0;
	vm_prot_t cur_prot, max_prot;
	kern_return_t (*_vm_remap)(vm_map_t, vm_address_t*, vm_size_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t*, vm_prot_t*, vm_inherit_t);
	_vm_remap = (kern_return_t (*)(vm_map_t, vm_address_t*, vm_size_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t*, vm_prot_t*, vm_inherit_t)) vm_remap_;
	ret = _vm_remap(task_map,
					(vm_address_t*) &target_address,
					size,
					0,
					task_map,
					address,
					FALSE,
					&cur_prot,
					&max_prot,
					VM_INHERIT_NONE
	);
	if(ret != KERN_SUCCESS) {
		return NULL;
	}
	return (void*) target_address;
}

uint64_t physical_read64(uint64_t paddr) {
	typedef uint64_t (*ml_phys_read_double_64)(uint64_t);
	uint64_t (*_ml_phys_read_double_64)(uint64_t);
	_ml_phys_read_double_64 = (ml_phys_read_double_64) phys_read64_;
	return _ml_phys_read_double_64(paddr);
}

uint32_t physical_read32(uint64_t paddr) {
	typedef uint32_t (*ml_phys_read_word_64)(uint64_t);
	uint32_t (*_ml_phys_read_word_64)(uint64_t);
	_ml_phys_read_word_64 = (ml_phys_read_word_64) phys_read32_;
	return _ml_phys_read_word_64(paddr);
}

uint16_t physical_read16(uint64_t paddr) {
	typedef uint16_t (*ml_phys_read_half_64)(uint64_t);
	uint16_t (*_ml_phys_read_half_64)(uint64_t);
	_ml_phys_read_half_64 = (ml_phys_read_half_64) phys_read16_;
	return _ml_phys_read_half_64(paddr);
}

uint8_t physical_read8(uint64_t paddr) {
	typedef uint8_t (*ml_phys_read_byte_64)(uint64_t);
	uint8_t (*_ml_phys_read_byte_64)(uint64_t);
	_ml_phys_read_byte_64 = (ml_phys_read_byte_64) phys_read8_;
	return _ml_phys_read_byte_64(paddr);
}

void physical_write64(uint64_t paddr, uint64_t value) {
	typedef void (*ml_phys_write_double_64)(uint64_t, uint64_t);
	void (*_ml_phys_write_double_64)(uint64_t, uint64_t);
	_ml_phys_write_double_64 = (ml_phys_write_double_64) phys_write64_;
	_ml_phys_write_double_64(paddr, value);
}

void physical_write32(uint64_t paddr, uint32_t value) {
	typedef void (*ml_phys_write_word_64)(uint64_t, uint32_t);
	void (*_ml_phys_write_word_64)(uint64_t, uint32_t);
	_ml_phys_write_word_64 = (ml_phys_write_word_64) phys_write32_;
	_ml_phys_write_word_64(paddr, value);
}

void physical_write16(uint64_t paddr, uint16_t value) {
	typedef void (*ml_phys_write_half_64)(uint64_t, uint16_t);
	void (*_ml_phys_write_half_64)(uint64_t, uint16_t);
	_ml_phys_write_half_64 = (ml_phys_write_half_64) phys_write16_;
	_ml_phys_write_half_64(paddr, value);
}

void physical_write8(uint64_t paddr, uint8_t value) {
	typedef void (*ml_phys_write_byte_64)(uint64_t, uint8_t);
	void (*_ml_phys_write_byte_64)(uint64_t, uint8_t);
	_ml_phys_write_byte_64 = (ml_phys_write_byte_64) phys_write8_;
	_ml_phys_write_byte_64(paddr, value);
}
