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

#include "kern_user.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>

const char *service_name = "IOKernelDarwinKitService";

mach_port_t connection = MACH_PORT_NULL;

mach_port_t open_kernel_tfp0_connection()
{
	io_connect_t conn;

	io_iterator_t iterator;

	io_service_t service;

	io_name_t name;

	kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(service_name), &iterator);

	if(iterator == MACH_PORT_NULL)
		return MACH_PORT_NULL;

	while((service = IOIteratorNext(iterator)) != 0)
	{
		kr = IOServiceOpen(service, mach_task_self(), 0, &conn);

		IOObjectRelease(service);

		if(kr == KERN_SUCCESS)
			break;

		IOServiceClose(connection);
	}

	if(kr != KERN_SUCCESS)
		return MACH_PORT_NULL;

	connection = conn;

	return connection;
}

void close_kernel_tfp0_connection()
{
	if(connection != MACH_PORT_NULL)
	{
		IOServiceClose(connection);

		connection = MACH_PORT_NULL;
	}
}

mach_port_t _task_for_pid(int pid)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) pid };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitTaskForPid, input, 1, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (mach_vm_address_t) 0;
	}

	return (mach_port_t) output[0];
}

mach_vm_address_t get_kernel_symbol(char *symname)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) strdup(symname), (uint64_t) strlen(symname) + 1 };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetKernelSymbol, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (mach_vm_address_t) 0;
	}

	return (mach_vm_address_t) output[0];
}

off_t get_kernel_slide()
{
	kern_return_t kr;

	uint64_t input[] = {};
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetKaslrSlide, input, 0, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (mach_vm_address_t) 0;
	}

	return (off_t) output[0];
}

mach_vm_address_t get_kernel_base()
{
	kern_return_t kr;

	uint64_t input[] = {};
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetKernelBase, input, 0, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		printf("get_kernel_base failed!\n");

		return (mach_vm_address_t) 0;
	}

	return (mach_vm_address_t) output[0];
}

bool kernel_hook_function(char *symname, mach_vm_address_t hook, size_t hook_size)
{
	mach_vm_address_t symaddr = get_kernel_symbol(symname);

	return kernel_hook(symaddr, hook, hook_size);
}

bool kernel_hook(mach_vm_address_t address, mach_vm_address_t hook, size_t hook_size)
{
	kern_return_t kr;

	char *hook_code = NULL;

	if(hook)
	{
		hook_code = malloc(hook_size);

		memcpy(hook_code, (void*) hook, hook_size);
	}

	uint64_t input[] = { address, (uint64_t) hook_code, hook_size };
	uint64_t output[] = { };

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitHookKernelFunction, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	free(hook_code);

	return true;
}

bool kernel_set_breakpoint_function(char *symname, mach_vm_address_t breakpoint_hook, size_t breakpoint_hook_size)
{
	mach_vm_address_t symaddr = get_kernel_symbol(symname);

	return kernel_set_breakpoint(symaddr, breakpoint_hook, breakpoint_hook_size);
}

bool kernel_set_breakpoint(mach_vm_address_t address, mach_vm_address_t breakpoint_hook, size_t breakpoint_hook_size)
{
	kern_return_t kr;

	char *breakpoint_hook_code = NULL;

	if(breakpoint_hook)
	{
		breakpoint_hook_code = malloc(breakpoint_hook_size);

		memcpy(breakpoint_hook_code, (void*) breakpoint_hook, breakpoint_hook_size);
	}

	uint64_t input[] = { address, (uint64_t) breakpoint_hook_code, breakpoint_hook_size };
	uint64_t output[] = { };

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitAddBreakpoint, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

uint64_t kernel_call_function(char *symname, uint64_t *arguments, size_t argcount)
{
	kern_return_t kr;

	uint64_t ret;

	uint64_t *args = malloc(argcount * sizeof(uint64_t) + sizeof(uint64_t));

	memcpy(args + 1, arguments, argcount * sizeof(uint64_t));

	mach_vm_address_t symaddr = get_kernel_symbol(symname);

	args[0] = symaddr;

	ret = kernel_call(symaddr, args, argcount + 1);

	return ret;
}

uint64_t kernel_call(mach_vm_address_t symaddr, uint64_t *arguments, size_t argcount)
{
	kern_return_t kr;

	uint64_t ret;

	uint64_t output[] = { 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelCall, arguments, argcount, 0, 0,  output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (uint64_t) -1;
	}

	return output[0];
}

bool kernel_read(mach_vm_address_t address, void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) address, (uint64_t) data, (uint64_t) size};
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelRead, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

uint8_t kernel_read8(mach_vm_address_t address)
{
	uint8_t value;

	bool ok = kernel_read(address, (void*) &value, sizeof(uint8_t));

	if(!ok)
		return 0;

	return value;
}

uint16_t kernel_read16(mach_vm_address_t address)
{
	uint16_t value;

	bool ok = kernel_read(address, (void*) &value, sizeof(uint16_t));

	if(!ok)
		return 0;

	return value;
}

uint32_t kernel_read32(mach_vm_address_t address)
{
	uint32_t value;

	bool ok = kernel_read(address, (void*) &value, sizeof(uint32_t));

	if(!ok)
		return 0;

	return value;
}

uint64_t kernel_read64(mach_vm_address_t address)
{
	uint64_t value;

	bool ok = kernel_read(address, (void*) &value, sizeof(uint64_t));

	if(!ok)
		return 0;

	return value;
}

bool kernel_write(mach_vm_address_t address, const void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) address, (uint64_t) data, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelWrite, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

bool kernel_write8(mach_vm_address_t address, uint8_t value)
{
	return kernel_write(address, &value, sizeof(uint8_t));
}

bool kernel_write16(mach_vm_address_t address, uint16_t value)
{
	return kernel_write(address, &value, sizeof(uint16_t));
}

bool kernel_write32(mach_vm_address_t address, uint32_t value)
{
	return kernel_write(address, &value, sizeof(uint32_t));
}

bool kernel_write64(mach_vm_address_t address, uint64_t value)
{
	return kernel_write(address, &value, sizeof(uint64_t));
}

mach_vm_address_t kernel_vm_allocate(size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) size };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmAllocate, input, 1, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (mach_vm_address_t) 0;
	}

	return (mach_vm_address_t) output[0];
}

void kernel_vm_deallocate(mach_vm_address_t address, size_t size)
{	
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) address, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmDeallocate, input, 2, 0, 0, output, &outputCnt, 0, 0);
}

bool kernel_vm_protect(mach_vm_address_t address, size_t size, vm_prot_t prot)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) address, (uint64_t) size, (uint64_t) prot};
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmProtect, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

void* kernel_vm_remap(mach_vm_address_t address, size_t size)
{
	kern_return_t kr;

	mach_vm_address_t target_address;

	vm_prot_t cur_prot, max_prot;

	uint64_t input[] = { (uint64_t) address, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmProtect, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return NULL;
	}

	target_address = (mach_vm_address_t) output[0];

	return (void*) target_address;
}

uint64_t kernel_virtual_to_physical(mach_vm_address_t vaddr)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) vaddr };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmProtect, input, 1, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}

bool phys_read(uint64_t paddr, void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) paddr, (uint64_t) data, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitPhysicalRead, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

uint64_t phys_read64(uint64_t paddr)
{
	uint64_t value;

	bool ok = phys_read(paddr, (void*) &value, sizeof(uint64_t));

	if(!ok)
		return 0;

	return value;
}

uint32_t phys_read32(uint64_t paddr)
{
	uint32_t value;

	bool ok = phys_read(paddr, (void*) &value, sizeof(uint32_t));

	if(!ok)
		return 0;

	return value;
}

uint16_t phys_read16(uint64_t paddr)
{
	uint16_t value;

	bool ok = phys_read(paddr, (void*) &value, sizeof(uint16_t));

	if(!ok)
		return 0;

	return value;
}

uint8_t phys_read8(uint64_t paddr)
{
	uint8_t value;

	bool ok = phys_read(paddr, (void*) &value, sizeof(uint8_t));

	if(!ok)
		return 0;

	return value;
}

bool phys_write(uint64_t paddr, const void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) paddr, (uint64_t) data, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitPhysicalWrite, input, 3, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}


void phys_write64(uint64_t paddr, uint64_t value)
{
	phys_write(paddr, &value, sizeof(uint64_t));
}

void phys_write32(uint64_t paddr, uint32_t value)
{
	phys_write(paddr, &value, sizeof(uint32_t));
}

void phys_write16(uint64_t paddr, uint16_t value)
{
	phys_write(paddr, &value, sizeof(uint16_t));
}

void phys_write8(uint64_t paddr, uint8_t value)
{
	phys_write(paddr, &value, sizeof(uint8_t));
}

void dump_kernel(char **kernel, size_t *size, off_t *slide)
{

}

uint64_t task_call(mach_port_t task_port, mach_vm_address_t symaddr, uint64_t *arguments, size_t argcount)
{
	kern_return_t kr;

	uint64_t ret;

	uint64_t output[] = { 0 };

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitMachVmCall, arguments, argcount, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (uint64_t) -1;
	}

	return output[0];
}

mach_vm_address_t get_task_for_pid(int pid)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) pid };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetTaskForPid, input, 1, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}

mach_vm_address_t get_proc_for_pid(int pid)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) pid };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetProcForPid, input, 1, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}

mach_vm_address_t get_task_by_name(char *name)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) strdup(name), strlen(name) + 1 };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetTaskByName, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}

mach_vm_address_t get_proc_by_name(char *name)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) strdup(name), strlen(name) + 1 };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitGetProcByName, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}

bool task_vm_read(mach_port_t task, mach_vm_address_t address, void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (mach_port_t) task, (uint64_t) address, (uint64_t) data, (uint64_t) size};
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitMachVmRead, input, 4, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

bool task_vm_write(mach_port_t task, mach_vm_address_t address, const void *data, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (mach_port_t) task, (uint64_t) address, (uint64_t) data, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitMachVmWrite, input, 4, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

mach_vm_address_t task_vm_allocate(mach_port_t task, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) task, (uint64_t) size };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitMachVmAllocate, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return (mach_vm_address_t) 0;
	}

	return (mach_vm_address_t) output[0];
}

void task_vm_deallocate(mach_port_t task, mach_vm_address_t address, size_t size)
{
	kern_return_t kr;

	uint64_t input[] = { (mach_port_t) task, (uint64_t) address, (uint64_t) size };
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitMachVmDeallocate, input, 3, 0, 0, output, &outputCnt, 0, 0);
}

bool task_vm_protect(mach_port_t task, mach_vm_address_t address, size_t size, vm_prot_t prot)
{
	kern_return_t kr;

	uint64_t input[] = { (mach_port_t) task, (uint64_t) address, (uint64_t) size, (uint64_t) prot};
	uint64_t output[] = {};

	uint32_t outputCnt = 0;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmProtect, input, 4, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return false;
	}

	return true;
}

uint64_t virtual_to_physical(mach_port_t task, mach_vm_address_t vaddr)
{
	kern_return_t kr;

	uint64_t input[] = { (uint64_t) task, (uint64_t) vaddr };
	uint64_t output[] = { (uint64_t) 0 };

	uint32_t outputCnt = 1;

	kr = IOConnectCallMethod(connection, kIOKernelDarwinKitKernelVmProtect, input, 2, 0, 0, output, &outputCnt, 0, 0);

	if(kr != KERN_SUCCESS)
	{
		return 0;
	}

	return output[0];
}