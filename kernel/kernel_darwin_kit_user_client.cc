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

#include "kernel_darwin_kit.h"
#include "kernel_darwin_kit_user_client.h"

#include "darwin_kit.h"

#include "kernel.h"
#include "kernel_patcher.h"

#include "task.h"

#include "section.h"
#include "segment.h"

#include "log.h"

#include <mach/vm_types.h>

extern "C" {
#include "kern.h"
}

OSDefineMetaClassAndStructors(IOKernelDarwinKitUserClient, IOUserClient)

IOKernelDarwinKitUserClient* IOKernelDarwinKitUserClient::rootKitUserClientWithKernel(
        xnu::Kernel* kernel, task_t owningTask, void* securityToken, UInt32 type) {
    IOKernelDarwinKitUserClient* client;

    client = new IOKernelDarwinKitUserClient();

    if (client) {
        if (!client->initRootKitUserClientWithKernel(kernel, owningTask, securityToken, type)) {
            client->release();

            return NULL;
        }
    }

    return client;
}

IOKernelDarwinKitUserClient* IOKernelDarwinKitUserClient::rootKitUserClientWithKernel(
    xnu::Kernel* kernel, task_t owningTask, void* securityToken, UInt32 type,
    OSDictionary* properties) {
    IOKernelDarwinKitUserClient* client;

    client = new IOKernelDarwinKitUserClient();

    if (client) {
        if (!client->initRootKitUserClientWithKernel(kernel, owningTask, securityToken, type,
                                                     properties)) {
            client->release();

            return NULL;
        }
    }

    return client;
}

bool IOKernelDarwinKitUserClient::initRootKitUserClientWithKernel(xnu::Kernel* kernel,
                                                                task_t owningTask,
                                                                void* securityToken, UInt32 type) {
    bool result = IOUserClient::initWithTask(owningTask, securityToken, type);

    if (!kernel)
        result = false;

    this->kernel = kernel;

    this->clientTask = owningTask;
    this->kernelTask = *(task_t*)kernel->getSymbolAddressByName("_kernel_task");

    return result;
}

bool IOKernelDarwinKitUserClient::initRootKitUserClientWithKernel(xnu::Kernel* kernel,
                                                                task_t owningTask,
                                                                void* securityToken, UInt32 type,
                                                                OSDictionary* properties) {
    bool result = IOUserClient::initWithTask(owningTask, securityToken, type, properties);

    if (!kernel)
        result = false;

    this->kernel = kernel;

    this->clientTask = owningTask;
    this->kernelTask = *(task_t*)kernel->getSymbolAddressByName("_kernel_task");

    return result;
}

bool IOKernelDarwinKitUserClient::start(IOService* provider) {
    IOKernelDarwinKitService* service = this->kernel->getRootKitService();

    this->rootkitService = service;

    return IOUserClient::start(provider);
}

void IOKernelDarwinKitUserClient::stop(IOService* provider) {
    return IOUserClient::stop(provider);
}

IOReturn IOKernelDarwinKitUserClient::clientClose() {
    return kIOReturnSuccess;
}

IOReturn IOKernelDarwinKitUserClient::clientDied() {
    IOReturn result = clientClose();

    return result;
}

void IOKernelDarwinKitUserClient::free() {}

IOExternalMethod* IOKernelDarwinKitUserClient::getExternalMethodForIndex(UInt32 index) {
    return NULL;
}

IOExternalTrap* IOKernelDarwinKitUserClient::getExternalTrapForIndex(UInt32 index) {
    return NULL;
}

UInt8* IOKernelDarwinKitUserClient::mapBufferFromClientTask(xnu::Mach::VmAddress uaddr, Size size,
                                                          IOOptionBits options,
                                                          IOMemoryDescriptor** desc,
                                                          IOMemoryMap** mapping) {
    UInt8* buffer;

    IOReturn ret;

    IOMemoryDescriptor* descriptor;

    IOMemoryMap* map;

    descriptor = IOMemoryDescriptor::withAddressRange(uaddr, size, options, this->getClientTask());

    if (!descriptor) {
        goto fail;
    }

    ret = descriptor->prepare(options);

    if (ret != kIOReturnSuccess) {
        goto fail;
    }

    map = descriptor->map();

    if (!map) {
        goto fail;
    }

    buffer = reinterpret_cast<UInt8*>(map->getVirtualAddress());

    if (!buffer) {
        goto fail;
    }

    *desc = descriptor;
    *mapping = map;

    return buffer;

fail:
    *desc = NULL;
    *mapping = NULL;

    return NULL;
}

IOReturn IOKernelDarwinKitUserClient::externalMethod(UInt32 selector,
                                                   IOExternalMethodArguments* arguments,
                                                   IOExternalMethodDispatch* dispatch,
                                                   OSObject* target, void* reference) {
    IOReturn result = kIOReturnSuccess;

    MAC_RK_LOG("MacRK::IOKernelDarwinKitUserClient::externalMethod() called!\n");

    switch (selector) {
    case kIOKernelDarwinKitHookKernelFunction:;

        if (arguments->scalarInputCount == 3) {
            KernelPatcher* patcher = rootkitService->getRootKit()->getKernelPatcher();

            IOMemoryDescriptor* descriptor;

            IOMemoryMap* map;

            bool success;

            xnu::Mach::VmAddress address = arguments->scalarInput[0];

            xnu::Mach::VmAddress hook = arguments->scalarInput[1];

            Size hook_size = arguments->scalarInput[2];

            Size code_size = hook_size % 0x1000 >= sizeof(UInt64)
                                 ? (hook_size - (hook_size % 0x1000)) + 0x1000
                                 : hook_size;

            if (hook) {
            }
        }

        break;
    case kIOKernelDarwinKitAddBreakpoint:;

        if (arguments->scalarInputCount == 3) {
            KernelPatcher* patcher = rootkitService->getRootKit()->getKernelPatcher();

            IOMemoryDescriptor* descriptor;

            IOMemoryMap* map;

            bool success;

            xnu::Mach::VmAddress breakpoint = arguments->scalarInput[0];

            xnu::Mach::VmAddress breakpoint_hook = arguments->scalarInput[1];

            Size breakpoint_hook_size = arguments->scalarInput[2];

            Size code_size = breakpoint_hook_size % 0x1000 > 0
                                 ? (breakpoint_hook_size - (breakpoint_hook_size % 0x1000)) + 0x1000
                                 : breakpoint_hook_size;

            xnu::Mach::VmAddress copyin;

            if (breakpoint_hook) {
            }
        }

        break;
    case kIOKernelDarwinKitKernelCall:;

        if (arguments->scalarInputCount > 1) {
            xnu::Mach::VmAddress func = arguments->scalarInput[0];

            Size argCount = arguments->scalarInputCount - 1;

            UInt64* args = new UInt64[argCount];

            for (UInt32 i = 1; i < argCount + 1; i++) {
                args[i - 1] = arguments->scalarInput[i];
            }

            UInt64 ret = kernel->call(func, (UInt64*)args, argCount);

            arguments->scalarOutput[0] = ret;

            delete[] args;
        }

        break;
    case kIOKernelDarwinKitGetKaslrSlide:;

        if (arguments) {
            if (arguments->scalarInputCount == 0) {
                UInt64 slide = Kernel::findKernelSlide();

                arguments->scalarOutput[0] = slide;
            }
        }

        break;
    case kIOKernelDarwinKitGetKernelBase:;

        if (arguments) {
            if (arguments->scalarInputCount == 0) {
                xnu::Mach::VmAddress base = kernel->getBase();

                arguments->scalarOutput[0] = base;
            }
        }

        break;
    case kIOKernelDarwinKitGetKernelSymbol:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                Symbol* symbol;

                xnu::Mach::VmAddress symaddr;

                UInt8* buf = this->mapBufferFromClientTask(arguments->scalarInput[0],
                                                           arguments->scalarInput[1],
                                                           kIODirectionOutIn, &descriptor, &map);

                char* symname = reinterpret_cast<char*>(buf);

                symaddr = kernel->getSymbolAddressByName(symname);

                arguments->scalarOutput[0] = symaddr;

                if (!symaddr) {
                    result = kIOReturnBadArgument;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();
            }
        }

        break;

    case kIOKernelDarwinKitGetKextSymbol:;

        if (arguments) {
            if (arguments->scalarInputCount == 4) {
                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                Symbol* symbol;

                xnu::Mach::VmAddress symaddr;

                UInt8* buf1 = this->mapBufferFromClientTask(arguments->scalarInput[0],
                                                            arguments->scalarInput[1],
                                                            kIODirectionOutIn, &descriptor, &map);

                UInt8* buf2 = this->mapBufferFromClientTask(arguments->scalarInput[2],
                                                            arguments->scalarInput[3],
                                                            kIODirectionOutIn, &descriptor, &map);

                char* kextidentifier = reinterpret_cast<char*>(buf1);

                xnu::Kext* kext =
                    this->getRootKitService()->getRootKit()->getKextByIdentifier(kextidentifier);

                if (kext) {
                    char* kextsymname = reinterpret_cast<char*>(buf2);

                    symaddr = kext->getSymbolAddressByName(kextsymname);

                    arguments->scalarOutput[0] = symaddr;

                    if (!symaddr) {
                        result = kIOReturnBadArgument;
                    }
                } else {
                    result = kIOReturnBadArgument;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();
            }
        }

        break;
    case kIOKernelDarwinKitKernelRead:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    this->mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                if (address && buf) {
                    success = kernel->read(address, (void*)buf, size);

                    if (!success) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();
            }
        }

        break;
    case kIOKernelDarwinKitKernelReadUnsafe:
        break;
    case kIOKernelDarwinKitKernelWrite:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    this->mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                if (address && buf) {
                    UInt8* buf_copy = new UInt8[size];

                    descriptor->readBytes(0, (void*)buf_copy, (UInt32)size);

                    kernel->write(address, (void*)buf_copy, size);

                    if (!success) {
                        result = kIOReturnNoMemory;
                    }

                    delete[] buf_copy;

                    if (map)
                        map->release();

                    if (descriptor)
                        descriptor->release();
                }
            } else {
                result = kIOReturnBadArgument;
            }
        }

        break;
    case kIOKernelDarwinKitKernelWriteUnsafe:
        break;
    case kIOKernelDarwinKitKernelVmAllocate:;

        if (arguments) {
            if (arguments->scalarInputCount == 1) {
                xnu::Mach::VmAddress address;

                Size size = arguments->scalarInput[0];

                address = kernel->vmAllocate(size);

                if (!address) {
                    result = kIOReturnNoMemory;
                }

                arguments->scalarOutput[0] = address;
            }
        }

        break;
    case kIOKernelDarwinKitKernelVmDeallocate:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                xnu::Mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                kernel->vmDeallocate(address, size);

                arguments->scalarOutput[0] = address;
            }
        }

        break;
    case kIOKernelDarwinKitKernelVmProtect:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                xnu::Mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                vm_prot_t prot = (vm_prot_t)arguments->scalarInput[2];

                if (address) {
                    success = kernel->vmProtect(address, size, prot);

                    if (!success) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                }
            }
        }

        break;
    case kIOKernelDarwinKitKernelVmRemap:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                xnu::Mach::VmAddress remapped;

                xnu::Mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                if (address) {
                    remapped =
                        reinterpret_cast<xnu::Mach::VmAddress>(kernel->vmRemap(address, size));

                    if (!remapped) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                }
            }
        }

        break;
    case kIOKernelDarwinKitKalloc:
        break;
    case kIOKernelDarwinKitPhysicalRead:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                UInt64 paddr = arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    this->mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                success = kernel->physicalRead(paddr, (void*)buf, size);

                if (!success) {
                    result = kIOReturnNoMemory;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();
            }
        }

        break;
    case kIOKernelDarwinKitPhysicalWrite:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                UInt64 paddr = arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    this->mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                success = kernel->physicalWrite(paddr, (void*)buf, size);

                if (!success) {
                    result = kIOReturnNoMemory;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();
            }
        }

        break;
    case kIOKernelDarwinKitKernelVirtualToPhysical:;

        if (arguments) {
            if (arguments->scalarInputCount == 1) {
                UInt64 physaddr;

                UInt64 vmaddr = (xnu::Mach::VmAddress)arguments->scalarInput[0];

                if (vmaddr) {
                    physaddr = kernel->virtualToPhysical(vmaddr);

                    if (!physaddr) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                }
            }
        }

        break;
    case kIOKernelDarwinKitTaskForPid:
        break;

    case kIOKernelDarwinKitGetTaskForPid:;

        if (arguments) {
            if (arguments->scalarInputCount == 1) {
                int pid = (int)arguments->scalarInput[0];

                xnu::Mach::VmAddress task =
                    reinterpret_cast<xnu::Mach::VmAddress>(Task::findTaskByPid(this->kernel, pid));

                if (!task) {
                    result = kIOReturnError;
                }

                arguments->scalarOutput[0] = task;
            }
        }

        break;

    case kIOKernelDarwinKitGetProcForPid:;

        if (arguments) {
            if (arguments->scalarInputCount == 1) {
                int pid = (int)arguments->scalarInput[0];

                xnu::Mach::VmAddress proc =
                    reinterpret_cast<xnu::Mach::VmAddress>(Task::findProcByPid(this->kernel, pid));

                if (!proc) {
                    result = kIOReturnError;
                }

                arguments->scalarOutput[0] = proc;
            }
        }

        break;

    case kIOKernelDarwinKitGetTaskByName:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                char* name = reinterpret_cast<char*>(this->mapBufferFromClientTask(
                    arguments->scalarInput[0], arguments->scalarInput[1], kIODirectionOutIn,
                    &descriptor, &map));

                MAC_RK_LOG("MacRK::finding task with name = 0x%llx\n", (UInt64)(name));

                xnu::Mach::VmAddress task = reinterpret_cast<xnu::Mach::VmAddress>(
                    Task::findTaskByName(this->kernel, name));

                if (!task) {
                    result = kIOReturnError;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();

                arguments->scalarOutput[0] = task;
            }
        }

        break;

    case kIOKernelDarwinKitGetProcByName:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                bool success;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* map;

                char* name = reinterpret_cast<char*>(this->mapBufferFromClientTask(
                    arguments->scalarInput[0], arguments->scalarInput[1], kIODirectionOutIn,
                    &descriptor, &map));

                MAC_RK_LOG("MacRK::finding proc with 0x%llx\n", (UInt64)(name));

                xnu::Mach::VmAddress proc = reinterpret_cast<xnu::Mach::VmAddress>(
                    Task::findProcByName(this->kernel, name));

                if (!proc) {
                    result = kIOReturnError;
                }

                if (map)
                    map->release();

                if (descriptor)
                    descriptor->release();

                arguments->scalarOutput[0] = proc;
            }
        }

        break;

    case kIOKernelDarwinKitMachVmRead:;

        if (arguments) {
            if (arguments->scalarInputCount == 4) {
#ifdef __x86_64__
                /*
                kern_return_t kr;

                IOMemoryDescriptor* descriptor;

                IOMemoryMap* mapping;

                mach_port_name_t task_port = (mach_port_name_t)arguments->scalarInput[0];

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_NULL)
                    break;

                UInt64 data = (UInt64)arguments->scalarInput[2];

                Size size = (Size)arguments->scalarInput[3];

                vm_map_t (*_convert_port_to_map_read)(ipc_port_t port);

                typedef vm_map_t (*convert_port_to_map_read)(ipc_port_t port);

                ipc_space_t (*_get_task_ipcspace)(task_t t);

                typedef ipc_space_t (*get_task_ipcspace)(task_t);

                ipc_entry_t (*_ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                typedef ipc_entry_t (*ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                _convert_port_to_map_read = reinterpret_cast<convert_port_to_map_read>(
                    this->kernel->getSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    this->kernel->getSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    this->kernel->getSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t map = _convert_port_to_map_read(port);

                Size data_size;

                UInt8* buf = this->mapBufferFromClientTask(data, size, kIODirectionOutIn,
                                                           &descriptor, &mapping);

                if (address != 0) {
                    kern_return_t (*_vm_read)(vm_map_t, vm_address_t, vm_offset_t, vm_address_t,
                                              vm_size_t*);

                    _vm_read = (kern_return_t(*)(vm_map_t, vm_address_t, vm_offset_t, vm_address_t,
                                                 vm_size_t*))vm_read_;

                    kr = _vm_read(map, address, size, (vm_address_t)buf, &data_size);

                    if (kr != KERN_SUCCESS) {
                        result = kIOReturnNoMemory;
                    }

                } else {
                    result = kIOReturnBadArgument;
                }

                if (mapping)
                    mapping->release();

                if (descriptor)
                    descriptor->release(); */
#endif
            }
        }

        break;
    case kIOKernelDarwinKitMachVmWrite:;

        if (arguments) {
            if (arguments->scalarInputCount == 4) {
#ifdef __x86_64__
                /* kern_return_t kr;

                mach_port_name_t task_port = (mach_port_name_t)arguments->scalarInput[0];

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_NULL)
                    break;

                UInt64 data = (UInt64)arguments->scalarInput[2];

                Size size = (Size)arguments->scalarInput[3];

                vm_map_t (*_convert_port_to_map_read)(ipc_port_t port);

                typedef vm_map_t (*convert_port_to_map_read)(ipc_port_t port);

                ipc_space_t (*_get_task_ipcspace)(task_t t);

                typedef ipc_space_t (*get_task_ipcspace)(task_t);

                ipc_entry_t (*_ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                typedef ipc_entry_t (*ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                _convert_port_to_map_read = reinterpret_cast<convert_port_to_map_read>(
                    this->kernel->getSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    this->kernel->getSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    this->kernel->getSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t dst_map = _convert_port_to_map_read(port);

                typedef vm_map_t (*get_task_map)(task_t task);
                vm_map_t (*_get_task_map)(task_t);

                _get_task_map = reinterpret_cast<get_task_map>(
                    this->kernel->getSymbolAddressByName("_get_task_map"));

                vm_map_t src_map = _get_task_map(getClientTask());

                struct vm_map_copy {
                    int type;
                    vm_object_offset_t offset;
                    vm_map_size_t size;
                    void* kdata;
                };

                typedef struct vm_map_copy* vm_map_copy_t;

                if (address != 0) {
                    vm_map_copy_t copy;

                    typedef kern_return_t (*vm_map_copyin)(
                        vm_map_t, vm_map_address_t, vm_map_size_t, boolean_t, vm_map_copy_t*);

                    kern_return_t (*_vm_map_copyin)(vm_map_t, vm_map_address_t, vm_map_size_t,
                                                    boolean_t, vm_map_copy_t*);

                    _vm_map_copyin = reinterpret_cast<vm_map_copyin>(
                        this->kernel->getSymbolAddressByName("_vm_map_copyin"));

                    kr = _vm_map_copyin(src_map, (vm_address_t)data, (vm_map_size_t)size, FALSE,
                                        &copy);

                    typedef kern_return_t (*vm_map_copy_overwrite)(
                        vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);

                    kern_return_t (*_vm_map_copy_overwrite)(
                        vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);

                    _vm_map_copy_overwrite = reinterpret_cast<vm_map_copy_overwrite>(
                        this->kernel->getSymbolAddressByName("_vm_map_copy_overwrite"));

                    kr = _vm_map_copy_overwrite(dst_map, address, copy, size, FALSE);

                    if (kr != KERN_SUCCESS) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                } */
#endif
            }
        }

        break;
    case kIOKernelDarwinKitMachVmAllocate:
        break;
    case kIOKernelDarwinKitMachVmDeallocate:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
#ifdef __x86_64__
                /*
                kern_return_t kr;

                mach_port_name_t task_port = (mach_port_name_t)arguments->scalarInput[0];

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[1];

                Size size = (Size)arguments->scalarInput[2];

                if (task_port == MACH_PORT_NULL)
                    break;

                vm_map_t (*_convert_port_to_map_read)(ipc_port_t port);

                typedef vm_map_t (*convert_port_to_map_read)(ipc_port_t port);

                ipc_space_t (*_get_task_ipcspace)(task_t t);

                typedef ipc_space_t (*get_task_ipcspace)(task_t);

                ipc_entry_t (*_ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                typedef ipc_entry_t (*ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                _convert_port_to_map_read = reinterpret_cast<convert_port_to_map_read>(
                    this->kernel->getSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    this->kernel->getSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    this->kernel->getSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t map = _convert_port_to_map_read(port);

                kr = vm_deallocate(map, address, size);

                if (kr != KERN_SUCCESS) {
                    result = kIOReturnNoMemory;
                } */
#endif
            }
        }
        break;

    case kIOKernelDarwinKitMachVmProtect:;

        if (arguments) {
            if (arguments->scalarInputCount == 4) {
#ifdef __x86_64__
                /* kern_return_t kr;

                mach_port_name_t task_port = (mach_port_name_t)arguments->scalarInput[0];

                xnu::Mach::VmAddress address = (xnu::Mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_NULL)
                    break;

                Size size = (Size)arguments->scalarInput[2];

                vm_prot_t prot = (vm_prot_t)arguments->scalarInput[3];

                vm_map_t (*_convert_port_to_map_read)(ipc_port_t port);

                typedef vm_map_t (*convert_port_to_map_read)(ipc_port_t port);

                ipc_space_t (*_get_task_ipcspace)(task_t t);

                typedef ipc_space_t (*get_task_ipcspace)(task_t);

                ipc_entry_t (*_ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                typedef ipc_entry_t (*ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                _convert_port_to_map_read = reinterpret_cast<convert_port_to_map_read>(
                    this->kernel->getSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    this->kernel->getSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    this->kernel->getSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t map = _convert_port_to_map_read(port);

                if (address != 0) {
                    kern_return_t (*_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t,
                                                 vm_prot_t);

                    _vm_protect = (kern_return_t(*)(vm_map_t, vm_address_t, vm_size_t, boolean_t,
                                                    vm_prot_t))vm_protect_;

                    kr = _vm_protect(map, address, size, true, prot);

                    if (kr != KERN_SUCCESS) {
                        result = kIOReturnNoMemory;
                    }
                } else {
                    result = kIOReturnBadArgument;
                } */
#endif
            }
        }

        break;
    case kIOKernelDarwinKitMachVmCall:
        break;
    case kIOKernelDarwinKitVirtualToPhysical:;

        if (arguments) {
            if (arguments->scalarInputCount == 2) {
                UInt64 paddr;

                xnu::Mach::Port task_port = (xnu::Mach::Port)arguments->scalarInput[0];

                xnu::Mach::VmAddress vaddr = (xnu::Mach::VmAddress)arguments->scalarInput[1];

                /*
                if(paddr)
                {
                    result = kIOReturnNoMemory;
                }
                */

                result = kIOReturnUnsupported;
            }
        }

        break;
    case kIOKernelDarwinKitMmap:
        break;
    case kIOKernelDarwinKitMachMsgSend:
        break;
    case kIOKernelDarwinKitCopyIn:
        break;
    case kIOKernelDarwinKitCopyOut:
        break;
    case kIOKernelDarwinKitCreateSharedMemory:
        break;
    case kIOKernelDarwinKitMapSharedMemory:
        break;

    default:
        result = IOUserClient::externalMethod(selector, arguments, NULL, target, reference);

        break;
    }

    return result;
}
