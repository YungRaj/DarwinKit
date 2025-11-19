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

#include "coverage.h"

#include "task.h"

#include "section.h"
#include "segment.h"

#include "log.h"

#include "libafl_fuzzer.h"

#include <mach/vm_types.h>

extern "C" {
#include "kern.h"
}

OSDefineMetaClassAndStructors(IOKernelDarwinKitUserClient, IOUserClient)

IOKernelDarwinKitUserClient* IOKernelDarwinKitUserClient::darwinKitUserClientWithKernel(
        xnu::Kernel* kernel, task_t owningTask, void* securityToken, UInt32 type) {
    IOKernelDarwinKitUserClient* client;

    client = new IOKernelDarwinKitUserClient();

    if (client) {
        if (!client->initDarwinKitUserClientWithKernel(kernel, owningTask, securityToken, type)) {
            client->release();

            return nullptr;
        }
    }

    return client;
}

IOKernelDarwinKitUserClient* IOKernelDarwinKitUserClient::darwinKitUserClientWithKernel(
    xnu::Kernel* kernel, task_t owningTask, void* securityToken, UInt32 type,
    OSDictionary* properties) {
    IOKernelDarwinKitUserClient* client;

    client = new IOKernelDarwinKitUserClient();

    if (client) {
        if (!client->initDarwinKitUserClientWithKernel(kernel, owningTask, securityToken, type,
                                                     properties)) {
            client->release();

            return nullptr;
        }
    }

    return client;
}

bool IOKernelDarwinKitUserClient::initDarwinKitUserClientWithKernel(xnu::Kernel* kern,
                                                                task_t owningTask,
                                                                void* securityToken, UInt32 type) {
    bool result = IOUserClient::initWithTask(owningTask, securityToken, type);

    kernel = kern;

    if (!kernel) {
        result = false;
    }

    clientTask = owningTask;
    kernelTask = *(task_t*)kernel->GetSymbolAddressByName("_kernel_task");

    return result;
}

bool IOKernelDarwinKitUserClient::initDarwinKitUserClientWithKernel(xnu::Kernel* kern,
                                                                task_t owningTask,
                                                                void* securityToken, UInt32 type,
                                                                OSDictionary* properties) {
    bool result = IOUserClient::initWithTask(owningTask, securityToken, type, properties);

    kernel = kern;

    if (!kernel) {
        result = false;
    }

    clientTask = owningTask;
    kernelTask = *(task_t*)kernel->GetSymbolAddressByName("_kernel_task");

    return result;
}

bool IOKernelDarwinKitUserClient::start(IOService* provider) {
    IOKernelDarwinKitService* service = kernel->GetDarwinKitService();

    darwinkitService = service;

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
    return nullptr;
}

IOExternalTrap* IOKernelDarwinKitUserClient::getExternalTrapForIndex(UInt32 index) {
    return nullptr;
}

UInt8* IOKernelDarwinKitUserClient::mapBufferFromClientTask(xnu::mach::VmAddress uaddr, Size size,
                                                          IOOptionBits options,
                                                          IOMemoryDescriptor** desc,
                                                          IOMemoryMap** mapping) {
    UInt8* buffer;

    IOReturn ret;

    IOMemoryDescriptor* descriptor;

    IOMemoryMap* map;

    descriptor = IOMemoryDescriptor::withAddressRange(uaddr, size, options, getClientTask());

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
    *desc = nullptr;
    *mapping = nullptr;

    return nullptr;
}

IOReturn IOKernelDarwinKitUserClient::externalMethod(UInt32 selector,
                                                   IOExternalMethodArguments* arguments,
                                                   IOExternalMethodDispatch* dispatch,
                                                   OSObject* target, void* reference) {
    IOReturn result = kIOReturnSuccess;

    DARWIN_KIT_LOG("DarwinKit::IOKernelDarwinKitUserClient::externalMethod() called!\n");

    switch (selector) {
    case kIOKernelDarwinKitHookKernelFunction:;

        if (arguments->scalarInputCount == 3) {
            KernelPatcher* patcher = darwinkitService->getDarwinKit()->GetKernelPatcher();

            IOMemoryDescriptor* descriptor;

            IOMemoryMap* map;

            bool success;

            xnu::mach::VmAddress address = arguments->scalarInput[0];

            xnu::mach::VmAddress hook = arguments->scalarInput[1];

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
            KernelPatcher* patcher = darwinkitService->getDarwinKit()->GetKernelPatcher();

            IOMemoryDescriptor* descriptor;

            IOMemoryMap* map;

            bool success;

            xnu::mach::VmAddress breakpoint = arguments->scalarInput[0];

            xnu::mach::VmAddress breakpoint_hook = arguments->scalarInput[1];

            Size breakpoint_hook_size = arguments->scalarInput[2];

            Size code_size = breakpoint_hook_size % 0x1000 > 0
                                 ? (breakpoint_hook_size - (breakpoint_hook_size % 0x1000)) + 0x1000
                                 : breakpoint_hook_size;

            xnu::mach::VmAddress copyin;

            if (breakpoint_hook) {
            }
        }

        break;
    case kIOKernelDarwinKitKernelCall:;

        if (arguments->scalarInputCount > 1) {
            xnu::mach::VmAddress func = arguments->scalarInput[0];

            Size argCount = arguments->scalarInputCount - 1;

            UInt64* args = new UInt64[argCount];

            for (UInt32 i = 1; i < argCount + 1; i++) {
                args[i - 1] = arguments->scalarInput[i];
            }

            UInt64 ret = kernel->Call(func, (UInt64*)args, argCount);

            arguments->scalarOutput[0] = ret;

            delete[] args;
        }

        break;
    case kIOKernelDarwinKitGetKaslrSlide:;

        if (arguments) {
            if (arguments->scalarInputCount == 0) {
                UInt64 slide = Kernel::FindKernelSlide();

                arguments->scalarOutput[0] = slide;
            }
        }

        break;
    case kIOKernelDarwinKitGetKernelBase:;

        if (arguments) {
            if (arguments->scalarInputCount == 0) {
                xnu::mach::VmAddress base = kernel->GetBase();

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

                xnu::mach::VmAddress symaddr;

                UInt8* buf = mapBufferFromClientTask(arguments->scalarInput[0],
                                                           arguments->scalarInput[1],
                                                           kIODirectionOutIn, &descriptor, &map);

                char* symname = reinterpret_cast<char*>(buf);

                symaddr = kernel->GetSymbolAddressByName(symname);

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

                xnu::mach::VmAddress symaddr;

                UInt8* buf1 = mapBufferFromClientTask(arguments->scalarInput[0],
                                                            arguments->scalarInput[1],
                                                            kIODirectionOutIn, &descriptor, &map);

                UInt8* buf2 = mapBufferFromClientTask(arguments->scalarInput[2],
                                                            arguments->scalarInput[3],
                                                            kIODirectionOutIn, &descriptor, &map);

                char* kextidentifier = reinterpret_cast<char*>(buf1);

                xnu::Kext* kext =
                    getDarwinKitService()->getDarwinKit()->GetKextByIdentifier(kextidentifier);

                if (kext) {
                    char* kextsymname = reinterpret_cast<char*>(buf2);

                    symaddr = kext->GetSymbolAddressByName(kextsymname);

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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                if (address && buf) {
                    success = kernel->Read(address, (void*)buf, size);

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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[0];

                UInt64 data = arguments->scalarInput[1];

                Size size = arguments->scalarInput[2];

                UInt8* buf =
                    mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                if (address && buf) {
                    UInt8* buf_copy = new UInt8[size];

                    descriptor->readBytes(0, (void*)buf_copy, (UInt32)size);

                    kernel->Write(address, (void*)buf_copy, size);

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
                xnu::mach::VmAddress address;

                Size size = arguments->scalarInput[0];

                address = kernel->VmAllocate(size);

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
                xnu::mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                kernel->VmDeallocate(address, size);

                arguments->scalarOutput[0] = address;
            }
        }

        break;
    case kIOKernelDarwinKitKernelVmProtect:;

        if (arguments) {
            if (arguments->scalarInputCount == 3) {
                bool success;

                xnu::mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                vm_prot_t prot = (vm_prot_t)arguments->scalarInput[2];

                if (address) {
                    success = kernel->VmProtect(address, size, prot);

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
                xnu::mach::VmAddress remapped;

                xnu::mach::VmAddress address = arguments->scalarInput[0];

                Size size = arguments->scalarInput[1];

                if (address) {
                    remapped =
                        reinterpret_cast<xnu::mach::VmAddress>(kernel->VmRemap(address, size));

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
                    mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                success = kernel->PhysicalRead(paddr, (void*)buf, size);

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
                    mapBufferFromClientTask(data, size, kIODirectionOutIn, &descriptor, &map);

                success = kernel->PhysicalWrite(paddr, (void*)buf, size);

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

                UInt64 vmaddr = (xnu::mach::VmAddress)arguments->scalarInput[0];

                if (vmaddr) {
                    physaddr = kernel->VirtualToPhysical(vmaddr);

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

                xnu::mach::VmAddress task =
                    reinterpret_cast<xnu::mach::VmAddress>(Task::FindTaskByPid(kernel, pid));

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

                xnu::mach::VmAddress proc =
                    reinterpret_cast<xnu::mach::VmAddress>(Task::FindProcByPid(kernel, pid));

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

                char* name = reinterpret_cast<char*>(mapBufferFromClientTask(
                    arguments->scalarInput[0], arguments->scalarInput[1], kIODirectionOutIn,
                    &descriptor, &map));

                DARWIN_KIT_LOG("DarwinKit::finding task with name = 0x%llx\n", (UInt64)(name));

                xnu::mach::VmAddress task = reinterpret_cast<xnu::mach::VmAddress>(
                    Task::FindTaskByName(kernel, name));

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

                char* name = reinterpret_cast<char*>(mapBufferFromClientTask(
                    arguments->scalarInput[0], arguments->scalarInput[1], kIODirectionOutIn,
                    &descriptor, &map));

                DARWIN_KIT_LOG("DarwinKit::finding proc with 0x%llx\n", (UInt64)(name));

                xnu::mach::VmAddress proc = reinterpret_cast<xnu::mach::VmAddress>(
                    Task::FindProcByName(kernel, name));

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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_nullptr)
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
                    kernel->GetSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    kernel->GetSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    kernel->GetSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t map = _convert_port_to_map_read(port);

                Size data_size;

                UInt8* buf = mapBufferFromClientTask(data, size, kIODirectionOutIn,
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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_nullptr)
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
                    kernel->GetSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    kernel->GetSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    kernel->GetSymbolAddressByName("_ipc_entry_lookup"));

                ipc_space_t space = _get_task_ipcspace(getClientTask());

                ipc_entry_t entry = _ipc_entry_lookup(space, task_port);

                ipc_port_t port = (ipc_port_t)entry->ie_object;

                vm_map_t dst_map = _convert_port_to_map_read(port);

                typedef vm_map_t (*get_task_map)(task_t task);
                vm_map_t (*_get_task_map)(task_t);

                _get_task_map = reinterpret_cast<get_task_map>(
                    kernel->GetSymbolAddressByName("_get_task_map"));

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
                        kernel->GetSymbolAddressByName("_vm_map_copyin"));

                    kr = _vm_map_copyin(src_map, (vm_address_t)data, (vm_map_size_t)size, FALSE,
                                        &copy);

                    typedef kern_return_t (*vm_map_copy_overwrite)(
                        vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);

                    kern_return_t (*_vm_map_copy_overwrite)(
                        vm_map_t, vm_map_offset_t, vm_map_copy_t, vm_map_size_t, boolean_t);

                    _vm_map_copy_overwrite = reinterpret_cast<vm_map_copy_overwrite>(
                        kernel->GetSymbolAddressByName("_vm_map_copy_overwrite"));

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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[1];

                Size size = (Size)arguments->scalarInput[2];

                if (task_port == MACH_PORT_nullptr)
                    break;

                vm_map_t (*_convert_port_to_map_read)(ipc_port_t port);

                typedef vm_map_t (*convert_port_to_map_read)(ipc_port_t port);

                ipc_space_t (*_get_task_ipcspace)(task_t t);

                typedef ipc_space_t (*get_task_ipcspace)(task_t);

                ipc_entry_t (*_ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                typedef ipc_entry_t (*ipc_entry_lookup)(ipc_space_t space, mach_port_name_t name);

                _convert_port_to_map_read = reinterpret_cast<convert_port_to_map_read>(
                    kernel->GetSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    kernel->GetSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    kernel->GetSymbolAddressByName("_ipc_entry_lookup"));

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

                xnu::mach::VmAddress address = (xnu::mach::VmAddress)arguments->scalarInput[1];

                if (task_port == MACH_PORT_nullptr)
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
                    kernel->GetSymbolAddressByName("_convert_port_to_map_read"));

                _get_task_ipcspace = reinterpret_cast<get_task_ipcspace>(
                    kernel->GetSymbolAddressByName("_get_task_ipcspace"));

                _ipc_entry_lookup = reinterpret_cast<ipc_entry_lookup>(
                    kernel->GetSymbolAddressByName("_ipc_entry_lookup"));

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

                xnu::mach::Port task_port = (xnu::mach::Port)arguments->scalarInput[0];

                xnu::mach::VmAddress vaddr = (xnu::mach::VmAddress)arguments->scalarInput[1];

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
    case kIOKernelDarwinKitEnableCoverage: {
        sanitizer_cov_enable_coverage();
        break;
    }
    case kIOKernelDarwinKitDisableCoverage: {
        sanitizer_cov_disable_coverage();
        break;
    }
    case kIOKernelDarwinKitStartHarness: {
        libafl_start_darwin_kit_fuzzer((char*) sanitizer_cov_get_bitmap());

        break;     
    }

    default:
        result = IOUserClient::externalMethod(selector, arguments, nullptr, target, reference);

        break;
    }

    return result;
}
