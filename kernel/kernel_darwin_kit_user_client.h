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
#include <IOKit/IOUserClient.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>

#include <types.h>

#include "api_util.h"
#include "kernel_darwin_kit.h"
#include "kernel.h"

namespace darwin {
class DarwinKit;
}

using namespace xnu;
using namespace darwin;

class IOKernelDarwinKitService;

class IOKernelDarwinKitUserClient : public IOUserClient {
    OSDeclareDefaultStructors(IOKernelDarwinKitUserClient)
 public:
    static IOKernelDarwinKitUserClient* darwinKitUserClientWithKernel(xnu::Kernel* kern,
                                                                               task_t owningTask,
                                                                               void* securityToken,
                                                                               UInt32 type);

    static IOKernelDarwinKitUserClient* darwinKitUserClientWithKernel(xnu::Kernel* kern,
                                                                  task_t owningTask,
                                                                  void* securityToken, UInt32 type,
                                                                  OSDictionary* properties);

    virtual bool initDarwinKitUserClientWithKernel(xnu::Kernel* kern, task_t owningTask,
                                                 void* securityToken, UInt32 type);

    virtual bool initDarwinKitUserClientWithKernel(xnu::Kernel* kern, task_t owningTask,
                                                 void* securityToken, UInt32 type,
                                                 OSDictionary* properties);

    virtual bool start(IOService* provider);
    virtual void stop(IOService* provider);

    virtual IOReturn clientClose();
    virtual IOReturn clientDied();

    virtual void free();

    virtual clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) override;

    virtual IOExternalMethod* getExternalMethodForIndex(UInt32 index);
    virtual IOExternalTrap* getExternalTrapForIndex(UInt32 index);

    virtual IOReturn externalMethod(UInt32 selector, IOExternalMethodArguments* arguments,
                                    IOExternalMethodDispatch* dispatch, OSObject* target,
                                    void* reference);

    IOKernelDarwinKitService* getDarwinKitService() {
        return darwinkitService;
    }

    task_t getClientTask() {
        return clientTask;
    }
    task_t getKernelTask() {
        return kernelTask;
    }

private:
    IOKernelDarwinKitService* darwinkitService;

    task_t clientTask;
    task_t kernelTask;

    xnu::Kernel* kernel;

    IOMemoryDescriptor *coverageMap = nullptr;

    void initDarwinKit();

    UInt8* mapBufferFromClientTask(xnu::mach::VmAddress uaddr, Size size, IOOptionBits options,
                                   IOMemoryDescriptor** desc, IOMemoryMap** mapping);

    IOMemoryDescriptor* mapCoverageBitmap();
};
