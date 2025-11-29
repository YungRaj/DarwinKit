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
#include <IOKit/IOService.h>

#include <types.h>

#include "darwin_kit.h"

#include "kernel.h"
#include "kext.h"

namespace darwin {
class DarwinKit;
};

class IOKernelDarwinKitService;
class IOKernelDarwinKitUserClient;

extern kern_return_t darwinkit_start(IOKernelDarwinKitService* service, xnu::Kernel* kernel,
                                     xnu::Kext** kext);
extern kern_return_t darwinkit_stop(IOKernelDarwinKitService* service, xnu::Kernel* kernel,
                                      xnu::Kext** kext);

extern darwin::DarwinKit* darwinkit_get_darwinkit();

class IOKernelDarwinKitService : public IOService {
    OSDeclareDefaultStructors(IOKernelDarwinKitService)
public:   
    virtual bool init(OSDictionary* properties) override;

    virtual void free() override;

    virtual bool start(IOService* provider) override;
    virtual void stop(IOService* provider) override;

    virtual IOService* probe(IOService* provider, SInt32* score) override;

    virtual void clientClosed(IOUserClient* client);

    darwin::DarwinKit* getDarwinKit() {
        return darwinkit;
    }

    xnu::Kernel* getKernel() {
        return kernel;
    }

    xnu::Kext* getKext() {
        return darwinkitKext;
    }

    xnu::mach::Port getKernelTaskPort() {
        return tfp0;
    }

    IOReturn createUserClient(task_t task, void* securityID, UInt32 type,
                              IOKernelDarwinKitUserClient** client);
    IOReturn createUserClient(task_t task, void* securityID, UInt32 type, OSDictionary* properties,
                              IOKernelDarwinKitUserClient** client);

    IOReturn newUserClient(task_t task, void* securityID, UInt32 type, OSDictionary* properties,
                           IOUserClient** client);
    IOReturn newUserClient(task_t task, void* securityID, UInt32 type, IOUserClient** client);

    IOReturn addUserClient(IOKernelDarwinKitUserClient* client);

    IOReturn removeUserClient(IOKernelDarwinKitUserClient* client);

    IOReturn detachUserClients();

private:
    darwin::DarwinKit* darwinkit;
    xnu::Kernel* kernel;
    xnu::Kext* darwinkitKext;
    xnu::mach::Port tfp0;
    OSSet* userClients;
};
