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

#include <stdint.h>
#include <string.h>

#include <kern/host.h>
#include <kern/task.h>

#include <mach/kmod.h>
#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/vm_types.h>

#include "kernel_darwin_kit.h"
#include "darwin_kit.h"

mrk::DarwinKit* rootkit = NULL;

mrk::DarwinKit* mac_rootkit_get_rootkit() {
    if (rootkit)
        return rootkit;

    return NULL;
}

kern_return_t mac_rootkit_start(IOKernelDarwinKitService* service, Kernel* kernel, Kext** kext) {
    kern_return_t ret = kIOReturnSuccess;

    rootkit = new mrk::DarwinKit(kernel);

    if (!rootkit) {
        ret = kIOReturnUnsupported;
    }

    *kext = rootkit->getKextByIdentifier("com.YungRaj.DarwinKit");

    if (!*kext) {
        MAC_RK_LOG("MacRK::mac_rootkit_start() cannot find com.YungRaj.DarwinKit kext!\n");
    } else {
        MAC_RK_LOG("MacRK::mac_rootkit_start() found com.YungRaj.DarwinKit kext!\n");
    }

    return ret;
}

kern_return_t mac_rootkit_stop(IOKernelDarwinKitService* service, Kernel* kernel, Kext** kext) {
    kern_return_t ret = kIOReturnSuccess;

    if (rootkit) {
        delete rootkit;

        rootkit = NULL;
    }

    return ret;
}

extern "C" {
kern_return_t kern_start(kmod_info_t* ki, void* data) {
    MAC_RK_LOG("DarwinKit::kmod_start()!\n");

    return KERN_SUCCESS;
}

kern_return_t kern_stop(kmod_info_t* ki, void* data) {
    MAC_RK_LOG("DarwinKit::kmod_stop()!\n");

    return KERN_SUCCESS;
}

extern kern_return_t _start(kmod_info_t*, void*);
extern kern_return_t _stop(kmod_info_t*, void*);

__private_extern__ kmod_start_func_t* _realmain = kern_start;
__private_extern__ kmod_stop_func_t* _antimain = kern_stop;

__attribute__((visibility("default")))
KMOD_EXPLICIT_DECL(com.YungRaj.DarwinKit, "1.0.1", _start, _stop);

__private_extern__ int _kext_apple_;
}