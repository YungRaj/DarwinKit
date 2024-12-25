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

extern "C" {
#include <sys/types.h>
}

#include <IOKit/IOService.h>

#include <types.h>

#include "api.h"
#include "api_util.h"

#include "vector.h"

#include "disassembler.h"

#include "hook.h"

namespace xnu {
class Kernel;
class Kext;
}; // namespace xnu

namespace darwin {
struct Plugin {
public:
    explicit Plugin(IOService* service, char* product, Size version, UInt32 runmode,
                    const char** disableArg, Size disableArgNum, const char** debugArg,
                    Size debugArgNum, const char** betaArg, Size betaArgNum);

    explicit Plugin(char* product, Size version, UInt32 runmode, const char** disableArg,
                    Size disableArgNum, const char** debugArg, Size debugArgNum,
                    const char** betaArg, Size betaArgNum);

    Size GetVersion() {
        return version;
    }

    IOService* GetService() {
        return service;
    }

    const char* GetProduct() {
        return product;
    }

    bool IsKextPlugin() {
        return service != nullptr;
    }

    void AddTarget(void* t) {
        union Target target;

        target.target = t;

        targets.push_back(target);
    }

    void AddHook(xnu::Kernel* kernel, Hook* hook) {
        AddTarget(kernel);
        hooks.push_back(hook);
    }

    void AddHook(xnu::Kext* kext, Hook* hook) {
        AddTarget(kext);
        hooks.push_back(hook);
    }

    void RemoveHook(Hook* hook) {
        hooks.erase(std::remove(hooks.begin(), hooks.end(), hook), hooks.end());
    }

    void (*pluginStart)();
    void (*pluginStop)();

private:
    union Target {
        void* target;

        xnu::Kernel* kernel;
        xnu::Kext* kext;
    };

    std::vector<union Target> targets;

    IOService* service;

    const char* product;

    Size version;

    UInt32 runmode;

    const char** disableArg;
    Size disableArgNum;

    const char** debugArg;
    Size debugArgNum;

    const char** betaArg;
    Size betaArgNum;

    std::vector<Hook*> hooks;
};
}; // namespace darwin
