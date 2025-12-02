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

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

#include <libkern/c++/OSSerialize.h>

#include <mach/mach_types.h>

#include <types.h>

namespace IOKit {
enum PCIRegister : UInt8 {
    kIOPCIConfigVendorID = 0x00,
    kIOPCIConfigDeviceID = 0x02,
    kIOPCIConfigCommand = 0x04,
    kIOPCIConfigStatus = 0x06,
    kIOPCIConfigRevisionID = 0x08,
    kIOPCIConfigClassCode = 0x09,
    kIOPCIConfigCacheLineSize = 0x0C,
    kIOPCIConfigLatencyTimer = 0x0D,
    kIOPCIConfigHeaderType = 0x0E,
    kIOPCIConfigBIST = 0xF,
    kIOPCIConfigBaseAddress0 = 0x10,
    kIOPCIConfigBaseAddress1 = 0x14,
    kIOPCIConfigBaseAddress2 = 0x18,
    kIOPCIConfigBaseAddress3 = 0x1C,
    kIOPCIConfigBaseAddress4 = 0x20,
    kIOPCIConfigBaseAddress5 = 0x24,
    kIOPCIConfigCardBusCISPtr = 0x28,
    kIOPCIConfigSubSystemVendorID = 0x2C,
    kIOPCIConfigSubSystemID = 0x2E,
    kIOPCIConfigExpansionROMBase = 0x30,
    kIOPCIConfigCapabilitiesPtr = 0x34,
    kIOPCIConfigInterruptLine = 0x3C,
    kIOPCIConfigInterruptPin = 0x3D,
    kIOPCIConfigMinimumGrant = 0x3E,
    kIOPCIConfigMaximumLatency = 0x3F,
    kIOPCIConfigGraphicsControl = 0x50
};

struct PCIConfigOffset {
    enum : Size {
        ConfigRead32 = 0x10A,
        ConfigWrite32 = 0x10B,
        ConfigRead16 = 0x10C,
        ConfigWrite16 = 0x10D,
        ConfigRead8 = 0x10E,
        ConfigWrite8 = 0x10F,
        GetBusNumber = 0x11D,
        GetDeviceNumber = 0x11E,
        GetFunctionNumber = 0x11F
    };
};

using t_PCIConfigRead8 = UInt32 (*)(IORegistryEntry* service, UInt32 space, UInt8 offset);
using t_PCIConfigRead16 = UInt16 (*)(IORegistryEntry* service, UInt32 space, UInt8 offset);
using t_PCIConfigRead32 = UInt8 (*)(IORegistryEntry* service, UInt32 space, UInt8 offset);

using t_PCIConfigWrite8 = void (*)(IORegistryEntry* service, UInt32 space, UInt8 offset,
                                   UInt32 data);
using t_PCIConfigWrite16 = void (*)(IORegistryEntry* service, UInt32 space, UInt8 offset,
                                    UInt16 data);
using t_PCIConfigWrite32 = void (*)(IORegistryEntry* service, UInt32 space, UInt8 offset,
                                    UInt8 data);

using t_PCIConfigGetBusNumber = UInt8 (*)(IORegistryEntry* service);
using t_PCIConfigGetDeviceNumber = UInt8 (*)(IORegistryEntry* service);
using t_PCIConfigGetFunctionNumber = UInt8 (*)(IORegistryEntry* service);

bool AwaitPublishing(IORegistryEntry* obj);

UInt32 ReadPCIConfigValue(IORegistryEntry* service, UInt32 reg, UInt32 space = 0, UInt32 size = 0);

void GetDeviceAddress(IORegistryEntry* service, UInt8& bus, UInt8& device, UInt8& function);

IORegistryEntry* FindEntryByPrefix(const char* path, const char* prefix,
                                   const IORegistryPlane* plane,
                                   bool (*proc)(void*, IORegistryEntry*) = nullptr,
                                   bool brute = false, void* user = nullptr);

IORegistryEntry* FindEntryByPrefix(IORegistryEntry* entry, const char* prefix,
                                   const IORegistryPlane* plane,
                                   bool (*proc)(void*, IORegistryEntry*) = nullptr,
                                   bool brute = false, void* user = nullptr);

template <typename T>
bool GetOSDataValue(const OSObject* obj, const char* name, T& value);

OSSerialize* GetProperty(IORegistryEntry* entry, const char* property);

void PatchVtableEntry(OSObject* object, void* entry, UInt32 idx);

void PatchVtable(OSObject* object, void* vtable);

}; // namespace IOKit
