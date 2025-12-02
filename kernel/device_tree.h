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

#include <types.h>

#include "api_util.h"

#ifdef __arm64__

namespace xnu {
class Kernel;
class DeviceTree;

#define DT_KEY_LEN 0x20

struct DeviceTreeNode {
    UInt32 n_properties;
    UInt32 n_children;
};

struct DeviceTreeProperty {
    char name[DT_KEY_LEN];
    UInt32 size;

    char val[0];
};

using dt_node_callback_t = Bool (*)(UInt32 depth, void* node, UInt32 size);
using dt_property_callback_t = Bool (*)(UInt32 depth, void* prop, UInt32 size);

static DeviceTree* deviceTree;

PE_state_t* PlatformExpertState(xnu::Kernel* kernel);

class DeviceTree {
public:
    explicit DeviceTree(xnu::Kernel* kernel)
        : kernel(kernel), device_tree(GetHead<xnu::mach::VmAddress>(kernel)),
          device_tree_sz(GetSize(kernel)) {}

    ~DeviceTree() = default;

    template <typename DeviceTree>
    static DeviceTree GetHead(xnu::Kernel* kernel) {
        PE_state_t* PE = xnu::PlatformExpertState(kernel);
        return reinterpret_cast<DeviceTree>(PE->deviceTreeHead);
        ;
    }

    static Size GetSize(xnu::Kernel* kernel) {
        PE_state_t* PE = xnu::PlatformExpertState(kernel);
        return PE->deviceTreeSize;
    }

    template <typename DeviceTree>
    DeviceTree GetAs() {
        return reinterpret_cast<DeviceTree>(device_tree);
    }

    Size GetSize() const {
        return device_tree_sz;
    }

    Size GetNodeSize(UInt32 depth, DeviceTreeNode* node);

    DeviceTreeNode* FindNode(char* nodename, UInt32* depth);
    DeviceTreeProperty* FindProperty(char* nodename, char* propname);

    Bool IterateNode(void** data, void* data_end, UInt32* depth, dt_node_callback_t node_cb,
                     dt_property_callback_t prop_cb, Bool* success);

    Bool IterateNodeProperties(void** data, void* data_end, UInt32* depth, DeviceTreeNode* node,
                               dt_property_callback_t prop_cb, Bool* success);

    void PrintData(UInt8* prop_data, UInt32 prop_size);

    void PrintNode(char* name);

    void Print(DeviceTreeNode* node, Size dt_size);

    template <typename T>
    T Dump();

private:
    xnu::Kernel* kernel;

    xnu::mach::VmAddress device_tree;
    Size device_tree_sz;
};

}; // namespace xnu

#endif