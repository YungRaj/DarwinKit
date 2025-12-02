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

#ifdef __arm64__

#include <arm64/patch_finder_arm64.h>

#include "device_tree.h"
#include "kernel.h"
#include "log.h"
#include "macho.h"

Bool is_ascii(char* c, Size len) {
    UInt32 zeros = 0;
    for (Size i = 0; i < len; i++) {
        if (c[i] < 0)
            return false;
        else if (c[i] == 0)
            zeros++;
    }
    return zeros < 3 ? true : false;
}

namespace xnu {

Bool DeviceTree::IterateNodeProperties(void** data, void* data_end, UInt32* depth,
                                       DeviceTreeNode* node, dt_property_callback_t prop_cb,
                                       Bool* success) {
    Bool cb;
    UInt8* p = (UInt8*)data;
    UInt8* end = (UInt8*)data_end;
    UInt32 n_props = node->n_properties;
    UInt32 n_children = node->n_children;
    *success = false;
    for (int i = 0; i < n_props; i++) {
        DeviceTreeProperty* prop = (DeviceTreeProperty*)p;
        if (p + sizeof(*prop) > end) {
            return false;
        }
        if (prop->name[sizeof(prop->name) - 1] != 0) {
            return false;
        }
        UInt32 prop_size = prop->size & ~0x80000000;
        UInt32 padded_size = (prop_size + 0x3) & ~0x3;
        if (p + padded_size > end) {
            if (p - padded_size + prop_size == end) {
                p = end;
            } else {
                return false;
            }
        }
        if (prop_cb) {
            cb = prop_cb(*depth + 1, (void*)prop, prop_size);
            if (cb) {
                *success = true;
                *data = p;
                return true;
            }
        }
        p += sizeof(*prop);
        p += padded_size;
    }
    *data = p;
    return true;
}

Size DeviceTree::GetNodeSize(UInt32 depth, DeviceTreeNode* node) {
    UInt8* dt = GetAs<UInt8*>();
    Size dt_size = GetSize();
    Bool ok;
    Bool success;
    void* dt_end = (void*)((UInt8*)dt + dt_size);
    UInt8* p = (UInt8*)node;
    p += sizeof(*node);
    if (p > (UInt8*)dt_end) {
        return 0;
    }
    UInt8* end = p;
    UInt32 n_props = node->n_properties;
    UInt32 n_children = node->n_children;
    ok = DeviceTree::IterateNodeProperties((void**)&end, dt_end, &depth, node, nullptr, &success);
    if (ok) {
        return (end - p) + sizeof(DeviceTreeNode);
    }
    return 0;
}

Bool DeviceTree::IterateNode(void** data, void* data_end, UInt32* depth, dt_node_callback_t node_cb,
                             dt_property_callback_t prop_cb, Bool* success) {
    Bool ok;
    Bool cb;
    UInt8* p = (UInt8*)*data;
    UInt8* end = (UInt8*)data_end;
    DeviceTreeNode* node = (DeviceTreeNode*)p;
    if (node_cb) {
        cb = node_cb(*depth, (void*)node, end - (UInt8*)node);
        if (cb) {
            *success = true;
            return true;
        }
    }
    p += sizeof(*node);
    if (p > end) {
        return false;
    }
    UInt32 n_props = node->n_properties;
    UInt32 n_children = node->n_children;
    ok = DeviceTree::IterateNodeProperties((void**)&p, data_end, depth, node, prop_cb, success);
    *data = p;
    if (*success) {
        return false;
    }
    if (!ok) {
        return false;
    }
    for (UInt32 i = 0; i < n_children; i++) {
        UInt32 child_depth = *depth + 1;
        ok = DeviceTree::IterateNode(data, data_end, &child_depth, node_cb, prop_cb, success);
        if (*success) {
            *depth = child_depth;
            return false;
        }
        if (!ok) {
            return false;
        }
    }
    return true;
}

DeviceTreeNode* DeviceTree::FindNode(char* nodename, UInt32* depth) {
    UInt8* dt = GetAs<UInt8*>();
    Size dt_size = GetSize();
    UInt8* root = (UInt8*)dt;
    *depth = 0;
    dt_property_callback_t prop_cb = [](UInt32 ndepth, void* property, UInt32 size) -> Bool {
        DeviceTreeProperty* prop = (DeviceTreeProperty*)property;
        if (strcmp(prop->name, "name") == 0) {
            return true;
        }
        return false;
    };
    auto node_cb = [prop_cb, &nodename, this](UInt32 ndepth, void* dtnode, UInt32 size) -> Bool {
        Bool ok;
        Bool success;
        DeviceTreeNode* node = (DeviceTreeNode*)dtnode;
        UInt8* p = (UInt8*)node;
        p += sizeof(*node);
        UInt32 node_size = DeviceTree::GetNodeSize(ndepth, node);
        // ok = DeviceTree::iterateNodeProperties((void**)&p, (void*)((UInt8*)node + node_size),
        // &ndepth,
        //                                         node, prop_cb, &success);
        if (ok && success) {
            DeviceTreeProperty* prop = (DeviceTreeProperty*)p;
            if (strcmp(nodename, (char*)&prop->val) == 0)
                return true;
        }
        return false;
    };
    Bool ok;
    Bool success = false;
    // ok = DeviceTree::iterateNode((void**)&root, (void*)(root + dt_size), depth,
    // (dt_node_callback_t) node_cb, nullptr,
    //                             &success);
    if (success) {
        DeviceTreeNode* node = (DeviceTreeNode*)root;
        return node;
    }
    return nullptr;
}

DeviceTreeProperty* DeviceTree::FindProperty(char* nodename, char* propname) {
    UInt8* dt = GetAs<UInt8*>();
    Size dt_size = GetSize();
    DeviceTreeNode* node;
    Bool ok;
    Bool success;
    UInt32 node_size;
    UInt32 depth = 0;
    node = DeviceTree::FindNode(nodename, &depth);
    node_size = DeviceTree::GetNodeSize(depth, node);
    if (node) {
        auto prop_cb = [propname](UInt32 depth, void* property, UInt32 size) -> Bool {
            DeviceTreeProperty* prop = (DeviceTreeProperty*)property;
            if (strcmp(prop->name, propname) == 0) {
                return true;
            }
            return false;
        };
        success = false;
        // ok = DeviceTree::iterateNode((void**)&node, (void*)((UInt8*)node + node_size), &depth,
        // nullptr,
        //                             (dt_property_callback_t) prop_cb, &success);
        if (success) {
            DeviceTreeProperty* prop = (DeviceTreeProperty*)node;
            DARWIN_KIT_LOG("%s %s ", nodename, prop->name);
            DeviceTree::PrintData((UInt8*)&prop->val, prop->size);
            return prop;
        }
    }
    return nullptr;
}

void DeviceTree::PrintData(UInt8* prop_data, UInt32 prop_size) {
    if (is_ascii((char*)prop_data, prop_size) && !prop_data[strlen((char*)prop_data)]) {
        DARWIN_KIT_LOG("%s ", (char*)prop_data);
    } else if (prop_size == sizeof(UInt64)) {
        DARWIN_KIT_LOG("0x%llx ", *(UInt64*)prop_data);
    } else if (prop_size == sizeof(UInt32)) {
        DARWIN_KIT_LOG("0x%x ", *(UInt32*)prop_data);
    } else {
        for (UInt32 j = 0; j < prop_size; j++)
            DARWIN_KIT_LOG("%x ", prop_data[j]);
    }
    DARWIN_KIT_LOG("\n");
}

void DeviceTree::PrintNode(char* nodename) {
    UInt8* dt = GetAs<UInt8*>();
    Size dt_size = GetSize();
    DeviceTreeNode* node;
    UInt32 depth;
    node = DeviceTree::FindNode(nodename, &depth);
    if (node) {
        Size node_size = DeviceTree::GetNodeSize(depth, node);
        DeviceTree::Print(node, node_size);
    }
}

void DeviceTree::Print(DeviceTreeNode* node, Size node_size) {
    Bool success = false;
    UInt32 depth = 0;
    UInt8* root = (UInt8*)node;
    Size sz = node_size;
    auto prop_cb = [this](UInt32 depth, void* property, UInt32 size) -> Bool {
        DeviceTreeProperty* prop = (DeviceTreeProperty*)property;
        UInt8* prop_data = (UInt8*)&prop->val;
        UInt32 prop_size = prop->size;
        for (UInt32 j = 0; j < depth; j++) {
            DARWIN_KIT_LOG("\t");
        }
        DARWIN_KIT_LOG("%s ", prop->name);
        PrintData(prop_data, prop_size);
        return false;
    };
    // DeviceTree::iterateNode((void**)&root, (void*)(root + sz), &depth, nullptr,
    // (dt_property_callback_t) prop_cb, &success);
}

template <typename T>
T DeviceTree::Dump() {
    UInt8* dt = GetAs<UInt8*>();
    Size dt_size = GetSize();
    UInt8* device_tree;
    UInt64 sz = dt_size;
    UInt64 off = 0;
    device_tree = new UInt8[sz];
    while (sz > 0) {
        UInt64 to_read = sz / 0x1000 > 0 ? 0x1000 : sz;
        if (!(UInt64*)(dt + off, device_tree + off, to_read)) {
            DARWIN_KIT_LOG("Failed to dump device tree at 0x%llx\n", dt + off);
            return nullptr;
        }
        sz -= to_read;
        off += to_read;
    }
    return reinterpret_cast<T>(device_tree);
}

PE_state_t* PlatformExpertState(xnu::Kernel* kernel) {
    uintptr_t device_tree;
    UInt64 deviceTreeHead;
    UInt32 deviceTreeSize;
    xnu::mach::VmAddress PE_state;
    xnu::mach::VmAddress boot_args;
    xnu::mach::VmAddress __ZN16IOPlatformExpert14getConsoleInfoEP8PE_Video =
        kernel->GetSymbolAddressByName("__ZN16IOPlatformExpert14getConsoleInfoEP8PE_Video");
    xnu::mach::VmAddress adrp_ins = arch::arm64::patchfinder::Step64(
        kernel->GetMachO(), __ZN16IOPlatformExpert14getConsoleInfoEP8PE_Video, 0xF0,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_adrp), -1, -1);
    using namespace arch::arm64;

    adr_t adrp = *(adr_t*)adrp_ins;
    UInt64 page = (((adrp.immhi << 2) | adrp.immlo)) << 12;
    xnu::mach::VmAddress add_ins = arch::arm64::patchfinder::Step64(
        kernel->GetMachO(), adrp_ins, 8,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_add_imm), NO_REG, NO_REG);
    add_imm_t add = *(add_imm_t*)add_ins;
    UInt64 page_offset = add.imm << (add.sh ? 12 : 0);
    PE_state = ((adrp_ins & ~0x3FFF) + (page | page_offset)) & ~((UInt64)0xF);
    return reinterpret_cast<PE_state_t*>(PE_state);
}

} // namespace xnu

#endif