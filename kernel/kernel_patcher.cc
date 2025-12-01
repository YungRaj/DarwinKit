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

#include "kernel_patcher.h"

#include "darwin_kit.h"
#include "arch.h"
#include "kernel_macho.h"
#include "hook.h"
#include "payload.h"
#include "kernel.h"
#include "task.h"
#include "disassembler.h"

#ifdef __arm64__

#include <arm64/patch_finder_arm64.h>

using namespace arch::arm64::patchfinder;

#elif __x86_64__

#include <x86_64/patch_finder_x86_64.h>

using namespace arch::x86_64::patchfinder;

#endif

using namespace arch;

namespace darwin {

static KernelPatcher* that = nullptr;

KernelPatcher::KernelPatcher(xnu::Kernel* kernel)
    : kernel(kernel),
      kextKmods(reinterpret_cast<xnu::KmodInfo**>(kernel->GetSymbolAddressByName("_kmod"))) {
    that = this;
    Initialize();
}

void KernelPatcher::Initialize() {
    ProcessAlreadyLoadedKexts();
    waitingForAlreadyLoadedKexts = false;
    InstallCopyClientEntitlementHook();
#ifdef __x86_64__
    // The binary load hook does not work on arm64 because symbol to hook does not exist
    InstallBinaryLoadHook();
    // The kext load hook does not work on arm64 because symbol to hook does not exist
    InstallKextLoadHook();
#endif
    // InstallDummyBreakpoint();
}

bool KernelPatcher::DummyBreakpoint(union arch::RegisterState* state) {
    RegisterState_x86_64* state_x86_64;
    RegisterState_arm64* state_arm64;
    switch (arch::GetCurrentArchitecture()) {
    case ARCH_x86_64:
        state_x86_64 = &state->state_x86_64;
        break;
    case ARCH_arm64:
        state_arm64 = &state->state_arm64;
        break;
    default:
        break;
    }
    return false;
}

Hook* KernelPatcher::InstallDummyBreakpoint() {
    Hook* hook;
    xnu::mach::VmAddress mach_msg_trap =
        GetKernel()->GetSymbolAddressByName("_mach_msg_trap");
    hook = Hook::CreateBreakpointForAddress(dynamic_cast<Task*>(GetKernel()),
                                      dynamic_cast<Patcher*>(this), mach_msg_trap);
    hook->AddBreakpoint((xnu::mach::VmAddress)KernelPatcher::DummyBreakpoint);
    return hook;
}

void KernelPatcher::OnOSKextSaveLoadedKextPanicList() {
    xnu::mach::VmAddress trampoline;
    if (!that) {
        return;
    }
    trampoline = that->GetKextLoadHook()->GetTrampolineFromChain(
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::OnOSKextSaveLoadedKextPanicList));
    typedef void (*OSKextSaveLoadedKextPanicList)();
    void (*_OSKextSavedLoadedKextPanicList)();
    _OSKextSavedLoadedKextPanicList = reinterpret_cast<OSKextSaveLoadedKextPanicList>(trampoline);
    _OSKextSavedLoadedKextPanicList();
    DARWIN_KIT_LOG("DarwinKit::OSKextSavedLoadedKextPanicList() hook!\n");
    if (that->waitingForAlreadyLoadedKexts) {
        that->ProcessAlreadyLoadedKexts();
        that->waitingForAlreadyLoadedKexts = false;
    } else {
#ifdef __x86_64__
        xnu::KmodInfo* kmod = *that->GetKextKmods();
        if (kmod) {
            that->ProcessKext(kmod, false);
        }
#endif
    }
}

void* KernelPatcher::OSKextLookupKextWithIdentifier(const char* identifier) {
    typedef void* (*lookupKextWithIdentifier)(const char*);
    void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);
    xnu::mach::VmAddress OSKext_lookupWithIdentifier =
        that->GetKernel()->GetSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");
    __ZN6OSKext24lookupKextWithIdentifierEPKc =
        reinterpret_cast<lookupKextWithIdentifier>(OSKext_lookupWithIdentifier);
#ifdef _x86_64__
    void* OSKext = __ZN6OSKext24lookupKextWithIdentifierEPKc(identifier);
    return OSKext;
#elif __arm64__
    return 0;
#endif
}

OSObject* KernelPatcher::CopyClientEntitlement(task_t task, const char* entitlement) {
    Hook* hook = that->GetCopyClientEntitlementHook();
    xnu::mach::VmAddress trampoline;
    DARWIN_KIT_LOG("DarwinKit::KernelPatcher::copyClientEntitlement() hook!\n");
    trampoline = hook->GetTrampolineFromChain(
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::CopyClientEntitlement));
    typedef OSObject* (*origCopyClientEntitlement)(task_t, const char*);
    OSObject* original = reinterpret_cast<origCopyClientEntitlement>(trampoline)(task, entitlement);
    if (strcmp(entitlement, "com.apple.private.audio.driver-host") == 0) {
        original = OSBoolean::withBoolean(true);
    }
    if (strcmp(entitlement, "com.apple.security.app-sandbox") == 0) {
        original = OSBoolean::withBoolean(false);
    }
    if (strcmp(entitlement, "com.apple.private.FairPlayIOKitUserClient.access") == 0) {
        original = OSBoolean::withBoolean(true);
    }
    if (strcmp(entitlement, "com.apple.private.ProvInfoIOKitUserClient.access") == 0) {
        original = OSBoolean::withBoolean(true);
    }
    if (that) {
        StoredArray<DarwinKit::EntitlementCallback>* entitlementCallbacks;
        DarwinKit* darwinkit = that->GetKernel()->GetDarwinKit();
        entitlementCallbacks = &darwinkit->GetEntitlementCallbacks();
        for (int i = 0; i < entitlementCallbacks->size(); i++) {
            auto handler = entitlementCallbacks->at(i);
            DarwinKit::EntitlementCallback callback = handler->first;
            void* user = handler->second;
            callback(user, task, entitlement, (void*)original);
        }
    }
    return original;
}

bool KernelPatcher::IOCurrentTaskHasEntitlement(const char* entitlement) {
    return true;
}

void KernelPatcher::TaskSetMainThreadQos(task_t task, thread_t thread) {
    Hook* hook = that->GetBinaryLoadHook();
    xnu::mach::VmAddress trampoline;
    trampoline = hook->GetTrampolineFromChain(
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::TaskSetMainThreadQos));
    typedef void* (*task_set_main_thread_qos)(task_t, thread_t);
    DARWIN_KIT_LOG("DarwinKit::task_set_main_thread_qos hook!\n");
    if (that) {
        StoredArray<DarwinKit::BinaryLoadCallback>* binaryLoadCallbacks;
        DarwinKit* darwinkit = that->GetKernel()->GetDarwinKit();
        binaryLoadCallbacks = &darwinkit->GetBinaryLoadCallbacks();
        for (int i = 0; i < binaryLoadCallbacks->size(); i++) {
            auto handler = binaryLoadCallbacks->at(i);
            DarwinKit::BinaryLoadCallback callback = handler->first;
            void* user = handler->second;
            // callback(user, task, thread);
        }
    }
    reinterpret_cast<task_set_main_thread_qos>(trampoline)(task, thread);
}

void KernelPatcher::FindAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                   const void* replace, Size replace_size) {
    void* res;
}

void KernelPatcher::RouteFunction(Hook* hook) {}

void KernelPatcher::OnKextLoad(void* kext, xnu::KmodInfo* kmod) {
    Kext::OnKextLoad(kext, kmod);
}

void KernelPatcher::OnExec(task_t task, const char* path, Size len) {}

void KernelPatcher::OnEntitlementRequest(task_t task, const char* entitlement, void* original) {}

Hook* KernelPatcher::InstallCopyClientEntitlementHook() {
    Hook* hook;
    xnu::mach::VmAddress orig_copyClientEntitlement;
    xnu::mach::VmAddress hooked_copyClientEntitlement;
    orig_copyClientEntitlement = GetKernel()->GetSymbolAddressByName(
        "__ZN12IOUserClient21copyClientEntitlementEP4taskPKc");
    hooked_copyClientEntitlement =
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::CopyClientEntitlement);
    char buffer[128];
    snprintf(buffer, 128, "0x%llx", orig_copyClientEntitlement);
    DARWIN_KIT_LOG("DarwinKit::__ZN12IOUserClient21copyClientEntitlementEP4taskPKc = %s\n", buffer);
    hook = Hook::CreateHookForFunction(GetKernel(), this, orig_copyClientEntitlement);
    InstallHook(hook, hooked_copyClientEntitlement);
    copyClientEntitlementHook = hook;
    return hook;
}

Hook* KernelPatcher::InstallHasEntitlementHook() {
    Hook* hook;
    xnu::mach::VmAddress orig_IOCurrentTaskHasEntitlement;
    xnu::mach::VmAddress hooked_IOCurrentTaskHasEntitlement;
    orig_IOCurrentTaskHasEntitlement =
        GetKernel()->GetSymbolAddressByName("_IOCurrentTaskHasEntitlement");
    hooked_IOCurrentTaskHasEntitlement =
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::IOCurrentTaskHasEntitlement);
    char buffer[128];
    snprintf(buffer, 128, "0x%llx", orig_IOCurrentTaskHasEntitlement);
    DARWIN_KIT_LOG("DarwinKit::_IOCurrentTaskHasEntitlement = %s\n", buffer);
    hook = Hook::CreateHookForFunction(GetKernel(), this, orig_IOCurrentTaskHasEntitlement);
    InstallHook(hook, hooked_IOCurrentTaskHasEntitlement);
    hasEntitlementHook = hook;
    return hook;
}

Hook* KernelPatcher::InstallBinaryLoadHook() {
    Hook* hook;
    xnu::mach::VmAddress orig_task_set_main_thread_qos;
    xnu::mach::VmAddress hooked_task_set_main_thread_qos;
    orig_task_set_main_thread_qos =
        GetKernel()->GetSymbolAddressByName("_task_main_thread_qos");
    hooked_task_set_main_thread_qos =
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::TaskSetMainThreadQos);
    hook = Hook::CreateHookForFunction(GetKernel(), this, orig_task_set_main_thread_qos);
    InstallHook(hook, hooked_task_set_main_thread_qos);
    binaryLoadHook = hook;
    return hook;
}

Hook* KernelPatcher::InstallKextLoadHook() {
    Hook* hook;
    xnu::mach::VmAddress orig_OSKextSaveLoadedKextPanicList;
    xnu::mach::VmAddress hooked_OSKextSaveLoadedKextPanicList;
    orig_OSKextSaveLoadedKextPanicList =
        GetKernel()->GetSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");
    hooked_OSKextSaveLoadedKextPanicList =
        reinterpret_cast<xnu::mach::VmAddress>(KernelPatcher::OnOSKextSaveLoadedKextPanicList);
    hook = Hook::CreateHookForFunction(GetKernel(), this, orig_OSKextSaveLoadedKextPanicList);
    InstallHook(hook, hooked_OSKextSaveLoadedKextPanicList);
    kextLoadHook = hook;
    return hook;
}

void KernelPatcher::RegisterCallbacks() {
    DarwinKit* darwinkit = GetKernel()->GetDarwinKit();
    darwinkit->RegisterEntitlementCallback(
        (void*)this, [](void* user, task_t task, const char* entitlement, void* original) {
            static_cast<KernelPatcher*>(user)->OnEntitlementRequest(task, entitlement, original);
        });
    darwinkit->RegisterBinaryLoadCallback(
        (void*)this, [](void* user, task_t task, const char* path, Size len) {
            static_cast<KernelPatcher*>(user)->OnExec(task, path, len);
        });
    darwinkit->RegisterKextLoadCallback((void*)this, [](void* user, void* kext, xnu::KmodInfo* kmod) {
        static_cast<KernelPatcher*>(user)->OnKextLoad(kext, kmod);
    });
}

void KernelPatcher::ProcessAlreadyLoadedKexts() {
#ifdef __x86_64__
    for (xnu::KmodInfo* kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (kmod->address && kmod->size) {
            char buffer1[128];
            char buffer2[128];
            snprintf(buffer1, 128, "0x%lx", kmod->address);
            snprintf(buffer2, 128, "0x%x", *(UInt32*)kmod->address);
            DARWIN_KIT_LOG("DarwinKit::KernelPatcher::processing Kext %s = %s @ %s\n", (char*)kmod->name,
                       buffer1, buffer2);
            ProcessKext(kmod, true);
        }
    }
#endif
#ifdef __arm64__
    xnu::mach::VmAddress kernel_cache = Kernel::FindKernelCache();
    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(kernel_cache);
    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(struct mach_header_64);
    for (int i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);
        if (load_command->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command* fileset_entry_command =
                reinterpret_cast<struct fileset_entry_command*>(load_command);
            xnu::mach::VmAddress base = fileset_entry_command->vmaddr;
            char* entry_id =
                reinterpret_cast<char*>(fileset_entry_command) + fileset_entry_command->entry_id;
            if (base && strcmp(entry_id, "com.apple.kernel") != 0) {
                xnu::KmodInfo* kmod = new xnu::KmodInfo;
                kmod->address = 0xfffffe0000000000 | base;
                kmod->size = 0;
                strlcpy(reinterpret_cast<char*>(&kmod->name), entry_id, strlen(entry_id) + 1);
                kmod->start = (xnu::KmodStartFunc*)0;
                kmod->stop = (xnu::KmodStopFunc*)0;
                ProcessKext(kmod, true);

                char buffer1[128];
                char buffer2[128];
                snprintf(buffer1, 128, "0x%llx", kmod->address);
                snprintf(buffer2, 128, "0x%x", *(UInt32*)kmod->address);
                DARWIN_KIT_LOG("DarwinKit::KernelPatcher::processing Kext %s = %s @ %s = %s\n", entry_id,
                           buffer1, entry_id, buffer2);
            }
        }
        q += load_command->cmdsize;
    }
#endif
    waitingForAlreadyLoadedKexts = false;
}

void KernelPatcher::ProcessKext(xnu::KmodInfo* kmod, bool loaded) {
    DarwinKit* darwinkit;
    void* OSKext;
    xnu::mach::VmAddress kmod_address = (xnu::mach::VmAddress)kmod->address;
    darwinkit = GetKernel()->GetDarwinKit();
    StoredArray<DarwinKit::KextLoadCallback> *kextLoadCallbacks = &darwinkit->GetKextLoadCallbacks();
    OSKext = KernelPatcher::OSKextLookupKextWithIdentifier(static_cast<char*>(kmod->name));
    for (int i = 0; i < kextLoadCallbacks->size(); i++) {
        auto handler = kextLoadCallbacks->at(i);
        DarwinKit::KextLoadCallback callback = handler->first;
        void* user = handler->second;
        callback(user, OSKext, kmod);
    }
}

xnu::mach::VmAddress KernelPatcher::InjectPayload(xnu::mach::VmAddress address, Payload* payload) {
    return (xnu::mach::VmAddress)0;
}

xnu::mach::VmAddress KernelPatcher::InjectSegment(xnu::mach::VmAddress address, Payload* payload) {
    return (xnu::mach::VmAddress)0;
}

#ifdef __arm64__
void KernelPatcher::PatchPmapEnterOptions() {
    using namespace arch::arm64;
    xnu::Kernel* kernel = kernel;
    MachO* macho = kernel->GetMachO();
    xnu::mach::VmAddress vm_allocate_external =
        kernel->GetSymbolAddressByName("_vm_allocate_external");
    char buffer[128];
    xnu::mach::VmAddress branch = arch::arm64::patchfinder::Step64(
        macho, vm_allocate_external, 0x10, reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b),
        -1, -1);
    bool sign;
    b_t b = *(b_t*)branch;
    UInt64 imm = b.imm;
    if (imm & 0x2000000) {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;
        sign = true;
    } else {
        sign = false;
    }
    imm *= (1 << 2);

    xnu::mach::VmAddress vm_allocate = sign ? branch - imm : branch + imm;
    branch = arch::arm64::patchfinder::Step64(
        macho, vm_allocate, 0x100, reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_bl), -1, -1);
    bl_t bl = *(bl_t*)branch;
    imm = bl.imm;
    if (imm & 0x2000000) {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;
        sign = true;
    } else {
        sign = false;
    }
    imm *= (1 << 2);

    UInt32 nop = 0xd503201f;
    xnu::mach::VmAddress vm_map_enter = sign ? branch - imm : branch + imm;
    xnu::mach::VmAddress pmap_enter_options_strref = arch::arm64::patchfinder::FindStringReference(
        macho, "pmap_enter_options(): attempt to add executable mapping to kernel_pmap @%s:%d", 1,
        __cstring_, __TEXT_PPL_BASE, false);
    xnu::mach::VmAddress pmap_enter_options = arch::arm64::patchfinder::FindFunctionBegin(
        macho, pmap_enter_options_strref - 0xFFF, pmap_enter_options_strref);
    xnu::mach::VmAddress panic = arch::arm64::patchfinder::StepBack64(
        macho, pmap_enter_options_strref - sizeof(UInt32) * 2, 0x20,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_adrp), -1, -1);
    xnu::mach::VmAddress panic_xref =
        arch::arm64::patchfinder::Xref64(macho, panic - 0xFFF, panic - sizeof(UInt32), panic);
    branch = arch::arm64::patchfinder::StepBack64(
        macho, panic_xref - sizeof(UInt32), 0x10,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);
    kernel->Write(branch, (void*)&nop, sizeof(nop));
    branch = arch::arm64::patchfinder::StepBack64(
        macho, branch - sizeof(UInt32), 0x20,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);
    kernel->Write(branch, (void*)&nop, sizeof(nop));
    branch = arch::arm64::patchfinder::StepBack64(
        macho, branch - sizeof(UInt32), 0x10,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);
    kernel->Write(branch, (void*)&nop, sizeof(nop));

    UInt32 mov_x26_0x7 = 0xd28000fa;
    kernel->Write(panic_xref - sizeof(UInt32) * 2, (void*)&mov_x26_0x7, sizeof(mov_x26_0x7));
    kernel->Write(panic_xref - sizeof(UInt32), (void*)&nop, sizeof(nop));
    kernel->Write(panic_xref + sizeof(UInt32), (void*)&nop, sizeof(nop));
    // UInt64 breakpoint = 0xD4388E40D4388E40;
    // write(vm_map_enter, (void*) &breakpoint, sizeof(UInt64));
    // DARWIN_KIT_LOG("DarwinKit::@ vm_map_enter = 0x%x\n", *(UInt32*) vm_map_enter);
}
#endif

void KernelPatcher::ApplyKernelPatch(struct KernelPatch* patch) {
    xnu::Kernel* kernel;
    MachO* macho;
    Symbol* symbol;
    const UInt8* find;
    const UInt8* replace;
    Size size;
    Size count;
    Offset offset;
    kernel = patch->kernel;
    macho = patch->macho;
    find = patch->find;
    replace = patch->replace;
    size = patch->size;
    count = patch->count;
    offset = patch->offset;
    if (!symbol) {
        // Patches everything you can N times;
        xnu::mach::VmAddress base = kernel->GetBase();
        xnu::mach::VmAddress current_address = base;
        Size size = macho->GetSize();
        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)find, size) != 0) {
                current_address++;
            }
            if (current_address != base + size) {
                kernel->Write(current_address, (void*)replace, size);
            }
        }
    } else {
        // Patches the function directed by symbol
        xnu::mach::VmAddress address = symbol->GetAddress();
        if (find) {
            // Searches up to N bytes from beginning of function
            // Uses patchfinder::findFunctionEnd() to get ending point
            xnu::mach::VmAddress current_address = address;
            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)find, size) == 0) {
                    kernel->Write(current_address, (void*)replace, size);
                }
                current_address++;
            }
        } else {
            // Uses offset provided by user to patch bytes in function
            kernel->Write(address + offset, (void*)replace, size);
        }
    }
    kernelPatches.push_back(patch);
}

void KernelPatcher::ApplyKextPatch(struct KextPatch* patch) {
    Kext* kext;
    MachO* macho;
    Symbol* symbol;
    const UInt8* find;
    const UInt8* replace;
    Size size;
    Size count;
    Offset offset;
    kext = patch->kext;
    macho = patch->macho;
    find = patch->find;
    replace = patch->replace;
    size = patch->size;
    count = patch->count;
    offset = patch->offset;
    if (!symbol) {
        // Patches everything you can N times;
        xnu::mach::VmAddress base = kext->GetBase();
        xnu::mach::VmAddress current_address = base;
        Size size = macho->GetSize();
        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)find, size) != 0) {
                current_address++;
            }
            if (current_address != base + size) {
                kernel->Write(current_address, (void*)replace, size);
            }
        }
    } else {
        // Patches the function directed by symbol
        xnu::mach::VmAddress address = symbol->GetAddress();
        if (find) {
            // Searches up to N bytes from beginning of function
            // Uses patchfinder::findFunctionEnd() to get ending point
            xnu::mach::VmAddress current_address = address;
            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)find, size) == 0) {
                    kernel->Write(current_address, (void*)replace, size);
                }
                current_address++;
            }
        } else {
            // Uses offset provided by user to patch bytes in function
            kernel->Write(address + offset, (void*)replace, size);
        }
    }
    kextPatches.push_back(patch);
}

void KernelPatcher::RemoveKernelPatch(struct KernelPatch* patch) {
    xnu::Kernel* kernel;
    MachO* macho;
    Symbol* symbol;
    const UInt8* find;
    const UInt8* replace;
    Size size;
    Size count;
    Offset offset;
    kernel = patch->kernel;
    macho = patch->macho;
    find = patch->find;
    replace = patch->replace;
    size = patch->size;
    count = patch->count;
    offset = patch->offset;
    if (!symbol) {
        // Patches everything you can N times;
        xnu::mach::VmAddress base = kernel->GetBase();
        xnu::mach::VmAddress current_address = base;
        Size size = macho->GetSize();
        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)replace, size) != 0) {
                current_address++;
            }
            if (current_address != base + size) {
                kernel->Write(current_address, (void*)find, size);
            }
        }
    } else {
        // Patches the function directed by symbol
        xnu::mach::VmAddress address = symbol->GetAddress();
        if (find) {
            // Searches up to N bytes from beginning of function
            // Uses patchfinder::findFunctionEnd() to get ending point
            xnu::mach::VmAddress current_address = address;
            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)replace, size) == 0) {
                    kernel->Write(current_address, (void*)find, size);
                }
                current_address++;
            }
        } else {
            // Uses offset provided by user to patch bytes in function
            kernel->Write(address + offset, (void*)find, size);
        }
    }
    kernelPatches.push_back(patch);
}

void KernelPatcher::RemoveKextPatch(struct KextPatch* patch) {
    Kext* kext;
    MachO* macho;
    Symbol* symbol;
    const UInt8* find;
    const UInt8* replace;
    Size size;
    Size count;
    Offset offset;
    kext = patch->kext;
    macho = patch->macho;
    find = patch->find;
    replace = patch->replace;
    size = patch->size;
    count = patch->count;
    offset = patch->offset;
    if (!symbol) {
        // Patches everything you can N times;
        xnu::mach::VmAddress base = kext->GetBase();
        xnu::mach::VmAddress current_address = base;
        Size size = macho->GetSize();
        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)replace, size) != 0) {
                current_address++;
            }
            if (current_address != base + size) {
                kernel->Write(current_address, (void*)find, size);
            }
        }

    } else {
        // Patches the function directed by symbol
        xnu::mach::VmAddress address = symbol->GetAddress();
        if (find) {
            // Searches up to N bytes from beginning of function
            // Uses patchfinder::findFunctionEnd() to get ending point
            xnu::mach::VmAddress current_address = address;
            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)replace, size) == 0) {
                    kernel->Write(current_address, (void*)find, size);
                }
                current_address++;
            }
        } else {
            // Uses offset provided by user to patch bytes in function
            kernel->Write(address + offset, (void*)find, size);
        }
    }
    kextPatches.push_back(patch);
}

} // namespace darwin