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

using namespace arch::arm64::PatchFinder;

#elif __x86_64__

#include <x86_64/patch_finder_x86_64.h>

using namespace arch::x86_64::PatchFinder;

#endif

using namespace arch;
using namespace darwin;

static KernelPatcher* that = nullptr;

KernelPatcher::KernelPatcher() {}

KernelPatcher::KernelPatcher(xnu::Kernel* kernel)
    : kernel(kernel),
      kextKmods(reinterpret_cast<xnu::KmodInfo**>(kernel->getSymbolAddressByName("_kmod"))) {
    that = this;

    initialize();
}

KernelPatcher::~KernelPatcher() {}

void KernelPatcher::initialize() {
    processAlreadyLoadedKexts();

    waitingForAlreadyLoadedKexts = false;

    installCopyClientEntitlementHook();

#ifdef __x86_64__
    // binary load hook does not work on arm64 because symbol to hook does not exist
    installBinaryLoadHook();

    // kext load hook does not work on arm64 because symbol to hook does not exist
    installKextLoadHook();
#endif

    // installDummyBreakpoint();
}

bool KernelPatcher::dummyBreakpoint(union arch::RegisterState* state) {
    RegisterState_x86_64* state_x86_64;
    RegisterState_arm64* state_arm64;

    switch (arch::getCurrentArchitecture()) {
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

Hook* KernelPatcher::installDummyBreakpoint() {
    Hook* hook;

    xnu::Mach::VmAddress mach_msg_trap =
        getKernel()->getSymbolAddressByName("_mach_msg_trap");

    hook = Hook::breakpointForAddress(dynamic_cast<Task*>(getKernel()),
                                      dynamic_cast<Patcher*>(this), mach_msg_trap);

    hook->addBreakpoint((xnu::Mach::VmAddress)KernelPatcher::dummyBreakpoint);

    return hook;
}

void KernelPatcher::onOSKextSaveLoadedKextPanicList() {
    xnu::Mach::VmAddress trampoline;

    if (!that)
        return;

    trampoline = that->getKextLoadHook()->getTrampolineFromChain(
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::onOSKextSaveLoadedKextPanicList));

    typedef void (*OSKextSaveLoadedKextPanicList)();

    void (*_OSKextSavedLoadedKextPanicList)();

    _OSKextSavedLoadedKextPanicList = reinterpret_cast<OSKextSaveLoadedKextPanicList>(trampoline);

    _OSKextSavedLoadedKextPanicList();

    DARWIN_RK_LOG("MacRK::OSKextSavedLoadedKextPanicList() hook!\n");

    if (that->waitingForAlreadyLoadedKexts) {
        that->processAlreadyLoadedKexts();

        that->waitingForAlreadyLoadedKexts = false;
    } else {

#ifdef __x86_64__
        xnu::KmodInfo* kmod = *that->getKextKmods();

        if (kmod) {
            that->processKext(kmod, false);
        }
#endif
    }
}

void* KernelPatcher::OSKextLookupKextWithIdentifier(const char* identifier) {
    typedef void* (*lookupKextWithIdentifier)(const char*);

    void* (*__ZN6OSKext24lookupKextWithIdentifierEPKc)(const char*);

    xnu::Mach::VmAddress OSKext_lookupWithIdentifier =
        that->getKernel()->getSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");

    __ZN6OSKext24lookupKextWithIdentifierEPKc =
        reinterpret_cast<lookupKextWithIdentifier>(OSKext_lookupWithIdentifier);

#ifdef _x86_64__
    void* OSKext = __ZN6OSKext24lookupKextWithIdentifierEPKc(identifier);

    return OSKext;
#elif __arm64__
    return 0;
#endif
}

OSObject* KernelPatcher::copyClientEntitlement(task_t task, const char* entitlement) {
    Hook* hook = that->getCopyClientEntitlementHook();

    xnu::Mach::VmAddress trampoline;

    DARWIN_RK_LOG("MacRK::KernelPatcher::copyClientEntitlement() hook!\n");

    trampoline = hook->getTrampolineFromChain(
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::copyClientEntitlement));

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

        DarwinKit* rootkit = that->getKernel()->getRootKit();

        entitlementCallbacks = &rootkit->getEntitlementCallbacks();

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

void KernelPatcher::taskSetMainThreadQos(task_t task, thread_t thread) {
    Hook* hook = that->getBinaryLoadHook();

    xnu::Mach::VmAddress trampoline;

    trampoline = hook->getTrampolineFromChain(
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::taskSetMainThreadQos));

    typedef void* (*task_set_main_thread_qos)(task_t, thread_t);

    DARWIN_RK_LOG("MacRK::task_set_main_thread_qos hook!\n");

    if (that) {
        StoredArray<DarwinKit::BinaryLoadCallback>* binaryLoadCallbacks;

        DarwinKit* rootkit = that->getKernel()->getRootKit();

        binaryLoadCallbacks = &rootkit->getBinaryLoadCallbacks();

        for (int i = 0; i < binaryLoadCallbacks->size(); i++) {
            auto handler = binaryLoadCallbacks->at(i);

            DarwinKit::BinaryLoadCallback callback = handler->first;

            void* user = handler->second;

            // callback(user, task, thread);
        }
    }

    reinterpret_cast<task_set_main_thread_qos>(trampoline)(task, thread);
}

void KernelPatcher::findAndReplace(void* data, Size data_size, const void* find, Size find_size,
                                   const void* replace, Size replace_size) {
    void* res;
}

void KernelPatcher::routeFunction(Hook* hook) {}

void KernelPatcher::onKextLoad(void* kext, xnu::KmodInfo* kmod) {
    Kext::onKextLoad(kext, kmod);
}

void KernelPatcher::onExec(task_t task, const char* path, Size len) {}

void KernelPatcher::onEntitlementRequest(task_t task, const char* entitlement, void* original) {}

Hook* KernelPatcher::installCopyClientEntitlementHook() {
    Hook* hook;

    xnu::Mach::VmAddress orig_copyClientEntitlement;
    xnu::Mach::VmAddress hooked_copyClientEntitlement;

    orig_copyClientEntitlement = getKernel()->getSymbolAddressByName(
        "__ZN12IOUserClient21copyClientEntitlementEP4taskPKc");

    hooked_copyClientEntitlement =
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::copyClientEntitlement);

    char buffer[128];

    snprintf(buffer, 128, "0x%llx", orig_copyClientEntitlement);

    DARWIN_RK_LOG("MacRK::__ZN12IOUserClient21copyClientEntitlementEP4taskPKc = %s\n", buffer);

    hook = Hook::hookForFunction(getKernel(), this, orig_copyClientEntitlement);

    installHook(hook, hooked_copyClientEntitlement);

    copyClientEntitlementHook = hook;

    return hook;
}

Hook* KernelPatcher::installHasEntitlementHook() {
    Hook* hook;

    xnu::Mach::VmAddress orig_IOCurrentTaskHasEntitlement;
    xnu::Mach::VmAddress hooked_IOCurrentTaskHasEntitlement;

    orig_IOCurrentTaskHasEntitlement =
        getKernel()->getSymbolAddressByName("_IOCurrentTaskHasEntitlement");

    hooked_IOCurrentTaskHasEntitlement =
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::IOCurrentTaskHasEntitlement);

    char buffer[128];

    snprintf(buffer, 128, "0x%llx", orig_IOCurrentTaskHasEntitlement);

    DARWIN_RK_LOG("MacRK::_IOCurrentTaskHasEntitlement = %s\n", buffer);

    hook = Hook::hookForFunction(getKernel(), this, orig_IOCurrentTaskHasEntitlement);

    installHook(hook, hooked_IOCurrentTaskHasEntitlement);

    hasEntitlementHook = hook;

    return hook;
}

Hook* KernelPatcher::installBinaryLoadHook() {
    Hook* hook;

    xnu::Mach::VmAddress orig_task_set_main_thread_qos;
    xnu::Mach::VmAddress hooked_task_set_main_thread_qos;

    orig_task_set_main_thread_qos =
        getKernel()->getSymbolAddressByName("_task_main_thread_qos");

    hooked_task_set_main_thread_qos =
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::taskSetMainThreadQos);

    hook = Hook::hookForFunction(getKernel(), this, orig_task_set_main_thread_qos);

    installHook(hook, hooked_task_set_main_thread_qos);

    binaryLoadHook = hook;

    return hook;
}

Hook* KernelPatcher::installKextLoadHook() {
    Hook* hook;

    xnu::Mach::VmAddress orig_OSKextSaveLoadedKextPanicList;
    xnu::Mach::VmAddress hooked_OSKextSaveLoadedKextPanicList;

    orig_OSKextSaveLoadedKextPanicList =
        getKernel()->getSymbolAddressByName("__ZN6OSKext24lookupKextWithIdentifierEPKc");

    hooked_OSKextSaveLoadedKextPanicList =
        reinterpret_cast<xnu::Mach::VmAddress>(KernelPatcher::onOSKextSaveLoadedKextPanicList);

    hook = Hook::hookForFunction(getKernel(), this, orig_OSKextSaveLoadedKextPanicList);

    installHook(hook, hooked_OSKextSaveLoadedKextPanicList);

    kextLoadHook = hook;

    return hook;
}

void KernelPatcher::registerCallbacks() {
    DarwinKit* rootkit = getKernel()->getRootKit();

    rootkit->registerEntitlementCallback(
        (void*)this, [](void* user, task_t task, const char* entitlement, void* original) {
            static_cast<KernelPatcher*>(user)->onEntitlementRequest(task, entitlement, original);
        });

    rootkit->registerBinaryLoadCallback(
        (void*)this, [](void* user, task_t task, const char* path, Size len) {
            static_cast<KernelPatcher*>(user)->onExec(task, path, len);
        });

    rootkit->registerKextLoadCallback((void*)this, [](void* user, void* kext, xnu::KmodInfo* kmod) {
        static_cast<KernelPatcher*>(user)->onKextLoad(kext, kmod);
    });
}

void KernelPatcher::processAlreadyLoadedKexts() {
#ifdef __x86_64__

    for (xnu::KmodInfo* kmod = *kextKmods; kmod; kmod = kmod->next) {
        if (kmod->address && kmod->size) {
            char buffer1[128];
            char buffer2[128];

            snprintf(buffer1, 128, "0x%lx", kmod->address);
            snprintf(buffer2, 128, "0x%x", *(UInt32*)kmod->address);

            DARWIN_RK_LOG("MacRK::KernelPatcher::processing Kext %s = %s @ %s\n", (char*)kmod->name,
                       buffer1, buffer2);

            processKext(kmod, true);
        }
    }

#endif

#ifdef __arm64__

    xnu::Mach::VmAddress kernel_cache = Kernel::findKernelCache();

    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(kernel_cache);

    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(struct mach_header_64);

    for (int i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);

        if (load_command->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command* fileset_entry_command =
                reinterpret_cast<struct fileset_entry_command*>(load_command);

            xnu::Mach::VmAddress base = fileset_entry_command->vmaddr;

            char* entry_id =
                reinterpret_cast<char*>(fileset_entry_command) + fileset_entry_command->entry_id;

            if (base && strcmp(entry_id, "com.apple.kernel") != 0) {
                xnu::KmodInfo* kmod = new xnu::KmodInfo;

                kmod->address = 0xfffffe0000000000 | base;
                kmod->size = 0;

                strlcpy(reinterpret_cast<char*>(&kmod->name), entry_id, strlen(entry_id) + 1);

                kmod->start = (xnu::KmodStartFunc*)0;
                kmod->stop = (xnu::KmodStopFunc*)0;

                processKext(kmod, true);

                char buffer1[128];
                char buffer2[128];

                snprintf(buffer1, 128, "0x%llx", kmod->address);
                snprintf(buffer2, 128, "0x%x", *(UInt32*)kmod->address);

                DARWIN_RK_LOG("MacRK::KernelPatcher::processing Kext %s = %s @ %s = %s\n", entry_id,
                           buffer1, entry_id, buffer2);
            }
        }

        q += load_command->cmdsize;
    }

#endif

    waitingForAlreadyLoadedKexts = false;
}

void KernelPatcher::processKext(xnu::KmodInfo* kmod, bool loaded) {
    DarwinKit* rootkit;

    void* OSKext;

    StoredArray<DarwinKit::KextLoadCallback>* kextLoadCallbacks;

    xnu::Mach::VmAddress kmod_address = (xnu::Mach::VmAddress)kmod->address;

    rootkit = getKernel()->getRootKit();

    kextLoadCallbacks = &rootkit->getKextLoadCallbacks();

    OSKext = KernelPatcher::OSKextLookupKextWithIdentifier(static_cast<char*>(kmod->name));

    for (int i = 0; i < kextLoadCallbacks->size(); i++) {
        auto handler = kextLoadCallbacks->at(i);

        DarwinKit::KextLoadCallback callback = handler->first;

        void* user = handler->second;

        callback(user, OSKext, kmod);
    }
}

xnu::Mach::VmAddress KernelPatcher::injectPayload(xnu::Mach::VmAddress address, Payload* payload) {
    return (xnu::Mach::VmAddress)0;
}

xnu::Mach::VmAddress KernelPatcher::injectSegment(xnu::Mach::VmAddress address, Payload* payload) {
    return (xnu::Mach::VmAddress)0;
}

#ifdef __arm64__
void KernelPatcher::patchPmapEnterOptions() {
    using namespace arch::arm64;

    xnu::Kernel* kernel = kernel;

    MachO* macho = kernel->getMachO();

    xnu::Mach::VmAddress vm_allocate_external =
        kernel->getSymbolAddressByName("_vm_allocate_external");

    char buffer[128];

    xnu::Mach::VmAddress branch = arch::arm64::PatchFinder::step64(
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

    xnu::Mach::VmAddress vm_allocate = sign ? branch - imm : branch + imm;

    branch = arch::arm64::PatchFinder::step64(
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

    xnu::Mach::VmAddress vm_map_enter = sign ? branch - imm : branch + imm;

    xnu::Mach::VmAddress pmap_enter_options_strref = arch::arm64::PatchFinder::findStringReference(
        macho, "pmap_enter_options(): attempt to add executable mapping to kernel_pmap @%s:%d", 1,
        __cstring_, __TEXT_PPL_BASE, false);

    xnu::Mach::VmAddress pmap_enter_options = arch::arm64::PatchFinder::findFunctionBegin(
        macho, pmap_enter_options_strref - 0xFFF, pmap_enter_options_strref);

    xnu::Mach::VmAddress panic = arch::arm64::PatchFinder::stepBack64(
        macho, pmap_enter_options_strref - sizeof(UInt32) * 2, 0x20,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_adrp), -1, -1);

    xnu::Mach::VmAddress panic_xref =
        arch::arm64::PatchFinder::xref64(macho, panic - 0xFFF, panic - sizeof(UInt32), panic);

    branch = arch::arm64::PatchFinder::stepBack64(
        macho, panic_xref - sizeof(UInt32), 0x10,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);

    kernel->write(branch, (void*)&nop, sizeof(nop));

    branch = arch::arm64::PatchFinder::stepBack64(
        macho, branch - sizeof(UInt32), 0x20,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);

    kernel->write(branch, (void*)&nop, sizeof(nop));

    branch = arch::arm64::PatchFinder::stepBack64(
        macho, branch - sizeof(UInt32), 0x10,
        reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_b_cond), -1, -1);

    kernel->write(branch, (void*)&nop, sizeof(nop));

    UInt32 mov_x26_0x7 = 0xd28000fa;

    kernel->write(panic_xref - sizeof(UInt32) * 2, (void*)&mov_x26_0x7, sizeof(mov_x26_0x7));

    kernel->write(panic_xref - sizeof(UInt32), (void*)&nop, sizeof(nop));

    kernel->write(panic_xref + sizeof(UInt32), (void*)&nop, sizeof(nop));

    // UInt64 breakpoint = 0xD4388E40D4388E40;

    // write(vm_map_enter, (void*) &breakpoint, sizeof(UInt64));

    // DARWIN_RK_LOG("MacRK::@ vm_map_enter = 0x%x\n", *(UInt32*) vm_map_enter);
}
#endif

void KernelPatcher::applyKernelPatch(struct KernelPatch* patch) {
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
        // patch everything you can N times;

        xnu::Mach::VmAddress base = kernel->getBase();

        xnu::Mach::VmAddress current_address = base;

        Size size = macho->getSize();

        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)find, size) != 0) {
                current_address++;
            }

            if (current_address != base + size) {
                kernel->write(current_address, (void*)replace, size);
            }
        }

    } else {
        // patch the function directed by symbol

        xnu::Mach::VmAddress address = symbol->getAddress();

        if (find) {
            // search up to N bytes from beginning of function
            // use PatchFinder::findFunctionEnd() to get ending point

            xnu::Mach::VmAddress current_address = address;

            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)find, size) == 0) {
                    kernel->write(current_address, (void*)replace, size);
                }

                current_address++;
            }
        } else {
            // use offset provided by user to patch bytes in function

            kernel->write(address + offset, (void*)replace, size);
        }
    }

    kernelPatches.push_back(patch);
}

void KernelPatcher::applyKextPatch(struct KextPatch* patch) {
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
        // patch everything you can N times;

        xnu::Mach::VmAddress base = kext->getBase();

        xnu::Mach::VmAddress current_address = base;

        Size size = macho->getSize();

        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)find, size) != 0) {
                current_address++;
            }

            if (current_address != base + size) {
                kernel->write(current_address, (void*)replace, size);
            }
        }

    } else {
        // patch the function directed by symbol

        xnu::Mach::VmAddress address = symbol->getAddress();

        if (find) {
            // search up to N bytes from beginning of function
            // use PatchFinder::findFunctionEnd() to get ending point

            xnu::Mach::VmAddress current_address = address;

            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)find, size) == 0) {
                    kernel->write(current_address, (void*)replace, size);
                }

                current_address++;
            }
        } else {
            // use offset provided by user to patch bytes in function

            kernel->write(address + offset, (void*)replace, size);
        }
    }

    kextPatches.push_back(patch);
}

void KernelPatcher::removeKernelPatch(struct KernelPatch* patch) {
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
        // patch everything you can N times;

        xnu::Mach::VmAddress base = kernel->getBase();

        xnu::Mach::VmAddress current_address = base;

        Size size = macho->getSize();

        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)replace, size) != 0) {
                current_address++;
            }

            if (current_address != base + size) {
                kernel->write(current_address, (void*)find, size);
            }
        }

    } else {
        // patch the function directed by symbol

        xnu::Mach::VmAddress address = symbol->getAddress();

        if (find) {
            // search up to N bytes from beginning of function
            // use PatchFinder::findFunctionEnd() to get ending point

            xnu::Mach::VmAddress current_address = address;

            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)replace, size) == 0) {
                    kernel->write(current_address, (void*)find, size);
                }

                current_address++;
            }
        } else {
            // use offset provided by user to patch bytes in function

            kernel->write(address + offset, (void*)find, size);
        }
    }

    kernelPatches.push_back(patch);
}

void KernelPatcher::removeKextPatch(struct KextPatch* patch) {
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
        // patch everything you can N times;

        xnu::Mach::VmAddress base = kext->getBase();

        xnu::Mach::VmAddress current_address = base;

        Size size = macho->getSize();

        for (int i = 0; current_address < base + size && (i < count || count == 0); i++) {
            while (current_address < base + size &&
                   memcmp((void*)current_address, (void*)replace, size) != 0) {
                current_address++;
            }

            if (current_address != base + size) {
                kernel->write(current_address, (void*)find, size);
            }
        }

    } else {
        // patch the function directed by symbol

        xnu::Mach::VmAddress address = symbol->getAddress();

        if (find) {
            // search up to N bytes from beginning of function
            // use PatchFinder::findFunctionEnd() to get ending point

            xnu::Mach::VmAddress current_address = address;

            for (int i = 0; i < 0x400; i++) {
                if (memcmp((void*)current_address, (void*)replace, size) == 0) {
                    kernel->write(current_address, (void*)find, size);
                }

                current_address++;
            }
        } else {
            // use offset provided by user to patch bytes in function

            kernel->write(address + offset, (void*)find, size);
        }
    }

    kextPatches.push_back(patch);
}