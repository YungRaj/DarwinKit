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

#include "kernel.h"

#include "log.h"

#include "kernel_darwin_kit.h"
#include "darwin_kit.h"

#include "kernel_macho.h"

extern "C" {
#include "kern.h"

#include <IOKit/IOLib.h>

#include <libkern/OSKextLib.h>

#include <mach/mach_types.h>

#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/vnode.h>

#include <vfs/vfs_support.h>
}

#ifdef __arm64__

#include <arm64/patch_finder_arm64.h>

using namespace arch::arm64::PatchFinder;

#elif __x86_64__

#include <x86_64/patch_finder_x86_64.h>

using namespace arch::x86_64::PatchFinder;

#endif

char* xnu::getKernelVersion() {
    char* kernelBuildVersion = new char[256];

    struct utsname kernelInfo;

    // uname(&kernelInfo);

    strlcpy(kernelBuildVersion, kernelInfo.version, 256);

    // DARWIN_RK_LOG("MacRK::macOS kernel version = %s\n", kernelInfo.version);

    return kernelBuildVersion;
}

extern int sysctl(int*, u_int, void*, Size*, void*, Size);

char* xnu::getOSBuildVersion() {
    int mib[2];

    Size len = 256;

    char* buildVersion = new char[len];

#define CTL_KERN 1
#define KERN_OSVERSION 65

    mib[0] = CTL_KERN;
    mib[1] = KERN_OSVERSION;

    /* if (sysctl(mib, 2, buildVersion, &len, nullptr, 0) == 0) {
        DARWIN_RK_LOG("MacRK::macOS OS build version = %s\n", buildVersion);
    } else {
        return nullptr;
    } */

    return buildVersion;
}

using namespace xnu;

Offset Kernel::tempExecutableMemoryOffset = 0;

UInt8 Kernel::tempExecutableMemory[tempExecutableMemorySize]
    __attribute__((section("__TEXT,__text")));

Kernel* Kernel::kernel = nullptr;

Kernel* Kernel::create(xnu::Mach::Port kernel_task_port) {
    if (!kernel)
        kernel = new Kernel(kernel_task_port);

    return kernel;
}

Kernel* Kernel::create(xnu::Mach::VmAddress cache, xnu::Mach::VmAddress base, Offset slide) {
    if (!kernel)
        kernel = new Kernel(cache, base, slide);

    return kernel;
}

Kernel* Kernel::create(xnu::Mach::VmAddress base, Offset slide) {
    if (!kernel)
        kernel = new Kernel(base, slide);

    return kernel;
}

Kernel::Kernel(xnu::Mach::Port kernel_task_port)
    : version(xnu::getKernelVersion()), osBuildVersion(xnu::getOSBuildVersion()),
      kernel_task_port(kernel_task_port), kernelWriteLock(IOSimpleLockAlloc()) {
    base = Kernel::findKernelBase();

    disassembler = new Disassembler(this);

    // kernelDebugKit = xnu::KDK::KDKFromBuildInfo(this, version, osBuildVersion);
}

Kernel::Kernel(xnu::Mach::VmAddress cache, xnu::Mach::VmAddress base, Offset slide)
    : version(xnu::getKernelVersion()), osBuildVersion(xnu::getOSBuildVersion()),
      macho(new KernelMachO(this)) {
    disassembler = new Disassembler(this);

    macho->initWithBase(base, slide);

    // kernelDebugKit = xnu::KDK::KDKFromBuildInfo(this, version, osBuildVersion);
}

Kernel::Kernel(xnu::Mach::VmAddress base, Offset slide)
    : version(xnu::getKernelVersion()), osBuildVersion(xnu::getOSBuildVersion()),
      macho(new KernelMachO(this)), kernelWriteLock(IOSimpleLockAlloc()) {
    disassembler = new Disassembler(this);

    macho->initWithBase(base, slide);

#ifdef __x86_64__

    getKernelObjects();

    // createKernelTaskPort();

    set_kernel_map(getKernelMap());

    set_vm_functions(
        getSymbolAddressByName("_vm_read_overwrite"),
        getSymbolAddressByName("_vm_write"), getSymbolAddressByName("_vm_protect"),
        getSymbolAddressByName("_vm_remap"), getSymbolAddressByName("_vm_allocate"),
        getSymbolAddressByName("_vm_deallocate"),
        getSymbolAddressByName("_vm_map_copyin"),
        getSymbolAddressByName("_vm_map_copy_overwrite"));

    set_phys_functions(getSymbolAddressByName("_pmap_find_phys"),
                       getSymbolAddressByName("_ml_phys_read_double_64"),
                       getSymbolAddressByName("_ml_phys_read_word_64"),
                       getSymbolAddressByName("_ml_phys_read_half_64"),
                       getSymbolAddressByName("_ml_phys_read_byte_64"),
                       getSymbolAddressByName("_ml_phys_write_double_64"),
                       getSymbolAddressByName("_ml_phys_write_word_64"),
                       getSymbolAddressByName("_ml_phys_write_half_64"),
                       getSymbolAddressByName("_ml_phys_write_byte_64"));

#endif

    // kernelDebugKit = xnu::KDK::KDKFromBuildInfo(this, version, osBuildVersion);
}

xnu::Mach::VmAddress Kernel::findKernelCache() {
    static xnu::Mach::VmAddress kernel_cache = 0;

    if (kernel_cache)
        return kernel_cache;

    xnu::Mach::VmAddress near = 0xfffffe0000000000 | reinterpret_cast<xnu::Mach::VmAddress>(IOLog);

    Size kaslr_align = 0x4000;

    near &= ~(kaslr_align - 1);

    bool found = false;

    while (true) {
        struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(near);

        if (mh->magic == MH_MAGIC_64) {
            if (mh->filetype == 0xC && mh->flags == 0 && mh->reserved == 0) {
                found = true;

                break;
            }
        }

        near -= kaslr_align;
    }

    if (found) {
        kernel_cache = near;

        return kernel_cache;
    }

    return 0;
}

xnu::Mach::VmAddress Kernel::findKernelCollection() {
    static xnu::Mach::VmAddress kernel_collection = 0;

    if (kernel_collection)
        return kernel_collection;

    xnu::Mach::VmAddress near = reinterpret_cast<xnu::Mach::VmAddress>(IOLog);

    Size kaslr_align = 0x1000;

    near &= ~(kaslr_align - 1);

    while (true) {
        struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(near);

        if (mh->magic == MH_MAGIC_64) {
            if (mh->filetype == 0xC && mh->flags == 0 && mh->reserved == 0) {
                break;
            }
        }

        near -= kaslr_align;
    }

    kernel_collection = near;

    return kernel_collection;
}

xnu::Mach::VmAddress Kernel::findKernelBase() {
    static xnu::Mach::VmAddress kernel_base = 0;

    if (kernel_base)
        return kernel_base;

    xnu::Mach::VmAddress kc;

#ifdef __arm64__

    kc = Kernel::findKernelCache();

    if (!kc)
        return 0;

    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(kc);

    UInt8* q = reinterpret_cast<UInt8*>(kc) + sizeof(struct mach_header_64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);

        if (load_command->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command* fileset_entry_command =
                reinterpret_cast<struct fileset_entry_command*>(load_command);

            char* entry_id =
                reinterpret_cast<char*>(fileset_entry_command) + fileset_entry_command->entry_id;

            if (strcmp(entry_id, "com.apple.kernel") == 0) {
                kernel_base = 0xfffffe0000000000 | fileset_entry_command->vmaddr;

                return kernel_base;
            }
        }

        q += load_command->cmdsize;
    }

    kernel_base = 0;

#endif

#ifdef __x86_64__

    kc = Kernel::findKernelCollection();

    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(kc);

    UInt8* q = reinterpret_cast<UInt8*>(kc) + sizeof(struct mach_header_64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);

        if (load_command->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            if (strncmp(segment_command->segname, "__TEXT_EXEC", strlen("__TEXT_EXEC")) == 0) {
                kernel_base = segment_command->vmaddr;

                break;
            }
        }

        q += load_command->cmdsize;
    }

#endif

    return kernel_base;
}

Offset Kernel::findKernelSlide() {
    xnu::Mach::VmAddress base;

    xnu::Mach::VmAddress text_base;

    xnu::Macho::Header64* mh;

    base = Kernel::findKernelBase();

#ifdef __arm64__

    if ((base - 0xfffffe0007004000) > 0xFFFFFFFF)
        panic("kernel base minus unslid base is overflown!");

    return (Offset)(base - 0xfffffe0007004000);

#endif

#ifdef __x86_64__

    if ((base - 0xffffff8000200000) > 0xFFFFFFFF)
        panic("kernel base minus unslid base is overflown!");

    mh = reinterpret_cast<struct mach_header_64*>(base);

    UInt8* q = reinterpret_cast<UInt8*>(base) + sizeof(xnu::Macho::Header64);

    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);

        if (load_command->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);

            if (strncmp(segment_command->segname, "__TEXT", strlen("__TEXT")) == 0) {
                text_base = segment_command->vmaddr;

                break;
            }
        }

        q += load_command->cmdsize;
    }

    return text_base - 0xfffffe0007004000;

#endif
}

xnu::Mach::VmAddress Kernel::getBase() {
    base = Kernel::findKernelBase();

    return base;
}

Offset Kernel::getSlide() {
    if (slide) {
        return slide;
    }

    slide = Kernel::findKernelSlide();

    return slide;
}

void Kernel::getKernelObjects() {
    char buffer1[128];
    char buffer2[128];
    char buffer3[128];

    task_t _kernel_task = *reinterpret_cast<task_t*>(getSymbolAddressByName("_kernel_task"));

    task = _kernel_task;

    typedef vm_map_t (*get_task_map)(task_t task);
    vm_map_t (*_get_task_map)(task_t);

    _get_task_map = reinterpret_cast<get_task_map>(getSymbolAddressByName("_get_task_map"));

    map = _get_task_map(_kernel_task);

    typedef pmap_t (*get_task_pmap)(task_t task);
    pmap_t (*_get_task_pmap)(task_t);

    _get_task_pmap =
        reinterpret_cast<get_task_pmap>(getSymbolAddressByName("_get_task_pmap"));

    pmap = _get_task_pmap(_kernel_task);

    snprintf(buffer1, 128, "0x%llx", (xnu::Mach::VmAddress)_get_task_map);
    snprintf(buffer2, 128, "0x%llx", (xnu::Mach::VmAddress)_get_task_pmap);

    DARWIN_RK_LOG("MacPE::get_task_map = %s get_task_pmap = %s\n", buffer1, buffer2);

    snprintf(buffer1, 128, "0x%llx", (xnu::Mach::VmAddress)getKernelTask());
    snprintf(buffer2, 128, "0x%llx", (xnu::Mach::VmAddress)getKernelMap());
    snprintf(buffer3, 128, "0x%llx", (xnu::Mach::VmAddress)getKernelPmap());

    DARWIN_RK_LOG("MacPE::kernel_task = %s kernel_map = %s kernel_pmap = %s!\n", buffer1, buffer2,
               buffer3);
}

void Kernel::createKernelTaskPort() {
    typedef vm_offset_t ipc_kobject_t;
    typedef natural_t ipc_kobject_type_t;

    typedef void (*ipc_kobject_set)(ipc_port_t port, ipc_kobject_t kobject,
                                    ipc_kobject_type_t type);
    void (*_ipc_kobject_set)(ipc_port_t port, ipc_kobject_t kobject, ipc_kobject_type_t type) = 0;

    typedef ipc_port_t (*ipc_port_alloc_special)(ipc_space_t);
    ipc_port_t (*_ipc_port_alloc_special)(ipc_space_t space) = 0;

    typedef void (*ipc_port_dealloc_special)(ipc_port_t port, ipc_space_t space);
    void (*_ipc_port_dealloc_special)(ipc_port_t port, ipc_space_t space) = 0;

    typedef ipc_port_t (*ipc_port_make_send)(ipc_port_t port);
    ipc_port_t (*_ipc_port_make_send)(ipc_port_t port) = 0;

    _ipc_kobject_set =
        reinterpret_cast<ipc_kobject_set>(getSymbolAddressByName("_ipc_kobject_set"));
    _ipc_port_alloc_special = reinterpret_cast<ipc_port_alloc_special>(
        getSymbolAddressByName("_ipc_port_alloc_special"));
    _ipc_port_dealloc_special = reinterpret_cast<ipc_port_dealloc_special>(
        getSymbolAddressByName("_ipc_port_dealloc_special"));
    _ipc_port_make_send =
        reinterpret_cast<ipc_port_make_send>(getSymbolAddressByName("_ipc_port_make_send"));

    task_t _kernel_task = *reinterpret_cast<task_t*>(getSymbolAddressByName("_kernel_task"));
    ipc_space_t _ipc_space_kernel =
        *reinterpret_cast<ipc_space_t*>(getSymbolAddressByName("_ipc_space_kernel"));

    char buffer1[128];
    char buffer2[128];
    char buffer3[128];

    snprintf(buffer1, 128, "0x%llx", (xnu::Mach::VmAddress)_ipc_kobject_set);
    snprintf(buffer2, 128, "0x%llx", (xnu::Mach::VmAddress)_ipc_port_alloc_special);
    snprintf(buffer3, 128, "0x%llx", (xnu::Mach::VmAddress)_ipc_port_make_send);

    DARWIN_RK_LOG("MacPE::ipc_kobject_set = %s ipc_port_alloc_special = %s ipc_port_make_send = %s\n",
               buffer1, buffer2, buffer3);

    snprintf(buffer1, 128, "0x%llx", (xnu::Mach::VmAddress)_kernel_task);
    snprintf(buffer2, 128, "0x%llx", (xnu::Mach::VmAddress)_ipc_space_kernel);

    DARWIN_RK_LOG("MacPE::kernel_task = %s ipc_space_kernel = %s\n", buffer1, buffer2);

    // use the host_priv to set host special port 4
    host_priv_t host = host_priv_self();

    if (!host)
        return;

    ipc_port_t port = _ipc_port_alloc_special(_ipc_space_kernel);

    if (!port)
        return;

#define IKOT_TASK 2

#define IO_BITS_KOTYPE 0x000003ff  /* used by the object */
#define IO_BITS_KOBJECT 0x00000800 /* port belongs to a kobject */

    UInt8* port_buf = reinterpret_cast<UInt8*>(port);

    // set io_bits of ipc_object
    *(UInt32*)(port_buf) = (*(UInt32*)port_buf & ~IO_BITS_KOTYPE);
    *(UInt32*)(port_buf) |= IKOT_TASK;
    *(UInt32*)(port_buf) |= IO_BITS_KOBJECT;

    // set kobject of ipc_port
    *(UInt64*)(port_buf + 0x68) = (UInt64)kernel_task;

    kernel_task_port = _ipc_port_make_send(port);
}

bool Kernel::setKernelWriting(bool enable) {
    static bool interruptsDisabled = false;

    Architecture* architecture = getRootKit()->getArchitecture();

    kern_return_t result = KERN_SUCCESS;

    if (enable) {
        interruptsDisabled = !setInterrupts(false);
    }

    if (architecture->setWPBit(!enable) != KERN_SUCCESS) {
        enable = false;

        result = KERN_FAILURE;
    }

    if (!enable) {
        if (!interruptsDisabled) {
            interruptsDisabled = setInterrupts(true);
        }
    }

    return interruptsDisabled;
}

bool Kernel::setNXBit(bool enable) {
    return false;
}

bool Kernel::setInterrupts(bool enable) {
    Architecture* architecture = getRootKit()->getArchitecture();

    return architecture->setInterrupts(enable);
}

UInt64 Kernel::call(char* symbolname, UInt64* arguments, Size argCount) {
    xnu::Mach::VmAddress func = getSymbolAddressByName(symbolname);

    return call(func, arguments, argCount);
}

UInt64 Kernel::call(xnu::Mach::VmAddress func, UInt64* arguments, Size argCount) {
    UInt64 ret = 0;

    xnu::Mach::VmAddress function = func;

#ifdef __arm64__

    __asm__ volatile("PACIZA %[pac]" : [pac] "+rm"(function));

#endif

    switch (argCount) {
    case 0: {
        typedef UInt64 (*function0)(void);

        function0 funk = reinterpret_cast<function0>(function);

        ret = (UInt64)(*funk)();

        break;
    }

    case 1: {
        typedef UInt64 (*function1)(UInt64);

        function1 funk = reinterpret_cast<function1>(function);

        ret = (UInt64)(*funk)(arguments[0]);

        break;
    }

    case 2: {
        typedef UInt64 (*function2)(UInt64, UInt64);

        function2 funk = reinterpret_cast<function2>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1]);

        break;
    }

    case 3: {
        typedef UInt64 (*function3)(UInt64, UInt64, UInt64);

        function3 funk = reinterpret_cast<function3>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2]);

        break;
    }

    case 4: {
        typedef UInt64 (*function4)(UInt64, UInt64, UInt64, UInt64);

        function4 funk = reinterpret_cast<function4>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3]);

        break;
    }

    case 5: {
        typedef UInt64 (*function5)(UInt64, UInt64, UInt64, UInt64, UInt64);

        function5 funk = reinterpret_cast<function5>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);

        break;
    }

    case 6: {
        typedef UInt64 (*function6)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64);

        function6 funk = reinterpret_cast<function6>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5]);

        break;
    }

    case 7: {
        typedef UInt64 (*function7)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64);

        function7 funk = reinterpret_cast<function7>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6]);

        break;
    }

    case 8: {
        typedef UInt64 (*function8)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64);

        function8 funk = reinterpret_cast<function8>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7]);

        break;
    }

    case 9: {
        typedef UInt64 (*function9)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                    UInt64);

        function9 funk = reinterpret_cast<function9>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8]);

        break;
    }

    case 10: {
        typedef UInt64 (*function10)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64);

        function10 funk = reinterpret_cast<function10>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9]);

        break;
    }

    case 11: {
        typedef UInt64 (*function11)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64);

        function11 funk = reinterpret_cast<function11>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10]);

        break;
    }

    case 12: {
        typedef UInt64 (*function12)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64);

        function12 funk = reinterpret_cast<function12>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11]);

        break;
    }

    case 13: {
        typedef UInt64 (*function13)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64);

        function13 funk = reinterpret_cast<function13>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12]);

        break;
    }

    case 14: {
        typedef UInt64 (*function14)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64);

        function14 funk = reinterpret_cast<function14>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13]);

        break;
    }

    case 15: {
        typedef UInt64 (*function15)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64);

        function15 funk = reinterpret_cast<function15>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14]);

        break;
    }

    case 16: {
        typedef UInt64 (*function16)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64);

        function16 funk = reinterpret_cast<function16>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14], arguments[15]);

        break;
    }

    case 17: {
        typedef UInt64 (*function17)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64);

        function17 funk = reinterpret_cast<function17>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14], arguments[15], arguments[16]);

        break;
    }

    case 18: {
        typedef UInt64 (*function18)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64);

        function18 funk = reinterpret_cast<function18>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14], arguments[15], arguments[16], arguments[17]);

        break;
    }

    case 19: {
        typedef UInt64 (*function19)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64);

        function19 funk = reinterpret_cast<function19>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14], arguments[15], arguments[16], arguments[17],
                              arguments[18]);

        break;
    }

    case 20: {
        typedef UInt64 (*function20)(UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
                                     UInt64, UInt64, UInt64, UInt64);

        function20 funk = reinterpret_cast<function20>(function);

        ret = (UInt64)(*funk)(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                              arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                              arguments[10], arguments[11], arguments[12], arguments[13],
                              arguments[14], arguments[15], arguments[16], arguments[17],
                              arguments[18], arguments[19]);

        break;
    }

    default:
        break;
    }

    return ret;
}

xnu::Mach::VmAddress Kernel::vmAllocate(Size size) {
    return kernel_vm_allocate(size);
}

#define VM_KERN_MEMORY_KEXT 6
#define VM_KERN_MEMORY_ANY 255

#define VM_INHERIT_SHARE ((vm_inherit_t)0)       /* shared with child */
#define VM_INHERIT_COPY ((vm_inherit_t)1)        /* copy into child */
#define VM_INHERIT_NONE ((vm_inherit_t)2)        /* absent from child */
#define VM_INHERIT_DONATE_COPY ((vm_inherit_t)3) /* copy and delete */

#define VM_INHERIT_DEFAULT VM_INHERIT_COPY

xnu::Mach::VmAddress Kernel::vmAllocate(Size size, UInt32 flags, xnu::Mach::VmProtection prot) {
    kern_return_t ret;

    xnu::Mach::VmAddress address = 0;

    xnu::Mach::VmAddress map;

#ifdef __x86_64__

    address = 0x1000;

    map = read64(getSymbolAddressByName("_g_kext_map"));

    UInt64 vmEnterArgs[13] = {map,
                              (UInt64)&address,
                              size,
                              0,
                              flags,
                              0,
                              VM_KERN_MEMORY_KEXT,
                              0,
                              0,
                              FALSE,
                              (UInt64)prot,
                              (UInt64)prot,
                              (UInt64)VM_INHERIT_DEFAULT};

    ret = static_cast<kern_return_t>(call("_vm_map_enter", vmEnterArgs, 13));

#elif __arm64__

#include <arm64/isa_arm64.h>

    using namespace arch::arm64;

    char buffer[128];

    /*
    xnu::Mach::VmAddress vm_allocate_external =
    getSymbolAddressByName("_vm_allocate_external");

    xnu::Mach::VmAddress branch = arch::arm64::PatchFinder::step64(macho,
    vm_allocate_external, 0x10, reinterpret_cast<bool(*)(UInt32*)>(arch::arm64::is_b), -1, -1);

    bool sign;

    b_t b = *(b_t*) branch;

    UInt64 imm = b.imm;

    if(imm & 0x2000000)
    {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;

        sign = true;
    } else
    {
        sign = false;
    }

    imm *= (1 << 2);

    xnu::Mach::VmAddress vm_allocate = sign ? branch - imm : branch + imm;

    branch = arch::arm64::PatchFinder::step64(macho, vm_allocate, 0x100,
    reinterpret_cast<bool(*)(UInt32*)>(arch::arm64::is_bl), -1, -1);

    bl_t bl = *(bl_t*) branch;

    imm = bl.imm;

    if(imm & 0x2000000)
    {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;

        sign = true;
    } else
    {
        sign = false;
    }

    imm *= (1 << 2);

    xnu::Mach::VmAddress vm_map_enter = sign ? branch - imm : branch + imm;

    map = *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_map"));

    address = *(UInt64*) (map + 32);

    UInt64 vmEnterArgs[13] = { map, (UInt64) &address, size, 0, flags, 0, 1, 0, 0, FALSE, (UInt64)
    prot, (UInt64) VM_PROT_ALL, (UInt64) VM_INHERIT_DEFAULT };

    ret = static_cast<kern_return_t>(call(vm_map_enter, vmEnterArgs, 13));
    */

    map = *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_map"));

    UInt64 vmAllocateExternalArgs[4] = {map, (UInt64)&address, size, VM_FLAGS_ANYWHERE};

    ret =
        static_cast<kern_return_t>(call("_vm_allocate_external", vmAllocateExternalArgs, 4));

    /*
    xnu::Mach::VmAddress vm_map_enter_mem_object_helper_strref =
    arch::arm64::PatchFinder::findStringReference(macho, "VM_FLAGS_RETURN_DATA_ADDR not expected for
    submap. @%s:%d", 1, __cstring_, __TEXT_XNU_BASE, false);

    xnu::Mach::VmAddress vm_map_enter_mem_object_helper =
    arch::arm64::PatchFinder::findFunctionBegin(macho, vm_map_enter_mem_object_helper_strref -
    0x2FFF, vm_map_enter_mem_object_helper_strref);

    UInt64 vmMapEnterMemObjectHelperArgs[15] = { map, (UInt64) &address, size, 0, VM_FLAGS_FIXED |
    VM_FLAGS_OVERWRITE, 0, 0, 0, 0, FALSE, VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_DEFAULT, 0, 0 };

    ret = static_cast<kern_return_t>(call(vm_map_enter_mem_object_helper,
    vmMapEnterMemObjectHelperArgs, 15)); */

    snprintf(buffer, 128, "0x%llx", address);

    DARWIN_RK_LOG("MacRK::vm_map_enter() return address = %s\n", buffer);

#endif

    if (ret != KERN_SUCCESS) {
        address = 0;
    }

    return address;
}

void Kernel::vmDeallocate(xnu::Mach::VmAddress address, Size size) {
    kernel_vm_deallocate(address, size);
}

bool Kernel::vmProtect(xnu::Mach::VmAddress address, Size size, xnu::Mach::VmProtection prot) {
    kern_return_t ret;

#ifdef __x86_64__

    UInt64 mlStaticProtectArgs[3] = {address, size, (UInt64)prot};

    ret = static_cast<kern_return_t>(call("_ml_static_protect", mlStaticProtectArgs, 3));

#elif __arm64__

    xnu::Mach::VmAddress ml_static_protect;

    xnu::Mach::VmAddress ml_static_protect_strref = arch::arm64::PatchFinder::findStringReference(
        macho, "ml_static_protect(): attempt to inject executable mapping on %p @%s:%d", 1,
        __cstring_, __TEXT_XNU_BASE, false);

    static bool patched = false;

    if (!patched) {
        UInt32 nop = 0xd503201f;

        xnu::Mach::VmAddress panic = arch::arm64::PatchFinder::stepBack64(
            macho, ml_static_protect_strref, 0x20,
            reinterpret_cast<bool (*)(UInt32*)>(arch::arm64::is_movz), -1, -1);

        xnu::Mach::VmAddress panic_xref =
            arch::arm64::PatchFinder::xref64(macho, panic - 0xFFF, panic, panic);

        char buffer[128];

        snprintf(buffer, 128, "0x%llx", panic_xref);

        DARWIN_RK_LOG("MacRK::panic_xref = %s\n", buffer);

        if (panic_xref) {
            *(UInt32*)panic_xref = nop;

            patched = true;
        }
    }

    ml_static_protect = arch::arm64::PatchFinder::findFunctionBegin(
        macho, ml_static_protect_strref - 0x2FF, ml_static_protect_strref);

    UInt64 mlStaticProtectArgs[3] = {address, size, (UInt64)prot};

    ml_set_interrupts_enabled(false);

    ret = static_cast<kern_return_t>(call(ml_static_protect, mlStaticProtectArgs, 3));

    ml_set_interrupts_enabled(true);

    if (ret != KERN_SUCCESS) {
        DARWIN_RK_LOG("MacRK::ml_static_protect failed! error = %d\n", ret);

        return false;
    }

#endif

    DARWIN_RK_LOG("MacRK::ml_static_protect success!\n");

    return ret == KERN_SUCCESS;
}

void* Kernel::vmRemap(xnu::Mach::VmAddress address, Size size) {

#ifdef __arm64__

#include <arm64/isa_arm64.h>

    using namespace arch::arm64;

    kern_return_t ret;

    char buffer[128];

    xnu::Mach::VmAddress map;

    xnu::Mach::VmAddress addr = 0;

    xnu::Mach::VmProtection cur_protection = VM_PROT_ALL;
    xnu::Mach::VmProtection max_protection = VM_PROT_ALL;

    xnu::Mach::VmAddress vm_map_remap;

    xnu::Mach::VmAddress vm_map_protect_strref = arch::arm64::PatchFinder::findStringReference(
        macho, "vm_map_protect(%p,0x%llx,0x%llx) new=0x%x wired=%x @%s:%d", 1, __cstring_,
        __TEXT_XNU_BASE, false);

    xnu::Mach::VmAddress cbz = arch::arm64::PatchFinder::stepBack64(
        macho, vm_map_protect_strref, 0xFFF, reinterpret_cast<bool (*)(UInt32*)>(is_cbz), -1, -1);

    cbz = arch::arm64::PatchFinder::stepBack64(macho, cbz - sizeof(UInt32), 0xFFF,
                                               reinterpret_cast<bool (*)(UInt32*)>(is_cbz), -1, -1);

    xnu::Mach::VmAddress branch = arch::arm64::PatchFinder::stepBack64(
        macho, cbz, 0x10, reinterpret_cast<bool (*)(UInt32*)>(is_bl), -1, -1);

    bool sign;

    bl_t bl = *(bl_t*)branch;

    UInt64 imm = bl.imm;

    if (imm & 0x2000000) {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;

        sign = true;
    } else {
        sign = false;
    }

    imm *= (1 << 2);

    vm_map_remap = sign ? branch - imm : branch + imm;

    map = *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_map"));

    UInt64 vmMapRemapArgs[13] = {map,
                                 (UInt64)&addr,
                                 size,
                                 0,
                                 VM_FLAGS_ANYWHERE,
                                 0,
                                 0,
                                 map,
                                 address,
                                 false,
                                 (UInt64)&cur_protection,
                                 (UInt64)&max_protection,
                                 (UInt64)VM_INHERIT_DEFAULT};

    ret = static_cast<kern_return_t>(call(vm_map_remap, vmMapRemapArgs, 13));

    if (ret != KERN_SUCCESS) {
        DARWIN_RK_LOG("MacRK::vm_map_remap failed!\n");

        return 0;
    }

    return reinterpret_cast<void*>(addr);

#endif

    return kernel_vm_remap(address, size);
}

UInt64 Kernel::virtualToPhysical(xnu::Mach::VmAddress address) {
    return kernel_virtual_to_physical(address);
}

bool Kernel::physicalRead(UInt64 paddr, void* data, Size size) {
    const UInt8* read_data = reinterpret_cast<UInt8*>(data);

    while (size > 0) {
        Size read_size = size;

        if (read_size >= 8)
            read_size = 8;
        else if (read_size >= 4)
            read_size = 4;
        else if (read_size >= 2)
            read_size = 2;
        else if (read_size >= 1)
            read_size = 1;

        if (read_size == 8)
            *(UInt64*)read_data = physical_read64(paddr);
        if (read_size == 4)
            *(UInt32*)read_data = physical_read32(paddr);
        if (read_size == 2)
            *(UInt16*)read_data = physical_read16(paddr);
        if (read_size == 1)
            *(UInt8*)read_data = physical_read8(paddr);

        paddr += read_size;
        read_data += read_size;
        size -= read_size;
    }

    return true;
}

UInt64 Kernel::physicalRead64(UInt64 paddr) {
    return physical_read64(paddr);
}

UInt32 Kernel::physicalRead32(UInt64 paddr) {
    return physical_read32(paddr);
}

UInt16 Kernel::physicalRead16(UInt64 paddr) {
    return physical_read16(paddr);
}

UInt8 Kernel::physicalRead8(UInt64 paddr) {
    return physical_read8(paddr);
}

bool Kernel::physicalWrite(UInt64 paddr, void* data, Size size) {
    const UInt8* write_data = reinterpret_cast<UInt8*>(data);

    while (size > 0) {
        Size write_size = size;

        if (write_size >= 8)
            write_size = 8;
        else if (write_size >= 4)
            write_size = 4;
        else if (write_size >= 2)
            write_size = 2;
        else if (write_size >= 1)
            write_size = 1;

        if (write_size == 8)
            physical_write64(paddr, *(UInt64*)write_data);
        if (write_size == 4)
            physical_write32(paddr, *(UInt32*)write_data);
        if (write_size == 2)
            physical_write16(paddr, *(UInt16*)write_data);
        if (write_size == 1)
            physical_write8(paddr, *(UInt8*)write_data);

        paddr += write_size;
        write_data += write_size;
        size -= write_size;
    }

    return true;
}

void Kernel::physicalWrite64(UInt64 paddr, UInt64 value) {
    return physical_write64(paddr, value);
}

void Kernel::physicalWrite32(UInt64 paddr, UInt32 value) {
    return physical_write32(paddr, value);
}

void Kernel::physicalWrite16(UInt64 paddr, UInt16 value) {
    return physical_write16(paddr, value);
}

void Kernel::physicalWrite8(UInt64 paddr, UInt8 value) {
    return physical_write8(paddr, value);
}

bool Kernel::read(xnu::Mach::VmAddress address, void* data, Size size) {
    ml_set_interrupts_enabled(false);

    for (int i = 0; i < size; i++)
        *((UInt8*)data + i) = *((UInt8*)address + i);

    ml_set_interrupts_enabled(true);

    // return kernel_read(address, data, size);

    return true;
}

bool Kernel::readUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return kernel_read_unsafe(address, data, size);
}

UInt8 Kernel::read8(xnu::Mach::VmAddress address) {
    UInt8 value;

    kernel_read(address, reinterpret_cast<void*>(&value), sizeof(value));

    return value;
}

UInt16 Kernel::read16(xnu::Mach::VmAddress address) {
    UInt16 value;

    kernel_read(address, reinterpret_cast<void*>(&value), sizeof(value));

    return value;
}

UInt32 Kernel::read32(xnu::Mach::VmAddress address) {
    UInt32 value;

    bool success = kernel_read(address, reinterpret_cast<void*>(&value), sizeof(value));

    if (!success)
        return 0;

    return value;
}

UInt64 Kernel::read64(xnu::Mach::VmAddress address) {
    UInt64 value;

    kernel_read(address, reinterpret_cast<void*>(&value), sizeof(value));

    return value;
}

bool Kernel::write(xnu::Mach::VmAddress address, void* data, Size size) {
#ifdef __x86_64__
    xnu::Mach::VmAddress pmap =
        *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_pmap"));

    UInt64 src_pmapFindPhysArgs[2] = {pmap, (UInt64)data};

    UInt64 dest_pmapFindPhysArgs[2] = {pmap, address};

    UInt64 src_ppnum;
    UInt64 src_pa;

    UInt64 dest_ppnum;
    UInt64 dest_pa;

    src_ppnum = call("_pmap_find_phys", src_pmapFindPhysArgs, 2);

    src_pa = ((src_ppnum << 12) | (src_ppnum ? (xnu::Mach::VmAddress)data & 0xFFF : 0));

    dest_ppnum = call("_pmap_find_phys", dest_pmapFindPhysArgs, 2);

    dest_pa = ((dest_ppnum << 12) | (dest_ppnum ? (xnu::Mach::VmAddress)address & 0xFFF : 0));

    if (src_pa && dest_pa) {
        UInt64 bcopyPhysArgs[3] = {src_pa, dest_pa, size};

        ml_set_interrupts_enabled(false);

        call("_bcopy_phys", bcopyPhysArgs, 3);

        ml_set_interrupts_enabled(true);

        return true;
    }

#elif __arm64__
    xnu::Mach::VmAddress pmap =
        *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_pmap"));

    UInt64 src_pmapFindPhysArgs[2] = {pmap, (UInt64)data};

    UInt64 dest_pmapFindPhysArgs[2] = {pmap, address};

    UInt64 src_ppnum;
    UInt64 src_pa;

    UInt64 dest_ppnum;
    UInt64 dest_pa;

    src_ppnum = call("_pmap_find_phys", src_pmapFindPhysArgs, 2);

    src_pa = ((src_ppnum << 14) | (src_ppnum ? (xnu::Mach::VmAddress)data & 0x3FFF : 0));

    dest_ppnum = call("_pmap_find_phys", dest_pmapFindPhysArgs, 2);

    dest_pa = ((dest_ppnum << 14) | (dest_ppnum ? (xnu::Mach::VmAddress)address & 0x3FFF : 0));

    if (src_pa && dest_pa) {
        UInt64 bcopyPhysArgs[3] = {src_pa, dest_pa, size};

        ml_set_interrupts_enabled(false);

        call("_bcopy_phys", bcopyPhysArgs, 3);

        ml_set_interrupts_enabled(true);

        return true;
    }

#include <arm64/isa_arm64.h>

    using namespace arch::arm64;

    xnu::Mach::VmAddress kernel_map =
        *reinterpret_cast<xnu::Mach::VmAddress*>(getSymbolAddressByName("_kernel_map"));

    xnu::Mach::VmAddress vm_map_copy_discard = getSymbolAddressByName("_vm_map_copy_discard");

    xnu::Mach::VmAddress ipc_kmsg_copyout_body_strref =
        arch::arm64::PatchFinder::findStringReference(
            macho, "Inconsistent OOL/copyout size on %p: expected %d, got %lld @%p @%s:%d", 1,
            __cstring_, __TEXT_XNU_BASE, false);

    xnu::Mach::VmAddress vm_map_copy_discard_xref =
        arch::arm64::PatchFinder::xref64(macho, ipc_kmsg_copyout_body_strref - 0xFFF,
                                         ipc_kmsg_copyout_body_strref, vm_map_copy_discard);

    xnu::Mach::VmAddress vm_map_copy_overwrite_branch = arch::arm64::PatchFinder::step64(
        macho, vm_map_copy_discard_xref, 0x100, reinterpret_cast<bool (*)(UInt32*)>(is_bl), -1, -1);

    vm_map_copy_overwrite_branch =
        arch::arm64::PatchFinder::step64(macho, vm_map_copy_overwrite_branch + sizeof(UInt32),
                                         0x100, reinterpret_cast<bool (*)(UInt32*)>(is_bl), -1, -1);

    vm_map_copy_overwrite_branch =
        arch::arm64::PatchFinder::step64(macho, vm_map_copy_overwrite_branch + sizeof(UInt32),
                                         0x100, reinterpret_cast<bool (*)(UInt32*)>(is_bl), -1, -1);

    bl_t bl = *(bl_t*)vm_map_copy_overwrite_branch;

    bool sign;

    UInt64 imm = bl.imm;

    if (imm & 0x2000000) {
        imm = ~(imm - 1);
        imm &= 0x1FFFFFF;

        sign = true;
    } else {
        sign = false;
    }

    imm *= (1 << 2);

    xnu::Mach::VmAddress vm_map_copy_overwrite =
        sign ? vm_map_copy_overwrite_branch - imm : vm_map_copy_overwrite_branch + imm;

    char buffer[128];

    snprintf(buffer, 128, "0x%llx", vm_map_copy_overwrite);

    DARWIN_RK_LOG("MacRK::Kernel vm_map_copy_overwrite = %s\n", buffer);

    struct vm_map_copy {
        int type;
        vm_object_offset_t offset;
        vm_map_size_t size;
        void* kdata;
    };

    typedef struct vm_map_copy* vm_map_copy_t;

    vm_map_copy_t copy;

    const UInt8* write_data = (UInt8*)data;

    while (size > 0) {
        Size write_size = size;

        if (write_size > 0x4000)
            write_size = 0x4000;

        UInt64 ret;

        UInt64 vmMapCopyInArgs[5] = {kernel_map, (UInt64)write_data, write_size, FALSE,
                                     (UInt64)&copy};

        ret = call("_vm_map_copyin", vmMapCopyInArgs, 5);

        UInt64 vmMapCopyOverwriteArgs[5] = {kernel_map, address, (UInt64)copy, write_size, FALSE};

        ret = call(vm_map_copy_overwrite, vmMapCopyOverwriteArgs, 5);

        address += write_size;
        write_data += write_size;
        size -= write_size;
    }

    return true;
#elif __x86_64__

    return kernel_write(address, data, size) || kernel_write_unsafe(address, data, size);

#endif
}

bool Kernel::writeUnsafe(xnu::Mach::VmAddress address, void* data, Size size) {
    return kernel_write_unsafe(address, data, size);
}

void Kernel::write8(xnu::Mach::VmAddress address, UInt8 value) {
    kernel_write(address, reinterpret_cast<const void*>(&value), sizeof(value));
}

void Kernel::write16(xnu::Mach::VmAddress address, UInt16 value) {
    kernel_write(address, reinterpret_cast<const void*>(&value), sizeof(value));
}

void Kernel::write32(xnu::Mach::VmAddress address, UInt32 value) {
    kernel_write(address, reinterpret_cast<const void*>(&value), sizeof(value));
}

void Kernel::write64(xnu::Mach::VmAddress address, UInt64 value) {
    kernel_write(address, reinterpret_cast<const void*>(&value), sizeof(value));
}

char* Kernel::readString(xnu::Mach::VmAddress address) {
    return nullptr;
}

Symbol* Kernel::getSymbolByName(char* symbolname) {
    Symbol* symbol = nullptr;

    symbol = macho->getSymbolByName(symbolname);

    if (kernelDebugKit) {
        if (!symbol) {
            symbol = kernelDebugKit->getKDKSymbolByName(symbolname);
        }
    }

    return symbol;
}

Symbol* Kernel::getSymbolByAddress(xnu::Mach::VmAddress address) {
    Symbol* symbol = nullptr;

    symbol = macho->getSymbolByAddress(address);

    if (kernelDebugKit) {
        if (!symbol) {
            symbol = kernelDebugKit->getKDKSymbolByAddress(address);
        }
    }

    return symbol;
}

xnu::Mach::VmAddress Kernel::getSymbolAddressByName(char* symbolname) {
    xnu::Mach::VmAddress symbolAddress = 0;

    symbolAddress = macho->getSymbolAddressByName(symbolname);

    if (kernelDebugKit) {
        if (!symbolAddress) {
            symbolAddress = kernelDebugKit->getKDKSymbolAddressByName(symbolname);
        }
    }

    return symbolAddress;
}