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

#include "dwarf.h"
#include "kernel.h"
#include "kernel_macho.h"
#include "macho.h"

#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>

#include <libkern/libkern.h>

#include <kern/task.h>

#include "strparse.h"

using namespace xnu;

struct macOSVersionMap {
    char* darwinVersion;
    char* xnuVersion;
    char* buildVersion;
    char* versionNumber;
};

struct macOSVersionMap macOSVersions[] = {
    {"24.1.0", "xnu-11215.41.3~13", "24B2091", "15.1.1"},
    {"24.1.0", "xnu-11215.41.3~13", "24B91", "15.1.1"},
    {"24.1.0", "xnu-11215.41.3~3", "24B2083", "15.1"},
    {"24.1.0", "xnu-11215.41.3~2", "24B83", "15.1"},
    {"24.0.0", "xnu-11215.1.12~1", "24A348", "15.0.1"},
    {"24.0.0", "xnu-11215.1.10~2", "24A335", "15.0"},
    {"23.6.0", "xnu-10063.141.1.701.1~1", "23H311", "14.7.2"},
    {"23.6.0", "xnu-10063.141.1.701.1~1", "23H222", "14.7.1"},
    {"23.6.0", "xnu-10063.141.1.700.5~1", "23H124", "14.7"},
    {"23.6.0", "xnu-10063.141.1~2", "23G93", "14.6.1"},
    {"23.6.0", "xnu-10063.141.1~2", "23G80", "14.6"},
    {"23.5.0", "xnu-10063.121.3~5", "23F79", "14.5"},
    {"23.4.0", "xnu-10063.101.17~1", "23E224", "14.4.1"},
    {"23.4.0", "xnu-10063.101.15~2", "23E214", "14.4"},
    {"23.3.0", "xnu-10002.81.5~7", "23D60", "14.3.1"},
    {"23.3.0", "xnu-10002.81.5~7", "23D56", "14.3"},
    {"23.2.0", "xnu-10002.61.3~2", "23C64", "14.2"},
    {"23.1.0", "xnu-10002.41.9~6", "23B92", "14.1.2"},
    {"23.1.0", "xnu-10002.41.9~6", "23B81", "14.1.1"},
    {"23.1.0", "xnu-10002.41.9~6", "23B74", "14.1"},
    {"23.0.0", "xnu-10002.1.13~1", "23A344", "14.0"},
    {"22.6.0", "xnu-8796.141.3.700.8~1", "22G120", "13.6"},
    {"22.6.0", "xnu-8796.141.3~6", "22G91", "13.5.2"},
    {"22.6.0", "xnu-8796.141.3~6", "22G90", "13.5.1"},
    {"22.6.0", "xnu-8796.141.3~6", "22G74", "13.5"},
    {"22.5.0", "xnu-8796.121.3~7", "22F82", "13.4.1"},
    {"22.5.0", "xnu-8796.121.2~5", "22F66", "13.4"},
    {"22.4.0", "xnu-8796.101.5~3", "22E261", "13.3.1"},
    {"22.4.0", "xnu-8796.101.5~3", "22E252", "13.3"},
    {"22.3.0", "xnu-8792.81.3~2", "22D68", "13.2.1"},
    {"22.3.0", "xnu-8792.81.2~2", "22D49", "13.2"},
    {"22.2.0", "xnu-8792.61.2~4", "22C65", "13.1"},
    {"22.1.0", "xnu-8792.41.9~2", "22A400", "13.0.1"},
    {"22.1.0", "xnu-8792.41.9~2", "22A380", "13.0"},
    {"21.6.0", "xnu-8020.140.49~2", "21G115", "12.6"},
    {"21.6.0", "xnu-8020.141.5~2", "21G83", "12.5.1"},
    {"21.6.0", "xnu-8020.140.41~1", "21G72", "12.5"},
    {"21.5.0", "xnu-8020.121.3~4", "2179", "12.4"},
    {"21.4.0", "xnu-8020.101.4~15", "21E258", "12.3.1"},
    {"21.3.0", "xnu-8019.80.24~20", "21D62", "12.2.1"},
    {"21.3.0", "xnu-8019.80.24~20", "21D49", "12.2"},
    {"21.2.0", "xnu-8019.61.5~1", "21C52", "12.1"},
    {"21.1.0", "xnu-8019.41.5~1", "21A559", "12.0.1"},
    {"21.0.1", "xnu-8019.30.61~4", "21A344", "12.0"},
    {"20.6.0", "xnu-7195.141.8~1", "20G165", "11.6.1"},
    {"20.6.0", "xnu-7195.141.6~3", "20G161", "11.6"},
    {"20.6.0", "xnu-7195.141.2~5", "20G143", "11.5.2"},
    {"20.6.0", "xnu-7195.141.2~5", "20G125", "11.5.1"},
    {"20.6.0", "xnu-7195.141.2~5", "20G121", "11.5"},
    {"20.5.0", "xnu-7195.121.3~9", "20F71", "11.4"},
    {"20.4.0", "xnu-7195.101.2~1", "20E241", "11.3.1"},
    {"20.4.0", "xnu-7195.101.1~3", "20E232", "11.3"},
    {"20.3.0", "xnu-7195.81.3~1", "20D91", "11.2.3"},
    {"20.3.0", "xnu-7195.81.3~1", "20D80", "11.2.2"},
    {"20.3.0", "xnu-7195.81.3~1", "20D74", "11.2.1"},
    {"20.3.0", "xnu-7195.81.3~1", "20D64", "11.2"},
    {"20.2.0", "xnu-7195.60.75~1", "20C69", "11.1"},
    {"20.1.0", "xnu-7195.50.7~2", "20B29", "11.0.1"},
    {"20.1.0", "xnu-7195.41.8~9", "20A2411", "11.0"},
};

char* GetBuildVersionFromOSVersion(char *osversion);
char* GetKDKWithBuildVersion(const char* basePath, const char* buildVersion);

kern_return_t ReadKDKKernelFromPath(xnu::Kernel* kernel, const char* path, char** out_buffer);

KDKKernelMachO::KDKKernelMachO(xnu::Kernel* kern, const char* path)
    : path(path)

{
    kernel = kern;
    aslr_slide = kernel->GetSlide();
    ReadKDKKernelFromPath(kernel, path, &buffer);
    if (!buffer) {
        panic("DarwinKit::KDK could not be read from disk at path %s\n", path);
    }
    header = reinterpret_cast<struct mach_header_64*>(buffer);
    symbolTable = new SymbolTable();
    base = GetBase();
    ParseMachO();
}

xnu::mach::VmAddress KDKKernelMachO::GetBase() {
    struct mach_header_64* hdr = header;
    UInt8* cmds = reinterpret_cast<UInt8*>(hdr) + sizeof(struct mach_header_64);
    UInt8* q = cmds;
    xnu::mach::VmAddress base = UINT64_MAX;
    for (int i = 0; i < hdr->ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* segment = reinterpret_cast<struct segment_command_64*>(q);
            UInt64 vmaddr = segment->vmaddr;
            UInt64 vmsize = segment->vmsize;
            UInt64 fileoffset = segment->fileoff;
            UInt64 filesize = segment->filesize;
            if (vmaddr < base) {
                base = vmaddr;
            }
        }
        q = q + load_cmd->cmdsize;
    }
    if (base == UINT64_MAX) {
        return 0;
    }
    return base;
}

void KDKKernelMachO::ParseSymbolTable(xnu::macho::Nlist64* symtab, UInt32 nsyms, char* strtab,
                                      Size strsize) {
    for (int i = 0; i < nsyms; i++) {
        Symbol* symbol;
        xnu::macho::Nlist64* nl = &symtab[i];
        char* name;
        xnu::mach::VmAddress address;
        name = &strtab[nl->n_strx];
        address = nl->n_value + kernel->GetSlide();
        // Adds the kernel slide so that the address is correct
        symbol =
            new Symbol(this, nl->n_type & N_TYPE, name, address, AddressToOffset(address),
                       SegmentForAddress(address), SectionForAddress(address));
        symbolTable->AddSymbol(symbol);
    }
    DARWIN_KIT_LOG("DarwinKit::KDKKernelMachO::%u syms!\n", nsyms);
}

char* GetBuildVersionFromOSVersion(char *osversion) {
    char kdkPath[1024];
    Size numEntries = sizeof(macOSVersions) / sizeof(macOSVersions[0]);
    for (int i = 0; i < numEntries; i++) {
        struct macOSVersionMap map = macOSVersions[i];
        if (strstr(osversion, map.xnuVersion) == 0) {
            return strdup(map.buildVersion);
        }
    }
    return nullptr;
}

char* GetKDKWithBuildVersion(const char* basePath, const char* buildVersion) {
    char kdkPath[1024];
    Size numEntries = sizeof(macOSVersions) / sizeof(macOSVersions[0]);
    for (int i = 0; i < numEntries; i++) {
        struct macOSVersionMap map = macOSVersions[i];
        if (strcmp(buildVersion, map.buildVersion) == 0) {
            snprintf(kdkPath, 1024, "%s/KDK_%s_%s.kdk", basePath, map.versionNumber,
                     map.buildVersion);
            return strdup(kdkPath);
        }
    }
    return nullptr;
}

kern_return_t ReadKDKKernelFromPath(xnu::Kernel* kernel, const char* path, char** out_buffer) {
    errno_t error = 0;
    vnode_t vnode = NULLVP;
    error = vnode_open(path, O_RDONLY, 0, 0, &vnode, vfs_context_current());
    if (error != 0) {
        DARWIN_KIT_LOG("Error opening file: %d\n", error);
        *out_buffer = nullptr;
        return KERN_FAILURE;
    }
    struct vnode_attr vattr;
    VATTR_INIT(&vattr);
    VATTR_WANTED(&vattr, va_data_size);
    error = vnode_getattr(vnode, &vattr, vfs_context_current());
    if (error != 0) {
        vnode_close(vnode, FREAD, vfs_context_current());
        *out_buffer = nullptr;
        DARWIN_KIT_LOG("DarwinKit:: KDK error getting file size: %d\n", error);
        return KERN_FAILURE;
    }
    Offset fileSize = vattr.va_data_size;
    char* buffer = (char*)IOMalloc((Size)fileSize);
    if (buffer == nullptr) {
        vnode_close(vnode, FREAD, vfs_context_current());
        *out_buffer = nullptr;
        DARWIN_KIT_LOG("DarwinKit:: KDK Memory allocation failed\n");
        return KERN_FAILURE;
    }
    Size bytesRead = 0;
    error = vn_rdwr(UIO_READ, vnode, buffer, (int)fileSize, 0, UIO_SYSSPACE, 0, kauth_cred_get(),
                    nullptr, kernel->GetProc());
    if (error != 0) {
        vnode_close(vnode, FREAD, vfs_context_current());
        *out_buffer = nullptr;
        DARWIN_KIT_LOG("DarwinKit:: KDK Error reading file: %d\n", error);
        IOFree(buffer, (Size)fileSize);
        return KERN_FAILURE;
    }
    vnode_close(vnode, FREAD, vfs_context_current());
    *out_buffer = buffer;
    return KERN_SUCCESS;
}

char* GetKDKKernelNameFromType(KDKKernelType type) {
    switch (type) {
    case KdkKernelTypeRelease:
        return "kernel";
    case KdkKernelTypeReleaseT6000:
        return "kernel.release.t6000";
    case KdkKernelTypeReleaseT6020:
        return "kernel.release.t6020";
    case KdkKernelTypeReleaseT8103:
        return "kernel.release.t8103";
    case KdkKernelTypeReleaseT8112:
        return "kernel.release.t8112";
    case KdkKernelTypeReleaseVmApple:
        return "kernel.release.vmapple";
    case KdkKernelTypeDevelopment:
        return "kernel.development";
    case KdkKernelTypeDevelopmentT6000:
        return "kernel.development.t6000";
    case KdkKernelTypeDevelopmentT6020:
        return "kernel.development.t6020";
    case KdkKernelTypeDevelopmentT8103:
        return "kernel.development.t8103";
    case KdkKernelTypeDevelopmentT8112:
        return "kernel.development.t8112";
    case KdkKernelTypeDevelopmentVmApple:
        return "kernel.development.vmapple";
    case KdkKernelTypeKasan:
        return "kernel.kasan";
    case KdkKernelTypeKasanT6000:
        return "kernel.kasan.t6000";
    case KdkKernelTypeKasanT6020:
        return "kernel.kasan.t6020";
    case KdkKernelTypeKasanT8103:
        return "kernel.kasan.t8103";
    case KdkKernelTypeKasanT8112:
        return "kernel.kasan.t8112";
    case KdkKernelTypeKasanVmApple:
        return "kernel.kasan.vmapple";
    default:
        return "";
    }
    return nullptr;
}

void KDK::GetKDKPathFromBuildInfo(char* buildVersion, char* outPath) {
    char* KDK = GetKDKWithBuildVersion("/Library/Developer/KDKs", buildVersion);
    if (outPath) {
        if (KDK) {
            strlcpy(outPath, KDK, KDK_PATH_SIZE);

            delete KDK;
        } else {
            *outPath = '\0';
        }
    }
}

void KDK::GetKDKKernelFromPath(char* path, char* kernelVersion, KDKKernelType* outType,
                               char* outKernelPath) {
    KDKKernelType type = KdkKernelTypeNone;
    if (strstr(kernelVersion, "RELEASE")) {
        if (strstr(kernelVersion, "T6000")) {
            type = KdkKernelTypeReleaseT6000;
        } else if (strstr(kernelVersion, "T6020")) {
            type = KdkKernelTypeReleaseT6020;
        } else if (strstr(kernelVersion, "T8103")) {
            type = KdkKernelTypeReleaseT8103;
        } else if (strstr(kernelVersion, "T8112")) {
            type = KdkKernelTypeReleaseT8112;
        } else if (strstr(kernelVersion, "VMAPPLE")) {
            type = KdkKernelTypeReleaseVmApple;
        } else {
            type = KdkKernelTypeRelease;
        }
    }
    if (strstr(kernelVersion, "DEVELOPMENT")) {
        if (strstr(kernelVersion, "T6000")) {
            type = KdkKernelTypeDevelopmentT6000;
        } else if (strstr(kernelVersion, "T6020")) {
            type = KdkKernelTypeDevelopmentT6020;
        } else if (strstr(kernelVersion, "T8103")) {
            type = KdkKernelTypeDevelopmentT8103;
        } else if (strstr(kernelVersion, "T8112")) {
            type = KdkKernelTypeDevelopmentT8112;
        } else if (strstr(kernelVersion, "VMAPPLE")) {
            type = KdkKernelTypeDevelopmentVmApple;
        } else {
            type = KdkKernelTypeDevelopment;
        }
    }
    if (strstr(kernelVersion, "KASAN")) {
        if (strstr(kernelVersion, "T6000")) {
            type = KdkKernelTypeKasanT6000;
        } else if (strstr(kernelVersion, "T6020")) {
            type = KdkKernelTypeKasanT6020;
        } else if (strstr(kernelVersion, "T8103")) {
            type = KdkKernelTypeKasanT8103;
        } else if (strstr(kernelVersion, "T8112")) {
            type = KdkKernelTypeKasanT8112;
        } else if (strstr(kernelVersion, "VMAPPLE")) {
            type = KdkKernelTypeKasanVmApple;
        } else {
            type = KdkKernelTypeKasan;
        }
    }
    if (type == KdkKernelTypeNone) {
        *outType = KdkKernelTypeNone;
        *outKernelPath = '\0';

    } else {
        *outType = type;
        snprintf(outKernelPath, KDK_PATH_SIZE, "%s/System/Library/Kernels/%s", path,
                 GetKDKKernelNameFromType(type));
    }
}

KDK* KDK::KDKFromBuildInfo(xnu::Kernel* kernel, char* buildVersion, char* kernelVersion) {
    return new KDK(kernel, KDK::KDKInfoFromBuildInfo(kernel, buildVersion, kernelVersion));
}

KDKInfo* KDK::KDKInfoFromBuildInfo(xnu::Kernel* kernel, char* buildVersion, char* kernelVersion) {
    struct KDKInfo* kdkInfo;
    if (!buildVersion || !kernelVersion) {
        if (!buildVersion)
            DARWIN_KIT_LOG("DarwinKit::macOS Build Version not found!");

        if (!kernelVersion)
            DARWIN_KIT_LOG("DarwinKit::macOS Kernel Version not found!");

        return nullptr;
    }
    kdkInfo = new KDKInfo;
    KDK::GetKDKPathFromBuildInfo(buildVersion, kdkInfo->path);
    KDK::GetKDKKernelFromPath(kdkInfo->path, kernelVersion, &kdkInfo->type, kdkInfo->kernelPath);
    if (kdkInfo->path[0] == '\0' || kdkInfo->type == KdkKernelTypeNone ||
        kdkInfo->kernelPath[0] == '\0') {
        delete kdkInfo;
        DARWIN_KIT_LOG("DarwinKit::Failed to find KDK with buildVersion %s and kernelVersion %s",
                   buildVersion, kernelVersion);
        return nullptr;
    }
    kdkInfo->kernelName = GetKDKKernelNameFromType(kdkInfo->type);
    snprintf(kdkInfo->kernelDebugSymbolsPath, KDK_PATH_SIZE,
             "%s/System/Library/Kernels/%s.dSYM/Contents/Resources/DWARF/%s", kdkInfo->path,
             kdkInfo->kernelName, kdkInfo->kernelName);
    return kdkInfo;
}

KDK::KDK(xnu::Kernel* kernel, struct KDKInfo* kdkInfo)
    : kernel(kernel), kdkInfo(kdkInfo), type(kdkInfo->type), path(kdkInfo->path),
      kernelWithDebugSymbols(
          dynamic_cast<KernelMachO*>(new KDKKernelMachO(kernel, kdkInfo->kernelDebugSymbolsPath))) {

}

xnu::mach::VmAddress KDK::GetKDKSymbolAddressByName(char* sym) {
    return kernelWithDebugSymbols->GetSymbolAddressByName(sym);
}

Symbol* KDK::GetKDKSymbolByName(char* symname) {
    return kernelWithDebugSymbols->GetSymbolByName(symname);
}

Symbol* KDK::GetKDKSymbolByAddress(xnu::mach::VmAddress address) {
    return kernelWithDebugSymbols->GetSymbolByAddress(address);
}

char* KDK::FindString(char* s) {}

template <typename T>
std::vector<Xref<T>*> KDK::GetExternalReferences(xnu::mach::VmAddress addr) {}

template <typename T>
std::vector<Xref<T>*> KDK::GetStringReferences(xnu::mach::VmAddress addr) {}

template <typename T>
std::vector<Xref<T>*> KDK::GetStringReferences(char* s) {}

void KDK::ParseDebugInformation() {}