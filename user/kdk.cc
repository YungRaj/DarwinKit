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
#include "kernel_machO.h"
#include "machO.h"

extern "C" {
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <dirent.h>
};

using namespace xnu;

char* findKDKWithBuildVersion(const char* basePath, const char* substring);

kern_return_t ReadKDKKernelFromPath(const char* path, char** out_buffer);

class KDKKernelMachO : public KernelMachO {
public:
    KDKKernelMachO(xnu::Kernel* kernel, const char* path)
        : kernel(kernel), path(path), kernelSlide(kernel->GetSlide()) {
        ReadKDKKernelFromPath(path, &buffer);
        if (!buffer) {
            DARWIN_KIT_LOG("DarwinKit::KDK could not be read from disk at path %s\n", path);
        } else {
            header = reinterpret_cast<struct mach_header_64*>(buffer);
            symbolTable = new SymbolTable();
            base = GetBase();
            ParseMachO();
        }
    }

    xnu::mach::VmAddress GetBase() {
        struct mach_header_64* hdr = header;
        UInt8* cmds = reinterpret_cast<UInt8*>(hdr) + sizeof(struct mach_header_64);
        UInt8* q = cmds;
        xnu::mach::VmAddress base = UINT64_MAX;
        for (int i = 0; i < hdr->ncmds; i++) {
            struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
            UInt32 cmdtype = load_cmd->cmd;
            UInt32 cmdsize = load_cmd->cmdsize;
            if (load_cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment =
                    reinterpret_cast<struct segment_command_64*>(q);
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

    void ParseSymbolTable(struct nlist_64* symtab, UInt32 nsyms, char* strtab, Size strsize) {
        for (int i = 0; i < nsyms; i++) {
            Symbol* symbol;
            struct nlist_64* nl = &symtab[i];
            char* name;
            xnu::mach::VmAddress address;
            name = &strtab[nl->n_strx];
            address = nl->n_value + kernelSlide;
            // Adds the kernel slide so that the address is correct
            symbol =
                new Symbol(this, nl->n_type & N_TYPE, name, address, AddressToOffset(address),
                           SegmentForAddress(address), SectionForAddress(address));
            symbolTable->AddSymbol(symbol);
        }
        DARWIN_KIT_LOG("DarwinKit::KDKKernelMachO::%u syms!\n", nsyms);
    }

private:
    xnu::Kernel* kernel;
    const char* path;
    Offset kernelSlide;
};

char* findKDKWithBuildVersion(const char* basePath, const char* substring) {
    DIR* dir = opendir(basePath);
    if (!dir) {
        DARWIN_KIT_LOG("Error opening directory");
        return nullptr;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strstr(entry->d_name, substring)) {
            char childName[KDK_PATH_SIZE];
            snprintf(childName, KDK_PATH_SIZE, "%s/%s", basePath, entry->d_name);
            DARWIN_KIT_LOG("Found KDK with build version '%s': %s\n", substring, childName);
            closedir(dir);
            return strdup(childName);
        }
    }
    closedir(dir);
    return nullptr;
}

kern_return_t ReadKDKKernelFromPath(const char* path, char** out_buffer) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        DARWIN_KIT_LOG("Error opening file: %s \n", path);
        *out_buffer = nullptr;
        return KERN_FAILURE;
    }
    Size size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char* buffer = (char*)malloc(size);
    Size bytes_read = 0;
    bytes_read = read(fd, buffer, size);
    close(fd);
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

void KDK::GetKDKPathFromBuildInfo(const char* buildVersion, char* outPath) {
    char* KDK = findKDKWithBuildVersion("/Library/Developer/KDKs", buildVersion);
    if (outPath) {
        if (KDK) {
            strlcpy(outPath, KDK, KDK_PATH_SIZE);
            delete KDK;
        } else {
            *outPath = '\0';
        }
    }
}

void KDK::GetKDKKernelFromPath(const char* path, const char* kernelVersion, KDKKernelType* outType,
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

void KDK::GetKDKKernelFromPath(const char* path, const char* kernelVersion, KDKKernelType* outType,
                               char* outKernelPath, bool vm) {
    if (vm) {
        KDKKernelType type = KdkKernelTypeNone;
        if (strstr(kernelVersion, "RELEASE")) {
            type = KdkKernelTypeReleaseVmApple;
        }
        if (strstr(kernelVersion, "DEVELOPMENT")) {
            type = KdkKernelTypeDevelopmentVmApple;
        }
        if (strstr(kernelVersion, "KASAN")) {
            type = KdkKernelTypeKasanVmApple;
        }
        if (type == KdkKernelTypeNone) {
            *outType = KdkKernelTypeNone;
            *outKernelPath = '\0';
        } else {
            *outType = type;

            snprintf(outKernelPath, KDK_PATH_SIZE, "%s/System/Library/Kernels/%s", path,
                     GetKDKKernelNameFromType(type));
        }
        printf("%s\n", outKernelPath);
    } else {
        KDK::GetKDKKernelFromPath(path, kernelVersion, outType, outKernelPath);
    }
}

KDK* KDK::KDKFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                           const char* kernelVersion) {
    return new KDK(kernel, KDK::KDKInfoFromBuildInfo(kernel, buildVersion, kernelVersion));
}

KDKInfo* KDK::KDKInfoFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                                   const char* kernelVersion) {
    struct KDKInfo* kdkInfo;
    if (!buildVersion || !kernelVersion) {
        if (!buildVersion) {
            DARWIN_KIT_LOG("DarwinKit::macOS Build Version not found!");
        }
        if (!kernelVersion) {
            DARWIN_KIT_LOG("DarwinKit::macOS Kernel Version not found!");
        }
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

KDKInfo* KDK::KDKInfoFromBuildInfo(xnu::Kernel* kernel, const char* buildVersion,
                                   const char* kernelVersion, bool vm) {
    struct KDKInfo* kdkInfo;
    if (!buildVersion || !kernelVersion) {
        if (!buildVersion) {
            DARWIN_KIT_LOG("DarwinKit::macOS Build Version not found!");
        }
        if (!kernelVersion) {
            DARWIN_KIT_LOG("DarwinKit::macOS Kernel Version not found!");
        }
        return nullptr;
    }
    kdkInfo = new KDKInfo;
    KDK::GetKDKPathFromBuildInfo(buildVersion, kdkInfo->path);
    KDK::GetKDKKernelFromPath(kdkInfo->path, kernelVersion, &kdkInfo->type, kdkInfo->kernelPath,
                              vm);
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

char* KDK::FindString(char* s) {
    return nullptr;
}

template <typename T>
std::vector<Xref<T>*> KDK::GetExternalReferences(xnu::mach::VmAddress addr) {}

template <typename T>
std::vector<Xref<T>*> KDK::GetStringReferences(xnu::mach::VmAddress addr) {}

template <typename T>
std::vector<Xref<T>*> KDK::GetStringReferences(const char* s) {}

void KDK::ParseDebugInformation() {}