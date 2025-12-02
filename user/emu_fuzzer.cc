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

#include "fuzzer.h"
#include "hypervisor.h"
#include "loader.h"
#include "log.h"

extern "C" {
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <mach-o.h>
};

namespace fuzzer {

Harness::Harness(xnu::Kernel* kernel)
    : fuzzBinary(new FuzzBinary),
      kdkInfo(xnu::KDK::KDKInfoFromBuildInfo(kernel, xnu::GetOSBuildVersion(),
                                             xnu::GetKernelVersion(), true)) {
    LoadKernel(
        "/Users/ilhanraja/Downloads/Files/Code/projects/MacRootKit/kernelcache.release.vma2.dec",
        0);
    // AddDebugSymbolsFromKernel(kdkInfo->kernelDebugSymbolsPath);

    loader = new fuzzer::Loader(this, fuzzBinary);

    StartKernel();
}

Harness::Harness(const char* binary) : fuzzBinary(new FuzzBinary) {}

Harness::Harness(const char* binary, const char* mapFile) : fuzzBinary(new FuzzBinary) {}

template <int CpuType>
char* Harness::GetMachOFromFatHeader(char* file_data) {
    struct fat_header* header = reinterpret_cast<struct fat_header*>(file_data);
    swap_fat_header(header, NXHostByteOrder());
    struct fat_arch* arch =
        reinterpret_cast<struct fat_arch*>(file_data + sizeof(struct fat_header));
    swap_fat_arch(arch, header->nfat_arch, NXHostByteOrder());
    for (int i = 0; i < header->nfat_arch; i++) {
        UInt32 cputype;
        UInt32 cpusubtype;
        UInt32 offset;
        cputype = arch->cputype;
        cpusubtype = arch->cpusubtype;
        offset = arch->offset;
#ifdef __arm64__
        static_assert(CpuType == CPU_TYPE_ARM64);

#elif __x86_64__
        static_assert(CpuType == CPU_TYPE_X86_64);

#endif
        if constexpr (CpuType == CPU_TYPE_ARM64) {
            if (cputype == CPU_TYPE_ARM64) {
                return file_data + offset;
            }
        }
        if constexpr (CpuType == CPU_TYPE_X86_64) {
            if (cputype == CPU_TYPE_X86_64) {
                return file_data + offset;
            }
        }
        arch++;
    }
    return nullptr;
}

void Harness::AddDebugSymbolsFromKernel(const char* kernelPath) {
    KernelMachO* macho = GetBinary<KernelMachO*>();
    xnu::mach::VmAddress loadAddress = reinterpret_cast<xnu::mach::VmAddress>(fuzzBinary->base);
    xnu::mach::VmAddress oldLoadAddress =
        reinterpret_cast<xnu::mach::VmAddress>(fuzzBinary->originalBase);
    char* file_data;
    int fd = open(kernelPath, O_RDONLY);
    if (fd == -1) {
        DARWIN_KIT_LOG("Error opening kernel Mach-O %s", kernelPath);

        return;
    }
    Offset file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    file_data = (char*)malloc(file_size);
    ssize_t bytes_read;
    bytes_read = read(fd, file_data, file_size);
    if (bytes_read != file_size) {
        DARWIN_KIT_LOG("Read file failed!\n");
        close(fd);
        return;
    }
    size_t total_size = 0;
    struct mach_header_64* header = reinterpret_cast<struct mach_header_64*>(file_data);
    UInt8* q = reinterpret_cast<UInt8*>(file_data + sizeof(struct mach_header_64));
    for (int i = 0; i < header->ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (cmdtype == LC_SYMTAB) {
            struct symtab_command* symtab_command =
                reinterpret_cast<struct symtab_command*>(load_cmd);
            struct nlist_64* symtab =
                reinterpret_cast<struct nlist_64*>(file_data + symtab_command->symoff);
            UInt32 nsyms = symtab_command->nsyms;
            char* strtab = reinterpret_cast<char*>(file_data + symtab_command->stroff);
            UInt32 strsize = symtab_command->strsize;
            if (nsyms > 0) {
                SymbolTable* symbolTable = macho->GetSymbolTable();
                for (int i = 0; i < nsyms; i++) {
                    Symbol* symbol;
                    struct nlist_64* nl = &symtab[i];
                    char* name;
                    xnu::mach::VmAddress address;
                    name = &strtab[nl->n_strx];
                    address = nl->n_value;
#ifdef __EXECUTE_IN_SAME_PROCESS__

                    address = (nl->n_value - oldLoadAddress) + loadAddress;

                    nl->n_value = address;

#endif
                    symbol = new Symbol(
                        macho, nl->n_type & N_TYPE, name, address, macho->AddressToOffset(address),
                        macho->SegmentForAddress(address), macho->SectionForAddress(address));
                    symbolTable->ReplaceSymbol(symbol);
                    printf("Symbol %s = 0x%llx\n", name, address);
                }
            }
        }
        q += cmdsize;
    }
    free(file_data);
}

template <typename Binary>
    requires AnyBinaryFormat<Binary>
void Harness::GetMappingInfo(char* file_data, Size* size, xnu::mach::VmAddress* load_addr) {
    if constexpr (std::is_same_v<Binary, MachO>) {
        struct mach_header_64* header = reinterpret_cast<struct mach_header_64*>(file_data);
        UInt8* q = reinterpret_cast<UInt8*>(file_data + sizeof(struct mach_header_64));
        for (int i = 0; i < header->ncmds; i++) {
            struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
            UInt32 cmdtype = load_cmd->cmd;
            UInt32 cmdsize = load_cmd->cmdsize;
            if (cmdtype == LC_SEGMENT_64) {
                struct segment_command_64* segment_command =
                    reinterpret_cast<struct segment_command_64*>(load_cmd);
                xnu::mach::VmAddress vmaddr = segment_command->vmaddr;
                if (vmaddr < *load_addr && strcmp(segment_command->segname, "__TEXT") == 0) {
                    *load_addr = vmaddr;
                }
                *size += segment_command->vmsize;
            }
            q += cmdsize;
        }
    }

    if constexpr (std::is_same_v<Binary, RawBinary>) {
    }
}

void Harness::UpdateSymbolTableForMappedMachO(char* file_data, xnu::mach::VmAddress newLoadAddress,
                                              xnu::mach::VmAddress oldLoadAddress) {

#ifdef __EXECUTE_IN_SAME_PROCESS__

    struct mach_header_64* header = reinterpret_cast<struct mach_header_64*>(file_data);
    UInt8* q = reinterpret_cast<UInt8*>(file_data + sizeof(struct mach_header_64));
    for (int i = 0; i < header->ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (cmdtype == LC_SYMTAB) {
            struct symtab_command* symtab_command =
                reinterpret_cast<struct symtab_command*>(load_cmd);
            struct nlist_64* symtab =
                reinterpret_cast<struct nlist_64*>(file_data + symtab_command->symoff);
            UInt32 nsyms = symtab_command->nsyms;
            char* strtab = reinterpret_cast<char*>(file_data + symtab_command->stroff);
            UInt32 strsize = symtab_command->strsize;
            if (nsyms > 0) {
                for (int i = 0; i < nsyms; i++) {
                    struct nlist_64* nl = &symtab[i];
                    char* name;
                    xnu::mach::VmAddress address;
                    name = &strtab[nl->n_strx];
                    address = nl->n_value;
                    printf("Symbol %s = 0x%llx\n", name, address);
                    nl->n_value = address;
                }
            }
        }
        q += cmdsize;
    };

#endif
}

void Harness::UpdateSegmentLoadCommandsForNewLoadAddress(char* file_data,
                                                         xnu::mach::VmAddress newLoadAddress,
                                                         xnu::mach::VmAddress oldLoadAddress) {
    struct mach_header_64* header = reinterpret_cast<struct mach_header_64*>(file_data);
    UInt8* q = reinterpret_cast<UInt8*>(file_data + sizeof(struct mach_header_64));
    for (int i = 0; i < header->ncmds; i++) {
        struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
        UInt32 cmdtype = load_cmd->cmd;
        UInt32 cmdsize = load_cmd->cmdsize;
        if (cmdtype == LC_SEGMENT_64) {
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_cmd);
            xnu::mach::VmAddress vmaddr = segment_command->vmaddr;
#ifdef __EXECUTE_IN_SAME_PROCESS__
            xnu::mach::VmAddress segment_adjusted_address =
                segment_command->fileoff + newLoadAddress;
            segment_command->vmaddr = segment_adjusted_address;

#endif
            printf("LC_SEGMENT_64 at 0x%llx - %s 0x%08llx to 0x%08llx \n", segment_command->fileoff,
                   segment_command->segname, segment_command->vmaddr,
                   segment_command->vmaddr + segment_command->vmsize);
            UInt8* sects = q + sizeof(struct segment_command_64);
            for (int j = 0; j < segment_command->nsects; j++) {
                struct section_64* section = reinterpret_cast<struct section_64*>(sects);
                xnu::mach::VmAddress sect_addr = section->addr;
                xnu::mach::VmAddress sect_adjusted_address =
                    (sect_addr - vmaddr) + segment_command->fileoff + newLoadAddress;
#ifdef __EXECUTE_IN_SAME_PROCESS__
                section->addr = sect_adjusted_address;
                section->offset = (sect_addr - vmaddr) + segment_command->fileoff;

#endif
                printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n", j, section->addr,
                       section->addr + section->size, section->sectname);
                memcpy((void*)sect_adjusted_address, file_data + section->offset, section->size);
                sects += sizeof(struct section_64);
            };
        }
        q += cmdsize;
    }
}

template <typename Binary, typename Seg>
    requires AnyBinaryFormat<Binary>
bool Harness::MapSegments(char* file_data, char* mapFile) {
    if constexpr (std::is_same_v<Binary, MachO> || std::is_same_v<Binary, KernelMachO>) {
        struct mach_header_64* header = reinterpret_cast<struct mach_header_64*>(file_data);
        UInt8* q = reinterpret_cast<UInt8*>(file_data + sizeof(struct mach_header_64));
        for (int i = 0; i < header->ncmds; i++) {
            struct load_command* load_cmd = reinterpret_cast<struct load_command*>(q);
            UInt32 cmdtype = load_cmd->cmd;
            UInt32 cmdsize = load_cmd->cmdsize;
            if (cmdtype == LC_SEGMENT_64) {
                struct segment_command_64* segment_command =
                    reinterpret_cast<struct segment_command_64*>(load_cmd);
                printf("LC_SEGMENT_64 at 0x%llx - %s 0x%08llx to 0x%08llx %u\n",
                       segment_command->fileoff, segment_command->segname, segment_command->vmaddr,
                       segment_command->vmaddr + segment_command->vmsize, segment_command->maxprot);
#ifdef __EXECUTE_IN_SAME_PROCESS__
                if (mprotect((void*)segment_command->vmaddr, segment_command->vmsize,
                             PROT_READ | PROT_WRITE) == -1) {
                    printf("mprotect(R/W) failed!\n");
                    return false;
                }
                memcpy((void*)segment_command->vmaddr, file_data + segment_command->fileoff,
                       segment_command->filesize);
                UInt8* sects = q + sizeof(struct segment_command_64);
                for (int j = 0; j < segment_command->nsects; j++) {
                    struct section_64* section = reinterpret_cast<struct section_64*>(sects);
                    xnu::mach::VmAddress sect_addr = section->addr;
                    printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n", j, section->addr,
                           section->addr + section->size, section->sectname);
                    memcpy((void*)section->addr, file_data + section->offset, section->size);
                    sects += sizeof(struct section_64);
                };
                if (mprotect((void*)segment_command->vmaddr, segment_command->vmsize,
                             segment_command->maxprot) == -1) {
                    printf("mprotect(maxprot) failed!\n");
                    return false;
                }
#endif
            }
            q += cmdsize;
        }
        return true;
    }
    if constexpr (std::is_same_v<Binary, RawBinary>) {
    }
    return false;
}

template <typename Binary, typename Seg>
    requires AnyBinaryFormat<Binary>
bool Harness::UnmapSegments() {}

void Harness::GetEntryPointFromKC(xnu::mach::VmAddress kc, xnu::mach::VmAddress* entryPoint) {
    struct mach_header_64* mh = reinterpret_cast<struct mach_header_64*>(kc);
    UInt8* q = reinterpret_cast<UInt8*>(kc) + sizeof(struct mach_header_64);
    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command = reinterpret_cast<struct load_command*>(q);
        if (load_command->cmd == LC_UNIXTHREAD) {
            struct unixthread_command* thread_command =
                reinterpret_cast<struct unixthread_command*>(load_command);
            DARWIN_KIT_LOG("DarwinKit::LC_UNIXTHREAD\n");
#ifdef __arm64__
            if (thread_command->flavor == ARM_THREAD_STATE64) {
                struct arm_thread_state64 {
                    __uint64_t x[29]; /* General purpose registers x0-x28 */
                    __uint64_t fp;    /* Frame pointer x29 */
                    __uint64_t lr;    /* Link register x30 */
                    __uint64_t sp;    /* Stack pointer x31 */
                    __uint64_t pc;    /* Program counter */
                    __uint32_t cpsr;  /* Current program status register */
                    __uint32_t flags; /* Flags describing structure format */
                }* state;

                state = (struct arm_thread_state64*)(thread_command + 1);

                DARWIN_KIT_LOG("DarwinKit::\tstate->pc = 0x%llx\n", state->pc);

                *entryPoint = state->pc;
            }
#endif
        }
        q += load_command->cmdsize;
    }
}

void Harness::GetKernelFromKC(xnu::mach::VmAddress kc, xnu::mach::VmAddress* kernelBase,
                              Offset* kernelFileOffset) {
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
                *kernelBase = fileset_entry_command->vmaddr;
                *kernelFileOffset = fileset_entry_command->fileoff;
                DARWIN_KIT_LOG("DarwinKit::Kernel found in kernelcache 0x%llx!\n", *kernelBase);
                return;
            }
        }
        q += load_command->cmdsize;
    }
}

bool Harness::LoadKernelCache(const char* kernelPath, xnu::mach::VmAddress* kernelCache,
                              Size* kernelCacheSize, Offset* loadOffset,
                              xnu::mach::VmAddress* loadAddress) {
    bool success;
    char* file_data;
    int fd = open(kernelPath, O_RDONLY);
    if (fd == -1) {
        printf("Error opening kernelcache %s", kernelPath);
        return false;
    }
    Offset file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    file_data = (char*)malloc(file_size);
    ssize_t bytes_read;
    bytes_read = read(fd, file_data, file_size);
    if (bytes_read != file_size) {
        printf("Read file failed!\n");
        close(fd);
        return false;
    }
    GetKernelFromKC((xnu::mach::VmAddress)file_data, loadAddress, loadOffset);
    Size size = 0;
    GetMappingInfo<MachO>((char*)file_data + *loadOffset, &size, loadAddress);
    *kernelCache = (xnu::mach::VmAddress)file_data;
    *kernelCacheSize = file_size;
    free(file_data);
    close(fd);
    return true;
fail:
    close(fd);
    printf("Load Kernel MachO failed!\n");
    return false;
}

template <typename Binary>
    requires(AnyBinaryFormat<Binary> && !MachOFormat<Binary>)
void Harness::LoadBinary(const char* path, const char* mapFile) {}

void Harness::StartKernel() {
    xnu::KernelMachO* kernelMachO = fuzzBinary->GetBinary<xnu::KernelMachO*>();
    xnu::mach::VmAddress entryPoint;
    GetEntryPointFromKC((xnu::mach::VmAddress)fuzzBinary->base, &entryPoint);
#ifdef __arm64__
    hypervisor = new darwin::vm::Hypervisor(this, (xnu::mach::VmAddress)fuzzBinary->originalBase,
                                            (xnu::mach::VmAddress)fuzzBinary->base,
                                            fuzzBinary->size, entryPoint);
#endif
}

void Harness::CallFunctionInKernel(const char* funcname) {
    printf("DarwinKit::Calling function %s in XNU kernel at address = 0x%llx\n", funcname);
#ifdef __arm64__
    // __asm__ volatile("PACIZA %[pac]" : [pac] "+rm" (start_kernel));
#endif
    typedef void (*XnuKernelEntryPoint)();
    // XnuKernelEntryPoint start = reinterpret_cast<XnuKernelEntryPoint>(start_kernel);
    // (void)(*start)();
}

void Harness::LoadKernel(const char* kernelPath, Offset slide) {
    xnu::mach::VmAddress kernelCache = 0;
    Size kernelCacheSize = 0;
    Offset loadOffset = 0;
    xnu::mach::VmAddress loadAddress = 0;
    if (LoadKernelCache(kernelPath, &kernelCache, &kernelCacheSize, &loadOffset, &loadAddress)) {
        fuzzBinary->path = kernelPath;
        fuzzBinary->base = reinterpret_cast<void*>(kernelCache);
        fuzzBinary->originalBase = reinterpret_cast<void*>(loadAddress);
        fuzzBinary->size = kernelCacheSize;
        fuzzBinary->binary = FuzzBinary::MakeBinary<KernelMachO*>(
            new KernelCacheMachO(kernelCache, (Offset)kernelCache + loadOffset));
    } else {
        fprintf(stderr, "Failed to load kernelcache!\n");
        exit(-1);
    }
}

void Harness::LoadKernelExtension(const char* path) {
    loader->LoadModuleFromKext(path);
}

template <typename Binary>
    requires AnyBinaryFormat<Binary>
void Harness::PopulateSymbolsFromMapFile(const char* mapFile) {}

template <typename T>
void Harness::Mutate(T data)
    requires FuzzableType<T>
{
    if constexpr (ScalarType<T>) {
    } else {
    }
}

template <typename Func, typename... Args, typename Binary, typename Sym>
    requires requires(Binary bin, Sym sym) {
        std::is_invocable_v<Func, Args...>;
        sym->GetName();
        sym->GetAddress();
        std::is_same_v<GetSymbolReturnType<Binary>, Sym>;
    }
std::invoke_result_t<Func, Args...> Harness::Execute(const char* name, Func func, Args... args) {}

} // namespace fuzzer