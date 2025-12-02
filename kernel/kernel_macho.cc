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
#include "kernel_macho.h"

#include "darwin_kit.h"
#include "kernel.h"

KernelMachO::KernelMachO(Kernel* kernel)
    : kernel(kernel), kernel_collection(
#ifdef __x86_64__
                          Kernel::FindKernelCollection()
#else
                          0
#endif
                              ),
      kernel_cache(
#ifdef __arm64__
          Kernel::FindKernelCache()
#else
          0
#endif
      ) {
}

Kext* KernelMachO::KextLoadedAt(Kernel* kernel, xnu::mach::VmAddress address) {
    darwin::DarwinKit* darwinkit = kernel->GetDarwinKit();
    return darwinkit->GetKextByAddress(address);
}

Kext* KernelMachO::KextWithIdentifier(Kernel* kernel, char* kextname) {
    darwin::DarwinKit* darwinkit = kernel->GetDarwinKit();
    return darwinkit->GetKextByIdentifier(kextname);
}

void KernelMachO::ParseLinkedit() {
    MachO::ParseLinkedit();
}

bool KernelMachO::ParseLoadCommands() {
    xnu::macho::Header64* mh = GetMachHeader();
    Size file_size;
    size = GetSize();
    file_size = size;

    UInt8* q = reinterpret_cast<UInt8*>(mh) + sizeof(xnu::macho::Header64);
    UInt32 current_offset = sizeof(xnu::macho::Header64);
    for (UInt32 i = 0; i < mh->ncmds; i++) {
        struct load_command* load_command =
            reinterpret_cast<struct load_command*>((*this)[current_offset]);
        UInt32 cmdtype = load_command->cmd;
        UInt32 cmdsize = load_command->cmdsize;
        if (cmdsize > mh->sizeofcmds - ((uintptr_t)load_command - (uintptr_t)(mh + 1))) {
            return false;
        }
        switch (cmdtype) {
        case LC_SEGMENT_64: {
            ;
            struct segment_command_64* segment_command =
                reinterpret_cast<struct segment_command_64*>(load_command);
            UInt32 nsects = segment_command->nsects;
            UInt32 sect_offset = current_offset + sizeof(struct segment_command_64);
            if (segment_command->fileoff > size ||
                segment_command->filesize > size - segment_command->fileoff) {
                return false;
            }
            char buffer1[128];
            char buffer2[128];
            snprintf(buffer1, 128, "0x%08llx", segment_command->vmaddr);
            snprintf(buffer2, 128, "0x%08llx", segment_command->vmaddr + segment_command->vmsize);
            vm_prot_t maxprot = segment_command->maxprot;
            char r[24];
            memcpy(r, ((maxprot & VM_PROT_READ) ? "read" : "-"), 24);
            char w[24];
            memcpy(w, ((maxprot & VM_PROT_WRITE) ? "write" : "-"), 24);
            char x[24];
            memcpy(x, ((maxprot & VM_PROT_EXECUTE) ? "execute" : "-"), 24);
            printf("DarwinKit::LC_SEGMENT_64 at 0x%llx (%s/%s/%s) - %s %s to %s \n",
                   segment_command->fileoff, r, w, x, segment_command->segname, buffer1, buffer2);
            if (!strcmp(segment_command->segname, "__LINKEDIT")) {
                linkedit = reinterpret_cast<UInt8*>(segment_command->vmaddr);
                linkedit_off = segment_command->fileoff;
                linkedit_size = segment_command->filesize;
            }
            int j = 0;
            if (nsects * sizeof(struct section_64) + sizeof(struct segment_command_64) > cmdsize) {
                return false;
            }
            Segment* segment = new Segment(segment_command);
            for (j = 0; j < nsects; j++) {
                struct section_64* section =
                    reinterpret_cast<struct section_64*>((*this)[sect_offset]);
                char buffer1[128];
                char buffer2[128];
                snprintf(buffer1, 128, "0x%08llx", section->addr);
                snprintf(buffer2, 128, "0x%08llx", section->addr + section->size);
                DARWIN_KIT_LOG("DarwinKit::\tSection %d: %s to %s - %s\n", j, buffer1, buffer2,
                               section->sectname);
                if (section->offset > size || section->size > size - section->offset) {
                    return false;
                }
                sect_offset += sizeof(struct section_64);
            }
            segments.push_back(segment);
            break;
        }
        case LC_SYMTAB: {
            ;
            struct symtab_command* symtab_command =
                reinterpret_cast<struct symtab_command*>(load_command);
            xnu::macho::Nlist64* symtab;
            UInt32 nsyms;
            char* strtab;
            UInt32 strsize;
            if (symtab_command->stroff > size || symtab_command->symoff > size ||
                symtab_command->nsyms >
                    (size - symtab_command->symoff) / sizeof(xnu::macho::Nlist64)) {
                return false;
            }
            DARWIN_KIT_LOG("DarwinKit::LC_SYMTAB\n");
            DARWIN_KIT_LOG("DarwinKit::\tSymbol Table is at offset 0x%x (%u) with %u entries \n",
                           symtab_command->symoff, symtab_command->symoff, symtab_command->nsyms);
            DARWIN_KIT_LOG(
                "DarwinKit::\tString Table is at offset 0x%x (%u) with size of %u bytes\n",
                symtab_command->stroff, symtab_command->stroff, symtab_command->strsize);
            if (kernel_cache) {
                symtab =
                    reinterpret_cast<xnu::macho::Nlist64*>(kernel_cache + symtab_command->symoff);
                nsyms = symtab_command->nsyms;
                strtab = reinterpret_cast<char*>(kernel_cache + symtab_command->stroff);
                strsize = symtab_command->strsize;
                char buffer1[128];
                char buffer2[128];
                snprintf(buffer1, 128, "0x%llx", (UInt64)symtab);
                snprintf(buffer2, 128, "0x%llx", (UInt64)strtab);
                DARWIN_KIT_LOG("DarwinKit::\tSymbol Table address = %s\n", buffer1);
                DARWIN_KIT_LOG("DarwinKit::\tString Table address = %s\n", buffer2);
            } else if (kernel_collection) {
                symtab = reinterpret_cast<xnu::macho::Nlist64*>(
                    linkedit + (symtab_command->symoff - linkedit_off));
                nsyms = symtab_command->nsyms;
                strtab =
                    reinterpret_cast<char*>(linkedit + (symtab_command->stroff - linkedit_off));
                strsize = symtab_command->strsize;
            } else {
                symtab = nullptr;
                nsyms = 0;
                strtab = nullptr;
                strsize = 0;
            }
            if (nsyms > 0) {
                ParseSymbolTable(symtab, nsyms, strtab, strsize);
            }
            break;
        }
        case LC_DYSYMTAB: {
            ;
            struct dysymtab_command* dysymtab_command =
                reinterpret_cast<struct dysymtab_command*>(load_command);
            if (dysymtab_command->extreloff > size ||
                dysymtab_command->nextrel >
                    (size - dysymtab_command->extreloff) / sizeof(struct relocation_info)) {
                return false;
            }
            DARWIN_KIT_LOG("DarwinKit::LC_DYSYMTAB\n");
            DARWIN_KIT_LOG("DarwinKit::\t%u local symbols at index %u\n",
                           dysymtab_command->ilocalsym, dysymtab_command->nlocalsym);
            DARWIN_KIT_LOG("DarwinKit::\t%u external symbols at index %u\n",
                           dysymtab_command->nextdefsym, dysymtab_command->iextdefsym);
            DARWIN_KIT_LOG("DarwinKit::\t%u undefined symbols at index %u\n",
                           dysymtab_command->nundefsym, dysymtab_command->iundefsym);
            DARWIN_KIT_LOG("DarwinKit::\t%u Indirect symbols at offset 0x%x\n",
                           dysymtab_command->nindirectsyms, dysymtab_command->indirectsymoff);
            break;
        }
        case LC_UUID: {
            ;
            struct uuid_command* uuid_command =
                reinterpret_cast<struct uuid_command*>(load_command);
            if (uuid_command->cmdsize != sizeof(struct uuid_command)) {
                return false;
            }
            DARWIN_KIT_LOG("DarwinKit::LC_UUID\n");
            DARWIN_KIT_LOG("DarwinKit::\tuuid = ");
            for (int j = 0; j < sizeof(uuid_command->uuid); j++) {
                DARWIN_KIT_LOG("%x", uuid_command->uuid[j]);
            }
            DARWIN_KIT_LOG("\n");
            break;
        }
        case LC_FUNCTION_STARTS: {
            ;
            struct linkedit_data_command* linkedit =
                reinterpret_cast<struct linkedit_data_command*>(load_command);
            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;
            DARWIN_KIT_LOG("DarwinKit::LC_FUNCTION_STARTS\n");
            DARWIN_KIT_LOG("DarwinKit::\tOffset = 0x%x Size = 0x%x\n", dataoff, datasize);
            break;
        }
        case LC_MAIN: {
            ;
            struct entry_point_command* ep =
                reinterpret_cast<struct entry_point_command*>(load_command);
            DARWIN_KIT_LOG("DarwinKit::LC_MAIN\n");
            DARWIN_KIT_LOG("DarwinKit::\tEntry Point = 0x%llx\n", base + ep->entryoff);
            entry_point = base + ep->entryoff;
            break;
        }
        case LC_UNIXTHREAD: {
            ;
            struct unixthread_command* thread_command =
                reinterpret_cast<struct unixthread_command*>(load_command);
            // if(thread_command->flavor != ARM_THREAD_STATE64)
            // return false;
            break;
        }

        case LC_DATA_IN_CODE: {
            ;
            struct linkedit_data_command* linkedit =
                reinterpret_cast<struct linkedit_data_command*>(load_command);
            UInt32 dataoff = linkedit->dataoff;
            UInt32 datasize = linkedit->datasize;
            DARWIN_KIT_LOG("DarwinKit::LC_DATA_IN_CODE\n");
            DARWIN_KIT_LOG("DarwinKit::\tOffset = 0x%x Size = 0x%x\n", dataoff, datasize);
            break;
        }
        }
        current_offset += cmdsize;
    }
    return true;
}

void KernelMachO::ParseMachO() {
    MachO::ParseMachO();
}